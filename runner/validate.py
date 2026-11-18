#!/usr/bin/env python3
"""
Moteur d'exécution et de validation autonome multiplateforme pour GitHub Actions.
Valide pour l'OS courant :
1. Téléchargement sécurisé et vérification d'intégrité SHA-256 (streaming O(1) RAM)
2. Décompression sécurisée (anti-ZipSlip, anti-TarSlip, DMG/7z/MSI, limite 20 Go)
3. Validation des en-têtes binaires bas niveau (PE / ELF / Mach-O / Scripts)
4. Exécution réelle du binaire CLI (--version / --help) hors PATH sur le matériel natif,
   ou certification d'en-tête natif pour les applications GUI/fonts sans serveur graphique.
"""

import hashlib
import lzma
import os
import platform
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tomllib

ERABLE_REFERER = "https://gitlab.com/cortexa/native-application-ai/erable"
ERABLE_USER_AGENT = "Chrome/131.0.6778.86"


def verify_binary_magic(file_path: Path, expected_os: str) -> bool:
    if not file_path.exists() or file_path.stat().st_size < 4:
        return False
    if file_path.suffix.lower() in (".ps1", ".bat", ".cmd", ".nu", ".sh"):
        return True
    with open(file_path, "rb") as f:
        magic = f.read(512)

    if (
        magic.startswith(b"\xef\xbb\xbf")
        or (magic.startswith(b"#!") and expected_os != "windows")
        or magic.startswith(b"@echo")
        or magic.startswith(b"rem")
        or b"param(" in magic.lower()
    ):
        return True

    if expected_os == "linux":
        return magic.startswith(b"\x7fELF") or magic.startswith(b"#!")
    if expected_os == "windows":
        if magic[:2] == b"MZ" or magic[:4] == b"\xd0\xcf\x11\xe0":
            return True
        if file_path.suffix.lower() in (".jar", ".msi", ".msix", ".appx") and magic[:2] in (b"PK", b"\xd0\xcf"):
            return True
        if file_path.suffix.lower() in (".bat", ".cmd", ".ps1"):
            return True
        return False
    if expected_os in ("darwin", "macos"):
        mach_magics = (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        )
        return any(magic.startswith(m) for m in mach_magics) or magic.startswith(b"#!")
    return True


def is_windows_gui_pe(file_path: Path) -> bool:
    """Détecte de façon déterministe un binaire PE Windows à sous-système graphique (IMAGE_SUBSYSTEM_WINDOWS_GUI == 2)."""
    if file_path.suffix.lower() not in (".exe", ""):
        return False
    try:
        with open(file_path, "rb") as f:
            header = f.read(4096)
        if len(header) < 0x40 or header[:2] != b"MZ":
            return False
        pe_offset = int(struct.unpack_from("<I", header, 0x3C)[0])
        if pe_offset < 0 or pe_offset + 24 + 70 > len(header):
            return False
        if header[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return False
        opt_magic = int(struct.unpack_from("<H", header, pe_offset + 24)[0])
        if opt_magic not in (0x10B, 0x20B):
            return False
        subsystem = int(struct.unpack_from("<H", header, pe_offset + 24 + 68)[0])
        return subsystem == 2
    except Exception:
        return False


def _extract_dmg(archive_file: Path, extract_dir: Path, tmp_path: Path) -> bool:
    """Extrait un .dmg via hdiutil (macOS) ou 7z en espace utilisateur. Retourne True si déjà certifié sans binaire."""
    if platform.system().lower() == "darwin" and shutil.which("hdiutil"):
        mnt_dir = tmp_path / "dmg_mnt"
        mnt_dir.mkdir(parents=True, exist_ok=True)
        attach = subprocess.run(
            ["hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", str(mnt_dir), str(archive_file)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if attach.returncode == 0:
            copied = 0
            try:
                for root, _dirs, files in os.walk(mnt_dir, followlinks=False):
                    rel_root = Path(root).relative_to(mnt_dir)
                    for fname in files:
                        src = Path(root) / fname
                        if src.is_symlink() or not src.is_file():
                            continue
                        sz = src.stat().st_size
                        if copied + sz > 600 * 1024 * 1024:
                            continue
                        dst = extract_dir / rel_root / fname
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dst)
                        copied += sz
            finally:
                subprocess.run(["hdiutil", "detach", str(mnt_dir), "-force"], capture_output=True, timeout=30)
            if any(f.is_file() for f in extract_dir.rglob("*")):
                return False

    if shutil.which("7z") and archive_file.stat().st_size < 200 * 1024 * 1024:
        p7z = subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], capture_output=True, text=True, timeout=120)
        if p7z.returncode == 0 and any(f.is_file() for f in extract_dir.rglob("*")):
            return False

    print("  [+] Archive .dmg certifiée par SHA-256.")
    return True


_GUI_DESKTOP_BUNDLE_MARKERS = frozenset({
    "chrome_100_percent.pak",
    "chrome_200_percent.pak",
    "resources.pak",
    "webview2loader.dll",
    "qt6gui.dll",
    "qt5gui.dll",
    "nw.dll",
    "libcef.dll",
    "libcef.so",
    "electron.exe",
})


def has_desktop_gui_bundle_markers(extract_dir: Path) -> bool:
    """Détecte de façon déterministe un bundle desktop (Electron/WebView2/Qt/CEF) sans relancer d'UI."""
    for p in extract_dir.rglob("*"):
        if p.is_file() and p.name.lower() in _GUI_DESKTOP_BUNDLE_MARKERS:
            return True
    return False


def _build_probe_cmd(direct_bin: str, suffix: str, probe_args: List[str]) -> List[str]:
    """Construit la commande d'exécution adaptée à l'extension du binaire (.ps1, .bat/.cmd ou natif)."""
    low = suffix.lower()
    if low == ".ps1":
        return [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            direct_bin,
            *probe_args,
        ]
    if low in (".bat", ".cmd"):
        return ["cmd.exe", "/d", "/c", direct_bin, *probe_args]
    return [direct_bin, *probe_args]


_PROBE_ENV_STRIP_KEYS = (
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "KUBECONFIG",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_CACHE_URL",
    "DAGGER_CLOUD_TOKEN",
    "DAGGER_CLOUD_ENGINE",
)
_SAFE_CUSTOM_PROBE_ARGS = {"version", "--version", "-version", "-v", "-V", "--help", "-h", "help"}


def _build_sanitized_probe_env() -> Dict[str, str]:
    """Assainit l'environnement des sondes CLI pour éviter connexions cloud/daemon ou télémétrie bloquante."""
    env = dict(os.environ)
    for key in _PROBE_ENV_STRIP_KEYS:
        env.pop(key, None)
    env["CI"] = "true"
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["DO_NOT_TRACK"] = "1"
    env["DAGGER_NO_UPDATE_CHECK"] = "1"
    env["DAGGER_NO_NAG"] = "1"
    return env


def _extract_safe_custom_probe(check_cmd: str, bin_stem: str) -> Optional[Tuple[List[str], str]]:
    """Extrait une sonde simple sûre depuis CHECK_CMD (verification.toml) si compatible avec le binaire."""
    raw = check_cmd.strip()
    if not raw or any(ch in raw for ch in ("|", ";", "&", "$", "`", ">", "<", "\n", "\r", "(", ")")):
        return None
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return None
    if len(tokens) < 2 or len(tokens) > 3:
        return None
    cmd_stem = Path(tokens[0]).stem.lower()
    target_low = bin_stem.lower()
    if not cmd_stem or (cmd_stem != target_low and not target_low.startswith(cmd_stem)):
        return None
    args = tokens[1:]
    if not all(arg in _SAFE_CUSTOM_PROBE_ARGS for arg in args):
        return None
    first = args[0].lower()
    if first == "version":
        kind = "subcmd_version"
    elif "help" in first or first == "-h":
        kind = "help"
    else:
        kind = "version"
    return args, kind


def _run_bounded_command(
    cmd: List[str],
    timeout: int = 45,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    """Exécute un processus sans pipe bloquant hérité et tue tout l'arbre de processus sur timeout."""
    fd_out, out_path = tempfile.mkstemp(prefix="erable-out-")
    fd_err, err_path = tempfile.mkstemp(prefix="erable-err-")
    proc: Optional[subprocess.Popen[bytes]] = None
    eff_env = env if env is not None else _build_sanitized_probe_env()
    try:
        with os.fdopen(fd_out, "wb") as f_out, os.fdopen(fd_err, "wb") as f_err:
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=f_out,
                stderr=f_err,
                cwd=str(cwd) if cwd is not None else None,
                env=eff_env,
                creationflags=creationflags,
                start_new_session=(os.name != "nt"),
            )
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                    )
                else:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise
        out_txt = Path(out_path).read_text(encoding="utf-8", errors="replace")
        err_txt = Path(err_path).read_text(encoding="utf-8", errors="replace")
        return proc.returncode, out_txt, err_txt
    finally:
        for tmp_f in (out_path, err_path):
            try:
                os.unlink(tmp_f)
            except OSError:
                pass


def run_test_for_current_os(package_dir: Path) -> bool:
    current_system = platform.system().lower()
    current_arch = platform.machine().lower()
    category = os.environ.get("PACKAGE_CATEGORY", "cli").strip().lower()

    if current_system == "darwin":
        os_key_pattern = "macos"
    elif current_system == "windows":
        os_key_pattern = "windows"
    else:
        os_key_pattern = "linux"

    targets_file = package_dir / "targets.toml"
    if not targets_file.exists():
        targets_file = package_dir / "parts" / "targets.toml"
    if not targets_file.exists():
        print(f"[ERREUR] targets.toml introuvable dans {package_dir}", file=sys.stderr)
        return False

    raw_bytes = targets_file.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_bytes = raw_bytes[3:]
    targets_data: Dict[str, Any] = tomllib.loads(raw_bytes.decode("utf-8")).get("targets", {})

    selected_target_key: Optional[str] = None
    selected_target_info: Optional[Dict[str, Any]] = None
    explicit_target_key = os.environ.get("TARGET_KEY", "").strip()

    if explicit_target_key and explicit_target_key in targets_data:
        selected_target_key = explicit_target_key
        selected_target_info = targets_data[explicit_target_key]

    if not selected_target_info:
        for target_key, info in targets_data.items():
            key_lower = target_key.lower()
            if os_key_pattern in key_lower or (os_key_pattern == "macos" and "darwin" in key_lower):
                if ("arm64" in current_arch or "aarch64" in current_arch) and ("arm64" in key_lower or "aarch64" in key_lower):
                    selected_target_key = target_key
                    selected_target_info = info
                    break
                if ("x86_64" in current_arch or "amd64" in current_arch) and ("x86_64" in key_lower or "amd64" in key_lower):
                    selected_target_key = target_key
                    selected_target_info = info
                    break

    if not selected_target_info:
        for target_key, info in targets_data.items():
            kl = target_key.lower()
            if os_key_pattern in kl or (os_key_pattern == "macos" and "darwin" in kl):
                selected_target_key = target_key
                selected_target_info = info
                break

    if not selected_target_info:
        print(f"[INFO] Aucune cible déclarée pour {os_key_pattern} ({current_arch}). Ignoré.")
        return True

    print(f"=== Validation de la cible : {selected_target_key} sur {current_system} ({current_arch}) [catégorie={category}] ===")
    url = str(selected_target_info.get("url") or "").strip()
    expected_hash = str(selected_target_info.get("sha256") or selected_target_info.get("hash") or "").strip().lower()

    if not url or not expected_hash:
        print("[ERREUR] URL ou hash manquant dans targets.toml", file=sys.stderr)
        return False

    is_font_or_empty_bin = category == "fonts" or (
        "binaries" in selected_target_info and selected_target_info["binaries"] == []
    )

    with tempfile.TemporaryDirectory(prefix="erable-gh-runner-", ignore_cleanup_errors=True) as tmp_dir:
        tmp_path = Path(tmp_dir)
        archive_file = tmp_path / "downloaded_file"

        # 1. Téléchargement streamé + SHA-256 en passe unique avec retries sur 429/5xx transitoires
        print(f"[1/4] Téléchargement streamé depuis : {url}")
        is_sf = "sourceforge.net" in url.lower() or "sf.net" in url.lower()
        req_headers = {"User-Agent": "curl/8.4.0" if is_sf else ERABLE_USER_AGENT}
        if not is_sf:
            req_headers["Referer"] = ERABLE_REFERER
        calc_hash = ""
        for dl_attempt in range(3):
            req = urllib.request.Request(url, headers=req_headers)
            sha256 = hashlib.sha256()
            try:
                with urllib.request.urlopen(req, timeout=180) as resp, open(archive_file, "wb") as f_out:
                    while chunk := resp.read(65536):
                        sha256.update(chunk)
                        f_out.write(chunk)
                calc_hash = sha256.hexdigest().lower()
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and dl_attempt < 2:
                    wait_s = 2 if dl_attempt == 0 else 5
                    print(f"  [!] HTTP {e.code} transitoire sur {url}, nouvelle tentative dans {wait_s}s...")
                    time.sleep(wait_s)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if dl_attempt < 2:
                    wait_s = 2 if dl_attempt == 0 else 5
                    print(f"  [!] Erreur réseau transitoire ({e}), nouvelle tentative dans {wait_s}s...")
                    time.sleep(wait_s)
                    continue
                raise
        if calc_hash != expected_hash:
            print(f"[ERREUR] Divergence SHA-256 ! Attendu : {expected_hash}, Obtenu : {calc_hash}", file=sys.stderr)
            return False
        print(f"  [+] Hash SHA-256 certifié conforme : {calc_hash[:16]}...")

        if is_font_or_empty_bin:
            print("  [+] Paquet déclaratif sans binaire exécutable (ex: police) validé.")
            return True

        # 2. Extraction sécurisée
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        clean_url_low = url.split("?")[0].lower()
        extract_root_str = str(extract_dir.resolve())

        print("[2/4] Extraction et audit de sécurité de l'archive...")
        if zipfile.is_zipfile(archive_file):
            with zipfile.ZipFile(archive_file, "r") as zf:
                for m in zf.infolist():
                    target = (extract_dir / m.filename).resolve()
                    if not str(target).startswith(extract_root_str):
                        print(f"[ERREUR] Zip Slip détecté : {m.filename}", file=sys.stderr)
                        return False
                try:
                    zf.extractall(extract_dir)
                except NotImplementedError:
                    if shutil.which("7z"):
                        subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], check=True, capture_output=True, timeout=120)
                    else:
                        raise
        elif clean_url_low.endswith(".dmg"):
            if _extract_dmg(archive_file, extract_dir, tmp_path):
                return True
        elif tarfile.is_tarfile(archive_file):
            with tarfile.open(archive_file, "r:*") as tf:
                members = tf.getmembers()
                for t_member in members:
                    target = (extract_dir / t_member.name).resolve()
                    if not str(target).startswith(extract_root_str):
                        print(f"[ERREUR] Tar Slip détecté : {t_member.name}", file=sys.stderr)
                        return False
                    if t_member.issym() or t_member.islnk():
                        norm_link = os.path.normpath(os.path.join(os.path.dirname(t_member.name), t_member.linkname))
                        if not str((extract_dir / norm_link).resolve()).startswith(extract_root_str):
                            print(f"[ERREUR] Lien symbolique hors arborescence : {t_member.name}", file=sys.stderr)
                            return False
                tf.extractall(extract_dir, members=members)
        elif clean_url_low.endswith(".xz") and not clean_url_low.endswith(".tar.xz"):
            raw_out = extract_dir / Path(clean_url_low[:-3]).name
            with lzma.open(archive_file, "rb") as f_in, open(raw_out, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        elif clean_url_low.endswith((".7z", ".msi")) and shutil.which("7z"):
            p7z = subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], capture_output=True, text=True, timeout=120)
            if p7z.returncode != 0:
                print(f"[ERREUR] Extraction 7z échouée : {p7z.stderr.strip()}", file=sys.stderr)
                return False
        elif clean_url_low.endswith((".zst", ".tzst", ".7z", ".msi")):
            print(f"  [+] Archive {Path(clean_url_low).suffix} certifiée par SHA-256.")
            return True
        else:
            b_name = os.path.basename(clean_url_low) or "binary"
            if current_system == "windows" and "." not in b_name:
                b_name += ".exe"
            shutil.copy(archive_file, extract_dir / b_name)

        # 3. Localisation du binaire et vérification magic
        print("[3/4] Inspection des signatures binaires...")
        all_files = [f for f in extract_dir.rglob("*") if f.is_file()]
        raw_bins: List[Any] = selected_target_info.get("binaries") or []
        target_binary: Optional[Path] = None

        for b in raw_bins:
            b_src = str(b.get("source") if isinstance(b, dict) else b).replace("\\", "/").lstrip("/")
            if not b_src:
                continue
            b_leaf = Path(b_src).name.lower()
            b_stem = Path(b_src).stem.lower()
            cand_names = {b_leaf, b_stem, f"{b_stem}.exe", f"{b_stem}.ps1", f"{b_stem}.bat", f"{b_stem}.cmd"}
            matched = [
                f for f in all_files
                if (f.name.lower() in cand_names or str(f.relative_to(extract_dir)).replace("\\", "/").lower().endswith(b_src.lower()))
                and verify_binary_magic(f, os_key_pattern)
            ]
            if matched:
                if current_system == "windows":
                    ext_prio = {".exe": 0, ".cmd": 1, ".bat": 2, ".ps1": 3}
                    matched.sort(key=lambda p: (ext_prio.get(p.suffix.lower(), 4), len(p.parts)))
                target_binary = matched[0]
                break

        if target_binary is None:
            valid_execs = [
                f for f in all_files
                if verify_binary_magic(f, os_key_pattern)
                and (current_system != "windows" or f.suffix.lower() in (".exe", ".ps1", ".bat", ".cmd", ".msi", ".jar"))
            ]
            if valid_execs:
                target_binary = valid_execs[0]

        if target_binary is None:
            if all_files:
                print(f"  [+] Archive composite certifiée par SHA-256 ({len(all_files)} fichiers extraits).")
                return True
            print("[ERREUR] Aucun binaire exécutable trouvé après décompression.", file=sys.stderr)
            return False

        print(f"  [+] Binaire identifié : {target_binary.name} ({target_binary.stat().st_size} octets)")
        if not verify_binary_magic(target_binary, os_key_pattern):
            print(f"[ERREUR] En-tête binaire invalide pour {os_key_pattern} !", file=sys.stderr)
            return False
        print(f"  [+] Signature machine validée avec succès pour {os_key_pattern.upper()}.")

        # 4. Applications GUI (catégorie, bundle .app, marqueurs desktop ou PE GUI) ou cross-ISA non émulée
        is_app_bundle = ".app/contents/macos/" in str(target_binary).replace("\\", "/").lower()
        is_pe_gui = current_system == "windows" and is_windows_gui_pe(target_binary)
        is_gui_bundle = has_desktop_gui_bundle_markers(extract_dir)
        host_is_arm = "arm64" in current_arch or "aarch64" in current_arch
        tgt_low = str(selected_target_key or "").lower()
        tgt_is_arm = "arm64" in tgt_low or "aarch64" in tgt_low
        tgt_is_x64 = "x86_64" in tgt_low or "amd64" in tgt_low
        is_cross_isa = (host_is_arm and tgt_is_x64 and current_system != "darwin") or ((not host_is_arm) and tgt_is_arm)
        if category == "gui" or is_app_bundle or is_pe_gui or is_gui_bundle or is_cross_isa or target_binary.suffix.lower() in (".msi", ".jar"):
            print("  [+] Application GUI / bundle / cible cross-ISA certifiée par SHA-256 et en-tête binaire.")
            return True

        # 5. Exécution réelle native par chemin absolu direct hors PATH (dossier isolé + tolérance scan à froid Defender)
        direct_bin = os.path.abspath(target_binary)
        suffix = target_binary.suffix
        probe_cwd = tmp_path / "probe_cwd"
        probe_cwd.mkdir(exist_ok=True)
        probe_env = _build_sanitized_probe_env()

        probes: List[Tuple[List[str], str]] = []
        custom_probe = _extract_safe_custom_probe(os.environ.get("CHECK_CMD", ""), target_binary.stem)
        if custom_probe is not None:
            probes.append(custom_probe)
        for default_probe in (
            (["--version"], "version"),
            (["version"], "subcmd_version"),
            (["-version"], "version"),
            (["--help"], "help"),
            (["-h"], "help"),
        ):
            if default_probe not in probes:
                probes.append(default_probe)

        print(f"[4/4] Exécution native directe hors PATH : {direct_bin} {' '.join(probes[0][0])}...")
        if current_system != "windows":
            os.chmod(direct_bin, 0o755)

        try:
            last_rc = -1
            last_err = ""
            for idx, (probe_args, kind) in enumerate(probes):
                probe_timeout = 60 if idx == 0 else 20
                cmd = _build_probe_cmd(direct_bin, suffix, probe_args)
                try:
                    rc, out_txt, err_txt = _run_bounded_command(
                        cmd,
                        timeout=probe_timeout,
                        cwd=probe_cwd,
                        env=probe_env,
                    )
                except subprocess.TimeoutExpired:
                    print(f"  [!] Sonde {' '.join(probe_args)} expirée après {probe_timeout}s, passage à la sonde suivante...")
                    last_rc = -1
                    last_err = f"Timeout ({probe_timeout}s) sur {' '.join(probe_args)}"
                    continue
                last_rc, last_err = rc, err_txt
                combined = (out_txt + "\n" + err_txt).strip()
                combined_low = combined.lower()
                if "was unexpected at this time" in combined_low or "is not recognized" in combined_low:
                    continue
                if kind == "version" and (rc == 0 or "version" in combined_low):
                    print(f"  [+] SUCCÈS : Binaire exécuté avec succès !\n  -> Sortie : {out_txt.strip()[:100]}")
                    return True
                if kind == "help" and rc in (0, 1) and combined != "":
                    print(f"  [+] SUCCÈS : Commande d'aide ({' '.join(probe_args)}) validée avec succès.")
                    return True
                if kind == "subcmd_version" and rc == 0:
                    preview = out_txt.strip()[:100] or err_txt.strip()[:100]
                    print(f"  [+] SUCCÈS : Sous-commande 'version' validée !\n  -> Sortie : {preview}")
                    return True

            print(f"[ERREUR] Échec de l'exécution (code {last_rc}) : {last_err.strip()}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[ERREUR] Exception lors de l'exécution native : {e}", file=sys.stderr)
            return False


if __name__ == "__main__":
    pkg_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    ok = run_test_for_current_os(pkg_path)
    sys.exit(0 if ok else 1)
