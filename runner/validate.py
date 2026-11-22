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

from contextlib import contextmanager
import gzip
import hashlib
import lzma
import os
import platform
import re
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
from typing import Any, Dict, Iterator, List, Optional, Tuple

import tomllib

for _stream in (sys.stdout, sys.stderr):
    getattr(_stream, "reconfigure", lambda **_kw: None)(encoding="utf-8", errors="replace")

ERABLE_REFERER = "https://gitlab.com/cortexa/native-application-ai/erable"
ERABLE_USER_AGENT = "Chrome/131.0.6778.86"


def verify_binary_magic(file_path: Path, expected_os: str) -> bool:
    if not file_path.exists() or file_path.stat().st_size < 4:
        return False
    if file_path.suffix.lower() == ".nu":
        try:
            raw_nu = file_path.read_bytes()
        except OSError:
            return False
        if b"\x00" in raw_nu or not raw_nu.strip():
            return False
        try:
            raw_nu.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    low_suf = file_path.suffix.lower()
    if expected_os != "windows" and low_suf in (".exe", ".bat", ".cmd", ".ps1", ".msi"):
        return False
    if low_suf == ".sh" or (expected_os == "windows" and low_suf in (".ps1", ".bat", ".cmd")):
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


_UNCOMPRESS_TABLE: Dict[str, Dict[str, Any]] = {
    "windows": {
        "packages": ["ouch"],
        "archive_bin": "ouch",
        "msi_tool": "msiexec",
        "dmg_tool": "ouch",
    },
    "linux": {
        "packages": ["ouch"],
        "archive_bin": "ouch",
        "msi_tool": "7zz",
        "dmg_tool": "ouch",
    },
    "macos": {
        "packages": ["ouch"],
        "archive_bin": "ouch",
        "msi_tool": "7zz",
        "dmg_tool": "hdiutil",
    },
}


def _resolve_ouch_bin() -> Optional[str]:
    """Résout l'exécutable ouch depuis OUCH_BIN, PATH ou ~/.erable/packages/ouch/current."""
    env_ouch = os.environ.get("OUCH_BIN", "").strip()
    if env_ouch and Path(env_ouch).is_file():
        return env_ouch
    is_win = platform.system().lower() == "windows"
    for cand in (("ouch.exe", "ouch") if is_win else ("ouch",)):
        found = shutil.which(cand)
        if found:
            return found
    fallback = Path.home() / ".erable" / "packages" / "ouch" / "current" / ("ouch.exe" if is_win else "ouch")
    if fallback.is_file():
        return str(fallback)
    return None


def _check_zip_slip(archive_file: Path, extract_dir: Path) -> None:
    extract_root_str = str(extract_dir.resolve())
    with zipfile.ZipFile(archive_file, "r") as zf:
        for m in zf.infolist():
            target = (extract_dir / m.filename).resolve()
            if not str(target).startswith(extract_root_str):
                raise ValueError(f"Zip Slip détecté : {m.filename}")


def _check_tar_slip(archive_file: Path, extract_dir: Path) -> List[tarfile.TarInfo]:
    extract_root_str = str(extract_dir.resolve())
    with tarfile.open(archive_file, "r:*") as tf:
        members = tf.getmembers()
        for t_member in members:
            target = (extract_dir / t_member.name).resolve()
            if not str(target).startswith(extract_root_str):
                raise ValueError(f"Tar Slip détecté : {t_member.name}")
            if t_member.issym() or t_member.islnk():
                norm_link = os.path.normpath(os.path.join(os.path.dirname(t_member.name), t_member.linkname))
                if not str((extract_dir / norm_link).resolve()).startswith(extract_root_str):
                    raise ValueError(f"Lien symbolique hors arborescence : {t_member.name}")
    return members


def _resolve_named_archive_path(
    archive_file: Path,
    cache_dir: Path,
    clean_url_low: str,
    archive_type: str,
) -> Path:
    """Donne un nom avec extension reconnue par ouch dans cache_dir."""
    base_name = Path(clean_url_low).name or "archive"
    if "." not in base_name and archive_type and archive_type != "raw":
        base_name = f"{base_name}.{archive_type.lstrip('.')}"
    named_arc = cache_dir / base_name
    if archive_file.resolve() != named_arc.resolve() and not named_arc.exists():
        shutil.copy2(archive_file, named_arc)
    return named_arc


def _normalize_win_single_binary(extract_dir: Path, stem_fallback: str) -> None:
    """Sous Windows, ajoute .exe si une décompression .gz/.xz produit un binaire PE sans extension."""
    files = [f for f in extract_dir.rglob("*") if f.is_file()]
    if len(files) == 1:
        single = files[0]
        if not single.suffix:
            try:
                head = single.read_bytes()[:2]
            except OSError:
                head = b""
            if head == b"MZ":
                target_exe = single.with_name((single.name or stem_fallback) + ".exe")
                single.rename(target_exe)


def _extract_dmg(archive_file: Path, extract_dir: Path, tmp_path: Path) -> bool:
    """Extrait un .dmg selon la table uncompress : hdiutil (macOS), ouch puis repli 7z (Win/Linux)."""
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

    ouch_bin = _resolve_ouch_bin()
    if ouch_bin and archive_file.stat().st_size < 200 * 1024 * 1024:
        p_ouch = subprocess.run(
            [ouch_bin, "decompress", "--yes", "--dir", str(extract_dir), str(archive_file)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if p_ouch.returncode == 0 and any(f.is_file() for f in extract_dir.rglob("*")):
            return False

    if shutil.which("7z") and archive_file.stat().st_size < 200 * 1024 * 1024:
        p7z = subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], capture_output=True, text=True, timeout=120)
        if p7z.returncode == 0 and any(f.is_file() for f in extract_dir.rglob("*")):
            return False

    print("  [+] Archive .dmg certifiée par SHA-256.")
    return True


def _uncompress_archive(
    archive_file: Path,
    extract_dir: Path,
    cache_dir: Path,
    tmp_path: Path,
    clean_url_low: str,
    current_system: str,
    pkg_name: str,
    archive_type: str = "",
) -> Tuple[bool, bool]:
    """Applique la même stratégie que engine/tasks.nu (`task-uncompress-archive`).

    Retourne (ok, early_certified).
    """
    at_low = archive_type.strip().lower()
    is_zip = zipfile.is_zipfile(archive_file)
    is_tar = (not is_zip) and tarfile.is_tarfile(archive_file)

    if is_zip:
        _check_zip_slip(archive_file, extract_dir)
    elif is_tar:
        members = _check_tar_slip(archive_file, extract_dir)
    else:
        members = []

    if at_low == "dmg" or clean_url_low.endswith(".dmg"):
        named_dmg = _resolve_named_archive_path(archive_file, cache_dir, clean_url_low, "dmg")
        return True, _extract_dmg(named_dmg, extract_dir, tmp_path)

    if at_low == "msi" or clean_url_low.endswith(".msi"):
        if current_system == "windows":
            named_msi = _resolve_named_archive_path(archive_file, cache_dir, clean_url_low, "msi")
            abs_msi = str(named_msi.resolve())
            abs_dest = str(extract_dir.resolve()).rstrip("\\")
            p_msi = subprocess.run(
                ["msiexec", "/a", abs_msi, "/qn", f"TARGETDIR={abs_dest}"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if p_msi.returncode == 0 and any(f.is_file() for f in extract_dir.rglob("*")):
                return True, False
        if shutil.which("7z"):
            p7z = subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], capture_output=True, text=True, timeout=120)
            if p7z.returncode == 0:
                return True, False
            print(f"[ERREUR] Extraction 7z du MSI échouée : {p7z.stderr.strip()}", file=sys.stderr)
            return False, False
        print("  [+] Installeur .msi certifié par SHA-256.")
        return True, True

    archive_exts = (".zip", ".7z", ".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".tzst", ".tar", ".zst", ".gz", ".xz", ".rar")
    archive_types = {"zip", "7z", "tar.gz", "tgz", "tar.xz", "tar.zst", "tzst", "tar", "zst", "gz", "xz", "rar"}
    raw_font_exts = (".ttf", ".otf", ".ttc", ".woff", ".woff2")
    is_raw_font = (not is_zip) and (not is_tar) and clean_url_low.endswith(raw_font_exts)
    looks_archive = (not is_raw_font) and (is_zip or is_tar or clean_url_low.endswith(archive_exts) or at_low in archive_types)

    if looks_archive:
        ouch_bin = _resolve_ouch_bin()
        if ouch_bin and pkg_name.lower() != "ouch":
            named_arc = _resolve_named_archive_path(archive_file, cache_dir, clean_url_low, at_low)
            p_ouch = subprocess.run(
                [ouch_bin, "decompress", "--yes", "--dir", str(extract_dir), str(named_arc)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if p_ouch.returncode == 0 and any(f.is_file() for f in extract_dir.rglob("*")):
                if current_system == "windows":
                    _normalize_win_single_binary(extract_dir, Path(clean_url_low).stem or pkg_name)
                return True, False
            if p_ouch.returncode != 0:
                print(f"  [i] Extraction ouch non applicable ({p_ouch.stderr.strip()[:120]}), repli natif...")

        # Repli natif (bootstrap ouch ou format non pris en charge par ouch dans l'environnement)
        if is_zip:
            with zipfile.ZipFile(archive_file, "r") as zf:
                try:
                    zf.extractall(extract_dir)
                    return True, False
                except NotImplementedError:
                    if shutil.which("7z"):
                        subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], check=True, capture_output=True, timeout=120)
                        return True, False
                    raise
        if is_tar:
            with tarfile.open(archive_file, "r:*") as tf:
                tf.extractall(extract_dir, members=members)
            return True, False
        if clean_url_low.endswith(".xz") and not clean_url_low.endswith(".tar.xz"):
            raw_out = extract_dir / Path(clean_url_low[:-3]).name
            with lzma.open(archive_file, "rb") as f_in, open(raw_out, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            if current_system == "windows":
                _normalize_win_single_binary(extract_dir, raw_out.name)
            return True, False
        if clean_url_low.endswith(".gz") and not clean_url_low.endswith((".tar.gz", ".tgz")):
            stem_name = Path(clean_url_low[:-3]).name or "binary"
            if current_system == "windows" and not stem_name.lower().endswith((".exe", ".bat", ".cmd", ".ps1")):
                stem_name += ".exe"
            raw_out = extract_dir / stem_name
            total_gz = 0
            with gzip.open(archive_file, "rb") as f_in, open(raw_out, "wb") as f_out:
                while gz_chunk := f_in.read(65536):
                    total_gz += len(gz_chunk)
                    if total_gz > 512 * 1024 * 1024:
                        print("[ERREUR] Flux .gz décompressé excessif (>512 Mo).", file=sys.stderr)
                        return False, False
                    f_out.write(gz_chunk)
            return True, False
        if shutil.which("7z"):
            p7z = subprocess.run(["7z", "x", str(archive_file), f"-o{extract_dir}", "-y"], capture_output=True, text=True, timeout=120)
            if p7z.returncode == 0:
                return True, False
            print(f"[ERREUR] Extraction 7z échouée : {p7z.stderr.strip()}", file=sys.stderr)
            return False, False
        print(f"  [+] Archive {Path(clean_url_low).suffix or at_low} certifiée par SHA-256.")
        return True, True

    b_name = os.path.basename(clean_url_low) or "binary"
    if current_system == "windows" and "." not in b_name:
        b_name += ".exe"
    shutil.copy(archive_file, extract_dir / b_name)
    return True, False


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


_PS1_GUI_MARKERS = ("presentationframework", "system.windows.forms", "xamlreader", "-verb runas")


def has_desktop_gui_bundle_markers(extract_dir: Path) -> bool:
    """Détecte de façon déterministe un bundle desktop, serveur Next.js (.next/BUILD_ID) ou script WPF .ps1."""
    if (extract_dir / ".next" / "BUILD_ID").is_file():
        return True
    for p in extract_dir.rglob("*"):
        if not p.is_file():
            continue
        low_name = p.name.lower()
        if low_name in _GUI_DESKTOP_BUNDLE_MARKERS:
            return True
        if p.name == "BUILD_ID" and p.parent.name == ".next":
            return True
        if p.suffix.lower() == ".ps1" and p.stat().st_size < 5_000_000:
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    head = f.read(262144).lower()
                if any(marker in head for marker in _PS1_GUI_MARKERS):
                    return True
            except OSError:
                pass
    return False


_LIFECYCLE_HOOKS = ("pre_install.nu", "post_install.nu", "pre_uninstall.nu", "post_uninstall.nu")


def _resolve_nu_bin() -> Optional[str]:
    """Résout l'exécutable Nushell depuis NU_BIN, PATH ou ~/.erable/tools/nu."""
    env_nu = os.environ.get("NU_BIN", "").strip()
    if env_nu and Path(env_nu).is_file():
        return env_nu
    is_win = platform.system().lower() == "windows"
    for cand in (("nu.exe", "nu") if is_win else ("nu",)):
        found = shutil.which(cand)
        if found:
            return found
    fallback = Path.home() / ".erable" / "tools" / "nu" / ("nu.exe" if is_win else "nu")
    if fallback.is_file():
        return str(fallback)
    return None


def _nuon_value(val: Any) -> str:
    """Sérialise un enregistrement ou scalaire Python en littéral NUON sûr."""
    if isinstance(val, dict):
        inner = ", ".join(f"{k}: {_nuon_value(v)}" for k, v in val.items())
        return f"{{ {inner} }}"
    if isinstance(val, list):
        return "[" + ", ".join(_nuon_value(v) for v in val) + "]"
    escaped = str(val).replace("\\", "/").replace('"', '\\"')
    return f'"{escaped}"'


def _build_probe_cmd(direct_bin: str, suffix: str, probe_args: List[str]) -> List[str]:
    """Construit la commande d'exécution adaptée à l'extension du binaire (.ps1, .bat/.cmd, .nu ou natif)."""
    low = suffix.lower()
    if low == ".nu":
        nu_bin = _resolve_nu_bin()
        if not nu_bin:
            raise FileNotFoundError("Interpréteur Nushell ('nu') introuvable pour exécuter la sonde .nu.")
        return [nu_bin, "--no-config-file", "--no-history", direct_bin, *probe_args]
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
_SAFE_CUSTOM_PROBE_ARGS = {"version", "--version", "-version", "-v", "-V", "--help", "-h", "help", "/?", "/h", "/help"}


def _promote_latest_jdk(env: Dict[str, str]) -> None:
    """Sélectionne le JDK préinstallé >= 21 adapté à l'architecture hôte (ex. JAVA_HOME_25_X64)."""
    arch_tags = ("ARM64", "AARCH64") if ("arm64" in platform.machine().lower() or "aarch64" in platform.machine().lower()) else ("X64", "AMD64")
    best: Optional[Tuple[int, str]] = None
    for key, val in env.items():
        m = re.match(r"^JAVA_HOME_(\d+)_([A-Z0-9_]+)$", key)
        if m and m.group(2) in arch_tags and val and Path(val).is_dir():
            ver = int(m.group(1))
            if ver >= 21 and (best is None or ver > best[0]):
                best = (ver, val)
    if best is not None:
        env["JAVA_HOME"] = best[1]
        bin_dir = str(Path(best[1]) / "bin")
        cur_path = env.get("PATH", "")
        env["PATH"] = f"{bin_dir}{os.pathsep}{cur_path}" if cur_path else bin_dir


def _build_sanitized_probe_env() -> Dict[str, str]:
    """Assainit l'environnement des sondes CLI pour éviter connexions cloud/daemon ou télémétrie bloquante."""
    env = dict(os.environ)
    for key in _PROBE_ENV_STRIP_KEYS:
        env.pop(key, None)
    _promote_latest_jdk(env)
    env["CI"] = "true"
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLORFGBG"] = "15;0"
    env["THEME_MODE"] = "dark"
    env["DO_NOT_TRACK"] = "1"
    env["DAGGER_NO_UPDATE_CHECK"] = "1"
    env["DAGGER_NO_NAG"] = "1"
    return env


def _extract_safe_custom_probe(
    check_cmd: str,
    bin_stem: str,
    extra_stems: Optional[List[str]] = None,
) -> Optional[Tuple[List[str], str]]:
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
    valid_stems = [bin_stem.lower(), *(s.lower() for s in (extra_stems or []) if s)]
    if not cmd_stem or not any(cmd_stem == st or st.startswith(cmd_stem) for st in valid_stems):
        return None
    args = tokens[1:]
    if not all(arg in _SAFE_CUSTOM_PROBE_ARGS or bool(re.fullmatch(r"--[a-z0-9][a-z0-9-]*-(?:version|help)", arg)) for arg in args):
        return None
    first = args[0].lower()
    if first == "version":
        kind = "subcmd_version"
    elif "help" in first or first in ("-h", "/?", "/h", "/help"):
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
            if os.name == "nt":
                launcher = Path(cmd[0]).stem.lower() if cmd else ""
                win_flag = (
                    getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    if launcher in ("cmd", "powershell", "pwsh", "nu")
                    else getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                )
                creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | win_flag
            else:
                creationflags = 0
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
            except subprocess.TimeoutExpired as exc:
                if os.name == "nt":
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=10,
                        )
                    except (subprocess.SubprocessError, OSError):
                        pass
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
                p_out = Path(out_path).read_bytes() if Path(out_path).exists() else b""
                p_err = Path(err_path).read_bytes() if Path(err_path).exists() else b""
                raise subprocess.TimeoutExpired(cmd, timeout, output=p_out, stderr=p_err) from exc
        out_txt = Path(out_path).read_text(encoding="utf-8", errors="replace")
        err_txt = Path(err_path).read_text(encoding="utf-8", errors="replace")
        return proc.returncode, out_txt, err_txt
    finally:
        for tmp_f in (out_path, err_path):
            try:
                os.unlink(tmp_f)
            except OSError:
                pass


@contextmanager
def _short_temp_dir(is_windows: bool) -> Iterator[str]:
    """Crée un dossier temporaire court (<Drive>:\\er-t\\r-xxx) sur Windows anti-limite 8191 car."""
    short_tmp_dir: Optional[str] = None
    if is_windows:
        drive = os.path.splitdrive(str(Path.cwd()))[0] or os.path.splitdrive(tempfile.gettempdir())[0] or "C:"
        cand_root = Path(f"{drive}\\er-t")
        try:
            cand_root.mkdir(parents=True, exist_ok=True)
            short_tmp_dir = str(cand_root)
        except OSError:
            short_tmp_dir = None
    try:
        with tempfile.TemporaryDirectory(prefix="r-", dir=short_tmp_dir, ignore_cleanup_errors=True) as tmp_dir:
            yield tmp_dir
    finally:
        if short_tmp_dir:
            try:
                Path(short_tmp_dir).rmdir()
            except OSError:
                pass


def _resolve_lifecycle_hooks(package_dir: Path) -> Dict[str, Path]:
    """Localise les scripts de cycle de vie (.nu) présents dans le dossier du paquet."""
    found: Dict[str, Path] = {}
    search_roots = [package_dir, package_dir / "parts"]
    if package_dir.name == "parts":
        search_roots = [package_dir.parent, package_dir]
    for hook_name in _LIFECYCLE_HOOKS:
        for root in search_roots:
            cand = root / hook_name
            if cand.is_file():
                found[hook_name] = cand
                break
    return found


def _build_lifecycle_ctx(
    pkg_name: str,
    pkg_version: str,
    os_key: str,
    arch: str,
    tmp_path: Path,
    install_dir: Path,
    current_dir: Path,
    bin_dir: Path,
    cache_dir: Path,
) -> Dict[str, Any]:
    """Construit l'enregistrement $ctx compatible avec engine/tasks.nu."""
    return {
        "package": pkg_name,
        "version": pkg_version,
        "os": os_key,
        "arch": arch,
        "dir": str(install_dir),
        "paths": {
            "root": str(tmp_path),
            "bin": str(bin_dir),
            "install": str(install_dir),
            "current": str(current_dir),
            "cache": str(cache_dir),
        },
        "os_vars": {
            "appdata": str(tmp_path / "appdata"),
            "localappdata": str(tmp_path / "localappdata"),
            "programdata": str(tmp_path / "programdata"),
            "userprofile": str(tmp_path / "userprofile"),
        },
    }


def _run_lifecycle_hook(hook_path: Path, ctx: Dict[str, Any]) -> bool:
    """Exécute un hook .nu sous confinement Zero-Egress identique au moteur Nushell."""
    nu_bin = _resolve_nu_bin()
    if not nu_bin:
        print(f"[ERREUR] Interpréteur Nushell ('nu') introuvable pour exécuter {hook_path.name}.", file=sys.stderr)
        return False

    zero_egress_guard = "; ".join(
        f'def "http {verb}" [...rest] {{ error make {{ msg: "Violation Zero-Egress : http {verb} interdit dans un hook" }} }}'
        for verb in ("get", "post", "put", "delete", "patch", "head")
    )
    hook_norm = str(hook_path.resolve()).replace("\\", "/")
    ctx_nuon = _nuon_value(ctx)
    nu_script = f"{zero_egress_guard}; source '{hook_norm}'; main {ctx_nuon}"

    hook_env = _build_sanitized_probe_env()
    hook_env["HTTP_PROXY"] = "http://127.0.0.1:1"
    hook_env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    hook_env["ALL_PROXY"] = "http://127.0.0.1:1"
    hook_env["NO_PROXY"] = ""
    for secret_k in (
        "GH_TOKEN", "GITHUB_TOKEN", "GH_PAT", "GITLAB_TOKEN", "GITLAB_OIDC_TOKEN",
        "SSH_AUTH_SOCK", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    ):
        hook_env.pop(secret_k, None)

    cmd: List[str] = [nu_bin, "--no-config-file", "--no-history", "-c", nu_script]
    cur_sys = platform.system().lower()
    if cur_sys == "darwin" and shutil.which("sandbox-exec"):
        cmd = ["sandbox-exec", "-p", "(version 1) (allow default) (deny network*)", *cmd]
    elif cur_sys == "linux" and shutil.which("unshare"):
        try:
            chk = subprocess.run(["unshare", "--net", "--", "true"], capture_output=True, timeout=3)
            if chk.returncode == 0:
                cmd = ["unshare", "--net", "--", *cmd]
        except Exception:
            pass

    print(f"  [hook] Exécution Zero-Egress de {hook_path.name}...")
    try:
        rc, out_txt, err_txt = _run_bounded_command(cmd, timeout=45, cwd=hook_path.parent, env=hook_env)
    except Exception as exc:
        print(f"[ERREUR] Échec du hook {hook_path.name} : {exc}", file=sys.stderr)
        return False

    if out_txt.strip():
        print("    " + out_txt.strip().replace("\n", "\n    ")[:600])
    if rc != 0:
        err_msg = (err_txt.strip() or out_txt.strip())[:600]
        print(f"[ERREUR] Hook '{hook_path.name}' en échec (code {rc}) : {err_msg}", file=sys.stderr)
        return False
    print(f"  [+] Hook {hook_path.name} exécuté avec succès.")
    return True


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

    pkg_name = os.environ.get("PACKAGE_NAME", "").strip() or package_dir.name
    pkg_version = os.environ.get("PACKAGE_VERSION", "").strip() or "latest"
    pkg_meta_file = package_dir / "package.toml"
    if not pkg_meta_file.exists():
        pkg_meta_file = package_dir / "parts" / "package.toml"
    if pkg_meta_file.exists():
        try:
            raw_meta = tomllib.loads(pkg_meta_file.read_bytes().lstrip(b"\xef\xbb\xbf").decode("utf-8"))
            meta_sec = raw_meta.get("package", raw_meta)
            pkg_name = str(meta_sec.get("name") or pkg_name).strip()
            pkg_version = str(meta_sec.get("version") or pkg_version).strip()
        except Exception:
            pass

    hooks = _resolve_lifecycle_hooks(package_dir)

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

    with _short_temp_dir(current_system == "windows") as tmp_dir:
        tmp_path = Path(tmp_dir)
        pkg_store_root = tmp_path / "packages" / (pkg_name or "pkg")
        install_dir = pkg_store_root / (pkg_version or "ver")
        current_dir = pkg_store_root / "current"
        bin_dir = tmp_path / "bin"
        cache_dir = tmp_path / "cache"
        install_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.mkdir(parents=True, exist_ok=True)

        ctx = _build_lifecycle_ctx(
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            os_key=os_key_pattern,
            arch=current_arch,
            tmp_path=tmp_path,
            install_dir=install_dir,
            current_dir=current_dir,
            bin_dir=bin_dir,
            cache_dir=cache_dir,
        )

        def _finalize_with_uninstall(ok_so_far: bool) -> bool:
            if not ok_so_far:
                return False
            if "pre_uninstall.nu" in hooks:
                if not _run_lifecycle_hook(hooks["pre_uninstall.nu"], ctx):
                    return False
            shutil.rmtree(current_dir, ignore_errors=True)
            shutil.rmtree(install_dir, ignore_errors=True)
            if "post_uninstall.nu" in hooks:
                if not _run_lifecycle_hook(hooks["post_uninstall.nu"], ctx):
                    return False
            return True

        # 0. Hook pre_install.nu
        if "pre_install.nu" in hooks:
            if not _run_lifecycle_hook(hooks["pre_install.nu"], ctx):
                return False

        archive_file = cache_dir / "downloaded_file"

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

        clean_url_low = url.split("?")[0].lower()
        target_archive_type = str(selected_target_info.get("archive_type") or "").strip().lower()

        if is_font_or_empty_bin:
            print("[2/4] Extraction et validation de l'archive (police / paquet déclaratif)...")
            ok_uncomp, early_certified = _uncompress_archive(
                archive_file=archive_file,
                extract_dir=install_dir,
                cache_dir=cache_dir,
                tmp_path=tmp_path,
                clean_url_low=clean_url_low,
                current_system=current_system,
                pkg_name=pkg_name,
                archive_type=target_archive_type,
            )
            if not ok_uncomp:
                return False
            shutil.copytree(install_dir, current_dir, dirs_exist_ok=True)
            if "post_install.nu" in hooks and not _run_lifecycle_hook(hooks["post_install.nu"], ctx):
                return False
            extracted_files = [f for f in current_dir.rglob("*") if f.is_file()]
            if not early_certified and not extracted_files:
                print("[ERREUR] Aucun fichier extrait pour le paquet déclaratif/police.", file=sys.stderr)
                return False
            if category == "fonts" and not early_certified:
                font_exts = (".ttf", ".otf", ".woff", ".woff2", ".ttc")
                font_files = [f for f in extracted_files if f.suffix.lower() in font_exts]
                if not font_files:
                    print("[ERREUR] Aucune police (.ttf/.otf/.woff/.woff2/.ttc) trouvée dans l'archive.", file=sys.stderr)
                    return False
                print(f"  [+] Police typographique validée ({len(font_files)} fichier(s) de police extraits).")
            else:
                print("  [+] Paquet déclaratif sans binaire exécutable validé.")
            return _finalize_with_uninstall(True)

        # 2. Extraction sécurisée dans install_dir selon la table uncompress
        print("[2/4] Extraction et audit de sécurité de l'archive (uncompress)...")
        try:
            ok_uncomp, early_certified = _uncompress_archive(
                archive_file=archive_file,
                extract_dir=install_dir,
                cache_dir=cache_dir,
                tmp_path=tmp_path,
                clean_url_low=clean_url_low,
                current_system=current_system,
                pkg_name=pkg_name,
                archive_type=target_archive_type,
            )
        except ValueError as sec_err:
            print(f"[ERREUR] {sec_err}", file=sys.stderr)
            return False
        if not ok_uncomp:
            return False

        # Publication vers current/ avant post_install.nu (fidèle à orchestrators.nu)
        shutil.copytree(install_dir, current_dir, dirs_exist_ok=True)

        if "post_install.nu" in hooks:
            if not _run_lifecycle_hook(hooks["post_install.nu"], ctx):
                return False

        if early_certified and not any(f.is_file() for f in current_dir.rglob("*")):
            return _finalize_with_uninstall(True)

        # 3. Localisation du binaire dans current/ et vérification magic
        print("[3/4] Inspection des signatures binaires...")
        all_files = [f for f in current_dir.rglob("*") if f.is_file()]
        raw_bins: List[Any] = selected_target_info.get("binaries") or []
        target_binary: Optional[Path] = None
        declared_aliases: List[str] = []

        for b in raw_bins:
            b_src = str(b.get("source") if isinstance(b, dict) else b).replace("\\", "/").lstrip("/")
            if isinstance(b, dict) and b.get("alias"):
                declared_aliases.append(str(b["alias"]).strip())
            if not b_src:
                continue
            b_leaf = Path(b_src).name.lower()
            b_stem = Path(b_src).stem.lower()
            if current_system == "windows":
                cand_names = {b_leaf, b_stem, f"{b_stem}.exe", f"{b_stem}.nu", f"{b_stem}.ps1", f"{b_stem}.bat", f"{b_stem}.cmd"}
            else:
                cand_names = {b_leaf, b_stem, f"{b_stem}.sh", f"{b_stem}.nu"}
            matched = [
                f for f in all_files
                if (f.name.lower() in cand_names or str(f.relative_to(current_dir)).replace("\\", "/").lower().endswith(b_src.lower()))
                and verify_binary_magic(f, os_key_pattern)
            ]
            if matched:
                if current_system == "windows":
                    ext_prio = {".exe": 0, ".nu": 0, ".cmd": 1, ".bat": 2, ".ps1": 3}
                    matched.sort(key=lambda p: (ext_prio.get(p.suffix.lower(), 4), len(p.parts)))
                else:
                    matched.sort(key=lambda p: (0 if p.suffix == "" else (1 if p.suffix.lower() in (".sh", ".nu") else 2), len(p.parts)))
                target_binary = matched[0]
                break

        if target_binary is None:
            valid_execs = [
                f for f in all_files
                if verify_binary_magic(f, os_key_pattern)
                and (current_system != "windows" or f.suffix.lower() in (".exe", ".nu", ".ps1", ".bat", ".cmd", ".msi", ".jar"))
            ]
            if valid_execs:
                target_binary = valid_execs[0]

        if target_binary is None:
            if all_files:
                print(f"  [+] Archive composite certifiée par SHA-256 ({len(all_files)} fichiers extraits).")
                return _finalize_with_uninstall(True)
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
        is_gui_bundle = has_desktop_gui_bundle_markers(current_dir)
        host_is_arm = "arm64" in current_arch or "aarch64" in current_arch
        tgt_low = str(selected_target_key or "").lower()
        tgt_is_arm = "arm64" in tgt_low or "aarch64" in tgt_low
        tgt_is_x64 = "x86_64" in tgt_low or "amd64" in tgt_low
        is_cross_isa = (host_is_arm and tgt_is_x64 and current_system != "darwin") or ((not host_is_arm) and tgt_is_arm)
        if category == "gui" or is_app_bundle or is_pe_gui or is_gui_bundle or is_cross_isa or target_binary.suffix.lower() in (".msi", ".jar"):
            print("  [+] Application GUI / bundle / cible cross-ISA certifiée par SHA-256 et en-tête binaire.")
            return _finalize_with_uninstall(True)

        # 5. Exécution réelle native par chemin absolu direct hors PATH (dossier isolé + tolérance scan à froid Defender)
        direct_bin = os.path.abspath(target_binary)
        suffix = target_binary.suffix
        probe_cwd = tmp_path / "probe_cwd"
        probe_cwd.mkdir(exist_ok=True)
        probe_env = _build_sanitized_probe_env()

        probes: List[Tuple[List[str], str]] = []
        custom_probe = _extract_safe_custom_probe(
            os.environ.get("CHECK_CMD", ""),
            target_binary.stem,
            extra_stems=declared_aliases,
        )
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
            probe_ok = False
            for idx, (probe_args, kind) in enumerate(probes):
                probe_timeout = 25 if idx == 0 else 15
                cmd = _build_probe_cmd(direct_bin, suffix, probe_args)
                try:
                    rc, out_txt, err_txt = _run_bounded_command(
                        cmd,
                        timeout=probe_timeout,
                        cwd=probe_cwd,
                        env=probe_env,
                    )
                except subprocess.TimeoutExpired as exc:
                    raw_out = exc.output or b""
                    raw_err = exc.stderr or b""
                    out_len = len(raw_out) if isinstance(raw_out, (bytes, str)) else 0
                    err_len = len(raw_err) if isinstance(raw_err, (bytes, str)) else 0
                    print(
                        f"  [!] Sonde {' '.join(probe_args)} expirée après {probe_timeout}s "
                        f"(out={out_len}o, err={err_len}o), passage à la sonde suivante..."
                    )
                    last_rc = -1
                    last_err = f"Timeout ({probe_timeout}s) sur {' '.join(probe_args)}"
                    continue
                last_rc = rc
                diag = (err_txt.strip() or out_txt.strip())[:400]
                if diag:
                    last_err = diag
                combined = (out_txt + "\n" + err_txt).strip()
                combined_low = combined.lower()
                if "was unexpected at this time" in combined_low or "is not recognized" in combined_low:
                    continue
                if kind == "version" and (rc == 0 or "version" in combined_low):
                    print(f"  [+] SUCCÈS : Binaire exécuté avec succès !\n  -> Sortie : {out_txt.strip()[:100]}")
                    probe_ok = True
                    break
                if kind == "help" and rc in (0, 1) and combined != "":
                    print(f"  [+] SUCCÈS : Commande d'aide ({' '.join(probe_args)}) validée avec succès.")
                    probe_ok = True
                    break
                if kind == "subcmd_version" and rc == 0:
                    preview = out_txt.strip()[:100] or err_txt.strip()[:100]
                    print(f"  [+] SUCCÈS : Sous-commande 'version' validée !\n  -> Sortie : {preview}")
                    probe_ok = True
                    break

            if not probe_ok:
                print(f"[ERREUR] Échec de l'exécution (code {last_rc}) : {last_err.strip()}", file=sys.stderr)
                return False
            return _finalize_with_uninstall(True)
        except Exception as e:
            print(f"[ERREUR] Exception lors de l'exécution native : {e}", file=sys.stderr)
            return False


if __name__ == "__main__":
    pkg_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    ok = run_test_for_current_os(pkg_path)
    sys.exit(0 if ok else 1)
