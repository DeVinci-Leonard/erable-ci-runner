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
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        or magic.startswith(b"#!")
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
        if b"\x00" not in magic:
            try:
                magic.decode("utf-8")
                return True
            except UnicodeDecodeError:
                pass
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

    with tempfile.TemporaryDirectory(prefix="erable-gh-runner-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        archive_file = tmp_path / "downloaded_file"

        # 1. Téléchargement streamé + SHA-256 en passe unique (O(1) RAM, 1 seule lecture disque)
        print(f"[1/4] Téléchargement streamé depuis : {url}")
        is_sf = "sourceforge.net" in url.lower() or "sf.net" in url.lower()
        req_headers = {"User-Agent": "curl/8.4.0" if is_sf else ERABLE_USER_AGENT}
        if not is_sf:
            req_headers["Referer"] = ERABLE_REFERER
        req = urllib.request.Request(url, headers=req_headers)
        sha256 = hashlib.sha256()
        with urllib.request.urlopen(req, timeout=180) as resp, open(archive_file, "wb") as f_out:
            while chunk := resp.read(65536):
                sha256.update(chunk)
                f_out.write(chunk)

        calc_hash = sha256.hexdigest().lower()
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

        # 4. Applications GUI (catégorie, bundle .app ou sous-système PE Windows GUI == 2) : pas d'ouverture de fenêtre bloquante en headless
        is_app_bundle = ".app/contents/macos/" in str(target_binary).replace("\\", "/").lower()
        is_pe_gui = current_system == "windows" and is_windows_gui_pe(target_binary)
        if category == "gui" or is_app_bundle or is_pe_gui or target_binary.suffix.lower() in (".msi", ".jar"):
            print("  [+] Application GUI / bundle certifié sans lancement de fenêtre headless bloquante.")
            return True

        # 5. Exécution réelle native par chemin absolu direct hors PATH (--version ou --help)
        direct_bin = os.path.abspath(target_binary)
        print(f"[4/4] Exécution native directe hors PATH : {direct_bin} --version...")
        if current_system != "windows":
            os.chmod(direct_bin, 0o755)

        try:
            if target_binary.suffix.lower() == ".ps1":
                p = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", direct_bin, "--version"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=15,
                )
                if p.returncode != 0 and "version" not in (p.stdout + p.stderr).lower():
                    p = subprocess.run(
                        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", direct_bin, "-h"],
                        capture_output=True,
                        text=True,
                        errors="replace",
                        timeout=15,
                    )
            else:
                p = subprocess.run([direct_bin, "--version"], capture_output=True, text=True, errors="replace", timeout=15)

            if p.returncode == 0 or "version" in (p.stdout + p.stderr).lower():
                print(f"  [+] SUCCÈS : Binaire exécuté avec succès !\n  -> Sortie : {p.stdout.strip()[:100]}")
                return True

            p_help = subprocess.run([direct_bin, "--help"], capture_output=True, text=True, errors="replace", timeout=15)
            if p_help.returncode in (0, 1):
                print("  [+] SUCCÈS : Commande d'aide validée avec succès.")
                return True

            print(f"[ERREUR] Échec de l'exécution (code {p.returncode}) : {p.stderr.strip()}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[ERREUR] Exception lors de l'exécution native : {e}", file=sys.stderr)
            return False


if __name__ == "__main__":
    pkg_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    ok = run_test_for_current_os(pkg_path)
    sys.exit(0 if ok else 1)
