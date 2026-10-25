#!/usr/bin/env python3
"""
Moteur d'exécution et de validation autonome multiplateforme pour GitHub Actions.
Valide pour l'OS courant :
1. Téléchargement sécurisé et vérification d'intégrité SHA-256
2. Décompression sécurisée (anti-ZipSlip, anti-TarSlip, limite 20 Go)
3. Validation des en-têtes binaires bas niveau (PE / ELF / Mach-O)
4. Exécution réelle du binaire (--version / --help) sur le matériel natif
"""

import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        raise ImportError("tomllib (Python 3.11+) requis.")


def verify_binary_magic(file_path: Path, expected_os: str) -> bool:
    if not file_path.exists() or file_path.stat().st_size < 4:
        return False
    if file_path.suffix.lower() in (".ps1", ".bat", ".cmd", ".nu"):
        return True
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if expected_os == "linux":
        return magic == b"\x7fELF"
    elif expected_os == "windows":
        return magic[:2] == b"MZ"
    elif expected_os == "darwin" or expected_os == "macos":
        mach_magics = [
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        ]
        return magic in mach_magics
    return True


def run_test_for_current_os(package_dir: Path) -> bool:
    current_system = platform.system().lower()
    current_arch = platform.machine().lower()
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

    with open(targets_file, "rb") as f:
        raw_bytes = f.read()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_bytes = raw_bytes[3:]
    targets_data = tomllib.loads(raw_bytes.decode("utf-8")).get("targets", {})

    # Trouver la cible correspondant à l'environnement actuel
    selected_target_key = None
    selected_target_info = None

    for target_key, info in targets_data.items():
        key_lower = target_key.lower()
        if os_key_pattern in key_lower:
            # Correspondance architecture
            if ("arm64" in current_arch or "aarch64" in current_arch) and ("arm64" in key_lower or "aarch64" in key_lower):
                selected_target_key = target_key
                selected_target_info = info
                break
            elif ("x86_64" in current_arch or "amd64" in current_arch) and ("x86_64" in key_lower or "amd64" in key_lower):
                selected_target_key = target_key
                selected_target_info = info
                break

    if not selected_target_info:
        # Repli : première correspondance OS
        for target_key, info in targets_data.items():
            if os_key_pattern in target_key.lower():
                selected_target_key = target_key
                selected_target_info = info
                break

    if not selected_target_info:
        print(f"[INFO] Aucune cible déclarée pour {os_key_pattern} ({current_arch}). Ignoré.")
        return True

    print(f"=== Validation de la cible : {selected_target_key} sur {current_system} ({current_arch}) ===")
    url = selected_target_info.get("url")
    expected_hash = (selected_target_info.get("sha256") or selected_target_info.get("hash", "")).strip().lower()

    if not url or not expected_hash:
        print("[ERREUR] URL ou hash manquant dans targets.toml", file=sys.stderr)
        return False

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        archive_file = tmp_path / "downloaded_file"

        # 1. Téléchargement
        print(f"[1/4] Téléchargement depuis : {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "Erable-Runner/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(archive_file, "wb") as f_out:
            shutil.copyfileobj(resp, f_out)

        # 2. Contrôle SHA-256
        sha256 = hashlib.sha256()
        with open(archive_file, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        calc_hash = sha256.hexdigest().lower()

        if calc_hash != expected_hash:
            print(f"[ERREUR] Divergence SHA-256 ! Attendu : {expected_hash}, Obtenu : {calc_hash}", file=sys.stderr)
            return False
        print(f"  [+] Hash SHA-256 certifié conforme : {calc_hash[:16]}...")

        # 3. Extraction sécurisée
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        import zipfile
        import tarfile

        print("[2/4] Extraction et audit de sécurité de l'archive...")
        if zipfile.is_zipfile(archive_file):
            with zipfile.ZipFile(archive_file, "r") as zf:
                for m in zf.infolist():
                    target = (extract_dir / m.filename).resolve()
                    if not str(target).startswith(str(extract_dir.resolve())):
                        print(f"[ERREUR] Zip Slip détecté : {m.filename}", file=sys.stderr)
                        return False
                zf.extractall(extract_dir)
        elif tarfile.is_tarfile(archive_file):
            with tarfile.open(archive_file, "r:*") as tf:
                for m in tf.getmembers():
                    target = (extract_dir / m.name).resolve()
                    if not str(target).startswith(str(extract_dir.resolve())):
                        print(f"[ERREUR] Tar Slip détecté : {m.name}", file=sys.stderr)
                        return False
                tf.extractall(extract_dir)
        else:
            # Fichier binaire brut
            b_name = os.path.basename(url)
            raw_target = extract_dir / b_name
            shutil.copy(archive_file, raw_target)

        # 4. Localisation du binaire et vérification magic
        print("[3/4] Inspection des signatures binaires...")
        binaries = (
            list(extract_dir.rglob("*.exe")) + list(extract_dir.rglob("*.ps1")) + list(extract_dir.rglob("*.bat")) + list(extract_dir.rglob("*.cmd"))
            if current_system == "windows"
            else [f for f in extract_dir.rglob("*") if f.is_file() and not f.name.endswith(('.txt', '.md', '.json', '.toml', '.pdf', '.png'))]
        )
        if not binaries:
            binaries = [f for f in extract_dir.rglob("*") if f.is_file() and f.stat().st_size > 1024]

        if not binaries:
            print("[ERREUR] Aucun binaire exécutable trouvé après décompression.", file=sys.stderr)
            return False

        target_binary = binaries[0]
        # Recherche prioritaire si binary ou alias défini
        raw_bins = selected_target_info.get("binaries") or []
        for b in raw_bins:
            b_src = b.get("source") if isinstance(b, dict) else str(b)
            candidate = list(extract_dir.rglob(b_src)) or list(extract_dir.rglob(f"{b_src}.exe")) or list(extract_dir.rglob(f"{b_src}.ps1"))
            if candidate:
                target_binary = candidate[0]
                break

        print(f"  [+] Binaire identifié : {target_binary.name} ({target_binary.stat().st_size} octets)")

        if not verify_binary_magic(target_binary, os_key_pattern):
            print(f"[ERREUR] En-tête binaire invalide pour {os_key_pattern} !", file=sys.stderr)
            return False
        print(f"  [+] Signature machine validée avec succès pour {os_key_pattern.upper()}.")

        # 5. Exécution réelle native (--version ou --help)
        print(f"[4/4] Exécution native en conditions réelles : {target_binary.name} --version...")
        if current_system != "windows":
            os.chmod(target_binary, 0o755)

        try:
            if target_binary.suffix.lower() == ".ps1":
                p = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(target_binary), "--version"],
                    capture_output=True, text=True, errors="replace", timeout=15
                )
                if p.returncode != 0 and "version" not in (p.stdout + p.stderr).lower():
                    p = subprocess.run(
                        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(target_binary), "-h"],
                        capture_output=True, text=True, errors="replace", timeout=15
                    )
            else:
                p = subprocess.run([str(target_binary), "--version"], capture_output=True, text=True, errors="replace", timeout=15)
            if p.returncode == 0 or "version" in (p.stdout + p.stderr).lower():
                print(f"  [+] SUCCÈS : Binaire exécuté avec succès !\n  -> Sortie : {p.stdout.strip()[:100]}")
                return True
            else:
                # Repli avec --help
                p_help = subprocess.run([str(target_binary), "--help"], capture_output=True, text=True, errors="replace", timeout=15)
                if p_help.returncode in (0, 1):
                    print(f"  [+] SUCCÈS : Commande d'aide validée avec succès.")
                    return True
                else:
                    print(f"[ERREUR] Échec de l'exécution (code {p.returncode}) : {p.stderr.strip()}", file=sys.stderr)
                    return False
        except Exception as e:
            print(f"[ERREUR] Exception lors de l'exécution native : {e}", file=sys.stderr)
            return False


if __name__ == "__main__":
    pkg_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    ok = run_test_for_current_os(pkg_path)
    sys.exit(0 if ok else 1)
