import io
import os
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))
import validate  # noqa: E402


class TestRunnerSecurityAndExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="erable-runner-test-"))
        self.ext = self.tmp / "extract"
        self.ext.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_extract_zip_safe_handles_goreleaser_dot_entry(self) -> None:
        arc = self.tmp / "carapace.zip"
        with zipfile.ZipFile(arc, "w") as zf:
            zf.writestr(".", b"synthetic-metadata-root")
            zf.writestr("./", b"")
            zf.writestr("carapace.exe", b"MZ-OK")

        validate._extract_zip_safe(arc, self.ext)
        self.assertTrue((self.ext / "carapace.exe").is_file())
        self.assertEqual((self.ext / "carapace.exe").read_bytes(), b"MZ-OK")

    def test_zip_slip_sibling_prefix_rejected(self) -> None:
        sibling = self.tmp / "extract_evil"
        sibling.mkdir(exist_ok=True)
        arc = self.tmp / "slip.zip"
        with zipfile.ZipFile(arc, "w") as zf:
            zf.writestr("../extract_evil/pwn.txt", b"bad")

        with self.assertRaises(ValueError):
            validate._extract_zip_safe(arc, self.ext)

    def test_tar_hardlink_escape_rejected(self) -> None:
        arc = self.tmp / "hardlink.tar"
        with tarfile.open(arc, "w") as tf:
            ti = tarfile.TarInfo("evil_link")
            ti.type = tarfile.LNKTYPE
            ti.linkname = "../../etc/passwd"
            tf.addfile(ti)

        with self.assertRaises(ValueError):
            validate._check_tar_slip(arc, self.ext)

    def test_validate_url_blocks_ssrf_and_imds(self) -> None:
        for bad_url in (
            "file:///etc/passwd",
            "http://example.com/app.zip",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/app.zip",
            "https://localhost/app.zip",
            "https://bit.ly/evil",
            "https://github.com/org/repo/releases/download/v1/pkg.deb",
        ):
            with self.assertRaises(ValueError, msg=bad_url):
                validate.validate_url_and_domain(bad_url, resolve_dns=False)

        with mock.patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]):
            with self.assertRaises(ValueError):
                validate.validate_url_and_domain("https://rebind.example.com/app.zip", resolve_dns=True)

        with mock.patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.121.4", 443))]):
            validate.validate_url_and_domain("https://github.com/org/repo/releases/download/v1/app.zip", resolve_dns=True)

    def test_sanitized_probe_env_strips_runner_secrets(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_ENV": "/tmp/evil_env",
                "GITHUB_PATH": "/tmp/evil_path",
                "EVENT_PAYLOAD": '{"secret": 1}',
                "INPUT_HOOKS_JSON": "secret",
                "GH_TOKEN": "ghp_secret",
                "PATH": os.environ.get("PATH", ""),
            },
            clear=False,
        ):
            clean = validate._build_sanitized_probe_env()
            self.assertNotIn("GITHUB_ENV", clean)
            self.assertNotIn("GITHUB_PATH", clean)
            self.assertNotIn("EVENT_PAYLOAD", clean)
            self.assertNotIn("INPUT_HOOKS_JSON", clean)
            self.assertNotIn("GH_TOKEN", clean)
            self.assertIn("PATH", clean)
            self.assertEqual(clean.get("CI"), "true")
            self.assertEqual(clean.get("NO_UPDATE_NOTIFIER"), "1")
            self.assertEqual(clean.get("BALENA_CLI_DISABLE_AUTO_UPDATE"), "1")

    def test_nuon_value_escapes_newlines_and_quotes(self) -> None:
        out = validate._nuon_value({"msg": 'line1\n"line2"'})
        self.assertNotIn("\n", out)
        self.assertIn('\\n\\"line2\\"', out)

    def test_verify_windows_pe_arch_rejects_mismatch(self) -> None:
        import struct

        def make_pe(machine: int, name: str) -> Path:
            buf = bytearray(0x100)
            buf[:2] = b"MZ"
            struct.pack_into("<I", buf, 0x3C, 0x80)
            buf[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<H", buf, 0x84, machine)
            p = self.tmp / name
            p.write_bytes(bytes(buf))
            return p

        arm_exe = make_pe(0xAA64, "arm.exe")
        x64_exe = make_pe(0x8664, "x64.exe")

        ok_arm_on_x64, err1 = validate.verify_windows_pe_arch(arm_exe, "x86_64-windows")
        self.assertFalse(ok_arm_on_x64)
        self.assertIn("ARM64", err1)

        ok_x64_on_arm, err2 = validate.verify_windows_pe_arch(x64_exe, "aarch64-windows")
        self.assertFalse(ok_x64_on_arm)
        self.assertIn("x86_64", err2)

        self.assertTrue(validate.verify_windows_pe_arch(arm_exe, "aarch64-windows")[0])
        self.assertTrue(validate.verify_windows_pe_arch(x64_exe, "x86_64-windows")[0])

    def test_resolve_linux_unshare_prefix_falls_back_to_sudo(self) -> None:
        class _FakeProc:
            def __init__(self, rc: int) -> None:
                self.returncode = rc

        def fake_which(name: str) -> str | None:
            return f"/usr/bin/{name}" if name in ("unshare", "sudo") else None

        def fake_run(cmd: list[str], **_kw: object) -> _FakeProc:
            if cmd[0] == "sudo":
                return _FakeProc(0)
            return _FakeProc(1)

        with (
            mock.patch("validate.shutil.which", side_effect=fake_which),
            mock.patch.dict(os.environ, {"USER": "runner"}, clear=False),
            mock.patch("validate.subprocess.run", side_effect=fake_run),
        ):
            pref = validate._resolve_linux_unshare_prefix()
        self.assertEqual(pref, ["sudo", "-n", "unshare", "--net", "--", "sudo", "-n", "-u", "runner", "--"])


if __name__ == "__main__":
    unittest.main()
