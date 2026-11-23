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

    def test_nuon_value_escapes_newlines_and_quotes(self) -> None:
        out = validate._nuon_value({"msg": 'line1\n"line2"'})
        self.assertNotIn("\n", out)
        self.assertIn('\\n\\"line2\\"', out)


if __name__ == "__main__":
    unittest.main()
