"""Check the packaging certificate and explicit signing-input boundary."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'work/tools'))
import apk_build


class SigningConfigTest(unittest.TestCase):
    def test_matching_certificate(self):
        with patch.object(apk_build, 'EXPECTED_CERT', 'a' * 64):
            self.assertEqual(apk_build.parse_certificate(
                'Signer #1 certificate SHA-256 digest: ' + ':'.join(['aa'] * 32)), 'a' * 64)

    def test_missing_mismatched_or_multiple_certificates(self):
        with patch.object(apk_build, 'EXPECTED_CERT', 'a' * 64):
            for text in ['', 'Signer #1 certificate SHA-256 digest: ' + 'b' * 64,
                         '\n'.join('Signer #' + str(n) + ' certificate SHA-256 digest: '
                                   + 'a' * 64 for n in (1, 2))]:
                with self.subTest(text=text), self.assertRaises(apk_build.BuildError):
                    apk_build.parse_certificate(text)

    def test_signing_inputs_must_be_explicit(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            root = Path(directory)
            tools = root / 'tools'
            tools.mkdir()
            java = root / 'java'
            java.touch()
            with self.assertRaisesRegex(apk_build.BuildError, 'APK_SIGN_ROOT and APK_CERT_SHA256'):
                apk_build.ApkBuilder(root, tools, java)


if __name__ == '__main__':
    unittest.main()
