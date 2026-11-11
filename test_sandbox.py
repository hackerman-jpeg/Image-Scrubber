"""Opt-in integration tests for actual macOS enforcement."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import core
import scrub_image as app
from PIL import Image


@unittest.skipUnless(
    sys.platform == 'darwin' and os.environ.get('RUN_SANDBOX_TESTS') == '1',
    'Set RUN_SANDBOX_TESTS=1 on a Mac to test OS enforcement',
)
class SandboxTests(unittest.TestCase):
    def test_permission_denials(self):
        with contextlib.redirect_stdout(io.StringIO()):
            app.isolation_check(30)

    def test_complete_batch(self):
        with tempfile.TemporaryDirectory(prefix='image-scrubber-live-') as name:
            folder = Path(name)
            Image.new('RGB', (120, 90), (63, 127, 191)).save(folder / 'fixture.png')
            result = subprocess.run(
                [sys.executable, '-I', '-B', str(ROOT / 'main_entry.py'), str(folder)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            outputs = list((folder / 'sanitized').glob('*.png'))
            self.assertEqual(len(outputs), 1)
            self.assertEqual(core.verify_png(outputs[0], hardened=True), (108, 81))


if __name__ == '__main__':
    unittest.main()
