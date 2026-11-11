"""Processing and validation tests using generated image fixtures."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib
import struct

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import core
import scrub_image as app
from PIL import Image, PngImagePlugin, ImageCms

REAL_RUN = subprocess.run


def run_fixture_worker(command, **kwargs):
    """Run generated fixtures in a worker; live OS enforcement is tested separately."""
    assert command[0] == '/usr/bin/sandbox-exec'
    command = command[command.index(sys.executable):]
    return REAL_RUN(command, **kwargs)


def run_test_command(command, **kwargs):
    """Substitute only the OS wrapper; keep attribute checks and other commands real."""
    if command[0] == '/usr/bin/sandbox-exec':
        return run_fixture_worker(command, **kwargs)
    return REAL_RUN(command, **kwargs)


@unittest.skipUnless(sys.platform == "darwin", "macOS required")
class ProcessingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='image-scrubber-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.out = self.base / 'out'
        self.out.mkdir()

    def source(self, name='source.png', mode='RGB', size=(100, 80), color=(123, 57, 199)):
        source = self.base / name
        Image.new(mode, size, color).save(source)
        return source

    def process(self, source, mode='hardened'):
        with mock.patch.object(app.subprocess, 'run', side_effect=run_test_command):
            return app.process_one(source, self.out, mode, 30)

    def test_hardened_resizes_and_clears_all_low_bits(self):
        image = Image.frombytes('RGB', (400, 300), os.urandom(400 * 300 * 3))
        source = self.base / 'low-bit-payload.png'
        image.save(source)
        record = self.process(source)
        self.assertEqual(record['dimensions'], [360, 270])
        with Image.open(record['output']) as result:
            self.assertTrue(all(value & 7 == 0 for value in result.tobytes()))
        core.verify_png(record['output'], hardened=True)

    def test_metadata_inventory_payload_removal_and_original_unchanged(self):
        source = self.base / 'private named screenshot.png'
        meta = PngImagePlugin.PngInfo()
        meta.add_text('Author', 'PRIVATE-USER')
        meta.add_itxt('XML:com.adobe.xmp', 'https://tracker.invalid/PRIVATE-TOKEN')
        image = Image.new('RGBA', (30, 20), (1, 2, 3, 0))
        image.save(source, pnginfo=meta)
        with source.open('ab') as output:
            output.write(b'INERT-PAYLOAD-DO-NOT-EXECUTE')
        before = source.read_bytes()
        record = self.process(source, mode='metadata')
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(record['source_sha256'], hashlib.sha256(before).hexdigest())
        self.assertTrue(any('Author' in x for x in record['removed_fields']))
        data = Path(record['output']).read_bytes()
        for secret in (b'PRIVATE-USER', b'PRIVATE-TOKEN', b'INERT-PAYLOAD-DO-NOT-EXECUTE'):
            self.assertNotIn(secret, data)
            self.assertNotIn(secret.decode(), json.dumps(record))
        with Image.open(record['output']) as result:
            self.assertEqual(result.getpixel((0, 0)), (255, 255, 255))

    def test_jpeg_gps_orientation(self):
        source = self.base / 'gps.jpg'
        exif = Image.Exif()
        exif[274] = 6
        exif[34853] = {1: 'N', 2: (38.0, 30.0, 0.0)}
        Image.new('RGB', (12, 4), 'blue').save(source, exif=exif)
        record = self.process(source, mode='metadata')
        self.assertEqual(record['dimensions'], [4, 12])
        self.assertTrue(any('GPSLatitude' in value for value in record['removed_fields']))

    def test_icc_conversion_in_metadata_mode(self):
        source = self.base / 'profile.png'
        profile = ImageCms.ImageCmsProfile(ImageCms.createProfile('sRGB')).tobytes()
        Image.new('RGB', (10, 9), (10, 20, 30)).save(source, icc_profile=profile)
        record = self.process(source, mode='metadata')
        with Image.open(record['output']) as result:
            self.assertEqual(result.getpixel((0, 0)), (10, 20, 30))
            self.assertFalse(result.info)

    def test_supported_formats(self):
        import pillow_heif
        pillow_heif.register_heif_opener()
        formats = [('heic', 'HEIF'), ('webp', 'WEBP'), ('bmp', 'BMP'), ('tiff', 'TIFF'), ('gif', 'GIF')]
        for suffix, format_name in formats:
            source = self.base / ('source.' + suffix)
            Image.new('RGB', (40, 30), 'red').save(source, format=format_name)
            self.assertEqual(self.process(source)['status'], 'verified')

    def test_large_and_tiny_images(self):
        for size in ((3000, 1800), (1, 1)):
            source = self.source(size=size)
            record = self.process(source)
            self.assertLessEqual(max(record['dimensions']), 1600)

    def test_animation_refused(self):
        source = self.base / 'animated.gif'
        Image.new('RGB', (4, 3), 'red').save(source, save_all=True,
            append_images=[Image.new('RGB', (4, 3), 'blue')])
        with self.assertRaisesRegex(RuntimeError, 'Multiple frames'):
            self.process(source)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_signatures_reject_active_and_disguised_formats(self):
        payloads = (b'<svg onload="alert(1)"></svg>', b'%!PS-Adobe', b'%PDF', b'#!/bin/bash\ntrue', b'MZ' + b'0' * 80)
        for data in payloads:
            source = self.base / 'disguised.png'
            source.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'Unsupported file signature'):
                self.process(source)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_symlinks_and_special_files_refused(self):
        source = self.source()
        link = self.base / 'link.png'
        link.symlink_to(source)
        with self.assertRaisesRegex(ValueError, 'Symbolic links'):
            self.process(link)
        fifo = self.base / 'fifo.png'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            app.read_regular(fifo, 100)

    def test_input_size_limit_before_read(self):
        source = self.source()
        with mock.patch.object(app, 'MAX_INPUT_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                self.process(source)

    def test_failure_deletes_unverified_output(self):
        source = self.source()
        with mock.patch.object(app, 'verify_png', side_effect=ValueError('bad output')):
            with self.assertRaisesRegex(ValueError, 'bad output'):
                self.process(source)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_worker_symlink_output_rejected(self):
        source = self.source()
        def bad_worker(work, arguments, timeout):
            (work / 'pixels.png').symlink_to(source)
            return {'ok': True, 'removed_fields': [], 'pixel_sha256': '0' * 64}
        with mock.patch.object(app, 'run_isolated', side_effect=bad_worker):
            with self.assertRaises(OSError):
                app.process_one(source, self.out, 'hardened', 30)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_second_pass_rejects_metadata_appended_data_and_changed_pixels(self):
        record = self.process(self.source())
        path = Path(record['output'])
        data = path.read_bytes()
        for bad in (data + b'PAYLOAD', data[:-1], data[:40] + bytes([data[40] ^ 1]) + data[41:]):
            path.write_bytes(bad)
            with self.assertRaises((ValueError, zlib.error)):
                core.verify_png(path)
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'digest'):
            core.verify_png(path, expected_digest='0' * 64)
        target = io.BytesIO()
        core.write_png(Image.new('RGB', (10, 10), (1, 2, 3)), target)
        path.write_bytes(target.getvalue())
        with self.assertRaisesRegex(ValueError, 'low-bit'):
            core.verify_png(path, hardened=True)

    def test_large_uncompressed_digest_and_filters(self):
        image = Image.frombytes('RGB', (800, 600), os.urandom(800 * 600 * 3))
        path = self.out / 'noise.png'
        with path.open('wb') as output:
            core.write_png(image, output)
        digest = hashlib.sha256(image.tobytes()).hexdigest()
        self.assertEqual(core.verify_png(path, expected_digest=digest), (800, 600))

    def test_valid_crc_metadata_and_extra_compressed_streams_rejected(self):
        header = (b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
        payload = zlib.compress(b'\0\x10\x20\x30')
        end = (b'IEND', b'')
        cases = [
            [header, (b'tEXt', b'Author\0SECRET'), (b'IDAT', payload), end],
            [header, (b'IDAT', payload + zlib.compress(b'SECRET')), end],
            [header, (b'IDAT', payload + b'SECRET'), end],
            [header, (b'IDAT', zlib.compress(b'\0\x10\x20\x30SECRET')), end],
            [header, header, (b'IDAT', payload), end],
        ]
        path = self.out / 'hostile.png'
        for parts in cases:
            contents = io.BytesIO()
            contents.write(core.SIGNATURE)
            for kind, data in parts:
                core.chunk(contents, kind, data)
            path.write_bytes(contents.getvalue())
            with self.assertRaises((ValueError, zlib.error)):
                core.verify_png(path)

    def test_extended_attributes(self):
        source = self.source()
        REAL_RUN(['/usr/bin/xattr', '-w', 'com.example.private', 'SECRET-ATTRIBUTE', str(source)], check=True)
        record = self.process(source)
        self.assertTrue(any('com.example.private' in value for value in record['removed_fields']))
        self.assertEqual(set(core.xattrs(record['output'])) - core.LOCAL_OS_ATTRIBUTES, set())
        REAL_RUN(['/usr/bin/xattr', '-w', 'com.example.private', 'SECRET-ATTRIBUTE', record['output']], check=True)
        with self.assertRaisesRegex(ValueError, 'extended attributes'):
            core.verify_png(record['output'])

    def test_folder_success_failure_skip_continue_and_private_report(self):
        folder = self.base / 'incoming'
        folder.mkdir()
        Image.new('RGB', (40, 30), 'red').save(folder / 'good.png')
        (folder / 'bad.jpg').write_text('not a jpeg')
        (folder / 'notes.txt').write_text('skip me')
        nested = folder / 'nested'
        nested.mkdir()
        Image.new('RGB', (40, 30), 'blue').save(nested / 'same.png')
        log = io.StringIO()
        with contextlib.redirect_stdout(log), mock.patch.object(sys, 'argv', ['scrub', str(folder), '--recursive']), \
                mock.patch.object(app, 'isolation_check'), \
                mock.patch.object(app.subprocess, 'run', side_effect=run_test_command):
            status = app.main()
        self.assertEqual(status, 1)
        self.assertIn('2 verified, 1 failed, 1 skipped', log.getvalue())
        report_path = next((folder / 'sanitized-reports').glob('*.json'))
        report = json.loads(report_path.read_bytes())
        self.assertEqual(report['summary'], {'verified': 2, 'failed': 1, 'skipped': 1})
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(list((folder / 'sanitized').glob('*.png'))), 2)
        files, skipped = app.collect(folder, folder / 'sanitized', True, False)
        self.assertEqual(len(files), 3)
        self.assertTrue(any(row['source'].endswith('sanitized') for row in skipped))

    def test_isolation_probe_failure_stops_before_decoding(self):
        source = self.source()
        with mock.patch.object(app, 'run_isolated', return_value={key: False for key in app.PROBE_KEYS}):
            with self.assertRaisesRegex(RuntimeError, 'isolation self-test failed'):
                app.isolation_check(30)

    def test_no_automatic_isolation_fallback(self):
        with mock.patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
            with tempfile.TemporaryDirectory(dir=self.base) as path:
                with self.assertRaisesRegex(RuntimeError, 'could not start'):
                    app.run_isolated(Path(path), ['hardened', 'PNG'], 10)

    def test_timeout_no_accepted_output(self):
        with mock.patch.object(app.subprocess, 'run', side_effect=subprocess.TimeoutExpired('decoder', 5)):
            with tempfile.TemporaryDirectory(dir=self.base) as path:
                with self.assertRaisesRegex(RuntimeError, 'timed out'):
                    app.run_isolated(Path(path), ['hardened', 'PNG'], 5)

    def test_verify_folder_and_nonrecursive_enumeration(self):
        source = self.source()
        record = self.process(source)
        arguments = ['scrub', str(self.out), '--verify']
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(sys, 'argv', arguments):
            self.assertEqual(app.main(), 0)
        nested = self.base / 'nested'
        nested.mkdir()
        (nested / 'image.png').write_bytes(source.read_bytes())
        files, _ = app.collect(self.base, self.out, False, False)
        self.assertNotIn(nested / 'image.png', files)


if __name__ == '__main__':
    unittest.main(verbosity=2)
