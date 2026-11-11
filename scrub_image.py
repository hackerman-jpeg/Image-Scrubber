#!/usr/bin/env python3
"""Rebuild one image or a folder; verify every saved PNG independently."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import uuid

from core import MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, verify_png, xattrs

CODE = Path(__file__).resolve().parent
EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tif', '.tiff', '.heic', '.heif'}
PROBE_KEYS = {'private_read_blocked', 'outside_write_blocked', 'network_blocked', 'child_process_blocked'}


def safe(value):
    """Escape paths and untrusted field names before printing them."""
    return json.dumps(str(value), ensure_ascii=True)


def read_regular(path, maximum):
    """Read a bounded regular file without following its final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('Not a regular file or size limit exceeded')
        data = file.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('File grew past size limit')
        return data


def sniff(data):
    """Choose an allowed decoder from the file signature, not its extension."""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'PNG'
    if data.startswith(b'\xff\xd8\xff'):
        return 'JPEG'
    if data.startswith((b'GIF87a', b'GIF89a')):
        return 'GIF'
    if data.startswith(b'BM'):
        return 'BMP'
    if data[:4] in (b'II*\0', b'MM\0*'):
        return 'TIFF'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'WEBP'
    if data[4:8] == b'ftyp' and any(brand in data[8:64] for brand in (b'heic', b'heix', b'hevc', b'hevx', b'mif1')):
        return 'HEIF'
    raise ValueError('Unsupported file signature (SVG, EPS, PDF, executables and other formats refused)')


def run_isolated(work, arguments, timeout):
    """Run a fresh restricted worker and read its bounded report."""
    if sys.platform != 'darwin' or not Path('/usr/bin/sandbox-exec').is_file():
        raise RuntimeError('This release requires macOS sandbox-exec; no images were decoded')
    parameters = {
        'RUNTIME': str(Path(sys.base_prefix).resolve()),
        'ENVIRONMENT': str(Path(sys.prefix).resolve()), 'CODE': str(CODE),
        'WORK': str(work.resolve()), 'PYTHON': sys.executable,
        'PYTHON_REAL': str(Path(sys.executable).resolve()),
    }
    policy = (CODE / 'decoder.sb').read_text(encoding='utf-8')
    # Import only Apple's loader bootstrap rules, not its broader system.sb.
    # Loader cache locations and bootstrap syscalls differ between macOS releases.
    dyld_support = Path('/System/Library/Sandbox/Profiles/dyld-support.sb')
    if dyld_support.is_file():
        policy += '\n(import "/System/Library/Sandbox/Profiles/dyld-support.sb")\n'
    # The generated policy belongs with the temporary job, not the installation.
    profile = work / 'effective-decoder.sb'
    profile.write_text(policy, encoding='utf-8')
    command = ['/usr/bin/sandbox-exec', '-f', str(profile)]
    for name, value in parameters.items():
        command += ['-D', name + '=' + value]
    command += [sys.executable, '-I', '-B', str(CODE / 'worker_entry.py'),
                str(work), str(min(timeout, 120)), *arguments]
    # Do not pass tokens or user-controlled Python startup settings to a decoder.
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'TMPDIR': str(work),
                   'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    try:
        process = subprocess.run(command, cwd=work, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE if arguments[0] == '--probe' else subprocess.DEVNULL,
                                 timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Decoder timed out; no output accepted') from None
    report_file = work / 'result.json'
    if not report_file.exists():
        detail = f' (exit status {process.returncode}'
        if process.returncode < 0:
            detail += f', signal {-process.returncode}'
        detail += ')'
        if arguments[0] == '--probe' and process.stderr:
            detail += ': ' + process.stderr[:1200].decode('utf-8', errors='backslashreplace').strip()
        raise RuntimeError('Restricted decoder could not start or crashed; no output accepted' + detail)
    report = json.loads(read_regular(report_file, 512 * 1024))
    if process.returncode != 0:
        explanations = {
            'OLD_PILLOW': 'Update required: Pillow 13 or newer',
            'OLD_HEIF': 'Update required: libheif 1.23.2 or newer',
            'DIMENSIONS': 'Image exceeds pixel/dimension limit',
            'MULTIFRAME': 'Multiple frames/pages refused; export a single still first',
            'LAB': 'LAB color is unsupported; export RGB first',
        }
        if isinstance(report, dict) and report.get('error_code') in explanations:
            raise RuntimeError(explanations[report['error_code']])
        error = report.get('error_class', 'decoder failure') if isinstance(report, dict) else 'decoder failure'
        raise RuntimeError('Decoder refused the image (' + str(error)[:80] + ')')
    return report


def isolation_check(timeout):
    """Require actual permission denials before processing any source images."""
    with tempfile.TemporaryDirectory(prefix='scrub-probe-') as work_name, \
            tempfile.TemporaryDirectory(prefix='scrub-canary-') as outside:
        canary = Path(outside) / 'private-canary'
        canary.write_text(uuid.uuid4().hex)
        result = run_isolated(Path(work_name), ['--probe', str(canary)], min(timeout, 30))
        if (
            not isinstance(result, dict)
            or set(result) != PROBE_KEYS
            or not all(value is True for value in result.values())
        ):
            raise RuntimeError('Decoder isolation self-test failed; no images were opened')
    print('Protection self-test PASS: private reads, outside writes, network and child processes blocked.')


def process_one(source, destination, mode, timeout):
    """Stage, reconstruct, and verify an image before publishing its output name."""
    if source.is_symlink():
        raise ValueError('Symbolic links are refused')
    attributes = xattrs(source)
    # The worker receives a bounded copy, not access to the original path.
    data = read_regular(source, MAX_INPUT_BYTES)
    format_name = sniff(data[:64])
    source_digest = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix='scrub-worker-') as name:
        work = Path(name)
        (work / 'input').write_bytes(data)
        del data
        result = run_isolated(work, [mode, format_name], timeout)
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise ValueError('Invalid worker report')
        fields = result.get('removed_fields')
        if (
            not isinstance(fields, list)
            or len(fields) > 1000
            or any(not isinstance(field, str) or len(field) > 300 for field in fields)
        ):
            raise ValueError('Invalid metadata inventory')
        digest = result.get('pixel_sha256', '')
        if not isinstance(digest, str) or len(digest) != 64 or any(x not in '0123456789abcdef' for x in digest):
            raise ValueError('Invalid pixel digest')
        # Treat worker output as untrusted: no symlinks, special files or source containers accepted.
        png = read_regular(work / 'pixels.png', MAX_OUTPUT_BYTES)
        fd, name = tempfile.mkstemp(prefix='.pending-', suffix='.tmp', dir=destination)
        pending = Path(name)
        output = destination / ('clean-' + uuid.uuid4().hex + '.png')
        published = False
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(png)
            xattrs(pending, clear=True)
            dimensions = verify_png(pending, hardened=mode == 'hardened', expected_digest=digest)
            # Atomically publish a verified inode; link() also refuses to overwrite any file.
            os.link(pending, output)
            published = True
            pending.unlink()
        except BaseException:
            pending.unlink(missing_ok=True)
            if published:
                output.unlink(missing_ok=True)
            raise
    return {
        'status': 'verified', 'source': str(source), 'output': str(output), 'source_sha256': source_digest,
        'source_format': format_name, 'mode': mode, 'dimensions': list(dimensions),
        'removed_fields': fields + ['Filesystem attribute: ' + key for key in attributes],
        'inventory_truncated': bool(result.get('inventory_truncated', False)),
        'checks': ['minimal PNG chunks only', 'checksums', 'bounded decompressed pixels',
                   'no appended bytes/extra compressed streams', 'pixel digest matches worker',
                   'no unexpected filesystem attributes'] +
                  (['max side 1600', 'lowest 3 color bits zero'] if mode == 'hardened' else []),
        'local_attributes': xattrs(output),
    }


def collect(folder, destination, recursive, verifying):
    """Enumerate candidates without following links or reprocessing output trees."""
    candidates, skipped = [], []
    extensions = {'.png'} if verifying else EXTENSIONS
    output_directories = {destination, destination.parent / (destination.name + '-reports')}

    def walk_error(error):
        skipped.append({'source': str(error.filename), 'reason': 'directory could not be read', 'problem': True})

    for root, directories, filenames in os.walk(folder, followlinks=False, onerror=walk_error):
        parent = Path(root)
        included = []
        for directory in sorted(directories):
            path = parent / directory
            if (
                directory.startswith('.')
                or path.is_symlink()
                or directory in ('sanitized', 'sanitized-reports')
                or path.resolve() in output_directories
            ):
                skipped.append({'source': str(path), 'reason': 'hidden, symbolic link, or output directory'})
            else:
                included.append(directory)
        directories[:] = included
        for filename in sorted(filenames):
            path = parent / filename
            if filename.startswith('.') or path.is_symlink() or path.suffix.lower() not in extensions:
                skipped.append({'source': str(path), 'reason': 'hidden, symbolic link, or unsupported extension'})
            else:
                candidates.append(path)
        if not recursive:
            break
    return candidates, skipped


def private_report(directory, contents):
    """Write an owner-readable report outside the shareable image directory."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='report-', suffix='.json', dir=directory)
    with os.fdopen(fd, 'w', encoding='utf-8') as report:
        json.dump(contents, report, ensure_ascii=True, indent=2)
    return Path(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, nargs='?', help='image file or folder')
    parser.add_argument('--recursive', action='store_true', help='include subfolders (no symbolic links)')
    parser.add_argument('--output-dir', type=Path, help='destination for clean images only')
    parser.add_argument('--mode', choices=['hardened', 'metadata'], default='hardened',
                        help='hardened changes pixels to disrupt some hidden data (default); metadata keeps detail')
    parser.add_argument('--verify', action='store_true', help='independently check existing outputs; no modifications')
    parser.add_argument('--timeout', type=int, default=90, help='wall-clock seconds per image, 5–600 (default 90)')
    parser.add_argument('--self-test', action='store_true', help='test decoder restrictions without opening images')
    args = parser.parse_args()
    if not 5 <= args.timeout <= 600:
        parser.error('--timeout must be between 5 and 600')
    try:
        if args.self_test:
            isolation_check(args.timeout)
            return 0
        if args.image is None:
            parser.error('an image file or folder is required')
        if args.image.is_symlink():
            raise ValueError('Input symbolic links are refused')
        source = args.image.resolve(strict=True)
        if not source.is_dir() and not source.is_file():
            raise ValueError('Input must be a regular image file or folder')
        destination = (args.output_dir or (source if source.is_dir() else source.parent) / 'sanitized').resolve()
        if source.is_dir() and destination == source:
            raise ValueError('Output folder must differ from input folder')
        # Enumeration finishes before creating any output; subsequent runs exclude output trees.
        if source.is_dir():
            files, skipped = collect(source, destination, args.recursive, args.verify)
        else:
            files, skipped = [source], []
        results = []
        if not args.verify and files:
            isolation_check(args.timeout)
            destination.mkdir(parents=True, exist_ok=True)
        for index, file in enumerate(files, 1):
            print(f'[{index}/{len(files)}] ' + safe(file), flush=True)
            try:
                if args.verify:
                    dimensions = verify_png(file, hardened=args.mode == 'hardened')
                    result = {'source': str(file), 'status': 'verified', 'dimensions': list(dimensions)}
                else:
                    result = process_one(file, destination, args.mode, args.timeout)
                    print('  PASS 1: rebuilt; detected source fields omitted (values withheld):')
                    for field in result['removed_fields']:
                        print('    - ' + safe(field))
                    if not result['removed_fields']:
                        print('    None reported by source decoder.')
                    if result['inventory_truncated']:
                        print('    Field inventory truncated; the source container was still discarded.')
                    print('  Discarded source container, previews, extra sections and appended bytes.')
                    print('  OUTPUT: ' + safe(result['output']))
                print('  PASS 2: independent saved-file structure and pixel checks passed.')
                if args.mode == 'hardened':
                    print('  Low-bit clearing and 1600-pixel side limit verified; hidden data may still remain.')
            except Exception as error:
                result = {'source': str(file), 'status': 'failed', 'error': str(error)[:500]}
                print('  FAILED: ' + safe(result['error']))
            results.append(result)
        failures = sum(row['status'] == 'failed' for row in results)
        successes = len(results) - failures
        problems = sum(bool(row.get('problem')) for row in skipped)
        for row in skipped:
            print('SKIPPED: ' + safe(row['source']) + ' (' + row['reason'] + ')')
        if not args.verify:
            report = private_report(destination.parent / (destination.name + '-reports'), {
                'version': 2, 'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'mode': args.mode, 'results': results, 'skipped': skipped,
                'summary': {'verified': successes, 'failed': failures, 'skipped': len(skipped)},
                'limits': 'Not proof of anonymity, malware-free pixels, tracker removal or watermark removal.',
            })
            print('PRIVATE REPORT (contains original paths; do not share): ' + safe(report))
        print(f'Finished: {successes} verified, {failures} failed, {len(skipped)} skipped.')
        print('No result certifies malware absence, anonymity, or removal of every hidden signal/watermark.')
        print('Share/open only the verified PNG copies. A recognizable picture can still be matched.')
        print('macOS may retain its local com.apple.provenance attribute outside image bytes.')
        return 1 if failures or problems or not files else 0
    except KeyboardInterrupt:
        print('Interrupted.', file=sys.stderr)
        return 130
    except Exception as error:
        print('STOPPED: ' + safe(error), file=sys.stderr)
        print('No protection was disabled. No unverified output was accepted.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
