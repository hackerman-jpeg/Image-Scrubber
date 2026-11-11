#!/usr/bin/env python3
"""Private decoder entry point. The launcher runs this under macOS restrictions."""
import errno
import hashlib
import io
import json
from pathlib import Path
import resource
import socket
import subprocess
import sys
import warnings

from core import MAX_PIXELS, MAX_SIDE, metadata_fields, write_png


class Rejected(Exception):
    """A fixed, non-source-controlled refusal code."""


def limits(seconds):
    """Bound CPU time, output size, and open files; disable core dumps."""
    for kind, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, seconds),
                        (resource.RLIMIT_FSIZE, 256 * 1024 * 1024),
                        (resource.RLIMIT_NOFILE, 128)):
        _, hard = resource.getrlimit(kind)
        value = min(value, hard) if hard != resource.RLIM_INFINITY else value
        resource.setrlimit(kind, (value, value))


def save_report(work, report):
    (work / 'result.json').write_text(json.dumps(report, ensure_ascii=True), encoding='utf-8')


def probe(work, canary):
    """Check denied operations using a disposable canary, never user images."""
    result = {}
    operations = {
        'private_read_blocked': lambda: Path(canary).read_bytes(),
        'outside_write_blocked': lambda: Path(canary + '.new').write_text('blocked'),
        'network_blocked': lambda: socket.create_connection(('127.0.0.1', 9), timeout=2),
        'child_process_blocked': lambda: subprocess.run([sys.executable, '-I', '-c', 'pass'], check=True),
    }
    for name, operation in operations.items():
        try:
            value = operation()
            if hasattr(value, 'close'):
                value.close()
            result[name] = False
        except OSError as error:
            result[name] = error.errno in (errno.EPERM, errno.EACCES)
    save_report(work, result)


def decode(work, mode, format_name):
    """Decode one allowed still image and write pixels to a new PNG container."""
    from PIL import Image, ImageCms, ImageFilter, ImageOps, __version__
    if int(__version__.split('.')[0]) < 13:
        raise Rejected('OLD_PILLOW')
    if format_name == 'HEIF':
        import pillow_heif
        version = tuple(int(x) for x in pillow_heif.libheif_info()['libheif'].split('.')[:3])
        if version < (1, 23, 2):
            raise Rejected('OLD_HEIF')
        pillow_heif.register_heif_opener()
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    warnings.simplefilter('error', Image.DecompressionBombWarning)
    with Image.open(work / 'input', formats=[format_name]) as original:
        if original.width * original.height > MAX_PIXELS or max(original.size) > MAX_SIDE:
            raise Rejected('DIMENSIONS')
        if getattr(original, 'n_frames', 1) != 1:
            raise Rejected('MULTIFRAME')
        removed = sorted(metadata_fields(original))
        original.load()
        image = ImageOps.exif_transpose(original)
        # Treat unusual image modes as unsupported rather than guessing at color transforms.
        if image.mode == 'LAB':
            raise Rejected('LAB')
        alpha = image.convert('RGBA').getchannel('A')
        if mode == 'metadata' and original.info.get('icc_profile'):
            color = image if image.mode in ('RGB', 'CMYK') else image.convert('RGB')
            rgb = ImageCms.profileToProfile(color,
                ImageCms.ImageCmsProfile(io.BytesIO(original.info['icc_profile'])),
                ImageCms.createProfile('sRGB'), outputMode='RGB')
        else:
            rgb = image.convert('RGB')
        clean = Image.new('RGB', rgb.size, 'white')
        clean.paste(rgb, (0, 0), alpha)
    changes = ['fresh RGB PNG', 'transparency flattened onto white', 'source container discarded']
    if mode == 'hardened':
        scale = min(0.9, 1600 / max(clean.size))
        size = tuple(max(1, int(side * scale)) for side in clean.size)
        clean = clean.resize(size, Image.Resampling.LANCZOS)
        clean = clean.filter(ImageFilter.GaussianBlur(radius=0.4))
        intermediate = io.BytesIO()
        clean.save(intermediate, format='JPEG', quality=80, subsampling=2,
                   exif=b'', icc_profile=None)
        intermediate.seek(0)
        with Image.open(intermediate, formats=['JPEG']) as lossy:
            clean = lossy.convert('RGB')
        clean = clean.point([value & 0xf8 for value in range(256)] * 3)
        changes += ['resized by at least 10% where dimensions allow; max side 1600',
                    'mild blur', 'JPEG quality 80 / chroma subsampling',
                    'lowest 3 bits of every color channel cleared',
                    'source color profile discarded without an extra ICC conversion step']
    else:
        changes += ['orientation applied', 'ICC converted to sRGB when present']
    with (work / 'pixels.png').open('wb') as out:
        write_png(clean, out)
    save_report(work, {
        'ok': True, 'removed_fields': [field[:300] for field in removed[:1000]],
        'inventory_truncated': len(removed) > 1000 or any(len(x) > 300 for x in removed),
        'pixel_sha256': hashlib.sha256(clean.tobytes()).hexdigest(), 'changes': changes,
        'format': format_name, 'mode': mode,
    })


def main():
    work = Path(sys.argv[1])
    try:
        limits(int(sys.argv[2]))
        if sys.argv[3] == '--probe':
            probe(work, sys.argv[4])
        else:
            decode(work, sys.argv[3], sys.argv[4])
    except Exception as error:
        # Exception values can contain attacker-controlled metadata. Keep only the class.
        save_report(work, {'ok': False, 'error_class': type(error).__name__,
                           'error_code': str(error) if isinstance(error, Rejected) else None})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
