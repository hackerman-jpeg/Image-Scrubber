#!/usr/bin/env python3
"""PNG encoding, structural validation, and metadata inventory helpers."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zlib

SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PIXELS = 50_000_000
MAX_SIDE = 32768
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 160 * 1024 * 1024
LOCAL_OS_ATTRIBUTES = {"com.apple.provenance"} if sys.platform == "darwin" else set()


def xattrs(path, clear=False):
    """List or clear filesystem attributes without interpreting image data."""
    # CPython's os.*xattr functions are not available on many Mac builds.
    if sys.platform == "darwin":
        command = ["/usr/bin/xattr"] + (["-c"] if clear else []) + [str(Path(path).resolve())]
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError("Could not clear/read filesystem extended attributes")
        return result.stdout.decode("utf-8", errors="backslashreplace").splitlines()
    if hasattr(os, "listxattr"):
        names = os.listxattr(path)
        if clear:
            for key in names:
                os.removexattr(path, key)
            return []
        return names
    raise ValueError("This system has no supported extended-attribute checker")


def chunk(out, kind, data):
    """Write a PNG chunk with its length and CRC."""
    out.write(struct.pack(">I", len(data)))
    out.write(kind + data)
    out.write(struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff))


def write_png(image, out):
    """Write only IHDR, IDAT and IEND. No source container bytes are copied."""
    width, height = image.size
    out.write(SIGNATURE)
    chunk(out, b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    encoder = zlib.compressobj(6)
    for y in range(height):
        data = encoder.compress(b"\0" + image.crop((0, y, width, y + 1)).tobytes())
        if data:
            chunk(out, b"IDAT", data)
    chunk(out, b"IDAT", encoder.flush())
    chunk(out, b"IEND", b"")


def verify_png(path, hardened=False, expected_digest=None):
    """Accept only the PNG subset produced by write_png, with bounded decompression."""
    total = 0
    decoder = zlib.decompressobj()
    seen_idat = False
    width = height = row_size = expected = None
    digest = hashlib.sha256()
    chunk_count = 0
    if Path(path).stat().st_size > MAX_OUTPUT_BYTES:
        raise ValueError("Output exceeds verification size limit")
    with open(path, "rb") as src:
        if src.read(8) != SIGNATURE:
            raise ValueError("Not a PNG file")
        while True:
            header = src.read(8)
            if len(header) != 8:
                raise ValueError("Missing or incomplete PNG chunk")
            length, kind = struct.unpack(">I4s", header)
            chunk_count += 1
            if chunk_count > 20000:
                raise ValueError("Too many PNG chunks")
            if kind not in (b"IHDR", b"IDAT", b"IEND"):
                raise ValueError("Unexpected chunk: " + repr(kind))
            if length > 16 * 1024 * 1024:
                raise ValueError("PNG chunk exceeds verification limit")
            data, crc = src.read(length), src.read(4)
            if len(data) != length or len(crc) != 4:
                raise ValueError("Truncated PNG chunk")
            if struct.unpack(">I", crc)[0] != zlib.crc32(kind + data) & 0xffffffff:
                raise ValueError("PNG checksum mismatch")
            if width is None and kind != b"IHDR":
                raise ValueError("IHDR must be first")
            if kind == b"IHDR":
                if width is not None or length != 13:
                    raise ValueError("Invalid or duplicate IHDR")
                width, height, depth, color, comp, filt, interlace = struct.unpack(">IIBBBBB", data)
                if not width or not height or max(width, height) > MAX_SIDE or width * height > MAX_PIXELS:
                    raise ValueError("Invalid dimensions or image exceeds 50 million pixels")
                if (depth, color, comp, filt, interlace) != (8, 2, 0, 0, 0):
                    raise ValueError("Expected 8-bit RGB without transparency or interlacing")
                row_size = 1 + 3 * width
                expected = row_size * height
                if hardened and max(width, height) > 1600:
                    raise ValueError("Hardened image exceeds 1600-pixel side limit")
            elif kind == b"IDAT":
                seen_idat = True
                pending = data
                while pending:
                    block = decoder.decompress(pending, 1024 * 1024)
                    pending = decoder.unconsumed_tail
                    if decoder.unused_data:
                        raise ValueError("Extra data after compressed pixels")
                    if total + len(block) > expected:
                        raise ValueError("Extra decompressed pixel data")
                    # Every scanline filter byte is zero in the format we write.
                    first_filter = (-total) % row_size
                    if any(block[i] != 0 for i in range(first_filter, len(block), row_size)):
                        raise ValueError("Unexpected scanline format")
                    # Hash/check pixel bytes only, excluding scanline filter bytes.
                    position = 0
                    for i in range(first_filter, len(block), row_size):
                        segment = block[position:i]
                        if hardened and any(value & 7 for value in segment):
                            raise ValueError("Hardened low-bit clearing check failed")
                        digest.update(segment)
                        position = i + 1
                    segment = block[position:]
                    if hardened and any(value & 7 for value in segment):
                        raise ValueError("Hardened low-bit clearing check failed")
                    digest.update(segment)
                    total += len(block)
            else:
                if length or not seen_idat or not decoder.eof or total != expected:
                    raise ValueError("Invalid end marker or incomplete pixel stream")
                if src.read(1):
                    raise ValueError("Appended data after image")
                break
    # This comparison checks the saved pixels, not the trustworthiness of their content.
    if expected_digest is not None and digest.hexdigest() != expected_digest:
        raise ValueError("Saved pixels failed digest comparison")
    if set(xattrs(path)) - LOCAL_OS_ATTRIBUTES:
        raise ValueError("Filesystem extended attributes remain")
    return width, height


def metadata_fields(image):
    """Collect field names only; metadata values stay out of logs and reports."""
    from PIL import ExifTags
    result = {"Image field: " + str(key) for key in image.info}
    exif = image.getexif()
    for tag in exif:
        result.add("EXIF: " + ExifTags.TAGS.get(tag, hex(tag)))
    for ifd in (34665, 34853, 40965):
        try:
            values = exif.get_ifd(ifd)
        except (KeyError, TypeError, ValueError, SyntaxError):
            continue
        table = ExifTags.GPSTAGS if ifd == 34853 else ExifTags.TAGS
        for tag in values:
            result.add(("GPS: " if ifd == 34853 else "EXIF subfield: ") + table.get(tag, hex(tag)))
    return result

