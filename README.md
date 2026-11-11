# Image Scrubber

A macOS terminal tool that rebuilds images as minimal PNG files, lists detected
metadata removed, and checks each saved file. It handles single images and folders.
Originals are left unchanged. Processing stays local.

## Requirements

- macOS with `/usr/bin/sandbox-exec`
- Python 3.10 or newer
- Internet access for the first-run dependency install and later updates

## Usage

Download or clone the repository, open Terminal in its directory, and run:

```bash
bash ./scrub-image "/path/to/image.jpg"
```

Process a folder and its subfolders:

```bash
bash ./scrub-image "/path/to/folder" --recursive
```

The first run installs dependencies into `.venv`. Later runs work offline.
Clean images go into `sanitized`. A separate `sanitized-reports` directory holds
the per-file report, including original paths and hashes. **Share the PNGs, not
the reports.** A failed image does not stop the rest of a batch.

Other options:

```bash
# Keep more image detail; remove container metadata without deliberate pixel disruption.
bash ./scrub-image "/path/to/folder" --recursive --mode metadata

# Choose where verified copies are saved.
bash ./scrub-image "/path/to/folder" --output-dir "/path/to/share"

# Check previously generated outputs without changing them.
bash ./scrub-image "/path/to/sanitized" --verify --recursive

# Check whether decoder restrictions work on this Mac, without opening images.
bash ./scrub-image --self-test

# Update dependencies within the supported version ranges.
bash ./scrub-image --update
```

Use `--mode metadata` when rechecking files produced in metadata mode.
Run `bash ./scrub-image --help` for all options.

## What changes

Both modes discard the source container, metadata, embedded previews, and
appended data. Orientation is applied and transparency becomes white. The output
contains only PNG format information and compressed RGB pixels.

The default **hardened** mode also shrinks the image to at most 90% of its
original dimensions, caps the longest side at 1600 pixels, applies mild blur and
JPEG recompression, and clears the lowest three bits of every color channel.
Tiny dimensions remain at least one pixel. These changes reduce quality and
disrupt some simple hidden-data methods. Metadata mode keeps the resolution and
converts supported color profiles to sRGB before discarding them.

A separate parser checks the saved file's chunks, checksums, pixel-stream length,
and pixel digest. Hardened outputs are also checked for the size cap and cleared
low bits. Output names are published only after verification.

Supported still images: JPEG, PNG, GIF, WebP, BMP, classic TIFF, and HEIC/HEIF.
Animated and multipage files are refused. SVG, EPS, PDF, RAW, video, JPEG2000, and
AVIF are not supported. Use a local output filesystem that supports hard links,
such as APFS. Hidden files, symbolic links, and output directories are skipped.

## Limits

This is not antivirus, an anonymizer, or proof that an image is malware-free.
It cannot guarantee removal of every watermark, tracker, or hidden pixel message.
Faces, screen text, locations, and other visible identifying content remain.
A recognizable image can still be matched by reverse-image search.

The decoder runs with macOS restrictions on file access, writes, networking, and
child processes. A live self-test must pass before any image is decoded. It stops
if protection cannot be established. Decoder or operating-system vulnerabilities
remain possible; use a disposable virtual machine for suspected malicious files.
See [SECURITY.md](SECURITY.md) for the checks, boundaries, and testing limitations.

## Development

```bash
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt
.venv/bin/python3 -m unittest discover -s tests -v
```

Processing tests use generated fixtures and substitute the worker launcher.
Run the additional live macOS isolation tests on an unrestricted Mac:

```bash
RUN_SANDBOX_TESTS=1 .venv/bin/python3 -m unittest discover -s tests -v
```

## License

[MIT](LICENSE)
