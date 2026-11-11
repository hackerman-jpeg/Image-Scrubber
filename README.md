# Image Scrubber

Remove metadata from images before sharing them, or rebuild received images as new PNG files.

Image Scrubber works with individual files and folders. It lists the metadata fields it found, checks every saved copy, and leaves your originals unchanged. Your images stay on your Mac.

## What you need

- macOS with `sandbox-exec` available.
- Python 3.10 or newer.
- An internet connection for the first setup and later updates.

The first run installs the image libraries into a local `.venv` folder. After that, processing works offline.

## Get started

Download or clone this repository and open Terminal in its folder. Give the script permission to run once:

```sh
chmod +x scrub-image
```

Then run it directly:

```sh
./scrub-image "/path/to/image.jpg"
```

To process a folder and its subfolders:

```sh
./scrub-image "/path/to/folder" --recursive
```

Without `--recursive`, only images directly inside the selected folder are processed.

You can drag a file or folder into Terminal to insert its path after `./scrub-image`.

## Where the results go

New images are saved in a `sanitized` folder beside the original image, or inside the folder you selected. They get new filenames that do not include the original names.

A separate `sanitized-reports` folder records what happened to each file. These reports include original paths and hashes.

**Share the new PNGs, not the reports or originals.**

If one image fails, the tool reports the problem and continues with the others. A PNG is made available only after its checks pass.

To choose another output folder:

```sh
./scrub-image "/path/to/folder" --recursive --output-dir "/path/to/share"
```

Use a local Mac disk, such as an APFS volume. The output folder must support hard links.

## Choose how much the image changes

### Hardened mode — the default

This removes metadata, resizes the picture, applies mild blur and recompression, and reduces fine color detail. The longest side is limited to 1600 pixels.

These changes disrupt some simple ways of hiding data in pixels. They also reduce image quality. Small text in screenshots may become harder to read.

### Metadata mode — keeps more detail

This keeps the original resolution and removes file metadata without deliberately disrupting pixel-level hidden data:

```sh
./scrub-image "/path/to/image.jpg" --mode metadata
```

Both modes produce an opaque PNG. Transparent areas become white.

## What the checks mean

The tool checks that the saved PNG contains only the expected image sections, has consistent pixel data, and has no extra metadata sections or appended data.

It also tests its macOS processing restrictions before opening images. If those protections cannot start, it stops.

**Passing these checks does not mean an image is anonymous or malware-free.**

Faces, names, screen text, locations, watermarks, and some hidden messages may remain. A recognizable picture can still be matched through reverse-image search.

Check and redact visible identifying details before posting. For suspected malicious files, use a disposable virtual machine rather than relying on this tool on your everyday Mac.

See [SECURITY.md](SECURITY.md) for the protection limits and testing status.

## Supported files

Still JPEG, PNG, GIF, WebP, BMP, classic TIFF, and HEIC/HEIF images.

Animated images, multipage files, videos, PDFs, SVGs, RAW files, JPEG2000, and AVIF are not supported. Hidden files, symbolic links, and recognized output folders are skipped.

## Other commands

Check previously generated images without changing them:

```sh
./scrub-image "/path/to/sanitized" --verify --recursive
```

Add `--mode metadata` when checking copies created in metadata mode.

Test the processing restrictions without opening images:

```sh
./scrub-image --self-test
```

Update the image libraries within the supported version ranges:

```sh
./scrub-image --update
```

Show all options:

```sh
./scrub-image --help
```

## Tests

After setup, run the processing tests:

```sh
.venv/bin/python3 -m unittest discover -s tests -v
```

Those tests use generated images and do not test macOS enforcement. To also run the live protection tests on a supported Mac:

```sh
RUN_SANDBOX_TESTS=1 .venv/bin/python3 -m unittest discover -s tests -v
```

## License

[MIT](LICENSE)
