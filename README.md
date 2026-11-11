# Image Scrubber

Remove image metadata, save a new PNG, and check the result.

Works with single images or whole folders. Your originals stay unchanged. Nothing is uploaded.

## 1. Set up

You need **macOS** and **Python 3.10 or newer**.

Download or clone this repository. Open Terminal in the `image-scrubber` folder, then run this once:

```sh
chmod +x scrub-image
```

The first time you use the tool, it downloads the image libraries. After setup, it works offline.

## 2. Clean your images

**One image:**

```sh
./scrub-image "/path/to/image.jpg"
```

**A folder, including its subfolders:**

```sh
./scrub-image "/path/to/folder" --recursive
```

**Tip:** Type `./scrub-image `, then drag an image or folder into Terminal to insert its path. For a folder, add ` --recursive` at the end.

## 3. Share the new copies

| Folder | What it contains | Share it? |
| --- | --- | --- |
| `sanitized` | New PNGs that passed the checks | Yes, after checking the picture itself |
| `sanitized-reports` | Results, original paths, and file hashes | Keep private |

These folders appear beside a single input image, or inside the input folder you selected.

The terminal lists detected metadata fields removed and the check result for each file. If one image fails, the others continue.

## Choose image quality

| Mode | What changes |
| --- | --- |
| **Hardened — default** | Removes metadata, shrinks the image, and changes fine detail to disrupt some simple hidden-data methods. Quality is reduced. |
| **Metadata** | Removes metadata and keeps the original resolution. Does not deliberately disrupt hidden data in pixels. |

To keep more detail:

```sh
./scrub-image "/path/to/image.jpg" --mode metadata
```

Both modes save an opaque PNG. Transparent areas become white.

## What it cannot promise

**This is not antivirus or a guarantee of anonymity.**

- Names, faces, screen text, and recognizable locations remain.
- Some hidden messages and watermarks may survive.
- A recognizable image can still be found through reverse-image search.

Check the picture before posting it. For suspected malicious files, use a disposable virtual machine.

The tool tests its macOS restrictions before opening images and stops if protection cannot start. The checks verify file structure; they do not prove that an image is malware-free.

[Read the security details and testing limits →](SECURITY.md)

## More options

| Task | Command |
| --- | --- |
| Choose an output folder | `./scrub-image "/path/to/image.jpg" --output-dir "/path/to/share"` |
| Recheck saved PNGs | `./scrub-image "/path/to/sanitized" --verify --recursive` |
| Test processing restrictions | `./scrub-image --self-test` |
| Update image libraries | `./scrub-image --update` |
| Show all options | `./scrub-image --help` |

When rechecking copies made in metadata mode, add `--mode metadata`.

<details>
<summary>Supported files and other requirements</summary>

- **Supported:** still JPEG, PNG, GIF, WebP, BMP, classic TIFF, and HEIC/HEIF.
- **Not supported:** animation, multipage images, video, PDF, SVG, RAW, JPEG2000, and AVIF.
- Hidden files, symbolic links, and recognized output folders are skipped.
- macOS must provide `sandbox-exec`.
- The output disk must support hard links. A local APFS disk works.

</details>

<details>
<summary>Run the tests</summary>

After setup:

```sh
.venv/bin/python3 -m unittest discover -s tests -v
```

The processing tests use generated images. They do not test macOS enforcement.

To include live protection tests on a supported Mac:

```sh
RUN_SANDBOX_TESTS=1 .venv/bin/python3 -m unittest discover -s tests -v
```

</details>

## License

[MIT](LICENSE)
