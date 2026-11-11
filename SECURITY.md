# Security

Image Scrubber creates a new image, removes file metadata, and checks the saved copy. Your original stays unchanged.

It reduces some privacy and security risks. It does not guarantee that an image is anonymous or free of malware.

## What it removes

The new copy does not carry over the original file’s:

- Location, camera, author, software, and capture-date metadata.
- Comments, embedded previews, and extra file sections.
- Data attached after the image.
- Original filename or filesystem attributes.

The default hardened mode also resizes, slightly blurs, and recompresses the picture, then clears some color information. This reduces image quality and disrupts some simple ways of hiding data in pixels.

## What can remain

The picture itself can still identify you through faces, names, addresses, reflections, screen text, account details, QR codes, or recognizable locations.

Some hidden messages, watermarks, and image fingerprints may survive. A recognizable picture can still be matched through reverse-image search.

The tool cannot undo tracking that happened when you opened an email, visited a page, or downloaded the original.

**Check the picture and redact visible identifying details before posting it.**

## How it handles received images

Each image is processed in a separate restricted process. Those restrictions are intended to:

- Block network connections and child processes.
- Limit access to files outside its working area and trusted software libraries.
- Prevent changes outside its temporary working area.
- Limit processing time and file size.

Before opening an image, the tool tests whether key restrictions work. If the test fails, it stops. It does not silently turn off protection.

Image decoders and macOS can still have vulnerabilities. These restrictions are an extra precaution, not a guarantee.

**For a file you suspect is malicious, use a disposable virtual machine with networking disabled and no sensitive files. Do not open the original first.**

## What the second check confirms

Before making the new PNG available, the tool checks that:

- It contains only the expected image sections.
- Its checksums and pixel data are consistent.
- It has no extra metadata sections or appended data.
- Hardened outputs meet the size limit and have the expected color bits cleared.
- No unexpected filesystem attributes remain.

These checks confirm the file’s structure. They do not prove that its pixels contain no hidden information or malware.

## Files you should share

**Share only the verified PNG copies.**

The separate reports contain original file paths and hashes. Keep those reports private.

macOS may attach its own `com.apple.provenance` attribute to a new file. This is outside the PNG’s contents and is allowed by the checker. Local attributes can travel through some sharing methods or archives. Websites may also add metadata after upload.

## Testing and updates

The processing tests use generated images. They check reconstruction, reports, error handling, and output verification. They do not test whether macOS enforces the restrictions.

Separate live tests check those restrictions. The current protection profile has not yet been validated in a complete live test in the release environment. The startup self-test must pass on your Mac before processing begins.

Keep macOS, Python, and the image libraries updated. Passing tests does not guarantee protection against every attack.

## Reporting a security problem

Use the repository’s private security reporting option if it is enabled.

Do not post personal images, private reports, passwords, or working exploit files in public issues. Use a generated or redacted example when possible.
```
