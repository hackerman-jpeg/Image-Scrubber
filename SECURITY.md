# Security model

Image Scrubber reconstructs still images and checks the resulting PNG structure.
It does not identify malware, establish anonymity, or certify that pixels contain
no hidden information.

## Processing boundary

The parent process reads a bounded copy of each input and selects a decoder from
its file signature. It never sends an original image to Pillow in the parent
process. Each image is decoded in a fresh `sandbox-exec` worker with:

- No network access or child-process creation.
- Read access to trusted runtime libraries, the decoder's source files, and its
  private working directory. Filesystem metadata and the root directory itself
  are readable; arbitrary user-file contents are not.
- Writes limited to the working directory and `/dev/null`.
- CPU, file-size, and open-file limits, disabled core dumps, and a wall timeout.

The policy includes Apple's installed `dyld-support.sb` rules when available.
These permit the system loader to start; the broader `system.sb` is not imported.
Trusted library and Python environment directories must not contain sensitive
unrelated files. Dependencies execute trusted code and must come from a trusted
source.

Before decoding, a live test requires permission denials for a private canary
read, an outside write, a network connection, and a child-process launch. Failure
stops processing. There is no automatic unrestricted fallback.

Inputs are limited to 256 MiB, 50 million pixels, and a 32768-pixel side. The
default wall timeout is 90 seconds per image; `--timeout` accepts 5–600 seconds.
CPU time is capped at 120 seconds even with a longer wall timeout. These controls
are not a hard resident-memory limit.

## Output verification

Worker output is treated as untrusted. The parent rejects symlinks and special
files, then uses a bounded parser to check:

- Only `IHDR`, `IDAT`, and `IEND` chunks, in the expected order.
- Valid chunk lengths and CRCs, within size and chunk-count limits.
- One complete compressed stream with exactly the expected RGB scanlines.
- No appended bytes or additional compressed streams.
- A pixel digest matching the worker's intended output.
- Hardened mode: a maximum 1600-pixel side and zeroed lowest three color bits.
- No unexpected filesystem extended attributes.

The PNG name is published atomically after verification. Files use owner-only
permissions. Failed outputs are removed. An interrupted run may leave a hidden
`.pending-*.tmp` file; it is not a verified output and can be deleted.

macOS may retain or reapply `com.apple.provenance`. This OS-managed attribute is
allowed and reported; it is outside the PNG bytes. Local attributes may travel
through archives or some sharing methods. Original timestamps are not preserved.

## What these checks do not establish

A compromised decoder could choose arbitrary pixels and supply a matching digest.
The parent can validate their structure, not their meaning. Low-bit clearing,
resampling, and recompression do not remove every possible covert channel or
resilient watermark. Visible identifying details and perceptual matches remain.
Metadata field inventories are bounded and are not exhaustive forensic reports.

Reconstruction cannot undo tracking that occurred when an email, page, download
link, or original image was accessed. A sharing platform may add metadata or
tracking after upload. No original image is opened in a viewer by this tool.

The operating system, native decoders, dependencies, and restrictions can have
vulnerabilities. Keep them updated. The HEIF worker refuses libheif older than
1.23.2, a documented security-fix floor; that is not a guarantee that newer
versions are free of vulnerabilities. For suspected exploits, use a disposable
virtual machine with networking disabled and no sensitive files.

## Testing

The processing suite uses generated benign fixtures and substitutes the restricted
worker launcher. It tests reconstruction, reports, verification, failures, and
cleanup; it does not test OS enforcement.

Live integration tests are enabled with `RUN_SANDBOX_TESTS=1`. They exercise the
actual restrictions and a complete generated-image batch. Restricted hosts may
deny nested sandbox creation. Such failures are reported rather than converted
to passing tests. Live enforcement of the current policy has not been validated
in the development environment used to prepare this release.

## Reporting an issue

For security-sensitive reports, use the repository's private vulnerability
reporting feature if enabled. Do not post exploit files, personal images, tokens,
or private reports in public issues. Public bug reports should use generated or
redacted fixtures and include macOS, Python, and dependency versions.

References:

- [Pillow security guidance](https://pillow.readthedocs.io/en/stable/handbook/security.html)
- [libheif security advisory](https://github.com/strukturag/libheif/security/advisories/GHSA-2jg2-4ch7-h545)
