# Media Lambda Packaging and Runtime Note

**Date:** 2026-04-06  
**Status:** Active Phase 2 packaging note  
**Scope:** Standardized zip build for `ingest-deep-validate-media` and its runtime dependency contract

---

## 1) Purpose

This note records the packaging and runtime contract for:

- `ingest-deep-validate-media`

Unlike the checksum Lambdas, this function does **not** package a native Python dependency such as `xxhash` into the zip.

Its main runtime dependency is:

- `ffprobe`

That dependency is provided by a Lambda layer, not by the function zip itself.

---

## 2) Build script

**Script path:**

```text
scripts/build-deep-validate-media.sh
```

```sh
#!/usr/bin/env bash
set -euo pipefail

LAMBDA_DIR="lambdas/ingest-deep-validate-media"
BUILD_DIR="${LAMBDA_DIR}/build"
PACKAGE_DIR="${BUILD_DIR}/package"
ZIP_PATH="${LAMBDA_DIR}/function.zip"

echo "==> Cleaning old build artifacts"
rm -rf "${BUILD_DIR}"
rm -f "${ZIP_PATH}"
mkdir -p "${PACKAGE_DIR}"

echo "==> Copying handler.py"
cp "${LAMBDA_DIR}/handler.py" "${PACKAGE_DIR}/handler.py"

echo "==> Creating function.zip"
cd "${PACKAGE_DIR}"
zip -r ../function.zip .
cd - >/dev/null

mv "${BUILD_DIR}/function.zip" "${ZIP_PATH}"

echo "==> Build complete"
echo "Output: ${ZIP_PATH}"

echo "==> Package contents"
unzip -l "${ZIP_PATH}" | sed -n '1,40p'
```

---

## 3) Output contract

The script produces:

```text
lambdas/ingest-deep-validate-media/function.zip
```

Current expected contents:

- `handler.py` only

This is intentional.

The function zip contains the handler code, while `ffprobe` is supplied separately through a Lambda layer.

---

## 4) Runtime contract

Confirmed live configuration:

- **Runtime:** `python3.12`
- **Architecture:** `x86_64`
- **Required layer:** `arn:aws:lambda:us-east-1:768979069717:layer:ffprobe:1`

Expected binary path in the Lambda runtime:

```text
/opt/bin/ffprobe
```

---

## 5) Why this packaging pattern is different from checksum Lambdas

### Checksum Lambdas
The checksum Lambdas package `xxhash` directly into `function.zip` because `xxhash` is a Python dependency that must match the Lambda runtime architecture.

### Media Lambda
The media Lambda does not currently package an extra Python dependency in the zip for probing.
Instead:

- the zip contains `handler.py`
- the runtime obtains `ffprobe` from the attached Lambda layer
- the handler calls the binary from `/opt/bin/ffprobe`

That means the media Lambda packaging pattern is:

- **zip build for handler code**
- **external layer for media probe binary**

---

## 6) Practical meaning

This script does **not** package `ffprobe` into the function zip.

It standardizes only the handler-code packaging side.

So the deployable function depends on both:

1. the correct `function.zip`
2. the correct `ffprobe` layer remaining attached

Both must be true for the function to work correctly.

---

## 7) Current Phase 2 meaning

With this note and the script, the media Lambda now has:

- a repeatable zip build path
- a documented runtime dependency contract
- a cleaner release baseline for later deployment standardization
