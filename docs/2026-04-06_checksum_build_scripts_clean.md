# Checksum Build Scripts

**Date:** 2026-04-06  
**Status:** Active Phase 2 packaging note  
**Scope:** Repeatable Docker-based zip build scripts for checksum Lambdas

---

## 1) Purpose

These two Lambdas were selected first for Phase 2 build/release standardization because both depend on the native-sensitive `xxhash` package.

Targets:

- `ingest-checksum-verify-mhl`
- `ingest-checksum-baseline`

The goal is to create repeatable build scripts that:

- use Docker as a Linux-compatible build environment
- produce Lambda-ready `function.zip`
- can be rerun later without guesswork

---

## 2) Target runtime / platform

**Target runtime:** AWS Lambda Python 3.11  
**Target platform:** Linux x86_64

Docker is used here because `xxhash` includes a compiled native binary that must match the Lambda runtime architecture.

---

## 3) Output contract

Each script produces:

```text
lambdas/<function-name>/function.zip
```

The generated zip should contain:

- `handler.py`
- `xxhash/`
- the Linux x86_64 compiled `xxhash` binary and metadata

---

## 4) build-checksum-verify-mhl.sh

**Script path:**

```text
scripts/build-checksum-verify-mhl.sh
```

```sh
#!/usr/bin/env bash
set -euo pipefail

LAMBDA_DIR="lambdas/ingest-checksum-verify-mhl"
BUILD_DIR="${LAMBDA_DIR}/build"
PACKAGE_DIR="${BUILD_DIR}/package"
ZIP_PATH="${LAMBDA_DIR}/function.zip"

echo "==> Cleaning old build artifacts"
rm -rf "${BUILD_DIR}"
rm -f "${ZIP_PATH}"
mkdir -p "${PACKAGE_DIR}"

echo "==> Copying handler.py"
cp "${LAMBDA_DIR}/handler.py" "${PACKAGE_DIR}/handler.py"

echo "==> Installing Linux-compatible dependencies with Docker"
docker run --rm \
  --platform linux/amd64 \
  --entrypoint /bin/sh \
  -v "$(pwd)/${PACKAGE_DIR}:/var/task" \
  public.ecr.aws/lambda/python:3.11 \
  -c "pip install --no-cache-dir xxhash -t /var/task"

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

## 5) build-checksum-baseline.sh

**Script path:**

```text
scripts/build-checksum-baseline.sh
```

```sh
#!/usr/bin/env bash
set -euo pipefail

LAMBDA_DIR="lambdas/ingest-checksum-baseline"
BUILD_DIR="${LAMBDA_DIR}/build"
PACKAGE_DIR="${BUILD_DIR}/package"
ZIP_PATH="${LAMBDA_DIR}/function.zip"

echo "==> Cleaning old build artifacts"
rm -rf "${BUILD_DIR}"
rm -f "${ZIP_PATH}"
mkdir -p "${PACKAGE_DIR}"

echo "==> Copying handler.py"
cp "${LAMBDA_DIR}/handler.py" "${PACKAGE_DIR}/handler.py"

echo "==> Installing Linux-compatible dependencies with Docker"
docker run --rm \
  --platform linux/amd64 \
  --entrypoint /bin/sh \
  -v "$(pwd)/${PACKAGE_DIR}:/var/task" \
  public.ecr.aws/lambda/python:3.11 \
  -c "pip install --no-cache-dir xxhash -t /var/task"

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

## 6) What this note means

These scripts do **not** convert the Lambdas into Docker container deployments.

Instead, they use Docker as a controlled Linux build environment to produce correct zip packages for Lambda functions with native dependencies.

This is a Phase 2 maintainer/developer packaging step, not end-user product packaging.
