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