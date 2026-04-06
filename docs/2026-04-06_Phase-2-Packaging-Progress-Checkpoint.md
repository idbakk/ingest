# Phase 2 Packaging Progress Checkpoint

**Date:** 2026-04-06  
**Status:** Active progress checkpoint for Phase 2 build/release hardening  
**Scope:** Checksum Lambda build standardization completed; media Lambda packaging path clarified

---

## 1) What was completed today

Completed and confirmed:

- clarified the purpose of Phase 2:
  - this phase is for **developer/operator build and release hardening**
  - this phase is **not** end-user product packaging
- standardized the Docker-based zip build flow for:
  - `ingest-checksum-verify-mhl`
  - `ingest-checksum-baseline`
- created repeatable build scripts under `scripts/`
- successfully rebuilt fresh `function.zip` packages for both checksum Lambdas
- confirmed the rebuilt zip packages contain the correct Linux x86_64 native `xxhash` binary
- confirmed the build scripts now act as a repeatable “factory,” not just one-off manual commands
- clarified the packaging model for `ingest-deep-validate-media`:
  - the function zip contains `handler.py`
  - `ffprobe` is provided separately by a Lambda layer

---

## 2) Why today’s work matters

Before today, working zip packages already existed, but the build process was still mostly manual and memory-driven.

Today’s change is important because it moves the checksum Lambdas from:

- “working package artifact exists”

to:

- “repeatable build procedure exists”

That is the core value of this Phase 2 step.

---

## 3) Locked packaging understanding from today

### 3.1 Checksum Lambdas

For the checksum Lambdas:

- the deployable artifact remains `function.zip`
- Docker is used as a controlled Linux-compatible build environment
- the goal is **not** to deploy Docker containers to Lambda
- the goal is to produce runtime-compatible zip artifacts in a repeatable way

### 3.2 Media Lambda

For `ingest-deep-validate-media`:

- the function zip is still a normal Lambda zip
- `ffprobe` is **not** bundled into the zip
- `ffprobe` is expected at `/opt/bin/ffprobe`
- the binary comes from a Lambda layer

That means the media Lambda packaging pattern is:

- zip build for handler code
- documented runtime dependency on an external layer

---

## 4) Proven results today

### 4.1 `ingest-checksum-verify-mhl`

Confirmed:

- build script ran successfully
- new `function.zip` was created
- package contained Linux x86_64 compiled `xxhash`

### 4.2 `ingest-checksum-baseline`

Confirmed:

- same repeatable build pattern works
- new `function.zip` was created
- package contained Linux x86_64 compiled `xxhash`

### 4.3 `ingest-deep-validate-media` runtime dependency check

Confirmed live configuration:

- runtime: `python3.12`
- architecture: `x86_64`
- required layer:
  - `arn:aws:lambda:us-east-1:768979069717:layer:ffprobe:1`

This means the media Lambda should be standardized next with:
- zip build for `handler.py`
- clear documentation of the required `ffprobe` layer

---

## 5) Build pattern established today

### Checksum build pattern

Common pattern now established:

1. create clean build workspace
2. copy `handler.py`
3. install Linux-compatible dependency in Docker
4. create `function.zip`
5. inspect zip contents

### Why Docker is used here

Docker is used because `xxhash` is a native compiled dependency and must match the Lambda runtime environment.

The current target is:

- Linux
- x86_64

---

## 6) What remains open

Not yet completed today:

- documentation note for the checksum build scripts
- standardized build script for `ingest-deep-validate-media`
- documentation note for media Lambda runtime assumptions
- deployment/release command standardization
- post-build smoke regression after redeployment

---

## 7) Immediate next steps

Next recommended sequence:

1. write down the checksum build script notes
   - script name
   - target Lambda
   - output path
   - Docker image
   - target architecture
   - why Docker is needed

2. create `build-deep-validate-media.sh`

3. document media Lambda runtime assumptions
   - runtime: `python3.12`
   - architecture: `x86_64`
   - required layer: `ffprobe:1`
   - expected binary path: `/opt/bin/ffprobe`

4. then move toward deployment/release standardization and smoke validation

---

## 8) Current checkpoint statement

**Checkpoint statement:**

As of 2026-04-06, the Phase 2 build/release path has been successfully standardized for the two native-sensitive checksum Lambdas using repeatable Docker-based zip builds, and the next packaging target is the media validation Lambda, whose handler zip and `ffprobe` layer dependency are now clearly separated.
