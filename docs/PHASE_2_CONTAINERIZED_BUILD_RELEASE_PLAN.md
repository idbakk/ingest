# PHASE_2_CONTAINERIZED_BUILD_RELEASE_PLAN.md

**Date:** 2026-04-06  
**Status:** Proposed Phase 2 plan for review and revision  
**Scope:** Minimal containerized build/release path for native-sensitive ingest Lambdas, followed by operational hardening

---

## 1) Purpose

Phase 2 exists to make packaging and release more reproducible for the parts of the ingest pipeline that already have real platform/runtime sensitivity.

This phase is **not** a full platform containerization effort.

It is intended to solve practical issues such as:

- Linux-compatible packaging for native Python dependencies
- repeatable Lambda build outputs
- cleaner release steps
- lower risk of local/macOS vs Lambda runtime mismatch
- a better base for later timeout, memory, and concurrency tuning

---

## 2) Why this phase comes next

The current lab has already landed and validated three artifact layers:

- `report.json` = compact deterministic operator summary
- `asset_report.json` = richer technical/media artifact
- `ai_report.json` = advisory AI layer

That makes this a good point to harden packaging and release before pushing into the next feature family.

This is especially relevant because the current pipeline already includes Lambdas with platform-sensitive behavior:

- checksum verification and baseline capture use `xxhash`
- media inspection depends on `ffprobe`
- larger media sizes will affect runtime, memory, timeout, and cost behavior

---

## 3) Phase 2 goal

Create a **minimal, repeatable, Linux-compatible build/release path** for the native-sensitive Lambdas first, then use that path as the base for operational hardening.

### Success definition

At the end of Phase 2:

- selected Lambdas can be packaged from a known Linux environment
- package outputs are reproducible and documented
- release steps are simple and repeatable
- rebuilt functions pass a minimum smoke/regression set
- packaging/runtime drift risk is reduced

---

## 4) In-scope Lambdas for Phase 2

Start with these three:

1. `ingest-checksum-verify-mhl`
2. `ingest-checksum-baseline`
3. `ingest-deep-validate-media`

### Why these first

#### `ingest-checksum-verify-mhl`

- uses native-sensitive hashing dependency (`xxhash`)
- already required platform-correct packaging during earlier work
- a packaging mismatch here directly breaks runtime behavior

#### `ingest-checksum-baseline`

- same native hashing concern as verify path
- should follow the same packaging discipline as the MHL verify branch

#### `ingest-deep-validate-media`

- depends on `ffprobe`
- runtime/tooling assumptions matter
- this is the most obvious place where packaging, layers, binaries, and execution environment intersect

---

## 5) Explicitly out of scope

Do **not** let Phase 2 expand into any of the following:

- full-platform containerization
- ECS redesign
- container image Lambda migration for the whole system
- AI model/container redesign
- direct video-content analysis
- automated remediation/processing
- broad infra refactor

Phase 2 is a **minimal build/release hardening phase**, not a platform rewrite.

---

## 6) Proposed deliverables

## 6.1 Build structure

Create a small build area, for example:

```text
build/
docker/
scripts/
```

Possible structure:

```text
docker/
  lambda-python311/
    Dockerfile   # optional if custom image is needed

scripts/
  build-checksum-verify-mhl.sh
  build-checksum-baseline.sh
  build-deep-validate-media.sh
  deploy-checksum-verify-mhl.sh
  deploy-checksum-baseline.sh
  deploy-deep-validate-media.sh
```

This does not need to be elegant yet. It needs to be reliable.

---

## 6.2 Packaging contract

Standardize these packaging rules:

- build from a Linux-compatible environment
- produce `function.zip`
- keep `handler.py` as the Lambda entry file
- keep dependencies at the zip root when needed
- document whether a Lambda depends on:
  - pure Python only
  - native Python dependency
  - external binary / layer

### Target output per Lambda

For each packaged Lambda:

- `handler.py`
- required dependency folders/modules
- optional documentation note about runtime assumptions

---

## 6.3 Build scripts

Each target Lambda should have a repeatable build script that:

1. clears prior build artifacts
2. copies the correct `handler.py`
3. installs required dependencies in a Linux-compatible environment
4. creates `function.zip`
5. optionally prints package contents or package size

### Minimum requirement

Even if you do not unify the whole build flow yet, each script must be:

- deterministic
- easy to rerun
- documented enough that future-you can trust it

---

## 6.4 Deployment scripts or release commands

For each in-scope Lambda, define a standard release step:

- `aws lambda update-function-code ...`
- optional `aws lambda update-function-configuration ...`
- any layer update steps if relevant

This can be script-based or written as canonical commands in a note.

---

## 6.5 Runtime dependency documentation

For each of the three Lambdas, record:

- runtime version
- native dependencies
- binary dependencies
- whether a layer is required
- expected timeout/memory starting point
- any known packaging risks

This is small work but high value.

---

## 7) Recommended implementation order

### Step 1 — checksum build path first

Start with:

1. `ingest-checksum-verify-mhl`
2. `ingest-checksum-baseline`

These are the cleanest first targets because both revolve around the same hashing/runtime packaging issue.

### Step 2 — media build path next

Then package:

3. `ingest-deep-validate-media`

This will force you to document the `ffprobe` dependency path cleanly.

### Step 3 — release notes / commands

Once the packages are reproducible, record the deployment path.

### Step 4 — smoke test

Run a limited validation set after rebuilt deployment.

Recommended minimum:

- R1 clean no-MHL baseline
- R5 unreadable media / policy reject

If time allows:

- R2 clean MHL verify

---

## 8) Operational hardening immediately after packaging

This is the work that should follow directly after the containerized build/release path is in place.

## 8.1 Why it comes here

Once the build path is reliable, you can make runtime decisions with much more confidence.

This matters because current runtime behavior depends on:

- file count
- file size
- checksum time
- media probe time
- total Lambda timeout
- memory allocation
- concurrency choices

## 8.2 Hardening topics

Review and tune:

- Lambda timeout
- Lambda memory
- parallel execution strategy
- large-file runtime behavior
- cost vs turnaround time

## 8.3 Expected output of hardening

A small operations note should record:

- starting timeout/memory values
- observed pain points
- revised recommended settings
- which Lambdas may outgrow Lambda limits first

---

## 9) Regression / validation discipline

After Phase 2 packaging changes, use the existing regression discipline rather than inventing a new one.

### Minimum smoke set

- `R1` clean no-MHL baseline
- `R5` unreadable media / policy reject

### Better confidence set

- `R1`
- `R2`
- `R5`

### Full pack later if needed

- `R1`
- `R2`
- `R3`
- `R4`
- `R5`

The point here is not exhaustive testing every time. It is proving that packaging changes did not silently break the currently frozen baseline.

---

## 10) Exit criteria for Phase 2

Phase 2 is complete when:

- the three target Lambdas can be rebuilt from a Linux-compatible path
- release steps are documented and repeatable
- at least the minimum smoke regression set passes after rebuilt deployment
- packaging/runtime assumptions are documented
- a first operational hardening note exists for timeout/memory/concurrency direction

---

## 11) Recommended checkpoint statement after completion

**Checkpoint statement:**

As of Phase 2 completion, the ingest lab has a minimal containerized build/release path for the native-sensitive checksum and media Lambdas, with documented packaging assumptions and a repeatable smoke-test discipline, creating a more stable base for later operational tuning and Tier 2 AI work.

---

## 12) What should come after Phase 2

After Phase 2 and immediate operational hardening, the next feature family should be:

## Tier 2 analytical advisory

That phase should focus on:

- better cross-asset pattern detection
- more balanced mixed-delivery summaries
- grouped issue interpretation
- stronger operator triage value

It should **not** jump directly to:

- direct video-content analysis
- AI-driven routing
- automated remediation

---

## 13) Current recommendation

Recommended next sequence:

1. review and revise this Phase 2 plan
2. build minimal containerized packaging path for checksum Lambdas
3. extend the same pattern to media validation Lambda
4. document release steps
5. run smoke regression
6. record operational hardening note
7. move to Tier 2 analytical advisory
