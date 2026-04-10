# Current Ingest Pipeline Progress

**Date:** 2026-04-10  
**Status:** Active checkpoint for current lab baseline  
**Purpose:** Compact project checkpoint for future chats and source-reference continuity

---

## 1) Current baseline in one paragraph

The ingest pipeline currently runs end to end from `_INGEST_DONE` trigger to deterministic reporting and advisory AI reporting. Structural validation is the hard gate. After preflight passes, the workflow writes a manifest, performs deep validation (checksum + media inspection + media policy), routes to either `READY_FOR_REVIEW` or `REJECTED_POLICY`, then writes three artifacts: a compact deterministic `report.json`, a richer technical `asset_report.json`, and a separate advisory `ai_report.json`.

---

## 2) Current live flow

1. S3 upload under `s3://ingest-raw/<project_code>/<asset_set>/`
2. User uploads `_INGEST_DONE`
3. Starter Lambda creates deterministic `job_id`, writes DynamoDB job row, starts Step Functions
4. Step Functions sets `VALIDATING`
5. `ingest-validate-files` performs structural/preflight validation and builds deterministic inventory
6. `ingest-write-manifest` writes manifest snapshot
7. Step Functions sets `DEEP_VALIDATING`
8. `ingest-detect-mhl` selects checksum mode
   - `.mhl present` -> `VERIFY_MHL`
   - `no .mhl` -> `BASELINE_ONLY`
9. `ingest-deep-validate-media` performs media classification + ffprobe-based inspection
10. `ingest-deep-validate-media-policy` evaluates media-policy findings
11. Deep-validation summary is compacted into one stored structure
12. Step Functions sets `DEEP_VALIDATED`
13. Routing:
   - policy findings present -> `REJECTED_POLICY`
   - otherwise -> `READY_FOR_REVIEW`
14. Artifacts written:
   - `manifest.json`
   - `asset_report.json`
   - `report.json`
   - `ai_report.json`

---

## 3) Locked behavior and semantics

### Trigger / ownership
- `_INGEST_DONE` is the only valid ingest trigger.
- The parent folder of `_INGEST_DONE` defines job scope.
- DynamoDB is the authoritative source of truth for job state.
- Step Functions owns state transitions.

### Validation boundary
- `VALIDATING` = structural / preflight validation only.
- Structural validation is the hard gate.
- If structural validation fails, workflow stops at `FAILED_VALIDATION`.

### Deep validation meaning
- `DEEP_VALIDATING` = heavy/content-level checks are running.
- `DEEP_VALIDATED` means deep validation completed and findings were recorded.
- `DEEP_VALIDATED` does **not** mean all deep checks passed.
- Actual quality/result meaning must be read from `deep_validation_summary`.

### Checksum policy
- `.mhl present` -> verify against MHL.
- `no .mhl` -> compute baseline hashes.
- Checksum negatives are recorded as findings; they do not automatically crash the workflow.
- Both checksum branches should keep a normalized shared summary shape.

### AI reporting policy
- AI output is advisory only.
- AI does not affect workflow routing or job state.
- AI failure writes a fallback artifact and does not break deterministic ingest.

---

## 4) Current artifact model

### 1. `manifest.json`
Frozen inventory snapshot after preflight validation.

### 2. `report.json`
Compact deterministic operator summary.

### 3. `asset_report.json`
Richer per-asset technical/media artifact.

### 4. `ai_report.json`
Separate advisory interpretation layer under `ai_feedback`.

---

## 5) Current state-machine baseline

The current Step Functions baseline is effectively **ASL v1.1 plus reporting/AI-report stages**.

Major implemented families now present in flow:
- preflight validation
- manifest writing
- checksum branching (`VERIFY_MHL` / `BASELINE_ONLY`)
- media inspection
- media policy evaluation
- compact deep-validation summary persistence
- ready/reject routing
- asset report writing
- compact report writing
- advisory AI report writing

---

## 6) Current implementation notes

### Checksum
- MHL verify handler supports structured failure results such as parse failure and mismatch cases.
- Baseline checksum handler computes S3-side baseline hashes when no MHL exists.
- Docker-based Linux-compatible zip build scripts were created for checksum Lambdas because of `xxhash`.

### Media inspection
- Media inspection classifies by extension and probes video/audio with `ffprobe`.
- The media Lambda zip currently contains handler code only.
- `ffprobe` is provided by Lambda layer at runtime.

### Reporting
- Deep-validation payload persisted to DynamoDB is compacted before storage.
- Report layer is intentionally split into deterministic and advisory artifacts.

---

## 7) Proven / locked milestone status

### Proven earlier in lab
- clean no-MHL baseline path
- clean MHL verify path
- corrupt MHL parse failure handled as structured result
- reject path writes deterministic artifacts

### Proven recently
- `asset_report.json` is wired and written
- `report.json` stays compact
- `ai_report.json` success path works
- `ai_report.json` reject/fail path works
- `ai_report.json` fallback path works
- AI remains advisory and separate from deterministic truth
- repeatable packaging scripts were added for checksum Lambdas and media Lambda zip build

---

## 8) Current recommended source set for future chats

If source space is limited, the most useful compact set to keep is:
- `INGEST_CONTRACT_V1.pdf`
- `2026-03-16_Ingest-Contract-Notes_Addendum.md`
- `PROJECT_RULES.md`
- `asl-v1-1.json`
- `REGRESSION_PACK_v1_1.md`
- `AI_REPORTING_PLAN_v1_5.md`
- this file: `CURRENT_INGEST_PROGRESS_2026-04-10.md`

Optional to keep if ongoing packaging/deployment work continues:
- `2026-04-06_checksum_build_scripts_clean.md`
- `2026-04-06_media_lambda_packaging_runtime_note.md`

---

## 9) Files most likely safe to merge or retire

These are mainly historical/exploratory notes rather than current canonical references:
- ``VALIDATING`.pdf` -> merge into contract/addendum if still needed
- `Baseline-s3-hash-data-is-a-snapshot-for-future-uses.txt` -> retire after checksum contract is preserved elsewhere
- `Lambda-Timeout-and-Cost.txt` -> merge into future ops/performance note or retire
- `AI_Report_Checkpoint.md` -> merge into this checkpoint or AI reporting plan

---

## 10) Current next-step direction

Most natural next steps are:
1. source cleanup / canonicalization
2. optional packaging-note consolidation
3. regression re-run after any ASL or handler edits
4. next feature family only after baseline remains stable

Strong candidates for next feature family:
- media-processing expansion
- localization-oriented metadata / deliverable rules
- later AI/vision layer for content understanding (kept separate from deterministic validation)

---

## 11) Practical reading rule for future chats

When resuming this project in a new chat:
- treat this file as the quick checkpoint
- use contract/addendum for locked semantics
- use ASL for actual orchestration shape
- use regression pack before accepting structural changes
- use code files only when inspecting implementation detail

