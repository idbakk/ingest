# Regression Pack v1.1

**Date:** 2026-03-25  
**Status:** Active regression pack for current ingest/report baseline  
**Scope:** Fast re-test set for report generation, deep-validation summary shape, and finding preservation

---

## 1) Purpose

This regression pack is the standard re-test set to run after changes to:

- Step Functions ASL
- checksum handlers
- media inspection / media-policy handlers
- report generation
- DynamoDB report-pointer persistence

The goal is simple:

**confirm that the current report/deep-validation baseline still behaves correctly after later changes.**

---

## 2) Standard assertion set

For each scenario, verify only the minimum contract:

- execution reaches the expected final route state
- report JSON is generated in S3
- `deep_validation` is compact
- `findings_count` matches the expected behavior
- raw deep-validation arrays are absent from report body

### Required compactness assertions

These must remain `false` in the report:

- `.deep_validation.checksum.verified_entries`
- `.deep_validation.checksum.actual_entries`
- `.deep_validation.checksum.hash_entries`
- `.deep_validation.checksum.mismatches`
- `.deep_validation.media.classified_entries`
- `.deep_validation.media.probed_entries`
- `.deep_validation.media.mismatches`
- `.deep_validation.media_policy.mismatches`

---

## 3) Regression matrix

| ID | Scenario | Purpose | Expected final state | Expected outcome | Expected findings |
|---|---|---|---|---|---|
| R1 | Clean no-MHL baseline | confirm baseline checksum path still works | `READY_FOR_REVIEW` | `PASS` | `0` |
| R2 | Clean MHL verify | confirm MHL checksum verify path still works | `READY_FOR_REVIEW` | `PASS` | `0` |
| R3 | Corrupt MHL parse fail | confirm structured checksum failure stays auditable | expected reject/review path per current routing | non-pass expected | `>= 1` |
| R4 | Checksum mismatch or missing file | confirm checksum negatives still surface cleanly | expected reject/review path per current routing | non-pass expected | `>= 1` |
| R5 | Unreadable media / policy reject | confirm media failure still preserves compact report plus findings | `REJECTED_POLICY` | `FAIL` | `>= 1` |

---

## 4) Common report checks

### 4.1 Summary check

```bash
aws s3 cp "$REPORT_S3_URI" - | jq '{
  workflow,
  outcome,
  preflight,
  deep_validation,
  findings_count: (.findings | length)
}'
```

### 4.2 Key-shape check

```bash
aws s3 cp "$REPORT_S3_URI" - | jq '{
  checksum_keys: (.deep_validation.checksum | keys),
  media_keys: (.deep_validation.media | keys),
  media_policy_keys: (.deep_validation.media_policy | keys)
}'
```

### 4.3 Raw-payload absence check

```bash
aws s3 cp "$REPORT_S3_URI" - | jq '{
  has_verified_entries: (.deep_validation.checksum | has("verified_entries")),
  has_actual_entries: (.deep_validation.checksum | has("actual_entries")),
  has_hash_entries: (.deep_validation.checksum | has("hash_entries")),
  has_checksum_mismatches: (.deep_validation.checksum | has("mismatches")),
  has_classified_entries: (.deep_validation.media | has("classified_entries")),
  has_probed_entries: (.deep_validation.media | has("probed_entries")),
  has_media_mismatches: (.deep_validation.media | has("mismatches")),
  has_policy_mismatches: (.deep_validation.media_policy | has("mismatches"))
}'
```

---

## 5) Scenario expectations

### R1 — Clean no-MHL baseline

Minimum pass criteria:

- `workflow.final_state = READY_FOR_REVIEW`
- `outcome.quality_outcome = PASS`
- `deep_validation.checksum.mode = BASELINE_ONLY`
- `findings_count = 0`

### R2 — Clean MHL verify

Minimum pass criteria:

- `workflow.final_state = READY_FOR_REVIEW`
- `outcome.quality_outcome = PASS`
- `deep_validation.checksum.mode = VERIFY_MHL`
- `deep_validation.checksum.ok = true`
- `findings_count = 0`

### R3 — Corrupt MHL parse fail

Minimum pass criteria:

- checksum branch remains structured rather than crashing
- `deep_validation.checksum.mode = VERIFY_MHL`
- `deep_validation.checksum.ok = false`
- checksum failure is visible through report outcome and/or findings
- report still stays compact

### R4 — Checksum mismatch or missing file

Minimum pass criteria:

- checksum failure is preserved in report outcome and findings
- report still stays compact
- report still writes successfully to S3

### R5 — Unreadable media / policy reject

Minimum pass criteria:

- `workflow.final_state = REJECTED_POLICY`
- `outcome.quality_outcome = FAIL`
- `deep_validation.media.ok = false` and/or `deep_validation.media_policy.ok = false`
- `findings_count >= 1`
- report still stays compact

---

## 6) Run discipline

Use this pack:

- after ASL edits
- after Lambda handler edits in checksum/media/reporting areas
- before freezing a new milestone
- before starting the next feature family

If time is limited:

- minimum smoke set = `R1 + R5`
- fuller confidence set = `R1 + R2 + R5`
- full current pack = `R1 + R2 + R3 + R4 + R5`

---

## 7) Current status of the pack

Already proven recently:

- `R1` clean no-MHL baseline
- `R5` unreadable media / policy reject

Previously established in the lab and should remain in the pack:

- `R2` clean MHL verify
- `R3` corrupt MHL parse fail
- `R4` checksum mismatch or missing file

---

## 8) Exit criteria for current baseline

The current report/deep-validation baseline remains healthy if:

- `R1` passes
- `R5` passes
- no raw deep-validation arrays reappear in the report
- report generation and S3 persistence still succeed

That is the minimum standard before moving deeper into the next milestone.
