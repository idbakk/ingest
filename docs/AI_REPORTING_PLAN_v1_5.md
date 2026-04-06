## Purpose

Build a separate, advisory AI reporting layer for the ingest pipeline.
The AI layer should

- read trusted pipeline artifacts,
- produce a useful narrative and triage summary, and
- write its output as a separate artifact without affecting authoritative validation or job-state decisions.

This keeps the current ingest contract clean:

- `report.json` = compact operator summary
- `asset_report.json` = richer technical/media artifact
- `ai_report.json` = AI-generated advisory interpretation

## Why this layer exists

The pipeline now produces two strong deterministic artifacts:

1. a compact operator-facing report
2. a richer per-asset technical report

That is the right foundation for AI.
Instead of making AI part of validation truth, AI should consume those artifacts and add value in these areas:

- faster human understanding
- issue triage
- pattern recognition across assets
- recommended attention points
- audience-specific summaries

## Guiding principles

1. **Advisory, not authoritative**
   - AI does not decide pass/fail.
   - AI does not write job state.
   - AI does not override deterministic findings.

2. **Artifact-driven**
   - AI is NOT the primary source of truth.
   - AI reads structured outputs from the pipeline.
   - AI should not be the first place where raw media truth is determined.

3. **Separation of concerns**
   - `report.json` (**Operation Summary**) remains compact and deterministic.
   - `asset_report.json` (**Technical Detail**) remains technical and machine-friendly.
   - `ai_report.json` contains interpretation, synthesis, and recommended attention.

4. **Safe for production growth**
   - Start with a thin, read-only advisory scope.
   - Expand later only after schema and value are proven.

5. **Grounded & Evidence-based**
   - AI must cite the specific data point (the "why") for every observation

6. **Cost & Latency Conscious**
   - Implement data pruning and token management to ensure the AI layer doesn't become a bottleneck or a financial drain

## Recommended tier model

### Tier 1 — Advisory summary

**Goal:** Tell the operator what happened and what deserves attention.

Inputs:

- `report.json`
- `asset_report.json`

Outputs:

- concise delivery summary
- notable findings
- recommended review points

Characteristics:

- simple narrative
- light triage
- no deep inference
- advisory only

### Tier 2 — Analytical advisory

**Goal:** Interpret the technical data and explain what it likely means.

Inputs:

- same artifacts as Tier 1
- possibly richer summaries or grouped asset facts

Outputs:

- grouped findings
- ranked risks
- likely causes / pattern observations
- audience-specific summaries

Characteristics:

- deeper reasoning across assets
- issue prioritization
- still advisory only

### Tier 3 — Decision support

**Goal:** Propose what should happen next.

Inputs:

- current artifacts
- possibly business rules/spec expectations/context

Outputs:

- proposed disposition
- remediation suggestions
- structured downstream actions

Characteristics:

- closest to operations
- highest guardrail requirement
- should still begin as advisory before any operational use

## Recommended V1 target

Build **Tier 1.5**:

- more than a simple prose summary
- includes prioritization and pattern recognition
- still strictly advisory
- no automated routing or job-state impact

This is a good balance between usefulness and control.

## V1 scope

The AI report should answer these questions:

1. What happened in this delivery?
2. Are there any issues or notable patterns?
3. Which files or findings deserve attention first?
4. What should an operator review next?

### Included in V1

- delivery summary
- health/risk overview
- highlighted issues from deterministic findings
- Pattern Recognition: Identifying issues that span multiple assets
- Prioritized attention points: Ranking issues by severity/impact
- Grounded Next Actions: Suggested human actions limited to a pre-defined set of business processes (e.g, "Request Redelivery", "Manual QC Required", "Check metadata")

### Out of scope for V1

- direct video-content analysis
- scene understanding
- vision-based QC
- AI-driven pass/fail decisions
- AI-driven state routing
- automated remediation or processing
- authoritative technical truth generation

## Proposed `ai_report.json` schema

```json
{
  "ai_report_version": "v1.0",
  "generated_at": "ISO-8601 UTC timestamp",
  "generation_status": "success | fallback",
  "model_info": {
    "provider": "AWS Bedrock",
    "model_id": "string",
    "temperature": 0.2
  },
  "job": {
    "job_id": "string",
    "project_code": "string",
    "trigger": "_INGEST_DONE",
    "ruleset_version": "v1.0"
  },
  "source_artifacts": {
    "report_s3_uri": "s3://...",
    "asset_report_s3_uri": "s3://..."
  },
  "workflow": {
    "final_state": "READY_FOR_REVIEW | REJECTED_POLICY | ...",
    "quality_outcome": "PASS | PASS_WITH_WARNING | FAIL"
  },
  "ai_feedback": {
    "section_marker": "AI_GENERATED_ADVISORY_FEEDBACK",
    "summary": {
      "headline": "string",
      "overall_assessment": "healthy | warning | at_risk",
      "operator_brief": "string"
    },
    "attention_points": [
      {
        "priority": "high | medium | low",
        "family": "checksum | media | media_policy | workflow | delivery",
        "asset_id": "string-or-null",
        "title": "string",
        "reason": "string",
        "evidence": ["string"]
      }
    ],
    "notable_assets": [
      {
        "asset_id": "string",
        "why_notable": "string",
        "evidence": ["string"]
      }
    ],
    "recommended_next_action": "string",
    "disclaimer": "This AI report is advisory and does not replace deterministic validation results."
  },
  "input_summary": {
    "total_assets": 0,
    "selected_assets": 0,
    "assets_with_findings": 0
  },
  "locations": {
    "ai_report_s3_uri": "s3://..."
  }
}
```

## Lambda flow & Data Handling

Recommended Lambda sequence:

1. **Read & Prune:** Read `report.json` and `asset_report.json`. If the combined payload exceeds a safety threshold (e.g., 100KB), the Lambda will:
   - Prioritize assets with existing warnings or errors.
   - Sample a subset of "healthy" assets for pattern analysis.
   - Strip redundant technical fields not required for advisory summary.
2. **Normalize:** Format the pruned data into a clean JSON structure for the LLM.
3. **Prompt:** Call the AI model with strict instructions to return the defined schema.
4. **Validate:** Ensure the AI output is valid JSON and maps to the V1 schema.
5. **Optionally** persist `ai_report_s3_uri` to DynamoDB

### Suggested location

- `s3://<bucket>/<project_code>/_ai_reports/<job_id>.json`

### Suggested DynamoDB fields

- `ai_report_s3_uri`
- `ai_report_bucket`
- `ai_report_key`
- `ai_report_generated_at`

## Prompt design principles

1. Tell the model its role clearly:
   - advisory ingest analyst
   - not a deterministic validator
   - do not invent missing facts

2. Give structured inputs, not raw dumps:
   - workflow summary
   - outcome summary
   - asset counts
   - prioritized findings
   - selected per-asset facts

3. Require grounded language:
   - distinguish facts from interpretation
   - avoid certainty when data is incomplete
   - do not claim failures that deterministic logic did not record

4. Require a fixed output contract:
   - headline
   - overall assessment
   - attention points
   - notable assets
   - recommended next action
   - disclaimer

## Guardrails

- AI output must be clearly labeled advisory.
- AI must not modify job state.
- AI should not be the only place findings are represented.
- If the model response is malformed, write a controlled fallback artifact instead of failing the whole ingest pipeline.
- AI failure should not invalidate deterministic ingest success.
- Fail-safe: If the LLM call fails or times out, write a "minimal advisory" file stating the AI summary is unavailable. AI availability must not change deterministic ingest results. If AI generation fails, write a fallback ai_report.json and preserve the existing workflow outcome.
- Token/Cost Cap: Hard limit on max token per request. Jobs exceeding a certain asset count will use a "Summary Only" prompt to reduce costs.
- Human-in-the-Loop: Human feedback data should be collected on AI accuracy and hallucination rates. (later stages)

## Failure handling

If the AI call fails:

- write a minimal fallback `ai_report.json` with:
  - generation status = fallback
  - reason/error summary
  - source artifact references
- do not break the deterministic ingest path

## Exit criteria for V1

V1 is complete when:

- the Lambda reads `report.json` and `asset_report.json`
- it writes `ai_report.json` to S3
- the output is structured and repeatable
- the report is useful to a human operator
- the AI layer remains clearly advisory
- deterministic validation and routing remain unchanged

T1.5 SYSTEM_PROMPT SNAP SHOT

"""You are an advisory ingest analyst for a media ingest pipeline.

Deterministic pipeline artifacts are the source of truth. You are not the source of truth.
Your job is to read trusted structured artifacts and produce a grounded, useful advisory JSON report.

Core rules:

1. Do not invent facts.
2. Do not contradict deterministic workflow state, quality outcome, findings, or asset metadata.
3. Use only information present in the provided artifacts.
4. Every attention point and notable asset must include short evidence strings copied or tightly paraphrased from the provided input facts.
5. Keep recommendations within the allowed next actions and make them consistent with the workflow outcome.
6. If data is limited, ambiguous, or incomplete, say so in the reason or evidence instead of overstating.
7. Keep the operator brief concise, practical, and written for a human operator.
8. Return JSON only. No markdown. No prose outside the JSON object.
9. Follow the requested output schema exactly.
10. If multiple findings or notable assets describe the same underlying issue, group them into a single entry with a combined reason rather than repeating it across separate entries.

Asset naming and selection rules:

1. Always use the exact `asset_id` from the input when referring to a file.
   1-1. If a finding applies to the whole delivery rather than a specific file — such as a workflow rejection, preflight failure, or job-level metadata issue — set asset_id to null.
2. Never refer to files by order or position such as "first asset", "second asset", or "third asset".
3. In `notable_assets`, use the real `asset_id` and explain a concrete reason tied to deterministic evidence.
4. If no asset is meaningfully notable, return an empty `notable_assets` list.
5. Do not invent distinctions that are not supported by the input.
6. Prefer asset-specific reasons over generic praise.

Writing guidance:

- Be specific, grounded, and brief.
- Prefer clear operational language over abstract commentary.
- For healthy deliveries, do not force warnings or notable assets.
- For failed or rejected deliveries, make the operator brief and recommended action clearly reflect that outcome.

For mixed deliveries, the operator brief must include a balanced delivery-level summary:

- total asset count
- how many assets are healthy/reviewable
- how many assets have blocking findings
- the main blocking reason for the affected assets

Do not describe only the failed assets when healthy assets are also present.
When some assets passed and some failed, state both clearly and concisely.

Keep attention_points focused on items that need operator attention.
Do not create attention points just to praise healthy assets.
"""
