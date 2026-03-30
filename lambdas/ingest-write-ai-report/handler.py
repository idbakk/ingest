# ingest-write-ai-report handler
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
bedrock = boto3.client("bedrock-runtime")

JOB_TABLE = os.environ.get("JOB_TABLE", "IngestJobs")
AI_REPORT_BUCKET = os.environ.get("AI_REPORT_BUCKET")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID")
BEDROCK_TEMPERATURE = float(os.environ.get("BEDROCK_TEMPERATURE", "0.0"))
BEDROCK_MAX_TOKENS = int(os.environ.get("BEDROCK_MAX_TOKENS", "1800"))
MAX_ASSETS_WITH_FINDINGS = int(os.environ.get("AI_MAX_ASSETS_WITH_FINDINGS", "25"))
MAX_HEALTHY_ASSET_SAMPLES = int(os.environ.get("AI_MAX_HEALTHY_ASSET_SAMPLES", "5"))
MAX_INPUT_BYTES = int(os.environ.get("AI_MAX_INPUT_BYTES", "100000"))
PERSIST_DDB_POINTER = os.environ.get("PERSIST_DDB_POINTER", "1") == "1"

ALLOWED_ASSESSMENTS = {"healthy", "warning", "at_risk"}
ALLOWED_PRIORITIES = {"high", "medium", "low"}
ALLOWED_ACTIONS = {
    "Proceed with human review",
    "Manual QC Required",
    "Request Redelivery",
    "Check metadata",
    "Investigate checksum findings",
    "Investigate media probe failure",
    "Review policy findings",
    "Review findings and request redelivery or remediation",
    "Investigate unreadable media and request corrected delivery",
    "AI summary unavailable",
}

SYSTEM_PROMPT = """You are an advisory ingest analyst for a media ingest pipeline.

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

OUTPUT_SCHEMA_HINT = {
    "ai_report_version": "v1.0",
    "ai_feedback": {
        "section_marker": "AI_GENERATED_ADVISORY_FEEDBACK",
        "summary": {
            "headline": "string",
            "overall_assessment": "healthy | warning | at_risk",
            "operator_brief": "string",
        },
        "attention_points": [
            {
                "priority": "high | medium | low",
                "family": "checksum | media | media_policy | workflow | delivery",
                "asset_id": "path-or-null",
                "title": "short string",
                "reason": "short grounded explanation",
                "evidence": ["short evidence string"],
            }
        ],
        "notable_assets": [
            {
                "asset_id": "path",
                "why_notable": "short grounded explanation",
                "evidence": ["short evidence string"],
            }
        ],
        "recommended_next_action": "Proceed with human review | Manual QC Required | Request Redelivery | Check metadata | Investigate checksum findings | Investigate media probe failure | Review policy findings | Review findings and request redelivery or remediation | Investigate unreadable media and request corrected delivery | AI summary unavailable",
        "disclaimer": "This AI report is advisory and does not replace deterministic validation results.",
    },
}

table = dynamodb.Table(JOB_TABLE)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_s3_uri(uri: str) -> Tuple[str, str]:
    if not uri or not uri.startswith("s3://"):
        raise ValueError(f"Invalid S3 URI: {uri}")
    remainder = uri[5:]
    parts = remainder.split("/", 1)
    bucket = parts[0]
    key = parts[1] if len(parts) > 1 else ""
    return bucket, key


def load_json_from_s3_uri(uri: str) -> Dict[str, Any]:
    bucket, key = parse_s3_uri(uri)
    resp = s3.get_object(Bucket=bucket, Key=key)
    return json.loads(resp["Body"].read().decode("utf-8"))


def load_job_row(job_id: str) -> Dict[str, Any]:
    resp = table.get_item(Key={"job_id": job_id})
    return resp.get("Item") or {}


def dump_json_bytes(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def pick_asset_id(asset: Dict[str, Any]) -> Optional[str]:
    return asset.get("path") or asset.get("s3_key")


def asset_has_findings(asset: Dict[str, Any]) -> bool:
    findings = asset.get("findings") or []
    return isinstance(findings, list) and len(findings) > 0


def asset_is_problematic(asset: Dict[str, Any]) -> bool:
    if asset_has_findings(asset):
        return True
    checksum = asset.get("checksum") or {}
    probe = asset.get("probe") or {}
    bad_checksum = checksum.get("status") in {
        "missing",
        "size_mismatch",
        "hash_mismatch",
        "hash_compute_error",
        "invalid_reference",
        "failed",
        "expected_only",
        "not_captured",
    }
    bad_probe = probe.get("unreadable") is True or probe.get("probe_error")
    return bad_checksum or bad_probe


def compact_probe_for_ai(probe: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(probe, dict):
        return {}
    return {
        "readable": probe.get("readable"),
        "unreadable": probe.get("unreadable"),
        "container": probe.get("container"),
        "duration_seconds": probe.get("duration_seconds"),
        "bit_rate": probe.get("bit_rate"),
        "file_size": probe.get("file_size"),
        "video_codec": probe.get("video_codec"),
        "video_profile": probe.get("video_profile"),
        "width": probe.get("width"),
        "height": probe.get("height"),
        "display_aspect_ratio": probe.get("display_aspect_ratio"),
        "pixel_format": probe.get("pixel_format"),
        "field_order": probe.get("field_order"),
        "frame_rate": probe.get("frame_rate"),
        "timecode": probe.get("timecode"),
        "audio_codec": probe.get("audio_codec"),
        "channels": probe.get("channels"),
        "channel_layout": probe.get("channel_layout"),
        "sample_rate": probe.get("sample_rate"),
        "bit_depth": probe.get("bit_depth"),
        "color_space": probe.get("color_space"),
        "color_primaries": probe.get("color_primaries"),
        "audio_stream_count": probe.get("audio_stream_count"),
        "probe_method": probe.get("probe_method"),
        "probe_error": probe.get("probe_error"),
    }


def compact_asset_for_ai(asset: Dict[str, Any]) -> Dict[str, Any]:
    checksum = asset.get("checksum") or {}
    findings = asset.get("findings") or []
    return {
        "asset_id": pick_asset_id(asset),
        "media_type": asset.get("media_type"),
        "extension": asset.get("extension"),
        "size": asset.get("size"),
        "checksum": {
            "mode": checksum.get("mode"),
            "status": checksum.get("status"),
            "algorithm": checksum.get("algorithm"),
            "expected_algorithm": checksum.get("expected_algorithm"),
            "actual_algorithm": checksum.get("actual_algorithm"),
            "mhl_key": checksum.get("mhl_key"),
        },
        "probe": compact_probe_for_ai(asset.get("probe") or {}),
        "findings": findings,
    }


def build_ai_input(report: Dict[str, Any], asset_report: Dict[str, Any]) -> Dict[str, Any]:
    assets = asset_report.get("assets") or []
    findings_assets = [a for a in assets if asset_has_findings(a)]
    problematic_assets = [a for a in assets if asset_is_problematic(a) and not asset_has_findings(a)]
    healthy_assets = [a for a in assets if not asset_is_problematic(a)]

    selected_assets: List[Dict[str, Any]] = []
    seen_ids = set()

    def add_assets(candidates: List[Dict[str, Any]], limit: int) -> None:
        for asset in candidates:
            asset_id = pick_asset_id(asset)
            if asset_id in seen_ids:
                continue
            seen_ids.add(asset_id)
            selected_assets.append(compact_asset_for_ai(asset))
            if len(selected_assets) >= limit:
                break

    add_assets(findings_assets, MAX_ASSETS_WITH_FINDINGS)
    remaining_problem_slots = MAX_ASSETS_WITH_FINDINGS + MAX_HEALTHY_ASSET_SAMPLES - len(selected_assets)
    if remaining_problem_slots > 0:
        add_assets(problematic_assets, len(selected_assets) + remaining_problem_slots)
    remaining_healthy_slots = MAX_ASSETS_WITH_FINDINGS + MAX_HEALTHY_ASSET_SAMPLES - len(selected_assets)
    if remaining_healthy_slots > 0:
        add_assets(healthy_assets, len(selected_assets) + remaining_healthy_slots)

    ai_input = {
        "job": report.get("job") or asset_report.get("job") or {},
        "workflow": report.get("workflow") or asset_report.get("workflow") or {},
        "outcome": report.get("outcome") or {},
        "preflight": report.get("preflight") or {},
        "deep_validation": report.get("deep_validation") or asset_report.get("deep_validation_summary") or {},
        "report_findings": report.get("findings") or [],
        "inventory_summary": asset_report.get("inventory_summary") or {},
        "tooling": asset_report.get("tooling") or {},
        "asset_counts": {
            "total_assets": len(assets),
            "assets_with_findings": len(findings_assets),
            "problematic_assets": len([a for a in assets if asset_is_problematic(a)]),
            "healthy_assets": len(healthy_assets),
            "selected_assets": len(selected_assets),
        },
        "selected_assets": selected_assets,
    }

    if dump_json_bytes(ai_input) <= MAX_INPUT_BYTES:
        return ai_input

    # Reduce healthy sample first, then reduce problematic non-finding assets.
    while dump_json_bytes(ai_input) > MAX_INPUT_BYTES and ai_input["selected_assets"]:
        # Prefer dropping healthy assets from the tail.
        idx_to_remove = None
        for idx in range(len(ai_input["selected_assets"]) - 1, -1, -1):
            asset = ai_input["selected_assets"][idx]
            if not (asset.get("findings") or []):
                idx_to_remove = idx
                break
        if idx_to_remove is None:
            idx_to_remove = len(ai_input["selected_assets"]) - 1
        ai_input["selected_assets"].pop(idx_to_remove)
        ai_input["asset_counts"]["selected_assets"] = len(ai_input["selected_assets"])

    return ai_input


def build_user_prompt(ai_input: Dict[str, Any]) -> str:
    return (
        "Produce an advisory ingest AI report using this exact JSON shape:\n"
        + json.dumps(OUTPUT_SCHEMA_HINT, ensure_ascii=False, indent=2)
        + "\n\nTrusted input:\n"
        + json.dumps(ai_input, ensure_ascii=False, indent=2)
    )


def extract_text_response(resp: Dict[str, Any]) -> str:
    output = resp.get("output") or {}
    message = output.get("message") or {}
    content = message.get("content") or []
    text_parts: List[str] = []
    for block in content:
        if isinstance(block, dict) and "text" in block:
            text_parts.append(block["text"])
    return "\n".join(text_parts).strip()


def try_parse_json(text: str) -> Dict[str, Any]:
    if not text:
        raise ValueError("Empty model response")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def choose_recommended_action(final_state: Optional[str], quality_outcome: Optional[str], attention_points: List[Dict[str, Any]]) -> str:
    families = {item.get("family") for item in attention_points if isinstance(item, dict)}

    if final_state == "REJECTED_POLICY" or quality_outcome == "FAIL":
        if "media" in families or "media_policy" in families:
            return "Investigate unreadable media and request corrected delivery"
        if "checksum" in families:
            return "Review findings and request redelivery or remediation"
        return "Review findings and request redelivery or remediation"

    if attention_points:
        if "checksum" in families:
            return "Investigate checksum findings"
        if "media" in families:
            return "Investigate media probe failure"
        if "media_policy" in families:
            return "Review policy findings"
        return "Manual QC Required"

    return "Proceed with human review"


def choose_operator_brief(
    headline: Optional[str],
    operator_brief: Optional[str],
    final_state: Optional[str],
    quality_outcome: Optional[str],
    attention_points: List[Dict[str, Any]],
) -> str:
    brief = (operator_brief or "").strip()
    families = {item.get("family") for item in attention_points if isinstance(item, dict)}

    if final_state == "REJECTED_POLICY" or quality_outcome == "FAIL":
        if "media" in families or "media_policy" in families:
            return "The delivery was rejected by policy due to unreadable media and probe failure."
        if "checksum" in families:
            return "The delivery was rejected after deterministic validation findings were recorded."
        return "The delivery was rejected after deterministic validation findings were recorded."

    if brief:
        lowered = brief.lower()
        if "pipeline has failed" in lowered:
            return "The delivery has validation findings and requires operator attention."
        return brief

    if headline:
        return headline

    return "AI advisory generated from deterministic ingest artifacts."


def normalize_ai_report_payload(
    payload: Dict[str, Any],
    final_state: Optional[str] = None,
    quality_outcome: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("AI payload must be a JSON object")

    # Accept either:
    # 1) legacy payload with summary/attention_points at top level
    # 2) new payload already wrapped in ai_feedback
    ai_feedback = payload.get("ai_feedback") if isinstance(payload.get("ai_feedback"), dict) else payload

    summary = ai_feedback.get("summary") or {}
    overall_assessment = summary.get("overall_assessment")
    if overall_assessment not in ALLOWED_ASSESSMENTS:
        overall_assessment = "warning"

    attention_points = ai_feedback.get("attention_points") or []
    normalized_attention: List[Dict[str, Any]] = []
    for item in attention_points[:10]:
        if not isinstance(item, dict):
            continue
        priority = item.get("priority")
        if priority not in ALLOWED_PRIORITIES:
            priority = "medium"
        normalized_attention.append(
            {
                "priority": priority,
                "family": item.get("family"),
                "asset_id": item.get("asset_id"),
                "title": item.get("title"),
                "reason": item.get("reason"),
                "evidence": item.get("evidence") or [],
            }
        )

    notable_assets = ai_feedback.get("notable_assets") or []
    normalized_notable: List[Dict[str, Any]] = []
    for item in notable_assets[:10]:
        if not isinstance(item, dict):
            continue
        normalized_notable.append(
            {
                "asset_id": item.get("asset_id"),
                "why_notable": item.get("why_notable"),
                "evidence": item.get("evidence") or [],
            }
        )

    headline = summary.get("headline")
    operator_brief = choose_operator_brief(
        headline=headline,
        operator_brief=summary.get("operator_brief"),
        final_state=final_state,
        quality_outcome=quality_outcome,
        attention_points=normalized_attention,
    )

    action = ai_feedback.get("recommended_next_action")
    if action not in ALLOWED_ACTIONS:
        action = choose_recommended_action(
            final_state=final_state,
            quality_outcome=quality_outcome,
            attention_points=normalized_attention,
        )

    disclaimer = (
        ai_feedback.get("disclaimer")
        or "This AI report is advisory and does not replace deterministic validation results."
    )

    normalized = {
        "ai_feedback": {
            "section_marker": "AI_GENERATED_ADVISORY_FEEDBACK",
            "summary": {
                "headline": headline,
                "overall_assessment": overall_assessment,
                "operator_brief": operator_brief,
            },
            "attention_points": normalized_attention,
            "notable_assets": normalized_notable,
            "recommended_next_action": action,
            "disclaimer": disclaimer,
        }
    }

    if (
        not normalized["ai_feedback"]["summary"]["headline"]
        or not normalized["ai_feedback"]["summary"]["operator_brief"]
    ):
        raise ValueError("AI payload missing required summary fields")

    return normalized


def invoke_bedrock_json(model_id: str, user_prompt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    resp = bedrock.converse(
        modelId=model_id,
        system=[{"text": SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": [{"text": user_prompt}]}],
        inferenceConfig={
            "maxTokens": BEDROCK_MAX_TOKENS,
            "temperature": BEDROCK_TEMPERATURE,
        },
    )
    text = extract_text_response(resp)
    payload = try_parse_json(text)
    return payload, resp


def update_dynamodb_pointer(job_id: str, ai_report_s3_uri: str, out_bucket: str, ai_report_key: str, generated_at: str) -> None:
    if not PERSIST_DDB_POINTER:
        return
    table.update_item(
        Key={"job_id": job_id},
        UpdateExpression=(
            "SET ai_report_s3_uri = :u, ai_report_bucket = :b, "
            "ai_report_key = :k, ai_report_generated_at = :t"
        ),
        ExpressionAttributeValues={
            ":u": ai_report_s3_uri,
            ":b": out_bucket,
            ":k": ai_report_key,
            ":t": generated_at,
        },
    )


def build_fallback_report(
    *,
    generated_at: str,
    model_id: Optional[str],
    report: Dict[str, Any],
    asset_report: Dict[str, Any],
    report_s3_uri: str,
    asset_report_s3_uri: str,
    reason: str,
) -> Dict[str, Any]:
    job = report.get("job") or asset_report.get("job") or {}
    workflow = report.get("workflow") or asset_report.get("workflow") or {}
    return {
        "ai_report_version": "v1.0",
        "generated_at": generated_at,
        "generation_status": "fallback",
        "model_info": {
            "provider": "AWS Bedrock",
            "model_id": model_id,
            "temperature": BEDROCK_TEMPERATURE,
        },
        "job": job,
        "source_artifacts": {
            "report_s3_uri": report_s3_uri,
            "asset_report_s3_uri": asset_report_s3_uri,
        },
        "workflow": {
            "final_state": workflow.get("final_state"),
            "quality_outcome": workflow.get("quality_outcome") or (report.get("outcome") or {}).get("quality_outcome"),
        },
        "ai_feedback": {
            "section_marker": "AI_GENERATED_ADVISORY_FEEDBACK",
            "summary": {
                "headline": "AI advisory unavailable",
                "overall_assessment": "warning",
                "operator_brief": "The deterministic ingest artifacts were written successfully, but the AI advisory report could not be generated.",
            },
            "attention_points": [
                {
                    "priority": "low",
                    "family": "workflow",
                    "asset_id": None,
                    "title": "AI report unavailable",
                    "reason": reason,
                    "evidence": [reason],
                }
            ],
            "notable_assets": [],
            "recommended_next_action": "AI summary unavailable",
            "disclaimer": "This AI report is advisory and does not replace deterministic validation results.",
        },
    }


def build_success_report(
    *,
    generated_at: str,
    model_id: str,
    report: Dict[str, Any],
    asset_report: Dict[str, Any],
    report_s3_uri: str,
    asset_report_s3_uri: str,
    normalized_payload: Dict[str, Any],
    ai_input: Dict[str, Any],
) -> Dict[str, Any]:
    job = report.get("job") or asset_report.get("job") or {}
    workflow = report.get("workflow") or asset_report.get("workflow") or {}
    return {
        "ai_report_version": "v1.0",
        "generated_at": generated_at,
        "generation_status": "success",
        "model_info": {
            "provider": "AWS Bedrock",
            "model_id": model_id,
            "temperature": BEDROCK_TEMPERATURE,
        },
        "job": job,
        "source_artifacts": {
            "report_s3_uri": report_s3_uri,
            "asset_report_s3_uri": asset_report_s3_uri,
        },
        "workflow": {
            "final_state": workflow.get("final_state"),
            "quality_outcome": workflow.get("quality_outcome") or (report.get("outcome") or {}).get("quality_outcome"),
        },
        "ai_feedback": normalized_payload["ai_feedback"],
        "input_summary": {
            "total_assets": (ai_input.get("asset_counts") or {}).get("total_assets"),
            "selected_assets": (ai_input.get("asset_counts") or {}).get("selected_assets"),
            "assets_with_findings": (ai_input.get("asset_counts") or {}).get("assets_with_findings"),
        },
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    report_s3_uri = event.get("report_s3_uri")
    asset_report_s3_uri = event.get("asset_report_s3_uri")

    if not job_id:
        raise ValueError("Missing required field: job_id")

    job_row = load_job_row(job_id)
    project_code = project_code or job_row.get("project_code")
    report_s3_uri = report_s3_uri or job_row.get("report_s3_uri")
    asset_report_s3_uri = asset_report_s3_uri or job_row.get("asset_report_s3_uri")

    if not project_code:
        raise ValueError("Missing required field: project_code")
    if not report_s3_uri:
        raise ValueError("Missing required field: report_s3_uri")
    if not asset_report_s3_uri:
        raise ValueError("Missing required field: asset_report_s3_uri")

    generated_at = utc_now_iso()
    report = load_json_from_s3_uri(report_s3_uri)
    asset_report = load_json_from_s3_uri(asset_report_s3_uri)

    out_bucket = AI_REPORT_BUCKET or parse_s3_uri(report_s3_uri)[0]
    ai_report_key = f"{project_code}/_ai_reports/{job_id}.json"
    ai_report_s3_uri = f"s3://{out_bucket}/{ai_report_key}"

    ai_input = build_ai_input(report, asset_report)

    try:
        if not BEDROCK_MODEL_ID:
            raise ValueError("Missing required environment variable: BEDROCK_MODEL_ID")

        user_prompt = build_user_prompt(ai_input)
        raw_payload, _raw_resp = invoke_bedrock_json(BEDROCK_MODEL_ID, user_prompt)
        normalized_payload = normalize_ai_report_payload(
            raw_payload,
            final_state=(report.get("workflow") or {}).get("final_state"),
            quality_outcome=((report.get("workflow") or {}).get("quality_outcome") or (report.get("outcome") or {}).get("quality_outcome")),
        )
        ai_report = build_success_report(
            generated_at=generated_at,
            model_id=BEDROCK_MODEL_ID,
            report=report,
            asset_report=asset_report,
            report_s3_uri=report_s3_uri,
            asset_report_s3_uri=asset_report_s3_uri,
            normalized_payload=normalized_payload,
            ai_input=ai_input,
        )
    except Exception as exc:
        ai_report = build_fallback_report(
            generated_at=generated_at,
            model_id=BEDROCK_MODEL_ID,
            report=report,
            asset_report=asset_report,
            report_s3_uri=report_s3_uri,
            asset_report_s3_uri=asset_report_s3_uri,
            reason=str(exc),
        )

    ai_report.setdefault("locations", {})["ai_report_s3_uri"] = ai_report_s3_uri

    try:
        s3.put_object(
            Bucket=out_bucket,
            Key=ai_report_key,
            Body=json.dumps(ai_report, ensure_ascii=False, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
    except ClientError as exc:
        raise RuntimeError(f"Failed to write ai report to {ai_report_s3_uri}: {exc}") from exc

    try:
        update_dynamodb_pointer(job_id, ai_report_s3_uri, out_bucket, ai_report_key, generated_at)
    except ClientError as exc:
        raise RuntimeError(f"AI report written but DynamoDB update failed: {exc}") from exc

    return {
        "ok": True,
        "job_id": job_id,
        "project_code": project_code,
        "ai_report_s3_uri": ai_report_s3_uri,
        "ai_report_bucket": out_bucket,
        "ai_report_key": ai_report_key,
        "ai_report_version": "v1.0",
        "generation_status": ai_report.get("generation_status"),
    }
