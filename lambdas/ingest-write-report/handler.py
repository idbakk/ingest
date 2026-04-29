# ingest-write-report handler
# v1.1 final report writer
# Writes ingest_report.json, ingest_report.html, and optional ingest_findings.csv.

import csv
import html
import io
import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

JOB_TABLE = os.environ.get("JOB_TABLE", "IngestJobs")
REPORT_BUCKET = os.environ.get("REPORT_BUCKET")  # optional override
WRITE_FINDINGS_CSV = os.environ.get("WRITE_FINDINGS_CSV", "1") == "1"

table = dynamodb.Table(JOB_TABLE)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_s3_uri(uri: str) -> Tuple[str, str]:
    if not uri or not uri.startswith("s3://"):
        raise ValueError(f"Invalid S3 URI: {uri}")
    remainder = uri[5:]
    parts = remainder.split("/", 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def load_json_from_s3_uri(uri: str) -> Dict[str, Any]:
    bucket, key = parse_s3_uri(uri)
    resp = s3.get_object(Bucket=bucket, Key=key)
    return json.loads(resp["Body"].read().decode("utf-8"))


def to_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    return value


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def esc(value: Any) -> str:
    return html.escape(text(value))


def load_job_row(job_id: str) -> Dict[str, Any]:
    response = table.get_item(Key={"job_id": job_id})
    return response.get("Item") or {}


def severity_for_family(family: str) -> str:
    if family in {"checksum", "media_policy"}:
        return "error"
    if family == "media":
        return "warning"
    return "info"


def finding_path(item: Dict[str, Any]) -> Optional[str]:
    return item.get("path") or item.get("asset_id") or item.get("key")


def build_finding_message(family: str, mismatch: Dict[str, Any]) -> str:
    mismatch_type = mismatch.get("type")
    path = finding_path(mismatch)
    if mismatch_type == "UNREADABLE_MEDIA":
        return f"Media policy recorded an unreadable media file: {path}"
    if mismatch_type == "MEDIA_PROBE_FAILED":
        return f"ffprobe could not read the media file: {path}"
    if mismatch_type == "VIDEO_STREAM_MISSING":
        return f"Readable video file is missing video stream metadata: {path}"
    if mismatch_type == "AUDIO_STREAM_MISSING":
        return f"Readable audio file is missing audio stream metadata: {path}"
    if mismatch_type == "VIDEO_DIMENSIONS_MISSING":
        return f"Readable video file is missing width/height metadata: {path}"
    if mismatch_type == "MEDIA_DURATION_MISSING_OR_ZERO":
        return f"Readable media file has missing or zero duration: {path}"
    if mismatch_type == "MISSING_CONTAINER_METADATA":
        return f"Readable media file is missing container metadata: {path}"
    if mismatch_type == "FILE_HASH_MISMATCH":
        return f"Checksum mismatch recorded for: {path}"
    if mismatch_type == "FILE_MISSING":
        return f"Expected file missing from delivery: {path}"
    if mismatch_type == "MHL_PARSE_FAILED":
        return "MHL parse failure was recorded."
    return f"{family} finding recorded for: {path or 'unknown path'}"


def extract_findings_from_family(family: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in payload.get("mismatches") or []:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "severity": severity_for_family(family),
                "family": family,
                "type": item.get("type"),
                "path": finding_path(item),
                "message": build_finding_message(family, item),
            }
        )
    return findings


def extract_findings(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for family in ["checksum", "media", "media_policy"]:
        payload = summary.get(family) or {}
        if isinstance(payload, dict):
            findings.extend(extract_findings_from_family(family, payload))
    return findings


def determine_quality_outcome(final_state: str, findings: List[Dict[str, Any]]) -> str:
    if final_state == "REJECTED_POLICY":
        return "FAIL"
    if findings:
        return "PASS_WITH_WARNING"
    return "PASS"


def build_headline(final_state: str, quality_outcome: str) -> str:
    if final_state == "REJECTED_POLICY":
        return "Rejected by policy"
    if final_state == "READY_FOR_REVIEW" and quality_outcome == "PASS":
        return "Ready for review"
    if final_state == "READY_FOR_REVIEW" and quality_outcome == "PASS_WITH_WARNING":
        return "Ready for review with warnings"
    return "Report generated"


def build_operator_summary(final_state: str, quality_outcome: str, deep_validation_summary: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    checksum = deep_validation_summary.get("checksum") or {}
    media = deep_validation_summary.get("media") or {}
    media_policy = deep_validation_summary.get("media_policy") or {}
    if final_state == "REJECTED_POLICY":
        return (
            "Deep validation completed and the delivery was rejected by policy. "
            f"Checksum reason: {checksum.get('reason')}. "
            f"Media reason: {media.get('reason')}. "
            f"Media policy reason: {media_policy.get('reason')}."
        )
    if quality_outcome == "PASS":
        return "Preflight validation passed. Deep validation completed. No blocking checksum, media, or media-policy findings were recorded."
    return f"Preflight validation passed. Deep validation completed. {len(findings)} finding(s) were recorded, but the delivery was not rejected by policy."


def build_recommended_action(final_state: str, quality_outcome: str) -> str:
    if final_state == "REJECTED_POLICY":
        return "Review findings and request redelivery or remediation."
    if quality_outcome == "PASS_WITH_WARNING":
        return "Review findings and decide downstream processing."
    return "Review and decide downstream processing."


def slim_state_history(state_history: Any) -> List[Dict[str, Any]]:
    if not isinstance(state_history, list):
        return []
    return [{"at": item.get("at"), "to": item.get("to")} for item in state_history if isinstance(item, dict)]


def compact_preflight(validate_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(validate_result, dict):
        return {"ok": True, "reason": "PREFLIGHT_VALIDATED"}
    return {"ok": validate_result.get("ok", True), "reason": validate_result.get("reason", "PREFLIGHT_VALIDATED")}


def compact_checksum_summary(checksum: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(checksum, dict):
        return {}
    mismatches = checksum.get("mismatches") or []
    return {
        "mode": checksum.get("mode"),
        "ok": checksum.get("ok"),
        "reason": checksum.get("reason"),
        "algorithm": checksum.get("algorithm"),
        "files_total": checksum.get("files_total"),
        "files_verified": checksum.get("files_verified"),
        "files_failed": checksum.get("files_failed"),
        "files_missing": checksum.get("files_missing"),
        "mismatch_count": len(mismatches),
    }


def compact_media_summary(media: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(media, dict):
        return {}
    mismatches = media.get("mismatches") or []
    summary = media.get("summary") or {}
    return {
        "ok": media.get("ok"),
        "reason": media.get("reason"),
        "files_total": media.get("files_total"),
        "files_media_candidate": media.get("files_media_candidate"),
        "files_non_media": media.get("files_non_media"),
        "files_ignored": media.get("files_ignored"),
        "video_count": summary.get("video_count"),
        "audio_count": summary.get("audio_count"),
        "image_count": summary.get("image_count"),
        "subtitle_count": summary.get("subtitle_count"),
        "unknown_media_count": summary.get("unknown_media_count"),
        "probe_attempted_count": summary.get("probe_attempted_count"),
        "probed_count": summary.get("probed_count"),
        "probe_failed_count": summary.get("probe_failed_count"),
        "mismatch_count": len(mismatches),
    }


def compact_media_policy_summary(media_policy: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(media_policy, dict):
        return {}
    mismatches = media_policy.get("mismatches") or []
    summary = media_policy.get("summary") or {}
    return {
        "ok": media_policy.get("ok"),
        "reason": media_policy.get("reason"),
        "policy_profile": media_policy.get("policy_profile"),
        "ruleset_version": media_policy.get("ruleset_version"),
        "files_evaluated": media_policy.get("files_evaluated"),
        "files_with_findings": media_policy.get("files_with_findings"),
        "finding_count": len(mismatches),
        "unreadable_count": summary.get("unreadable_count"),
        "missing_container_count": summary.get("missing_container_count"),
        "video_stream_missing_count": summary.get("video_stream_missing_count"),
        "audio_stream_missing_count": summary.get("audio_stream_missing_count"),
        "duration_missing_or_zero_count": summary.get("duration_missing_or_zero_count"),
        "dimension_missing_count": summary.get("dimension_missing_count"),
    }


def compact_deep_validation_summary(summary: Any) -> Any:
    if not isinstance(summary, dict):
        return summary
    return {
        "checksum": compact_checksum_summary(summary.get("checksum") or {}),
        "media": compact_media_summary(summary.get("media") or {}),
        "media_policy": compact_media_policy_summary(summary.get("media_policy") or {}),
    }


def build_ai_advisory(ai_report: Optional[Dict[str, Any]], ai_report_s3_uri: Optional[str]) -> Dict[str, Any]:
    if not isinstance(ai_report, dict):
        return {
            "section_marker": "AI_GENERATED_ADVISORY_FEEDBACK",
            "generation_status": "unavailable",
            "model_info": {},
            "summary": {
                "headline": "AI advisory unavailable",
                "overall_assessment": "warning",
                "operator_brief": "No AI advisory artifact was available when the final ingest report was generated.",
            },
            "attention_points": [],
            "notable_assets": [],
            "recommended_next_action": "AI summary unavailable",
            "disclaimer": "This AI advisory section is generated from deterministic pipeline artifacts and does not replace validation results.",
            "source_ai_report_s3_uri": ai_report_s3_uri,
        }
    feedback = ai_report.get("ai_feedback") or {}
    summary = feedback.get("summary") or {}
    return {
        "section_marker": feedback.get("section_marker", "AI_GENERATED_ADVISORY_FEEDBACK"),
        "generation_status": ai_report.get("generation_status"),
        "model_info": ai_report.get("model_info") or {},
        "summary": {
            "headline": summary.get("headline"),
            "overall_assessment": summary.get("overall_assessment"),
            "operator_brief": summary.get("operator_brief"),
        },
        "attention_points": feedback.get("attention_points") or [],
        "notable_assets": feedback.get("notable_assets") or [],
        "recommended_next_action": feedback.get("recommended_next_action"),
        "disclaimer": feedback.get("disclaimer", "This AI advisory section is generated from deterministic pipeline artifacts and does not replace validation results."),
        "source_ai_report_s3_uri": ai_report_s3_uri,
    }


def build_findings_csv(report: Dict[str, Any]) -> str:
    output = io.StringIO()
    fields = ["row_type", "job_id", "project_code", "final_state", "quality_outcome", "severity", "family", "type", "path", "message", "recommended_action"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    job = report.get("job") or {}
    workflow = report.get("workflow") or {}
    outcome = report.get("outcome") or {}
    base = {
        "job_id": job.get("job_id"),
        "project_code": job.get("project_code"),
        "final_state": workflow.get("final_state"),
        "quality_outcome": outcome.get("quality_outcome"),
        "recommended_action": outcome.get("recommended_action"),
    }
    writer.writerow({"row_type": "summary", **base, "severity": "", "family": "delivery", "type": "SUMMARY", "path": "", "message": outcome.get("operator_summary")})
    for finding in report.get("findings") or []:
        writer.writerow({"row_type": "finding", **base, "severity": finding.get("severity"), "family": finding.get("family"), "type": finding.get("type"), "path": finding.get("path"), "message": finding.get("message")})
    return output.getvalue()


def badge_class(value: Any) -> str:
    value_upper = text(value).upper()
    if value_upper in {"PASS", "READY_FOR_REVIEW", "TRUE", "OK", "MEDIA_POLICY_OK", "BASELINE_CAPTURED", "VERIFIED", "HEALTHY"}:
        return "good"
    if value_upper in {"FAIL", "REJECTED_POLICY", "FALSE", "MEDIA_POLICY_WITH_FINDINGS", "MEDIA_INSPECTED_WITH_ERROR", "AT_RISK"}:
        return "bad"
    if "WARN" in value_upper:
        return "warn"
    return "neutral"


def badge(value: Any) -> str:
    return '<span class="badge ' + badge_class(value) + '">' + esc(value) + '</span>'


def kv_table(data: Dict[str, Any]) -> str:
    rows = []
    for key, value in data.items():
        rows.append("<tr><th>" + esc(key.replace("_", " ").title()) + "</th><td>" + esc(value) + "</td></tr>")
    return "<table class='kv'>" + "".join(rows) + "</table>"


def findings_table(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "<p class='muted'>No findings recorded.</p>"
    rows = []
    for item in findings:
        rows.append(
            "<tr><td>" + badge(item.get("severity")) + "</td><td>" + esc(item.get("family")) + "</td><td>" + esc(item.get("type")) + "</td><td><code>" + esc(item.get("path")) + "</code></td><td>" + esc(item.get("message")) + "</td></tr>"
        )
    return "<table><thead><tr><th>Severity</th><th>Family</th><th>Type</th><th>Path</th><th>Message</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def artifacts_table(artifacts: Dict[str, Any]) -> str:
    rows = []
    for key, uri in artifacts.items():
        if uri:
            rows.append("<tr><th>" + esc(key.replace("_", " ").title()) + "</th><td><code>" + esc(uri) + "</code></td></tr>")
    return "<table class='kv'>" + "".join(rows) + "</table>"


def ai_section(ai_advisory: Dict[str, Any]) -> str:
    summary = ai_advisory.get("summary") or {}
    points = ai_advisory.get("attention_points") or []
    notable = ai_advisory.get("notable_assets") or []
    point_rows = []
    for item in points:
        evidence = "; ".join(text(x) for x in item.get("evidence") or [])
        point_rows.append("<tr><td>" + badge(item.get("priority")) + "</td><td>" + esc(item.get("family")) + "</td><td><code>" + esc(item.get("asset_id")) + "</code></td><td>" + esc(item.get("title")) + "</td><td>" + esc(item.get("reason")) + "</td><td>" + esc(evidence) + "</td></tr>")
    points_html = "<p class='muted'>No AI attention points.</p>" if not point_rows else "<table><thead><tr><th>Priority</th><th>Family</th><th>Asset</th><th>Title</th><th>Reason</th><th>Evidence</th></tr></thead><tbody>" + "".join(point_rows) + "</tbody></table>"
    notable_rows = []
    for item in notable:
        evidence = "; ".join(text(x) for x in item.get("evidence") or [])
        notable_rows.append("<tr><td><code>" + esc(item.get("asset_id")) + "</code></td><td>" + esc(item.get("why_notable")) + "</td><td>" + esc(evidence) + "</td></tr>")
    notable_html = "<p class='muted'>No notable assets selected by AI.</p>" if not notable_rows else "<table><thead><tr><th>Asset</th><th>Why Notable</th><th>Evidence</th></tr></thead><tbody>" + "".join(notable_rows) + "</tbody></table>"
    return "".join([
        "<section class='card ai-card'><h2>AI Advisory</h2>",
        "<p class='section-note'>Advisory comments generated from deterministic pipeline artifacts. This section does not replace validation results.</p>",
        "<div class='grid two'><div><h3>", esc(summary.get("headline")), "</h3><p>", esc(summary.get("operator_brief")), "</p></div>",
        "<div><p><strong>Generation status:</strong> ", badge(ai_advisory.get("generation_status")), "</p><p><strong>Assessment:</strong> ", badge(summary.get("overall_assessment")), "</p><p><strong>Recommended next action:</strong> ", esc(ai_advisory.get("recommended_next_action")), "</p></div></div>",
        "<h3>AI Attention Points</h3>", points_html,
        "<h3>Notable Assets</h3>", notable_html,
        "<p class='disclaimer'>", esc(ai_advisory.get("disclaimer")), "</p></section>",
    ])


def build_html_report(report: Dict[str, Any]) -> str:
    job = report.get("job") or {}
    workflow = report.get("workflow") or {}
    outcome = report.get("outcome") or {}
    preflight = report.get("preflight") or {}
    deep = report.get("deep_validation") or {}
    checksum = deep.get("checksum") or {}
    media = deep.get("media") or {}
    media_policy = deep.get("media_policy") or {}
    findings = report.get("findings") or []
    css = """
    body{margin:0;padding:32px;background:#f6f8fb;color:#172033;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}.page{max-width:1120px;margin:0 auto}.hero,.card{background:#fff;border:1px solid #d7dde8;border-radius:18px;padding:24px;margin-top:18px;box-shadow:0 8px 20px rgba(16,24,40,.04)}.hero{margin-top:0}.hero h1{margin:0 0 8px;font-size:32px}.muted,.section-note{color:#667085}.grid{display:grid;gap:16px}.grid.two{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}.grid.three{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:16px}.metric{background:#fff;border:1px solid #d7dde8;border-radius:14px;padding:16px}.label{color:#667085;font-size:13px;margin-bottom:8px}.value{font-size:18px;font-weight:700}h2{margin:0 0 14px;font-size:22px}h3{margin:18px 0 10px;font-size:16px}table{width:100%;border-collapse:collapse;margin-top:10px;font-size:14px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #d7dde8;vertical-align:top}th{color:#667085;font-weight:600}.kv th{width:260px}code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;word-break:break-all}.badge{display:inline-block;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:700;white-space:nowrap}.good{background:#e8f5e9;color:#1b5e20}.warn{background:#fff8e1;color:#8a5a00}.bad{background:#ffebee;color:#b71c1c}.neutral{background:#eef2f7;color:#344054}.ai-card{background:#f4f0ff}.disclaimer{color:#667085;font-size:13px;margin-top:18px}
    """
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>Ingest Report - ", esc(job.get("job_id")), "</title><style>", css, "</style></head><body><main class='page'>",
        "<section class='hero'><h1>Ingest Report</h1><p>", esc(outcome.get("operator_summary")), "</p>",
        "<div class='grid three'><div class='metric'><div class='label'>Final State</div><div class='value'>", badge(workflow.get("final_state")), "</div></div>",
        "<div class='metric'><div class='label'>Quality Outcome</div><div class='value'>", badge(outcome.get("quality_outcome")), "</div></div>",
        "<div class='metric'><div class='label'>Findings</div><div class='value'>", esc(len(findings)), "</div></div></div></section>",
        "<section class='card'><h2>Job</h2>", kv_table(job), "</section>",
        "<section class='card'><h2>Outcome</h2>", kv_table(outcome), "</section>",
        "<section class='card'><h2>Validation Summary</h2><div class='grid three'>",
        "<div class='metric'><div class='label'>Preflight</div><div class='value'>", badge(preflight.get("reason")), "</div></div>",
        "<div class='metric'><div class='label'>Checksum</div><div class='value'>", badge(checksum.get("reason")), "</div></div>",
        "<div class='metric'><div class='label'>Media Policy</div><div class='value'>", badge(media_policy.get("reason")), "</div></div></div>",
        "<h3>Checksum</h3>", kv_table(checksum), "<h3>Media</h3>", kv_table(media), "<h3>Media Policy</h3>", kv_table(media_policy), "</section>",
        "<section class='card'><h2>Findings</h2>", findings_table(findings), "</section>",
        "<section class='card'><h2>Supporting Artifacts</h2>", artifacts_table(report.get("supporting_artifacts") or {}), "</section>",
        ai_section(report.get("ai_advisory") or {}),
        "</main></body></html>",
    ]
    return "".join(parts)


def put_text_object(bucket: str, key: str, body: str, content_type: str) -> None:
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"), ContentType=content_type)


def update_report_pointers(job_id: str, report_bucket: str, json_key: str, html_key: str, csv_key: Optional[str], json_uri: str, html_uri: str, csv_uri: Optional[str], generated_at: str) -> None:
    update_expression = (
        "SET report_s3_uri = :json_uri, report_bucket = :bucket, report_key = :json_key, report_generated_at = :generated_at, "
        "ingest_report_json_s3_uri = :json_uri, ingest_report_html_s3_uri = :html_uri, "
        "ingest_report_json_key = :json_key, ingest_report_html_key = :html_key, ingest_report_generated_at = :generated_at"
    )
    values = {
        ":json_uri": json_uri,
        ":html_uri": html_uri,
        ":bucket": report_bucket,
        ":json_key": json_key,
        ":html_key": html_key,
        ":generated_at": generated_at,
    }
    if csv_key and csv_uri:
        update_expression += ", ingest_findings_csv_s3_uri = :csv_uri, ingest_findings_csv_key = :csv_key"
        values[":csv_uri"] = csv_uri
        values[":csv_key"] = csv_key
    table.update_item(Key={"job_id": job_id}, UpdateExpression=update_expression, ExpressionAttributeValues=values)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    ruleset_version = event.get("ruleset_version", "v1.0")
    trigger = event.get("trigger")
    ingest_folder = event.get("ingest_folder")
    manifest_s3_uri = event.get("manifest_s3_uri")
    final_state = event.get("final_state")
    raw_deep_validation_summary = event.get("deep_validation_summary") or {}
    validate_result = event.get("validate_result")
    asset_report_s3_uri = event.get("asset_report_s3_uri")
    ai_report_s3_uri = event.get("ai_report_s3_uri")

    if not job_id or not project_code:
        raise ValueError("Missing required fields: job_id and project_code")
    if not manifest_s3_uri:
        raise ValueError("Missing required field: manifest_s3_uri")
    if not final_state:
        raise ValueError("Missing required field: final_state")
    if not isinstance(raw_deep_validation_summary, dict):
        raise ValueError("deep_validation_summary must be a dict")

    job_row = to_jsonable(load_job_row(job_id))
    asset_report_s3_uri = asset_report_s3_uri or job_row.get("asset_report_s3_uri")
    ai_report_s3_uri = ai_report_s3_uri or job_row.get("ai_report_s3_uri")
    if not asset_report_s3_uri:
        raise ValueError("Missing required field: asset_report_s3_uri")
    if not ai_report_s3_uri:
        raise ValueError("Missing required field: ai_report_s3_uri")

    manifest_bucket, _ = parse_s3_uri(manifest_s3_uri)
    report_bucket = REPORT_BUCKET or manifest_bucket
    report_prefix = f"{project_code}/_reports/{job_id}"
    json_key = f"{report_prefix}/ingest_report.json"
    html_key = f"{report_prefix}/ingest_report.html"
    csv_key = f"{report_prefix}/ingest_findings.csv" if WRITE_FINDINGS_CSV else None
    json_uri = f"s3://{report_bucket}/{json_key}"
    html_uri = f"s3://{report_bucket}/{html_key}"
    csv_uri = f"s3://{report_bucket}/{csv_key}" if csv_key else None

    findings = extract_findings(raw_deep_validation_summary)
    compact_deep_validation = compact_deep_validation_summary(raw_deep_validation_summary)
    quality_outcome = determine_quality_outcome(final_state, findings)
    generated_at = utc_now_iso()

    try:
        ai_report = load_json_from_s3_uri(ai_report_s3_uri)
    except Exception as exc:
        ai_report = None
        print(f"WARNING: Failed to load AI report from {ai_report_s3_uri}: {exc}")

    report = {
        "report_type": "INGEST_REPORT",
        "report_version": "v1.1",
        "generated_at": generated_at,
        "job": {"job_id": job_id, "project_code": project_code, "trigger": trigger, "ruleset_version": ruleset_version},
        "locations": {"ingest_folder": ingest_folder, "manifest_s3_uri": manifest_s3_uri, "ingest_report_json_s3_uri": json_uri, "ingest_report_html_s3_uri": html_uri, "ingest_findings_csv_s3_uri": csv_uri},
        "workflow": {"final_state": final_state, "deep_validation_completed": True, "preflight_state": "PREFLIGHT_VALIDATED", "deep_validation_state": "DEEP_VALIDATED", "route_state": final_state},
        "outcome": {
            "quality_outcome": quality_outcome,
            "headline": build_headline(final_state, quality_outcome),
            "operator_summary": build_operator_summary(final_state, quality_outcome, compact_deep_validation, findings),
            "recommended_action": build_recommended_action(final_state, quality_outcome),
        },
        "preflight": compact_preflight(validate_result),
        "deep_validation": compact_deep_validation,
        "findings": findings,
        "state_history": slim_state_history(job_row.get("state_history") or []),
        "supporting_artifacts": {"manifest_s3_uri": manifest_s3_uri, "asset_report_s3_uri": asset_report_s3_uri, "ai_report_s3_uri": ai_report_s3_uri, "ingest_report_json_s3_uri": json_uri, "ingest_report_html_s3_uri": html_uri, "ingest_findings_csv_s3_uri": csv_uri},
        "ai_advisory": build_ai_advisory(ai_report, ai_report_s3_uri),
    }

    try:
        put_text_object(report_bucket, json_key, json.dumps(report, ensure_ascii=False, indent=2), "application/json; charset=utf-8")
        put_text_object(report_bucket, html_key, build_html_report(report), "text/html; charset=utf-8")
        if csv_key:
            put_text_object(report_bucket, csv_key, build_findings_csv(report), "text/csv; charset=utf-8")
    except ClientError as exc:
        raise RuntimeError(f"Failed to write ingest report artifacts under s3://{report_bucket}/{report_prefix}/: {exc}") from exc

    try:
        update_report_pointers(job_id, report_bucket, json_key, html_key, csv_key, json_uri, html_uri, csv_uri, generated_at)
    except ClientError as exc:
        raise RuntimeError(f"Ingest report written but DynamoDB update failed: {exc}") from exc

    return {
        "ok": True,
        "job_id": job_id,
        "project_code": project_code,
        "final_state": final_state,
        "report_s3_uri": json_uri,
        "report_bucket": report_bucket,
        "report_key": json_key,
        "report_version": "v1.1",
        "ingest_report_json_s3_uri": json_uri,
        "ingest_report_html_s3_uri": html_uri,
        "ingest_findings_csv_s3_uri": csv_uri,
        "ingest_report_json_key": json_key,
        "ingest_report_html_key": html_key,
        "ingest_findings_csv_key": csv_key,
    }
