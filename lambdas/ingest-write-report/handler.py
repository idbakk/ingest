# ingest-write-report handler

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


def to_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    return value


def severity_for_family(family: str) -> str:
    if family in {"checksum", "media_policy"}:
        return "error"
    if family == "media":
        return "warning"
    return "info"


def build_finding_message(family: str, mismatch: Dict[str, Any]) -> str:
    mismatch_type = mismatch.get("type")
    path = mismatch.get("path")

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

    return f"{family} finding recorded for: {path or 'unknown path'}"


def extract_findings_from_family(family: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    mismatches = payload.get("mismatches") or []

    for item in mismatches:
        findings.append(
            {
                "severity": severity_for_family(family),
                "family": family,
                "type": item.get("type"),
                "path": item.get("path"),
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


def build_operator_summary(
    final_state: str,
    quality_outcome: str,
    deep_validation_summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> str:
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
        return (
            "Preflight validation passed. Deep validation completed. "
            "No blocking checksum, media, or media-policy findings were recorded."
        )

    return (
        "Preflight validation passed. Deep validation completed. "
        f"{len(findings)} finding(s) were recorded, but the delivery was not rejected by policy."
    )


def build_recommended_action(final_state: str, quality_outcome: str) -> str:
    if final_state == "REJECTED_POLICY":
        return "Review findings and request redelivery or remediation."
    if quality_outcome == "PASS_WITH_WARNING":
        return "Review findings and decide downstream processing."
    return "Review and decide downstream processing."


def slim_state_history(state_history: Any) -> List[Dict[str, Any]]:
    if not isinstance(state_history, list):
        return []

    slimmed: List[Dict[str, Any]] = []
    for item in state_history:
        if not isinstance(item, dict):
            continue
        slimmed.append(
            {
                "at": item.get("at"),
                "to": item.get("to"),
            }
        )
    return slimmed


def load_job_row(job_id: str) -> Dict[str, Any]:
    response = table.get_item(Key={"job_id": job_id})
    return response.get("Item") or {}


def compact_preflight(validate_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(validate_result, dict):
        return {
            "ok": True,
            "reason": "PREFLIGHT_VALIDATED",
        }

    return {
        "ok": validate_result.get("ok", True),
        "reason": validate_result.get("reason", "PREFLIGHT_VALIDATED"),
    }




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

def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    ruleset_version = event.get("ruleset_version", "v1.0")
    trigger = event.get("trigger")
    ingest_folder = event.get("ingest_folder")
    manifest_s3_uri = event.get("manifest_s3_uri")
    final_state = event.get("final_state")
    raw_deep_validation_summary = event.get("deep_validation_summary") or {}
    validate_result = event.get("validate_result")

    if not job_id or not project_code:
        raise ValueError("Missing required fields: job_id and project_code")
    if not manifest_s3_uri:
        raise ValueError("Missing required field: manifest_s3_uri")
    if not final_state:
        raise ValueError("Missing required field: final_state")
    if not isinstance(raw_deep_validation_summary, dict):
        raise ValueError("deep_validation_summary must be a dict")

    manifest_bucket, _ = parse_s3_uri(manifest_s3_uri)
    report_bucket = REPORT_BUCKET or manifest_bucket
    report_key = f"{project_code}/_reports/{job_id}.json"
    report_s3_uri = f"s3://{report_bucket}/{report_key}"

    job_row = to_jsonable(load_job_row(job_id))
    state_history = slim_state_history(job_row.get("state_history") or [])

    findings = extract_findings(raw_deep_validation_summary)
    compact_deep_validation = compact_deep_validation_summary(raw_deep_validation_summary)
    quality_outcome = determine_quality_outcome(final_state, findings)

    generated_at = utc_now_iso()

    report = {
        "report_version": "v1.0",
        "generated_at": generated_at,
        "job": {
            "job_id": job_id,
            "project_code": project_code,
            "trigger": trigger,
            "ruleset_version": ruleset_version,
        },
        "locations": {
            "ingest_folder": ingest_folder,
            "manifest_s3_uri": manifest_s3_uri,
            "report_s3_uri": report_s3_uri,
        },
        "workflow": {
            "final_state": final_state,
            "deep_validation_completed": True,
            "preflight_state": "PREFLIGHT_VALIDATED",
            "deep_validation_state": "DEEP_VALIDATED",
            "route_state": final_state,
        },
        "outcome": {
            "quality_outcome": quality_outcome,
            "headline": build_headline(final_state, quality_outcome),
            "operator_summary": build_operator_summary(
                final_state=final_state,
                quality_outcome=quality_outcome,
                deep_validation_summary=compact_deep_validation,
                findings=findings,
            ),
            "recommended_action": build_recommended_action(final_state, quality_outcome),
        },
        "preflight": compact_preflight(validate_result),
        "deep_validation": compact_deep_validation,
        "findings": findings,
        "state_history": state_history,
    }

    try:
        s3.put_object(
            Bucket=report_bucket,
            Key=report_key,
            Body=json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to write report to {report_s3_uri}: {e}") from e

    try:
        table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET report_s3_uri = :u, report_bucket = :b, report_key = :k, report_generated_at = :t",
            ExpressionAttributeValues={
                ":u": report_s3_uri,
                ":b": report_bucket,
                ":k": report_key,
                ":t": generated_at,
            },
        )
    except ClientError as e:
        raise RuntimeError(f"Report written but DynamoDB update failed: {e}") from e

    return {
        "ok": True,
        "job_id": job_id,
        "project_code": project_code,
        "final_state": final_state,
        "report_s3_uri": report_s3_uri,
        "report_bucket": report_bucket,
        "report_key": report_key,
        "report_version": "v1.0",
    }

