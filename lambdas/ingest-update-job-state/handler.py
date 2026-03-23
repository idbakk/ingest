import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List

import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ.get("JOB_TABLE", "IngestJobs"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def get_nested(dct: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    cur: Any = dct
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def to_dynamodb_compatible(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_dynamodb_compatible(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_dynamodb_compatible(v) for v in value]
    if isinstance(value, float):
        return Decimal(str(value))
    return value


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
    # Support BOTH payload styles:
    # (A) New style: { job_id, new_state, ... }
    # (B) v1/v1-1 style: { policy: { job_id, state: { next } ... }, impl: {...} }
    job_id = get_nested(event, ["policy", "job_id"]) or event.get("job_id")
    new_state = get_nested(event, ["policy", "state", "next"]) or event.get("new_state")

    if not job_id or not new_state:
        raise ValueError("job_id and new_state are required.")

    ruleset_version = get_nested(event, ["policy", "ruleset_version"]) or event.get("ruleset_version")
    project_code = get_nested(event, ["policy", "project_code"]) or event.get("project_code")
    trigger = get_nested(event, ["impl", "event", "trigger"]) or event.get("trigger")
    execution_id = get_nested(event, ["impl", "orchestration", "execution_id"]) or event.get("execution_id")
    entered_time = get_nested(event, ["impl", "orchestration", "entered_time"]) or event.get("entered_time")

    # Optional persistence fields already being sent by ASL
    manifest_s3_uri = (
        get_nested(event, ["results", "manifest", "Payload", "manifest_s3_uri"])
        or event.get("manifest_s3_uri")
    )
    deep_validation_summary = event.get("deep_validation_summary")
    validation_errors = event.get("validation_errors")
    policy_reason = event.get("policy_reason")

    # Slim down deep validation before persisting to DynamoDB
    if deep_validation_summary is not None:
        deep_validation_summary = compact_deep_validation_summary(deep_validation_summary)

    ts = now_iso()

    history_entry: Dict[str, Any] = {
        "at": ts,
        "to": new_state,
        "by": "stepfunctions",
        "project_code": project_code,
        "trigger": trigger,
        "execution_id": execution_id,
        "entered_time": entered_time,
        "ruleset_version": ruleset_version,
    }

    if policy_reason is not None:
        history_entry["policy_reason"] = policy_reason

    if isinstance(validation_errors, list):
        history_entry["validation_error_count"] = len(validation_errors)

    expr_names: Dict[str, str] = {
        "#s": "state",
    }

    expr_vals: Dict[str, Any] = {
        ":s": new_state,
        ":u": ts,
        ":h": [history_entry],
        ":empty": [],
    }

    update_parts: List[str] = [
        "#s = :s",
        "updated_at = :u",
        "state_history = list_append(if_not_exists(state_history, :empty), :h)",
    ]

    if manifest_s3_uri is not None:
        expr_names["#muri"] = "manifest_s3_uri"
        expr_vals[":muri"] = manifest_s3_uri
        update_parts.append("#muri = :muri")

    if deep_validation_summary is not None:
        expr_names["#dvs"] = "deep_validation_summary"
        expr_vals[":dvs"] = deep_validation_summary
        update_parts.append("#dvs = :dvs")

    if validation_errors is not None:
        expr_names["#ve"] = "validation_errors"
        expr_vals[":ve"] = validation_errors
        update_parts.append("#ve = :ve")

    if policy_reason is not None:
        expr_names["#pr"] = "policy_reason"
        expr_vals[":pr"] = policy_reason
        update_parts.append("#pr = :pr")

    update_expr = "SET " + ", ".join(update_parts)

    expr_vals = to_dynamodb_compatible(expr_vals)

    table.update_item(
        Key={"job_id": job_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )

    response = {
        "ok": True,
        "job_id": job_id,
        "new_state": new_state,
        "updated_at": ts,
    }

    if manifest_s3_uri is not None:
        response["manifest_s3_uri"] = manifest_s3_uri

    if policy_reason is not None:
        response["policy_reason"] = policy_reason

    if deep_validation_summary is not None:
        response["deep_validation_summary_persisted"] = True

    if validation_errors is not None:
        response["validation_errors_persisted"] = True

    return response