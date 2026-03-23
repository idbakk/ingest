import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from decimal import Decimal

import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ.get("JOB_TABLE", "IngestJobs"))

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def get_nested(dct: Dict[str, Any], path: List[str], default: Any = None):
    cur: Any = dct
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def to_dynamodb_compatible(value):
    if isinstance(value, dict):
        return {k: to_dynamodb_compatible(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_dynamodb_compatible(v) for v in value]
    if isinstance(value, float):
        return Decimal(str(value))
    return value


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
    manifest_s3_uri = get_nested(event, ["results", "manifest", "Payload", "manifest_s3_uri"]) or event.get("manifest_s3_uri")
    deep_validation_summary = event.get("deep_validation_summary")
    validation_errors = event.get("validation_errors")
    policy_reason = event.get("policy_reason")

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
        expr_names["#muri"] = "manifest_s3_mri"
        expr_vals[":muri"] = manifest_s3_uri
        update_parts.append("#muri = :muri")

    if deep_validation_summary is not None:
        expr_names["#dvs"] = "deep_validation_summary"
        expr_vals[":dvs"] = deep_validation_summary
        update_parts.append("#dvs = :dvs")

    if validation_errors is not None:
        expr_names["#ve"] = "validation_erros"
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

