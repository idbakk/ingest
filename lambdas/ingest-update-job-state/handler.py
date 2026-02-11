import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ.get("JOB_TABLE", "IngestJobs"))

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def get_nested(dct, path, default=None):
    cur = dct
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

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

    ts = now_iso()
    history_entry = {
        "at": ts,
        "to": new_state,
        "by": "stepfunctions",
        "project_code": project_code,
        "trigger": trigger,
        "execution_id": execution_id,
        "entered_time": entered_time,
        "ruleset_version": ruleset_version,
    }

    # Only set fields if they are not None (avoids writing NULL)
    expr_names = {"#s": "state"}
    expr_vals = {":s": new_state, ":u": ts, ":h": [history_entry]}
    update_expr = "SET #s = :s, updated_at = :u ADD state_history :h"

    # (If your state_history is a List, use list_append instead of ADD)
    # DynamoDB lists can't use ADD; they need list_append.
    # We'll do the safe list_append version:
    update_expr = "SET #s = :s, updated_at = :u, state_history = list_append(if_not_exists(state_history, :empty), :h)"
    expr_vals[":empty"] = []

    table.update_item(
        Key={"job_id": job_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )

    return {"ok": True, "job_id": job_id, "new_state": new_state, "updated_at": ts}
