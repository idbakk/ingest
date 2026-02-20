import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

JOB_TABLE = os.environ.get("JOB_TABLE", "IngestJobs")
MANIFEST_BUCKET = os.environ.get("MANIFEST_BUCKET")  # if empty, defaults to impl.s3.bucket
RULESET_VERSION_DEFAULT = os.environ.get("RULESET_VERSION", "v1.0")

table = dynamodb.Table(JOB_TABLE)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_in(d: Dict[str, Any], path: str) -> Optional[Any]:
    """
    Tiny safe getter: get_in(event, "validate_result.inventory")
    """
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def handler(event, context):
    # ---- Required identifiers ----
    job_id = event.get("job_id")
    project_code = event.get("project_code")

    if not job_id or not project_code:
        raise ValueError("Missing required fields: job_id and project_code")

    # ---- S3 location inputs ----
    bucket = get_in(event, "impl.s3.bucket") or event.get("bucket")
    prefix = get_in(event, "impl.s3.prefix") or event.get("folder_path") or get_in(event, "impl.s3.folder_path")

    if not bucket or prefix is None:
        raise ValueError("Missing required S3 location: impl.s3.bucket and impl.s3.prefix (or folder_path)")

    # normalize prefix to end with /
    if prefix != "" and not prefix.endswith("/"):
        prefix = prefix + "/"

    ingest_folder_uri = f"s3://{bucket}/{prefix}"

    # ---- Policy ----
    ruleset_version = get_in(event, "policy.ruleset_version") or event.get("ruleset_version") or RULESET_VERSION_DEFAULT

    # ---- Validation output ----
    inventory = (
        get_in(event, "validate_result.inventory")
        or event.get("inventory")
        or []
    )
    stats = (
        get_in(event, "validate_result.stats")
        or event.get("stats")
        or {}
    )

    if not isinstance(inventory, list):
        raise ValueError("inventory must be a list")

    # ---- Timestamps / state ----
    created_at = utc_now_iso()
    validated_at = (
        get_in(event, "validate_result.validated_at")
        or event.get("validated_at")
        or created_at
    )

    manifest: Dict[str, Any] = {
        "manifest_version": "v1.0",
        "job_id": job_id,
        "project_code": project_code,
        "ruleset_version": ruleset_version,
        "ingest_folder": ingest_folder_uri,
        "impl": {
            "s3": {"bucket": bucket, "prefix": prefix}
        },
        "state": {
            "name": "VALIDATED",
            "reason": "validation_succeeded"
        },
        "created_at": created_at,
        "validated_at": validated_at,
        "inventory": inventory,
        "stats": stats,
    }

    # ---- Write to S3 ----
    out_bucket = MANIFEST_BUCKET or bucket
    manifest_key = f"{project_code}/_manifests/{job_id}.json"
    manifest_s3_uri = f"s3://{out_bucket}/{manifest_key}"

    try:
        s3.put_object(
            Bucket=out_bucket,
            Key=manifest_key,
            Body=json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8"),
            ContentType="application/json",
        )
    except ClientError as e:
        raise RuntimeError(f"Failed to write manifest to {manifest_s3_uri}: {e}") from e

    # ---- Update DynamoDB (recommended) ----
    # Store pointer so you can find it without scanning S3
    try:
        table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET manifest_s3_uri = :u, manifest_bucket = :b, manifest_key = :k, updated_at = :t",
            ExpressionAttributeValues={
                ":u": manifest_s3_uri,
                ":b": out_bucket,
                ":k": manifest_key,
                ":t": created_at
            },
        )
    except ClientError as e:
        # If the job record isn't found or table key schema differs, you’ll see it here.
        raise RuntimeError(f"Manifest written but DynamoDB update failed: {e}") from e

    # Return manifest pointer forward in the state machine
    return {
        "manifest_s3_uri": manifest_s3_uri,
        "manifest_bucket": out_bucket,
        "manifest_key": manifest_key,
        "manifest_version": "v1.0",
    }
