import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import boto3

s3 = boto3.client("s3")

# Optional guardrails
MAX_KEYS = int(os.environ.get("MAX_KEYS", "5000"))         # cap listing for safety
ALLOW_ZERO_BYTE = os.environ.get("ALLOW_ZERO_BYTE", "0") == "1"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def list_all_objects(bucket: str, prefix: str, max_keys: int) -> List[Dict[str, Any]]:
    """
    Lists objects under prefix (paginated), up to max_keys total.
    Returns raw S3 objects (dicts with Key, Size, ETag, LastModified, etc.)
    """
    items: List[Dict[str, Any]] = []
    token = None

    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token

        resp = s3.list_objects_v2(**kwargs)
        contents = resp.get("Contents", [])
        items.extend(contents)

        if len(items) >= max_keys:
            # hard stop to protect cost/time if someone drops huge folder
            return items[:max_keys]

        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
            continue

        return items


def validate_objects(objects: List[Dict[str, Any]], marker_key: str) -> Tuple[bool, List[str]]:
    """
    Basic structural validation:
    - folder not empty (excluding marker)
    - no missing metadata we rely on
    - optionally enforce non-zero size
    """
    errors: List[str] = []

    # Exclude marker file from payload set
    payload = [o for o in objects if o.get("Key") != marker_key]

    if len(payload) == 0:
        errors.append("EMPTY_FOLDER: no payload objects found (excluding _INGEST_DONE)")
        return False, errors

    for o in payload:
        key = o.get("Key")
        size = o.get("Size")
        etag = o.get("ETag")

        if not key:
            errors.append("BAD_OBJECT: missing Key")
            continue

        if size is None:
            errors.append(f"BAD_OBJECT: missing Size ({key})")
        elif (not ALLOW_ZERO_BYTE) and size == 0:
            errors.append(f"ZERO_BYTE_OBJECT: {key}")

        # ETag is useful for minimal integrity checks later
        if not etag:
            errors.append(f"BAD_OBJECT: missing ETag ({key})")

    return (len(errors) == 0), errors


def handler(event, context):
    """
    Expected input from Step Functions:
    {
      "job_id": "...",
      "project_code": "...",
      "bucket": "...",
      "folder_path": "TEST/2010/",
      "object_key": "TEST/2010/_INGEST_DONE",
      "ingest_folder": "s3://bucket/TEST/2010/",
      "trigger": "_INGEST_DONE",
      "created_at": "..."
    }
    """
    bucket = event.get("bucket")
    folder_path = event.get("folder_path")
    marker_key = event.get("object_key")  # should end with _INGEST_DONE

    if not bucket or not folder_path or not marker_key:
        return {
            "ok": False,
            "validated_at": now_iso(),
            "reason": "INVALID_INPUT",
            "errors": ["Missing required fields: bucket, folder_path, object_key"],
        }

    # Ensure prefix ends with /
    prefix = folder_path if folder_path.endswith("/") else folder_path + "/"

    # 1) List objects
    objects = list_all_objects(bucket=bucket, prefix=prefix, max_keys=MAX_KEYS)

    # If S3 returns nothing at all, likely wrong prefix or permissions or timing
    if len(objects) == 0:
        return {
            "ok": False,
            "validated_at": now_iso(),
            "reason": "FOLDER_NOT_FOUND_OR_EMPTY",
            "errors": [f"No objects found under prefix: {prefix}"],
        }

    # 2) Validate
    ok, errors = validate_objects(objects=objects, marker_key=marker_key)

    # 3) Build deterministic inventory snapshot (for manifest step)
    # Keep it compact: Key, Size, ETag, LastModified
    inventory = []
    for o in objects:
        k = o.get("Key")
        if not k or k == marker_key:
            continue
        inventory.append(
            {
                "key": k,
                "size": int(o.get("Size", 0)),
                "etag": o.get("ETag"),
                "last_modified": o.get("LastModified").isoformat() if o.get("LastModified") else None,
            }
        )

    # Sort for determinism
    inventory.sort(key=lambda x: x["key"])

    return {
        "ok": ok,
        "validated_at": now_iso(),
        "reason": "OK" if ok else "FAILED_VALIDATION",
        "errors": errors,
        "stats": {
            "object_count_including_marker": len(objects),
            "payload_file_count": len(inventory),
            "max_keys_cap": MAX_KEYS,
        },
        "inventory": inventory,
    }
