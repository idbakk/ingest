import hashlib
from typing import Any, Dict, List

import boto3
import xxhash

s3 = boto3.client("s3")


def normalize_folder_path(folder_path: str) -> str:
    if folder_path and not folder_path.endswith("/"):
        return folder_path + "/"
    return folder_path or ""


def relative_path_from_key(key: str, folder_path: str) -> str:
    prefix = normalize_folder_path(folder_path)
    if key.startswith(prefix):
        return key[len(prefix):]
    return key


def build_inventory_lookup(inventory: List[Dict[str, Any]], folder_path: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    for item in inventory:
        key = item.get("key")
        if not key:
            continue

        entries.append(
            {
                "path": relative_path_from_key(key, folder_path),
                "s3_key": key,
                "size": item.get("size"),
                "last_modified": item.get("last_modified"),
                "etag": item.get("etag"),
                "algorithm": None,
                "hash_value": None,
                "verified_at": None,
            }
        )

    entries.sort(key=lambda x: x["path"])
    return entries


def create_hasher(algorithm: str):
    algo = (algorithm or "").lower()

    if algo == "md5":
        return hashlib.md5()
    if algo == "sha1":
        return hashlib.sha1()
    if algo == "sha256":
        return hashlib.sha256()
    if algo == "xxh64":
        return xxhash.xxh64()

    raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compute_s3_hash(bucket: str, key: str, algorithm: str, chunk_size: int = 8 * 1024 * 1024) -> str:
    hasher = create_hasher(algorithm)
    response = s3.get_object(Bucket=bucket, Key=key)
    stream = response["Body"]

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)

    return hasher.hexdigest()


def baseline_actual_entries(
    bucket: str,
    actual_entries: List[Dict[str, Any]],
    algorithm: str,
) -> Dict[str, Any]:
    mismatches: List[Dict[str, Any]] = []
    verified_entries: List[Dict[str, Any]] = []

    files_total = len(actual_entries)
    files_verified = 0
    files_failed = 0
    files_missing = 0

    for actual in actual_entries:
        path = actual.get("path")
        s3_key = actual.get("s3_key")

        try:
            computed_hash = compute_s3_hash(bucket, s3_key, algorithm)
        except Exception as exc:
            mismatches.append(
                {
                    "type": "HASH_COMPUTE_ERROR",
                    "path": path,
                    "expected": None,
                    "actual": {
                        "algorithm": algorithm,
                        "s3_key": s3_key,
                        "size": actual.get("size"),
                        "error": str(exc),
                    },
                }
            )
            files_failed += 1
            continue

        actual["algorithm"] = algorithm
        actual["hash_value"] = computed_hash

        files_verified += 1
        verified_entries.append(
            {
                "path": path,
                "algorithm": algorithm,
                "hash_value": computed_hash,
                "size": actual.get("size"),
                "s3_key": s3_key,
            }
        )

    ok = files_failed == 0
    reason = "BASELINE_CAPTURED" if ok else "BASELINE_CAPTURE_FAILED"

    return {
        "ok": ok,
        "reason": reason,
        "files_total": files_total,
        "files_verified": files_verified,
        "files_failed": files_failed,
        "files_missing": files_missing,
        "mismatches": mismatches,
        "verified_entries": verified_entries,
        "actual_entries": actual_entries,
    }


def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    bucket = event.get("bucket")
    folder_path = event.get("folder_path")
    manifest_s3_uri = event.get("manifest_s3_uri")
    inventory = event.get("inventory") or []
    algorithm = event.get("algorithm") or "xxh64"

    if not bucket:
        raise ValueError("Missing required field: bucket")
    if not folder_path:
        raise ValueError("Missing required field: folder_path")
    if not isinstance(inventory, list):
        raise ValueError("inventory must be a list")

    actual_entries = build_inventory_lookup(inventory, folder_path)

    baseline = baseline_actual_entries(
        bucket=bucket,
        actual_entries=actual_entries,
        algorithm=algorithm,
    )

    return {
        "mode": "BASELINE_ONLY",
        "ok": baseline["ok"],
        "reason": baseline["reason"],
        "job_id": job_id,
        "project_code": project_code,
        "manifest_s3_uri": manifest_s3_uri,
        "algorithm": algorithm,
        "files_total": baseline["files_total"],
        "files_verified": baseline["files_verified"],
        "files_failed": baseline["files_failed"],
        "files_missing": baseline["files_missing"],
        "mismatches": baseline["mismatches"],
        "verified_entries": baseline["verified_entries"],
        "hash_entries": [],
        "actual_entries": baseline["actual_entries"],
    }
