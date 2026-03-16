import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

import boto3
import hashlib
import xxhash  # pip install xxhash

s3 = boto3.client("s3")


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def detect_namespace(root: ET.Element) -> Optional[str]:
    if root.tag.startswith("{") and "}" in root.tag:
        return root.tag[1:].split("}", 1)[0]
    return None


def load_text_from_s3(bucket: str, key: str) -> str:
    response = s3.get_object(Bucket=bucket, Key=key)
    return response["Body"].read().decode("utf-8")


def normalize_folder_path(folder_path: str) -> str:
    if folder_path and not folder_path.endswith("/"):
        return folder_path + "/"
    return folder_path or ""


def build_relative_path(full_key: str, folder_path: str) -> str:
    prefix = normalize_folder_path(folder_path)
    if full_key.startswith(prefix):
        return full_key[len(prefix):]
    return full_key


def build_inventory_lookup(
    inventory: List[Dict[str, Any]],
    folder_path: str,
) -> List[Dict[str, Any]]:
    actual_entries: List[Dict[str, Any]] = []

    for item in inventory:
        key = item.get("key")
        if not key:
            continue

        actual_entries.append(
            {
                "path": build_relative_path(key, folder_path),
                "s3_key": key,
                "size": item.get("size"),
                "last_modified": item.get("last_modified"),
                "etag": item.get("etag"),
                "algorithm": None,
                "hash_value": None,
                "verified_at": None,
            }
        )

    return actual_entries


def parse_mhl_v1(root: ET.Element) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    for hash_el in root.findall("hash"):
        file_text = hash_el.findtext("file")
        size_text = hash_el.findtext("size")
        last_mod = hash_el.findtext("lastmodificationdate")
        hash_date = hash_el.findtext("hashdate")

        algorithm = None
        hash_value = None

        for child in list(hash_el):
            child_name = strip_namespace(child.tag)
            if child_name in {"file", "size", "lastmodificationdate", "hashdate"}:
                continue
            if child.text and child.text.strip():
                algorithm = child_name
                hash_value = child.text.strip()
                break

        entries.append(
            {
                "path": file_text.strip() if file_text else None,
                "size": int(size_text) if size_text else None,
                "last_modified": last_mod,
                "algorithm": algorithm,
                "hash_value": hash_value,
                "hash_date": hash_date,
            }
        )

    return entries


def parse_mhl_v2(root: ET.Element) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    namespace = detect_namespace(root)
    ns = {"m": namespace} if namespace else {}
    hash_elements = root.findall(".//m:hashes/m:hash", ns) if namespace else root.findall(".//hashes/hash")

    for hash_el in hash_elements:
        path_el = hash_el.find("m:path", ns) if namespace else hash_el.find("path")
        if path_el is None:
            continue

        path_text = (path_el.text or "").strip()
        size_text = path_el.attrib.get("size")
        last_mod = path_el.attrib.get("lastmodificationdate")

        algorithm = None
        hash_value = None
        hash_date = None

        for child in list(hash_el):
            child_name = strip_namespace(child.tag)
            if child_name == "path":
                continue

            child_text = (child.text or "").strip()
            if not child_text:
                continue

            algorithm = child_name
            hash_value = child_text
            hash_date = child.attrib.get("hashdate")
            break

        entries.append(
            {
                "path": path_text or None,
                "size": int(size_text) if size_text else None,
                "last_modified": last_mod,
                "algorithm": algorithm,
                "hash_value": hash_value,
                "hash_date": hash_date,
            }
        )

    return entries


def validate_hash_entries(entries: List[Dict[str, Any]]) -> None:
    for idx, entry in enumerate(entries):
        if not entry.get("path"):
            raise ValueError(f"Invalid MHL entry at index {idx}: missing path")
        if not entry.get("algorithm"):
            raise ValueError(f"Invalid MHL entry at index {idx}: missing algorithm")
        if not entry.get("hash_value"):
            raise ValueError(f"Invalid MHL entry at index {idx}: missing hash_value")
        if entry.get("size") is None:
            raise ValueError(f"Invalid MHL entry at index {idx}: missing size")


def parse_mhl_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    root_name = strip_namespace(root.tag)
    if root_name != "hashlist":
        raise ValueError(f"Unexpected root tag: {root.tag}")

    version = root.attrib.get("version", "unknown")
    namespace = detect_namespace(root)

    if version.startswith("2"):
        entries = parse_mhl_v2(root)
    else:
        entries = parse_mhl_v1(root)

    validate_hash_entries(entries)

    return {
        "mhl_version": version,
        "namespace": namespace,
        "hash_entries": entries,
        "hash_entry_count": len(entries),
    }


def choose_mhl_key(mhl_keys: List[str]) -> str:
    normalized = sorted([k for k in mhl_keys if k])

    if not normalized:
        raise ValueError("MHL_NOT_FOUND")

    if len(normalized) > 1:
        raise ValueError(f"AMBIGUOUS_MHL_PACKAGE: {normalized}")

    return normalized[0]

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


def verify_expected_vs_actual(
    bucket: str,
    expected_entries: List[Dict[str, Any]],
    actual_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    actual_by_path = {entry["path"]: entry for entry in actual_entries if entry.get("path")}

    mismatches: List[Dict[str, Any]] = []
    verified_entries: List[Dict[str, Any]] = []

    files_total = len(expected_entries)
    files_verified = 0
    files_failed = 0
    files_missing = 0

    for expected in expected_entries:
        expected_path = expected.get("path")
        expected_size = expected.get("size")
        expected_algorithm = expected.get("algorithm")
        expected_hash = expected.get("hash_value")

        actual = actual_by_path.get(expected_path)

        if not actual:
            mismatches.append(
                {
                    "type": "MISSING_FILE",
                    "path": expected_path,
                    "expected": {
                        "size": expected_size,
                        "algorithm": expected_algorithm,
                        "hash_value": expected_hash,
                    },
                    "actual": None,
                }
            )
            files_failed += 1
            files_missing += 1
            continue

        if expected_size is not None and actual.get("size") != expected_size:
            mismatches.append(
                {
                    "type": "SIZE_MISMATCH",
                    "path": expected_path,
                    "expected": {
                        "size": expected_size,
                        "algorithm": expected_algorithm,
                        "hash_value": expected_hash,
                    },
                    "actual": {
                        "size": actual.get("size"),
                        "s3_key": actual.get("s3_key"),
                    },
                }
            )
            files_failed += 1
            continue

        try:
            computed_hash = compute_s3_hash(bucket, actual["s3_key"], expected_algorithm)
        except Exception as exc:
            mismatches.append(
                {
                    "type": "HASH_COMPUTE_ERROR",
                    "path": expected_path,
                    "expected": {
                        "algorithm": expected_algorithm,
                        "hash_value": expected_hash,
                    },
                    "actual": {
                        "s3_key": actual.get("s3_key"),
                        "error": str(exc),
                    },
                }
            )
            files_failed += 1
            continue

        actual["algorithm"] = expected_algorithm
        actual["hash_value"] = computed_hash

        if (computed_hash or "").lower() != (expected_hash or "").lower():
            mismatches.append(
                {
                    "type": "HASH_MISMATCH",
                    "path": expected_path,
                    "expected": {
                        "algorithm": expected_algorithm,
                        "hash_value": expected_hash,
                        "size": expected_size,
                    },
                    "actual": {
                        "algorithm": expected_algorithm,
                        "hash_value": computed_hash,
                        "size": actual.get("size"),
                        "s3_key": actual.get("s3_key"),
                    },
                }
            )
            files_failed += 1
            continue

        files_verified += 1
        verified_entries.append(
            {
                "path": expected_path,
                "algorithm": expected_algorithm,
                "hash_value": computed_hash,
                "size": actual.get("size"),
                "s3_key": actual.get("s3_key"),
            }
        )

    ok = files_failed == 0
    reason = "VERIFIED" if ok else "VERIFICATION_FAILED"

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

def build_verify_failure_result(
    *,
    reason: str,
    job_id: str,
    project_code: str,
    manifest_s3_uri: str,
    actual_entries: List[Dict[str, Any]],
    mismatch_type: str,
    error_message: str,
    mhl_key: Optional[str] = None,
    mhl_keys: Optional[List[str]] = None,
) -> Dict[str, Any]:
    actual_payload: Dict[str, Any] = {
        "error": error_message,
    }

    if mhl_key is not None:
        actual_payload["mhl_key"] = mhl_key

    if mhl_keys is not None:
        actual_payload["mhl_keys"] = mhl_keys

    return {
        "mode": "VERIFY_MHL",
        "ok": False,
        "reason": reason,
        "job_id": job_id,
        "project_code": project_code,
        "manifest_s3_uri": manifest_s3_uri,
        "mhl_key": mhl_key,
        "mhl_version": None,
        "hash_entry_count": 0,
        "files_total": 0,
        "files_verified": 0,
        "files_failed": 1,
        "files_missing": 0,
        "mismatches": [
            {
                "type": mismatch_type,
                "path": mhl_key,
                "expected": None,
                "actual": actual_payload,
            }
        ],
        "verified_entries": [],
        "hash_entries": [],
        "actual_entries": actual_entries,
    }

def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    bucket = event.get("bucket")
    folder_path = event.get("folder_path")
    manifest_s3_uri = event.get("manifest_s3_uri")
    inventory = event.get("inventory") or []
    mhl_keys = event.get("mhl_keys") or []

    if not bucket:
        raise ValueError("Missing required field: bucket")
    if not folder_path:
        raise ValueError("Missing required field: folder_path")
    if not mhl_keys:
        raise ValueError("Missing required field: mhl_keys")

    actual_entries = build_inventory_lookup(inventory, folder_path)

    try:
        mhl_key = choose_mhl_key(mhl_keys)
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("AMBIGUOUS_MHL_PACKAGE"):
            return build_verify_failure_result(
                reason="AMBIGUOUS_MHL_PACKAGE",
                job_id=job_id,
                project_code=project_code,
                manifest_s3_uri=manifest_s3_uri,
                actual_entries=actual_entries,
                mismatch_type="AMBIGUOUS_MHL_PACKAGE",
                error_message=msg,
                mhl_keys=sorted([k for k in mhl_keys if k]),
            )

        return build_verify_failure_result(
            reason="INVALID_MHL",
            job_id=job_id,
            project_code=project_code,
            manifest_s3_uri=manifest_s3_uri,
            actual_entries=actual_entries,
            mismatch_type="INVALID_MHL",
            error_message=msg,
            mhl_keys=sorted([k for k in mhl_keys if k]),
        )

    try:
        xml_text = load_text_from_s3(bucket, mhl_key)
        parsed = parse_mhl_xml(xml_text)
    except ET.ParseError as exc:
        return build_verify_failure_result(
            reason="MHL_PARSE_FAILED",
            job_id=job_id,
            project_code=project_code,
            manifest_s3_uri=manifest_s3_uri,
            actual_entries=actual_entries,
            mismatch_type="MHL_PARSE_FAILED",
            error_message=str(exc),
            mhl_key=mhl_key,
        )
    except ValueError as exc:
        return build_verify_failure_result(
            reason="INVALID_MHL",
            job_id=job_id,
            project_code=project_code,
            manifest_s3_uri=manifest_s3_uri,
            actual_entries=actual_entries,
            mismatch_type="INVALID_MHL",
            error_message=str(exc),
            mhl_key=mhl_key,
        )

    verification = verify_expected_vs_actual(
        bucket=bucket,
        expected_entries=parsed["hash_entries"],
        actual_entries=actual_entries,
    )

    return {
        "mode": "VERIFY_MHL",
        "ok": verification["ok"],
        "reason": verification["reason"],
        "job_id": job_id,
        "project_code": project_code,
        "manifest_s3_uri": manifest_s3_uri,
        "mhl_key": mhl_key,
        "mhl_version": parsed["mhl_version"],
        "hash_entry_count": parsed["hash_entry_count"],
        "files_total": verification["files_total"],
        "files_verified": verification["files_verified"],
        "files_failed": verification["files_failed"],
        "files_missing": verification["files_missing"],
        "mismatches": verification["mismatches"],
        "verified_entries": verification["verified_entries"],
        "hash_entries": parsed["hash_entries"],
        "actual_entries": verification["actual_entries"],
    }