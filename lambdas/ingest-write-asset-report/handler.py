
# ingest-write-asset-report_handler_v1_probe_expanded

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
ASSET_REPORT_BUCKET = os.environ.get("ASSET_REPORT_BUCKET")  # optional override

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


def normalize_folder_path(folder_path: str) -> str:
    if folder_path and not folder_path.endswith("/"):
        return folder_path + "/"
    return folder_path or ""


def build_relative_path(full_key: str, folder_path: str) -> str:
    prefix = normalize_folder_path(folder_path)
    if full_key.startswith(prefix):
        return full_key[len(prefix):]
    return full_key


def get_nested(dct: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    cur: Any = dct
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def load_json_from_s3_uri(uri: str) -> Dict[str, Any]:
    bucket, key = parse_s3_uri(uri)
    response = s3.get_object(Bucket=bucket, Key=key)
    return json.loads(response["Body"].read().decode("utf-8"))


def load_job_row(job_id: str) -> Dict[str, Any]:
    response = table.get_item(Key={"job_id": job_id})
    return response.get("Item") or {}


def determine_quality_outcome(final_state: str, findings_count: int) -> str:
    if final_state == "REJECTED_POLICY":
        return "FAIL"
    if findings_count > 0:
        return "PASS_WITH_WARNING"
    return "PASS"


def build_manifest_inventory_index(
    manifest: Dict[str, Any],
    folder_path: str,
) -> Dict[str, Dict[str, Any]]:
    inventory = manifest.get("inventory") or []
    by_path: Dict[str, Dict[str, Any]] = {}

    for item in inventory:
        if not isinstance(item, dict):
            continue

        s3_key = item.get("key")
        if not s3_key:
            continue

        path = build_relative_path(s3_key, folder_path)

        by_path[path] = {
            "path": path,
            "s3_key": s3_key,
            "size": item.get("size"),
            "etag": item.get("etag"),
            "last_modified": item.get("last_modified"),
            "extension": None,
            "media_type": None,
            "classification_method": None,
            "checksum": {
                "mode": None,
                "status": None,
                "algorithm": None,
                "expected_algorithm": None,
                "expected_hash": None,
                "actual_algorithm": None,
                "actual_hash": None,
                "size_expected": None,
                "size_actual": item.get("size"),
                "verified_at": None,
                "mhl_key": None,
            },
            "probe": {
                "readable": None,
                "unreadable": None,
                "container": None,
                "duration_seconds": None,
                "bit_rate": None,
                "file_size": None,
                "video_codec": None,
                "video_profile": None,
                "width": None,
                "height": None,
                "display_aspect_ratio": None,
                "pixel_format": None,
                "field_order": None,
                "frame_rate": None,
                "timecode": None,
                "audio_codec": None,
                "channels": None,
                "channel_layout": None,
                "sample_rate": None,
                "bit_depth": None,
                "color_space": None,
                "color_primaries": None,
                "audio_stream_count": None,
                "probe_method": None,
                "probe_error": None,
            },
            "findings": [],
        }

    return by_path


def ensure_asset(
    assets_by_path: Dict[str, Dict[str, Any]],
    path: Optional[str],
    *,
    s3_key: Optional[str] = None,
    size: Any = None,
    etag: Optional[str] = None,
    last_modified: Optional[str] = None,
) -> Dict[str, Any]:
    key = path or s3_key or "__unknown__"

    if key not in assets_by_path:
        assets_by_path[key] = {
            "path": path,
            "s3_key": s3_key,
            "size": size,
            "etag": etag,
            "last_modified": last_modified,
            "extension": None,
            "media_type": None,
            "classification_method": None,
            "checksum": {
                "mode": None,
                "status": None,
                "algorithm": None,
                "expected_algorithm": None,
                "expected_hash": None,
                "actual_algorithm": None,
                "actual_hash": None,
                "size_expected": None,
                "size_actual": size,
                "verified_at": None,
                "mhl_key": None,
            },
            "probe": {
                "readable": None,
                "unreadable": None,
                "container": None,
                "duration_seconds": None,
                "bit_rate": None,
                "file_size": None,
                "video_codec": None,
                "video_profile": None,
                "width": None,
                "height": None,
                "display_aspect_ratio": None,
                "pixel_format": None,
                "field_order": None,
                "frame_rate": None,
                "timecode": None,
                "audio_codec": None,
                "channels": None,
                "channel_layout": None,
                "sample_rate": None,
                "bit_depth": None,
                "color_space": None,
                "color_primaries": None,
                "audio_stream_count": None,
                "probe_method": None,
                "probe_error": None,
            },
            "findings": [],
        }

    asset = assets_by_path[key]

    if path is not None:
        asset["path"] = path
    if s3_key is not None:
        asset["s3_key"] = s3_key
    if size is not None:
        asset["size"] = size
        if asset.get("checksum"):
            asset["checksum"]["size_actual"] = size
    if etag is not None:
        asset["etag"] = etag
    if last_modified is not None:
        asset["last_modified"] = last_modified

    return asset


def apply_checksum_data(
    assets_by_path: Dict[str, Dict[str, Any]],
    checksum: Dict[str, Any],
) -> None:
    if not isinstance(checksum, dict):
        return

    mode = checksum.get("mode")
    default_algorithm = checksum.get("algorithm")
    mhl_key = checksum.get("mhl_key")

    for actual in checksum.get("actual_entries") or []:
        if not isinstance(actual, dict):
            continue
        asset = ensure_asset(
            assets_by_path,
            actual.get("path"),
            s3_key=actual.get("s3_key"),
            size=actual.get("size"),
            etag=actual.get("etag"),
            last_modified=actual.get("last_modified"),
        )
        asset["checksum"]["mode"] = mode
        asset["checksum"]["actual_algorithm"] = actual.get("algorithm") or default_algorithm
        asset["checksum"]["actual_hash"] = actual.get("hash_value")
        asset["checksum"]["verified_at"] = actual.get("verified_at")
        asset["checksum"]["mhl_key"] = mhl_key

    for expected in checksum.get("hash_entries") or []:
        if not isinstance(expected, dict):
            continue
        asset = ensure_asset(
            assets_by_path,
            expected.get("path"),
            size=expected.get("size"),
            last_modified=expected.get("last_modified"),
        )
        asset["checksum"]["mode"] = mode
        asset["checksum"]["expected_algorithm"] = expected.get("algorithm")
        asset["checksum"]["expected_hash"] = expected.get("hash_value")
        asset["checksum"]["size_expected"] = expected.get("size")
        asset["checksum"]["mhl_key"] = mhl_key

    for verified in checksum.get("verified_entries") or []:
        if not isinstance(verified, dict):
            continue
        asset = ensure_asset(
            assets_by_path,
            verified.get("path"),
            s3_key=verified.get("s3_key"),
            size=verified.get("size"),
        )
        asset["checksum"]["mode"] = mode
        asset["checksum"]["algorithm"] = verified.get("algorithm") or default_algorithm
        asset["checksum"]["actual_algorithm"] = verified.get("algorithm") or default_algorithm
        asset["checksum"]["actual_hash"] = verified.get("hash_value")
        asset["checksum"]["verified_at"] = verified.get("verified_at")
        asset["checksum"]["mhl_key"] = mhl_key

    mismatch_by_path: Dict[str, List[Dict[str, Any]]] = {}
    for mismatch in checksum.get("mismatches") or []:
        if not isinstance(mismatch, dict):
            continue
        path = mismatch.get("path")
        mismatch_by_path.setdefault(path or "__unknown__", []).append(mismatch)

    for asset in assets_by_path.values():
        path_key = asset.get("path") or "__unknown__"
        family_mismatches = mismatch_by_path.get(path_key, [])
        ck = asset["checksum"]
        ck["mode"] = ck["mode"] or mode
        ck["algorithm"] = ck["algorithm"] or ck["expected_algorithm"] or ck["actual_algorithm"] or default_algorithm
        ck["actual_algorithm"] = ck["actual_algorithm"] or default_algorithm
        ck["mhl_key"] = ck["mhl_key"] or mhl_key

        if family_mismatches:
            mismatch_types = {m.get("type") for m in family_mismatches}
            if "MISSING_FILE" in mismatch_types:
                ck["status"] = "missing"
            elif "SIZE_MISMATCH" in mismatch_types:
                ck["status"] = "size_mismatch"
            elif "HASH_MISMATCH" in mismatch_types:
                ck["status"] = "hash_mismatch"
            elif "HASH_COMPUTE_ERROR" in mismatch_types:
                ck["status"] = "hash_compute_error"
            elif "MHL_PARSE_FAILED" in mismatch_types or "INVALID_MHL" in mismatch_types or "AMBIGUOUS_MHL_PACKAGE" in mismatch_types:
                ck["status"] = "invalid_reference"
            else:
                ck["status"] = "failed"
            continue

        if mode == "BASELINE_ONLY":
            if ck.get("actual_hash"):
                ck["status"] = "baselined"
            else:
                ck["status"] = "not_captured"
        elif mode == "VERIFY_MHL":
            if ck.get("expected_hash") and ck.get("actual_hash"):
                ck["status"] = "verified"
            elif ck.get("expected_hash"):
                ck["status"] = "expected_only"
            elif ck.get("actual_hash"):
                ck["status"] = "actual_only"
            else:
                ck["status"] = "not_checked"


def apply_media_data(
    assets_by_path: Dict[str, Dict[str, Any]],
    media: Dict[str, Any],
) -> Dict[str, Any]:
    tooling = {
        "ffprobe_available": None,
        "ffprobe_version_line": None,
        "ffprobe_error": None,
    }

    if not isinstance(media, dict):
        return tooling

    ffprobe_version = media.get("ffprobe_version") or {}
    if isinstance(ffprobe_version, dict):
        tooling["ffprobe_available"] = ffprobe_version.get("available")
        tooling["ffprobe_version_line"] = ffprobe_version.get("version_line")
        tooling["ffprobe_error"] = ffprobe_version.get("stderr")

    for classified in media.get("classified_entries") or []:
        if not isinstance(classified, dict):
            continue
        asset = ensure_asset(
            assets_by_path,
            classified.get("path"),
            s3_key=classified.get("s3_key"),
            size=classified.get("size"),
            etag=classified.get("etag"),
            last_modified=classified.get("last_modified"),
        )
        asset["extension"] = classified.get("extension")
        asset["media_type"] = classified.get("media_type")
        asset["classification_method"] = classified.get("classification_method")

    for probed in media.get("probed_entries") or []:
        if not isinstance(probed, dict):
            continue
        asset = ensure_asset(
            assets_by_path,
            probed.get("path"),
            s3_key=probed.get("s3_key"),
        )
        asset["media_type"] = asset.get("media_type") or probed.get("media_type")
        asset["probe"] = {
            "readable": probed.get("readable"),
            "unreadable": probed.get("unreadable"),
            "container": probed.get("container"),
            "duration_seconds": probed.get("duration_seconds"),
            "bit_rate": probed.get("bit_rate"),
            "file_size": probed.get("file_size"),
            "video_codec": probed.get("video_codec"),
            "video_profile": probed.get("video_profile"),
            "width": probed.get("width"),
            "height": probed.get("height"),
            "display_aspect_ratio": probed.get("display_aspect_ratio"),
            "pixel_format": probed.get("pixel_format"),
            "field_order": probed.get("field_order"),
            "frame_rate": probed.get("frame_rate"),
            "timecode": probed.get("timecode"),
            "audio_codec": probed.get("audio_codec"),
            "channels": probed.get("channels"),
            "channel_layout": probed.get("channel_layout"),
            "sample_rate": probed.get("sample_rate"),
            "bit_depth": probed.get("bit_depth"),
            "color_space": probed.get("color_space"),
            "color_primaries": probed.get("color_primaries"),
            "audio_stream_count": probed.get("audio_stream_count"),
            "probe_method": probed.get("probe_method"),
            "probe_error": probed.get("probe_error"),
        }

    return tooling


def add_path_findings(
    assets_by_path: Dict[str, Dict[str, Any]],
    family: str,
    mismatches: Any,
) -> None:
    if not isinstance(mismatches, list):
        return

    for mismatch in mismatches:
        if not isinstance(mismatch, dict):
            continue

        actual = mismatch.get("actual") or {}
        path = mismatch.get("path")
        asset = ensure_asset(
            assets_by_path,
            path,
            s3_key=actual.get("s3_key"),
            size=actual.get("size"),
        )
        asset["findings"].append(
            {
                "family": family,
                "type": mismatch.get("type"),
                "expected": mismatch.get("expected"),
                "actual": actual if actual != {} else mismatch.get("actual"),
            }
        )


def build_asset_report(
    *,
    job_id: str,
    project_code: str,
    trigger: Optional[str],
    ruleset_version: str,
    ingest_folder: Optional[str],
    manifest_s3_uri: str,
    final_state: str,
    validate_result: Optional[Dict[str, Any]],
    checksum: Dict[str, Any],
    media: Dict[str, Any],
    media_policy: Dict[str, Any],
    job_row: Dict[str, Any],
) -> Dict[str, Any]:
    manifest = load_json_from_s3_uri(manifest_s3_uri)
    folder_path = get_nested(manifest, ["impl", "s3", "prefix"]) or ""
    assets_by_path = build_manifest_inventory_index(manifest, folder_path)

    apply_checksum_data(assets_by_path, checksum)
    tooling = apply_media_data(assets_by_path, media)
    add_path_findings(assets_by_path, "checksum", checksum.get("mismatches"))
    add_path_findings(assets_by_path, "media", media.get("mismatches"))
    add_path_findings(assets_by_path, "media_policy", media_policy.get("mismatches"))

    assets: List[Dict[str, Any]] = list(assets_by_path.values())
    assets.sort(key=lambda item: ((item.get("path") is None), item.get("path") or item.get("s3_key") or ""))

    findings_count = sum(len(asset.get("findings") or []) for asset in assets)
    quality_outcome = determine_quality_outcome(final_state, findings_count)

    return {
        "asset_report_version": "v1.0",
        "generated_at": utc_now_iso(),
        "job": {
            "job_id": job_id,
            "project_code": project_code,
            "trigger": trigger,
            "ruleset_version": ruleset_version,
        },
        "locations": {
            "ingest_folder": ingest_folder,
            "manifest_s3_uri": manifest_s3_uri,
        },
        "workflow": {
            "final_state": final_state,
            "quality_outcome": quality_outcome,
        },
        "inventory_summary": {
            "payload_file_count": len(assets),
            "manifest_stats": manifest.get("stats") or {},
        },
        "deep_validation_summary": {
            "checksum": {
                "mode": checksum.get("mode"),
                "ok": checksum.get("ok"),
                "reason": checksum.get("reason"),
                "algorithm": checksum.get("algorithm"),
                "files_total": checksum.get("files_total"),
                "files_verified": checksum.get("files_verified"),
                "files_failed": checksum.get("files_failed"),
                "files_missing": checksum.get("files_missing"),
                "mismatch_count": len(checksum.get("mismatches") or []),
                "mhl_key": checksum.get("mhl_key"),
                "mhl_version": checksum.get("mhl_version"),
                "hash_entry_count": checksum.get("hash_entry_count"),
            },
            "media": {
                "ok": media.get("ok"),
                "reason": media.get("reason"),
                "files_total": media.get("files_total"),
                "files_media_candidate": media.get("files_media_candidate"),
                "files_non_media": media.get("files_non_media"),
                "files_ignored": media.get("files_ignored"),
                "mismatch_count": len(media.get("mismatches") or []),
                "summary": media.get("summary") or {},
            },
            "media_policy": {
                "ok": media_policy.get("ok"),
                "reason": media_policy.get("reason"),
                "policy_profile": media_policy.get("policy_profile"),
                "ruleset_version": media_policy.get("ruleset_version"),
                "files_evaluated": media_policy.get("files_evaluated"),
                "files_with_findings": media_policy.get("files_with_findings"),
                "mismatch_count": len(media_policy.get("mismatches") or []),
                "summary": media_policy.get("summary") or {},
            },
        },
        "tooling": tooling,
        "artifacts": {
            "manifest": to_jsonable(manifest),
            "job_row_snapshot": {
                "state": job_row.get("state"),
                "manifest_s3_uri": job_row.get("manifest_s3_uri"),
                "report_s3_uri": job_row.get("report_s3_uri"),
            },
        },
        "assets": to_jsonable(assets),
        "findings_count": findings_count,
    }


def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    ruleset_version = event.get("ruleset_version", "v1.0")
    trigger = event.get("trigger")
    ingest_folder = event.get("ingest_folder")
    manifest_s3_uri = event.get("manifest_s3_uri")
    final_state = event.get("final_state")
    validate_result = event.get("validate_result")

    checksum = event.get("checksum") or get_nested(event, ["results", "checksum", "Payload"], {})
    media = event.get("media") or get_nested(event, ["results", "media", "Payload"], {})
    media_policy = event.get("media_policy") or get_nested(event, ["results", "media_policy", "Payload"], {})

    if not job_id or not project_code:
        raise ValueError("Missing required fields: job_id and project_code")
    if not manifest_s3_uri:
        raise ValueError("Missing required field: manifest_s3_uri")
    if not final_state:
        raise ValueError("Missing required field: final_state")

    manifest_bucket, _ = parse_s3_uri(manifest_s3_uri)
    out_bucket = ASSET_REPORT_BUCKET or manifest_bucket
    asset_report_key = f"{project_code}/_asset_reports/{job_id}.json"
    asset_report_s3_uri = f"s3://{out_bucket}/{asset_report_key}"

    job_row = to_jsonable(load_job_row(job_id))

    asset_report = build_asset_report(
        job_id=job_id,
        project_code=project_code,
        trigger=trigger,
        ruleset_version=ruleset_version,
        ingest_folder=ingest_folder,
        manifest_s3_uri=manifest_s3_uri,
        final_state=final_state,
        validate_result=validate_result,
        checksum=checksum if isinstance(checksum, dict) else {},
        media=media if isinstance(media, dict) else {},
        media_policy=media_policy if isinstance(media_policy, dict) else {},
        job_row=job_row,
    )

    asset_report["locations"]["asset_report_s3_uri"] = asset_report_s3_uri

    try:
        s3.put_object(
            Bucket=out_bucket,
            Key=asset_report_key,
            Body=json.dumps(asset_report, ensure_ascii=False, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
    except ClientError as exc:
        raise RuntimeError(f"Failed to write asset report to {asset_report_s3_uri}: {exc}") from exc

    try:
        table.update_item(
            Key={"job_id": job_id},
            UpdateExpression=(
                "SET asset_report_s3_uri = :u, asset_report_bucket = :b, "
                "asset_report_key = :k, asset_report_generated_at = :t"
            ),
            ExpressionAttributeValues={
                ":u": asset_report_s3_uri,
                ":b": out_bucket,
                ":k": asset_report_key,
                ":t": utc_now_iso(),
            },
        )
    except ClientError as exc:
        raise RuntimeError(f"Asset report written but DynamoDB update failed: {exc}") from exc

    return {
        "ok": True,
        "job_id": job_id,
        "project_code": project_code,
        "final_state": final_state,
        "asset_report_s3_uri": asset_report_s3_uri,
        "asset_report_bucket": out_bucket,
        "asset_report_key": asset_report_key,
        "asset_report_version": "v1.0",
    }
