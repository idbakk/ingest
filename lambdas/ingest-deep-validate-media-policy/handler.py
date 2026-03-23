from typing import Any, Dict, List, Optional

POLICY_PROFILE = "generic_baseline"
RULESET_VERSION_DEFAULT = "v1.0"


def is_positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and value > 0


def append_mismatch(
    mismatches: List[Dict[str, Any]],
    mismatch_type: str,
    entry: Dict[str, Any],
    details: Optional[Dict[str, Any]] = None,
) -> None:
    mismatches.append(
        {
            "type": mismatch_type,
            "path": entry.get("path"),
            "expected": None,
            "actual": {
                "s3_key": entry.get("s3_key"),
                "media_type": entry.get("media_type"),
                **(details or {}),
            },
        }
    )


def evaluate_entry(
    entry: Dict[str, Any],
    mismatches: List[Dict[str, Any]],
    counters: Dict[str, int],
) -> bool:
    """
    Returns True if this entry has one or more findings.
    """
    media_type = entry.get("media_type")
    readable = entry.get("readable")

    has_finding = False

    if readable is False:
        counters["unreadable_count"] += 1
        append_mismatch(
            mismatches,
            "UNREADABLE_MEDIA",
            entry,
            {
                "probe_error": entry.get("probe_error"),
                "readable": readable,
            },
        )
        has_finding = True
        return has_finding

    # Only evaluate readable probed A/V entries
    if readable is not True:
        return has_finding

    container = entry.get("container")
    duration_seconds = entry.get("duration_seconds")

    if not container:
        counters["missing_container_count"] += 1
        append_mismatch(
            mismatches,
            "MISSING_CONTAINER_METADATA",
            entry,
            {
                "container": container,
            },
        )
        has_finding = True

    if not is_positive_number(duration_seconds):
        counters["duration_missing_or_zero_count"] += 1
        append_mismatch(
            mismatches,
            "MEDIA_DURATION_MISSING_OR_ZERO",
            entry,
            {
                "duration_seconds": duration_seconds,
            },
        )
        has_finding = True

    if media_type == "video":
        video_codec = entry.get("video_codec")
        width = entry.get("width")
        height = entry.get("height")

        if not video_codec:
            counters["video_stream_missing_count"] += 1
            append_mismatch(
                mismatches,
                "VIDEO_STREAM_MISSING",
                entry,
                {
                    "video_codec": video_codec,
                },
            )
            has_finding = True

        if not is_positive_number(width) or not is_positive_number(height):
            counters["dimension_missing_count"] += 1
            append_mismatch(
                mismatches,
                "VIDEO_DIMENSIONS_MISSING",
                entry,
                {
                    "width": width,
                    "height": height,
                },
            )
            has_finding = True

    elif media_type == "audio":
        audio_codec = entry.get("audio_codec")
        audio_stream_count = entry.get("audio_stream_count")

        if not audio_codec or not is_positive_number(audio_stream_count):
            counters["audio_stream_missing_count"] += 1
            append_mismatch(
                mismatches,
                "AUDIO_STREAM_MISSING",
                entry,
                {
                    "audio_codec": audio_codec,
                    "audio_stream_count": audio_stream_count,
                },
            )
            has_finding = True

    return has_finding


def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    manifest_s3_uri = event.get("manifest_s3_uri")
    ruleset_version = event.get("ruleset_version") or RULESET_VERSION_DEFAULT
    media_result = event.get("media_result") or {}

    if not isinstance(media_result, dict):
        raise ValueError("media_result must be a dict")

    probed_entries = media_result.get("probed_entries") or []
    if not isinstance(probed_entries, list):
        raise ValueError("media_result.probed_entries must be a list")

    if len(probed_entries) == 0:
        return {
            "mode": "Media Policy",
            "ok": True,
            "reason": "MEDIA_POLICY_NOT_APPLICABLE",
            "job_id": job_id,
            "project_code": project_code,
            "manifest_s3_uri": manifest_s3_uri,
            "policy_profile": POLICY_PROFILE,
            "ruleset_version": ruleset_version,
            "files_evaluated": 0,
            "files_with_findings": 0,
            "mismatches": [],
            "summary": {
                "entries_evaluated": 0,
                "unreadable_count": 0,
                "missing_container_count": 0,
                "video_stream_missing_count": 0,
                "audio_stream_missing_count": 0,
                "duration_missing_or_zero_count": 0,
                "dimension_missing_count": 0,
            },
        }

    mismatches: List[Dict[str, Any]] = []
    counters: Dict[str, int] = {
        "unreadable_count": 0,
        "missing_container_count": 0,
        "video_stream_missing_count": 0,
        "audio_stream_missing_count": 0,
        "duration_missing_or_zero_count": 0,
        "dimension_missing_count": 0,
    }

    files_with_findings = 0

    for entry in probed_entries:
        if evaluate_entry(entry=entry, mismatches=mismatches, counters=counters):
            files_with_findings += 1

    mismatches.sort(key=lambda x: (x.get("path") or "", x.get("type") or ""))

    ok = files_with_findings == 0
    reason = "MEDIA_POLICY_OK" if ok else "MEDIA_POLICY_WITH_FINDINGS"

    return {
        "mode": "Media Policy",
        "ok": ok,
        "reason": reason,
        "job_id": job_id,
        "project_code": project_code,
        "manifest_s3_uri": manifest_s3_uri,
        "policy_profile": POLICY_PROFILE,
        "ruleset_version": ruleset_version,
        "files_evaluated": len(probed_entries),
        "files_with_findings": files_with_findings,
        "mismatches": mismatches,
        "summary": {
            "entries_evaluated": len(probed_entries),
            **counters,
        },
    }