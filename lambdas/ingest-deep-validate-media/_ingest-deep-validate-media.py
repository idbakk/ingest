# Libraries
import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set
import boto3

s3 = boto3.client("s3")

PROBE_MEDIA_TYPES: Set[str] = {"video", "audio"}
FFPROBE_BIN = "/opt/bin/ffprobe"
TMP_DIR = "/tmp"

# Media Index
VIDEO_EXTENSIONS: Set[str] = {".mov", ".mp4", ".mxf", ".mkv", ".avi"}
AUDIO_EXTENSIONS: Set[str] = {".wav", ".mp3", ".aac", ".m4a", ".flac"}
IMAGE_EXTENSIONS: Set[str] = {".exr", ".dpx", ".jpg", ".jpeg", ".png", ".tif", ".tiff"}
SUBTITLE_EXTENSIONS: Set[str] = {".srt", ".vtt", ".itt", ".stl"}
IGNORED_EXTENSIONS: Set[str] = {".mhl"}
IGNORED_BASENAMES: Set[str] = {"_INGEST_DONE"}


def normalize_folder_path(folder_path: str) -> str:
    if folder_path and not folder_path.endswith("/"):
        return folder_path + "/"
    return folder_path or ""


def relative_path_from_key(key: str, folder_path: str) -> str:
    prefix = normalize_folder_path(folder_path)
    if key.startswith(prefix):
        return key[len(prefix):]
    return key


def split_extension(path: str) -> str:
    if not path:
        return ""

    dot_index = path.rfind(".")
    if dot_index == -1:
        return ""
    return path[dot_index:].lower()


def basename(path: str) -> str:
    if not path:
        return ""
    return path.rsplit("/", 1)[-1]


def classify_extension(ext: str) -> str:
    if ext in VIDEO_EXTENSIONS:
        return "video"
    if ext in AUDIO_EXTENSIONS:
        return "audio"
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in SUBTITLE_EXTENSIONS:
        return "subtitle"
    return "non_media"


def classify_inventory(
    inventory: List[Dict[str, Any]],
    folder_path: str,
) -> Dict[str, Any]:
    classified_entries: List[Dict[str, Any]] = []

    files_total = 0
    files_media_candidate = 0
    files_non_media = 0
    files_ignored = 0

    video_count = 0
    audio_count = 0
    image_count = 0
    subtitle_count = 0
    unknown_media_count = 0

    for item in inventory:
        key = item.get("key")
        if not key:
            continue

        files_total += 1

        path = relative_path_from_key(key, folder_path)
        base = basename(path)
        ext = split_extension(path)

        if base in IGNORED_BASENAMES or ext in IGNORED_EXTENSIONS:
            files_ignored += 1
            continue

        media_type = classify_extension(ext)

        if media_type == "non_media":
            files_non_media += 1
            continue

        files_media_candidate += 1

        if media_type == "video":
            video_count += 1
        elif media_type == "audio":
            audio_count += 1
        elif media_type == "image":
            image_count += 1
        elif media_type == "subtitle":
            subtitle_count += 1
        else:
            unknown_media_count += 1

        classified_entries.append(
            {
                "path": path,
                "s3_key": key,
                "size": item.get("size"),
                "etag": item.get("etag"),
                "last_modified": item.get("last_modified"),
                "extension": ext,
                "media_type": media_type,
                "classification_method": "extension",
            }
        )

    classified_entries.sort(key=lambda x: x["path"])

    return {
        "ok": True,
        "reason": "MEDIA_CLASSIFICATION_CAPTURED",
        "files_total": files_total,
        "files_media_candidate": files_media_candidate,
        "files_non_media": files_non_media,
        "files_ignored": files_ignored,
        "mismatches": [],
        "classified_entries": classified_entries,
        "summary": {
            "video_count": video_count,
            "audio_count": audio_count,
            "image_count": image_count,
            "subtitle_count": subtitle_count,
            "unknown_media_count": unknown_media_count,
        },
    }


def get_ffprobe_version() -> Dict[str, Any]:
    try:
        result = subprocess.run(
            [FFPROBE_BIN, "-version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        first_line = ""
        if result.stdout:
            first_line = result.stdout.splitlines()[0]

        return {
            "available": result.returncode == 0,
            "returncode": result.returncode,
            "version_line": first_line,
            "stderr": result.stderr.strip() if result.stderr else "",
        }
    except Exception as e:
        return {
            "available": False,
            "returncode": None,
            "version_line": "",
            "stderr": str(e),
        }


# FFPROBE Helper
def select_probe_candidates(classified_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        entry
        for entry in classified_entries
        if entry.get("media_type") in PROBE_MEDIA_TYPES
    ]


def safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def download_s3_to_tmp(bucket: str, key: str) -> str:
    suffix = split_extension(key) or ".bin"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=TMP_DIR) as tmp:
        local_path = tmp.name

    s3.download_file(bucket, key, local_path)
    return local_path


def run_ffprobe(local_path: str) -> Dict[str, Any]:
    cmd = [
        FFPROBE_BIN,
        "-v", "error",
        "-print_format", "json",
        "-show_format",
        "-show_streams",
        local_path,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "ffprobe failed")

    return json.loads(result.stdout or "{}")


def build_probe_success_entry(
    classified_entry: Dict[str, Any],
    probe_data: Dict[str, Any],
) -> Dict[str, Any]:
    streams = probe_data.get("streams") or []
    format_info = probe_data.get("format") or {}

    video_streams = [s for s in streams if s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]

    first_video = video_streams[0] if video_streams else {}
    first_audio = audio_streams[0] if audio_streams else {}

    format_name = format_info.get("format_name")
    container = format_name.split(",")[0] if format_name else None

    return {
        "path": classified_entry.get("path"),
        "s3_key": classified_entry.get("s3_key"),
        "media_type": classified_entry.get("media_type"),
        "readable": True,
        "unreadable": False,
        "container": container,
        "video_codec": first_video.get("codec_name"),
        "audio_codec": first_audio.get("codec_name"),
        "duration_seconds": safe_float(format_info.get("duration")),
        "width": safe_int(first_video.get("width")),
        "height": safe_int(first_video.get("height")),
        "audio_stream_count": len(audio_streams),
        "probe_method": "ffprobe",
    }


def build_probe_failure_entry(
    classified_entry: Dict[str, Any],
    error_message: str,
) -> Dict[str, Any]:
    return {
        "path": classified_entry.get("path"),
        "s3_key": classified_entry.get("s3_key"),
        "media_type": classified_entry.get("media_type"),
        "readable": False,
        "unreadable": True,
        "container": None,
        "video_codec": None,
        "audio_codec": None,
        "duration_seconds": None,
        "width": None,
        "height": None,
        "audio_stream_count": None,
        "probe_method": "ffprobe",
        "probe_error": error_message,
    }

# Handler
def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    bucket = event.get("bucket")
    manifest_s3_uri = event.get("manifest_s3_uri")
    folder_path = event.get("folder_path")
    inventory = event.get("inventory") or []

    if not bucket:
        raise ValueError("Missing required field: bucket")
    if not folder_path:
        raise ValueError("Missing required field: folder_path")
    if not isinstance(inventory, list):
        raise ValueError("inventory must be a list")

    result = classify_inventory(inventory=inventory, folder_path=folder_path)

    mismatches = list(result["mismatches"])
    summary = dict(result["summary"])
    probed_entries: List[Dict[str, Any]] = []
    
    probe_attempted_count = 0
    probed_count = 0
    probe_failed_count = 0
    ok = result["ok"]

    probe_candidates = select_probe_candidates(result["classified_entries"])

    for probe_candidate in probe_candidates:
        probe_attempted_count += 1
        local_path = None

        try:
            local_path = download_s3_to_tmp(bucket=bucket, key=probe_candidate["s3_key"])
            probe_data = run_ffprobe(local_path)
            probed_entries.append(build_probe_success_entry(probe_candidate, probe_data))
            probed_count += 1

        except Exception as exc:
            ok = False
            probe_failed_count += 1
            probed_entries.append(build_probe_failure_entry(probe_candidate, str(exc)))
            mismatches.append(
                {
                    "type": "MEDIA_PROBE_FAILED",
                    "path": probe_candidate.get("path"),
                    "expected": None,
                    "actual": {
                        "s3_key": probe_candidate.get("s3_key"),
                        "media_type": probe_candidate.get("media_type"),
                        "error": str(exc),
                    },
                }
            )

        finally:
            if local_path and os.path.exists(local_path):
                os.remove(local_path)

    if probe_attempted_count == 0:
        reason = "NO_VIDEO_OR_AUDIO_FOUND"
    elif probe_failed_count > 0:
        reason = "MEDIA_INSPECTED_WITH_ERROR"
    else:
        reason = "MEDIA_INSPECTED"

    summary["probe_attempted_count"] = probe_attempted_count
    summary["probed_count"] = probed_count
    summary["probe_failed_count"] = probe_failed_count

    return {
        "mode": "Media Inspection",
        "ok": ok,
        "reason": reason,
        "job_id": job_id,
        "project_code": project_code,
        "manifest_s3_uri": manifest_s3_uri,
        "files_total": result["files_total"],
        "files_media_candidate": result["files_media_candidate"],
        "files_non_media": result["files_non_media"],
        "files_ignored": result["files_ignored"],
        "mismatches": mismatches,
        "classified_entries": result["classified_entries"],
        "probed_entries": probed_entries,
        "summary": summary,
    }
