from typing import Any, Dict, List, Set


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


def handler(event, context):
    job_id = event.get("job_id")
    project_code = event.get("project_code")
    manifest_s3_uri = event.get("manifest_s3_uri")
    folder_path = event.get("folder_path")
    inventory = event.get("inventory") or []

    if not folder_path:
        raise ValueError("Missing required field: folder_path")
    if not isinstance(inventory, list):
        raise ValueError("inventory must be a list")

    result = classify_inventory(inventory=inventory, folder_path=folder_path)

    return {
        "mode": "Media Classification",
        "ok": result["ok"],
        "reason": result["reason"],
        "job_id": job_id,
        "project_code": project_code,
        "manifest_s3_uri": manifest_s3_uri,
        "files_total": result["files_total"],
        "files_media_candidate": result["files_media_candidate"],
        "files_non_media": result["files_non_media"],
        "files_ignored": result["files_ignored"],
        "mismatches": result["mismatches"],
        "classified_entries": result["classified_entries"],
        "summary": result["summary"],
    }
