import json
from typing import Any, Dict, List

def handler(event, context):
    """
    Expected input:
      {
        "job_id": "...",
        "project_code" : "...",
        "manifest_s3_uri" : "s3://...",
        "inventory" : [{"key": "...", ...}, ...]
      }
    """
    inventory: List[Dict[str, Any]] = event.get("inventory") or []

    mhl_keys = []
    for item in inventory:
        key = (item.get("key") or "").strip()
        if key.lower().endswith(".mhl"):
            mhl_keys.append(key)

    return {
        "mhl_present": len(mhl_keys) > 0,
        "mhl_keys": sorted(mhl_keys),
        "count_inventory": len(inventory)
    }

