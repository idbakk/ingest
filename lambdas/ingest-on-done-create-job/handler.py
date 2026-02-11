import json
import hashlib
import os
import boto3
from urllib.parse import unquote_plus
from datetime import datetime, timezone
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ.get("JOB_TABLE", "IngestJobs"))

sfn = boto3.client("stepfunctions")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_job_id(project_code: str, folder_path: str) -> str:
    raw = f"{project_code}:{folder_path}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def handler(event, context):
    if not STATE_MACHINE_ARN:
        raise RuntimeError("Missing required environment variable: STATE_MACHINE_ARN")

    # 1) Extract S3 info + decode key
    try:
        record = event["Records"][0]
        bucket = record["s3"]["bucket"]["name"]
        raw_key = record["s3"]["object"]["key"]
        object_key = unquote_plus(raw_key)
    except (KeyError, IndexError) as err:
        print("Invalid event structure", err, event)
        return {"status": "error", "message": "Invalid event structure"}

    # 2) Guard: only react to _INGEST_DONE
    if not object_key.endswith("_INGEST_DONE"):
        print(f"Ignored: {object_key}")
        return {"status": "ignored", "reason": "not_ingest_done_marker"}

    # 3) Guard: must be inside a folder
    if "/" not in object_key:
        print(f"Ignored root file: {object_key}")
        return {"status": "ignored", "reason": "file_in_root"}

    folder_path = object_key.rsplit("/", 1)[0] + "/"
    project_code = folder_path.split("/", 1)[0]

    job_id = generate_job_id(project_code, folder_path)
    current_ts = now_iso()

    job_item = {
        "job_id": job_id,
        "project_code": project_code,
        "ingest_folder": f"s3://{bucket}/{folder_path}",
        "state": "CREATED",
        "trigger": "_INGEST_DONE",
        "created_at": current_ts,
        "last_seen_at": current_ts,
        "last_seen_object_key": object_key,
        "ruleset_version": "v1.0",
    }

    # 6) Create job only if not exists
    created_new = False
    try:
        table.put_item(
            Item=job_item,
            ConditionExpression="attribute_not_exists(#pk)",
            ExpressionAttributeNames={"#pk": "job_id"},
        )
        created_new = True
        print(f"New job created: {job_id}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            created_new = False
        else:
            raise

    # 7) Duplicate → only update last_seen*
    if not created_new:
        seen_ts = now_iso()
        print(f"Job exists, updating timestamp: {job_id}")
        table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET last_seen_at = :t, last_seen_object_key = :k",
            ExpressionAttributeValues={":t": seen_ts, ":k": object_key},
        )
        return {
            "status": "duplicate_ingest_done_ignored",
            "job_id": job_id,
            "ingest_folder": job_item["ingest_folder"],
        }

    # 8) Start Step Functions for new job
    execution_input = {
        "job_id": job_id,
        "project_code": project_code,
        "bucket": bucket,
        "object_key": object_key,
        "folder_path": folder_path,
        "ingest_folder": job_item["ingest_folder"],
        "trigger": job_item["trigger"],
        "created_at": job_item["created_at"],
    }

    try:
        resp = sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=job_id,
            input=json.dumps(execution_input),
        )
        return {
            "status": "job_created_and_execution_started",
            "job_id": job_id,
            "execution_arn": resp.get("executionArn"),
        }
    except ClientError as e:
        if e.response["Error"]["Code"] == "ExecutionAlreadyExists":
            print(f"SFN Execution already exists for {job_id}")
            return {"status": "job_created_but_execution_already_exists", "job_id": job_id}

        # Optional but recommended: mark the job as failed to start orchestration
        table.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :s, start_error = :e, last_seen_at = :t",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":s": "ERROR_STARTING",
                ":e": e.response["Error"],
                ":t": now_iso(),
            },
        )
        raise
