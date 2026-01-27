import json
import hashlib
import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("JOB_TABLE", "IngestJobs")
table = dynamodb.Table(TABLE_NAME)


def generate_job_id(project_code: str, folder_path: str) -> str:
	"""
	Deterministic job ID.
	Same project + same folder => same job_id
	"""
	raw = f"{project_code}:{folder_path}"
	return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def handler(event, context):
	#1. Extract S3 info
	record = event["Records"][0]
	bucket = record["s3"]["bucket"]["name"]
	object_key = record["s3"]["object"]["key"]
	
	#2. Guard: only react to _INGEST_DONE
	if not object_key.endswith("_INGEST_DONE"):
		return {"status" : "ignored"}
		
	#3. Derive folder path
	folder_path = object_key.rsplit("/", 1)[0] + "/"
	project_code = folder_path.split("/")[0]
	
	#4. Generate job_id
	job_id = generate_job_id(project_code, folder_path)
	
	#5. Build job record
	job_item = {
		"job_id": job_id,
		"project_code": project_code,
		"ingest_folder": f"s3://{bucket}/{folder_path}",
		"state": "CREATED",
		"trigger": "_INGEST_DONE",
		"created_at": datetime.utcnow().isoformat() + "Z",
	}
	
	#6. Write to DynamoDB (atomic, conditional)
	try:
		table.put_item(
			Item=job_item,
			ConditionExpression="attribute_not_exists(job_id)",
		)
		return {"status": "job_created", "job_id": job_id}
		
	except ClientError as e:
		if e.response ["Error"]["Code"] == "ConditionalCheckFailedException":
		# Job already exists
			return {"status": "job_already_exists", "job_id": job_id}
		else:
			# Real failure
			raise 