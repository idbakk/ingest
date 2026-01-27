# ============================================================================
# LIBRARY IMPORTS - These are all Python built-in modules or AWS SDK libraries
# ============================================================================

# json: Python built-in library for working with JSON data (not used in this code)
import json

# hashlib: Python built-in library for generating cryptographic hashes
import hashlib

# os: Python built-in library for interacting with the operating system
import os

# datetime: Python built-in library for working with dates and times
from datetime import datetime

# boto3: AWS SDK for Python - used to interact with AWS services
import boto3

# ClientError: Exception class from boto3 for handling AWS API errors
from botocore.exceptions import ClientError

# ============================================================================
# AWS DYNAMODB SETUP
# ============================================================================

# VARIABLE: dynamodb
# Creates a DynamoDB resource object using boto3 (AWS library)
# This object provides high-level access to DynamoDB tables
dynamodb = boto3.resource("dynamodb")

# VARIABLE: TABLE_NAME
# Gets the DynamoDB table name from environment variable "JOB_TABLE"
# If the environment variable doesn't exist, defaults to "IngestJobs"
# os.environ.get() is a Python built-in method
TABLE_NAME = os.environ.get("JOB_TABLE", "IngestJobs")

# VARIABLE: table
# Creates a reference to the specific DynamoDB table we'll be working with
# This allows us to perform operations like put_item, get_item, etc.
table = dynamodb.Table(TABLE_NAME)

# ============================================================================
# FUNCTION: generate_job_id
# ============================================================================
def generate_job_id(project_code: str, folder_path: str) -> str:
	"""
	Deterministic job ID.
	Same project + same folder => same job_id
	"""
	# VARIABLE: raw
	# Creates a combined string from project_code and folder_path
	# This string will be used to generate a consistent hash
	# The format is "project_code:folder_path"
	raw = f"{project_code}:{folder_path}"
	
	# Returns a SHA-256 hash of the raw string
	# BREAKDOWN:
	# - raw.encode("utf-8"): Python built-in method that converts string to bytes
	# - hashlib.sha256(): Python hashlib function that creates SHA-256 hash object
	# - .hexdigest(): hashlib method that returns hash as a hexadecimal string
	# This ensures the same input always produces the same job_id (deterministic)
	return hashlib.sha256(raw.encode("utf-8")).hexdigest()

# ============================================================================
# FUNCTION: handler (AWS Lambda entry point)
# ============================================================================
def handler(event, context):
	# PARAMETER: event - AWS Lambda built-in parameter containing trigger data (S3 event)
	# PARAMETER: context - AWS Lambda built-in parameter with runtime information
	
	# ========================================================================
	# STEP 1: Extract S3 information from the event
	# ========================================================================
	
	# VARIABLE: record
	# Extracts the first S3 event record from the event object
	# AWS Lambda passes S3 events in event["Records"] as a list
	record = event["Records"][0]
	
	# VARIABLE: bucket
	# Extracts the S3 bucket name where the file was uploaded
	# Navigates through the event structure to get bucket name
	bucket = record["s3"]["bucket"]["name"]
	
	# VARIABLE: object_key
	# Extracts the S3 object key (file path) of the uploaded file
	# This is the full path to the file within the bucket
	object_key = record["s3"]["object"]["key"]
	
	# ========================================================================
	# STEP 2: Guard clause - only process files ending with "_INGEST_DONE"
	# ========================================================================
	
	# Checks if the uploaded file's name ends with "_INGEST_DONE"
	# object_key.endswith() is a Python built-in string method
	# If the file doesn't match, exit early and ignore this event
	if not object_key.endswith("_INGEST_DONE"):
		# Returns a dictionary indicating the event was ignored
		# This Lambda function only processes "_INGEST_DONE" marker files
		return {"status" : "ignored"}
		
	# ========================================================================
	# STEP 3: Derive the folder path and project code from the object key
	# ========================================================================
	
	# VARIABLE: folder_path
	# Extracts the directory path from the object_key
	# BREAKDOWN:
	# - object_key.rsplit("/", 1): Python built-in method that splits from right
	#   Splits at the last "/" to separate folder from filename
	# - [0]: Takes the folder portion (before the last "/")
	# - + "/": Adds trailing slash to make it a proper folder path
	# Example: "project1/data/file.txt" becomes "project1/data/"
	folder_path = object_key.rsplit("/", 1)[0] + "/"
	
	# VARIABLE: project_code
	# Extracts the project code from the folder path
	# Assumes project code is the first part of the path (before first "/")
	# .split("/") is a Python built-in string method
	# [0] gets the first element
	# Example: "project1/data/" becomes "project1"
	project_code = folder_path.split("/")[0]
	
	# ========================================================================
	# STEP 4: Generate a unique, deterministic job ID
	# ========================================================================
	
	# VARIABLE: job_id
	# Calls the generate_job_id function to create a consistent hash-based ID
	# Same project_code + folder_path will always generate the same job_id
	job_id = generate_job_id(project_code, folder_path)
	
	# ========================================================================
	# STEP 5: Build the job record to store in DynamoDB
	# ========================================================================
	
	# VARIABLE: job_item
	# Creates a dictionary representing a job record with all relevant metadata
	job_item = {
		# The unique identifier for this job (hash-based)
		"job_id": job_id,
		
		# The project this job belongs to
		"project_code": project_code,
		
		# The S3 location of the ingested data folder
		# Format: s3://bucket-name/folder/path/
		"ingest_folder": f"s3://{bucket}/{folder_path}",
		
		# Initial state of the job when first created
		"state": "CREATED",
		
		# What triggered this job (the _INGEST_DONE marker file)
		"trigger": "_INGEST_DONE",
		
		# Timestamp when the job was created
		# BREAKDOWN:
		# - datetime.utcnow(): Python datetime built-in method for current UTC time
		# - .isoformat(): Python datetime method to format as ISO 8601 string
		# - + "Z": Adds UTC timezone indicator
		# Example: "2025-01-23T10:30:45.123456Z"
		"created_at": datetime.utcnow().isoformat() + "Z",
	}
	
	# ========================================================================
	# STEP 6: Write the job record to DynamoDB with conditional check
	# ========================================================================
	
	# try-except: Python built-in error handling structure
	try:
		# Attempts to insert the job item into the DynamoDB table
		# table.put_item(): boto3 (AWS library) method to insert/update items
		table.put_item(
			# Item: The data to store (our job_item dictionary)
			Item=job_item,
			
			# ConditionExpression: AWS DynamoDB conditional write feature
			# "attribute_not_exists(job_id)" ensures we only create NEW jobs
			# If job_id already exists, this will fail (prevents duplicates)
			# This is an atomic operation - prevents race conditions
			ConditionExpression="attribute_not_exists(job_id)",
		)
		
		# If successful, return success status with the job_id
		return {"status": "job_created", "job_id": job_id}
		
	# Catches AWS client errors (boto3 exception type)
	# VARIABLE: e - the exception object containing error details
	except ClientError as e:
		
		# Check if the error is specifically a "ConditionalCheckFailedException"
		# This means the job_id already exists in the table
		# e.response: boto3 exception attribute containing AWS error response
		if e.response ["Error"]["Code"] == "ConditionalCheckFailedException":
			# Job already exists in the database
			# This is not an error - just means the job was already created
			# Return a status indicating the job already exists
			return {"status": "job_already_exists", "job_id": job_id}
		else:
			# Any other AWS error is a real failure
			# Re-raise the exception to be handled by Lambda runtime
			# raise: Python built-in keyword to re-throw an exception
			raise