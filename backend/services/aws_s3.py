import boto3
import os

def s3_client():
    # boto3 automatically reads AWS env vars or ~/.aws/credentials
    region = os.environ.get("AWS_REGION", "us-east-1")
    return boto3.client("s3", region_name=region)

def upload_file_to_s3(local_path, bucket_name, object_name):
    s3 = s3_client()
    try:
        s3.upload_file(local_path, bucket_name, object_name)
    except Exception as e:
        return {"error": str(e)}
    return f"s3://{bucket_name}/{object_name}"
