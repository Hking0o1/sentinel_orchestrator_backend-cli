import boto3
from botocore.client import Config
from config.settings import settings
import os

class StorageClient:
    def __init__(self):
        self.s3 = boto3.client(
            "s3",
            endpoint_url=f"http://{settings.MINIO_ENDPOINT}",
            aws_access_key_id=settings.MINIO_ROOT_USER,
            aws_secret_access_key=settings.MINIO_ROOT_PASSWORD,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1" # MinIO default
        )
        self.bucket = settings.MINIO_BUCKET_NAME

    def upload_file(self, file_path: str, object_name: str = None) -> str:
        """Uploads a file to MinIO and returns the download URL."""
        if object_name is None:
            object_name = os.path.basename(file_path)

        try:
            self.s3.upload_file(file_path, self.bucket, object_name)
            # Return a URL accessible to the user
            return f"{settings.MINIO_PUBLIC_ENDPOINT}/{self.bucket}/{object_name}"
        except Exception as e:
            print(f"[Storage] Upload failed: {e}")
            return None

storage = StorageClient()