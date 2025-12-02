import os
import uuid
from typing import Optional, BinaryIO
from minio import Minio
from minio.error import S3Error

class ObjectStore:
    def __init__(self):
        self.endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
        self.access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        self.secure = os.getenv("MINIO_SECURE", "false").lower() == "true"
        self.client: Optional[Minio] = None
        self.bucket_name = "threat-intel-artifacts"
    
    def connect(self):
        """Connect to MinIO"""
        if not self.client:
            self.client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure
            )
            self._ensure_bucket()
    
    def _ensure_bucket(self):
        """Ensure bucket exists"""
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
        except S3Error as e:
            print(f"Bucket creation error: {e}")
    
    def upload_file(self, file_path: str, object_name: str = None) -> Optional[str]:
        """Upload file to object store"""
        self.connect()
        try:
            if not object_name:
                object_name = f"{uuid.uuid4()}_{os.path.basename(file_path)}"
            
            self.client.fput_object(
                self.bucket_name,
                object_name,
                file_path
            )
            return object_name
        except S3Error as e:
            print(f"Upload error: {e}")
            return None
    
    def upload_data(self, data: bytes, object_name: str, content_type: str = "application/octet-stream") -> Optional[str]:
        """Upload binary data to object store"""
        self.connect()
        try:
            self.client.put_object(
                self.bucket_name,
                object_name,
                data,
                len(data),
                content_type=content_type
            )
            return object_name
        except S3Error as e:
            print(f"Upload data error: {e}")
            return None
    
    def download_file(self, object_name: str, file_path: str) -> bool:
        """Download file from object store"""
        self.connect()
        try:
            self.client.fget_object(self.bucket_name, object_name, file_path)
            return True
        except S3Error as e:
            print(f"Download error: {e}")
            return False
    
    def download_data(self, object_name: str) -> Optional[bytes]:
        """Download binary data from object store"""
        self.connect()
        try:
            response = self.client.get_object(self.bucket_name, object_name)
            return response.read()
        except S3Error as e:
            print(f"Download data error: {e}")
            return None
        finally:
            response.close()
            response.release_conn()
    
    def delete_file(self, object_name: str) -> bool:
        """Delete file from object store"""
        self.connect()
        try:
            self.client.remove_object(self.bucket_name, object_name)
            return True
        except S3Error as e:
            print(f"Delete error: {e}")
            return False
    
    def list_files(self, prefix: str = "") -> list:
        """List files in object store"""
        self.connect()
        try:
            objects = self.client.list_objects(self.bucket_name, prefix=prefix, recursive=True)
            return [obj.object_name for obj in objects]
        except S3Error as e:
            print(f"List error: {e}")
            return []
    
    def get_file_info(self, object_name: str) -> Optional[dict]:
        """Get file metadata"""
        self.connect()
        try:
            stat = self.client.stat_object(self.bucket_name, object_name)
            return {
                "size": stat.size,
                "content_type": stat.content_type,
                "last_modified": stat.last_modified,
                "etag": stat.etag
            }
        except S3Error as e:
            print(f"Stat error: {e}")
            return None
    
    def generate_presigned_url(self, object_name: str, expires_seconds: int = 3600) -> Optional[str]:
        """Generate presigned URL for temporary access"""
        self.connect()
        try:
            return self.client.presigned_get_object(
                self.bucket_name,
                object_name,
                expires_seconds
            )
        except S3Error as e:
            print(f"Presigned URL error: {e}")
            return None

# Global object store instance
_object_store: Optional[ObjectStore] = None

def get_object_store() -> ObjectStore:
    """Get global object store instance"""
    global _object_store
    if _object_store is None:
        _object_store = ObjectStore()
        _object_store.connect()
    return _object_store
