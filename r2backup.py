"""S3 兼容对象存储备份客户端（Cloudflare R2 / MinIO）。

移植自 CTA 项目 caa-v2/server/internal/caa/security/r2backup/client.go：
- endpoint 由 AccountID 推导（https://{id}.r2.cloudflarestorage.com）或自定义（MinIO）
- Test / PutFile / PutBytes / List / GetToFile / Get / Remove / PresignURL
- SecretKey 掩码语义：读取配置不回传，保存时等于掩码则保持原值
"""
from __future__ import annotations

import urllib.parse
from typing import Any

import boto3
from botocore.client import Config as BotoConfig

R2_REGION = "auto"
SECRET_MASK = "********"


class NotConfiguredError(RuntimeError):
    pass


def resolve_endpoint(cfg: dict[str, Any]) -> str:
    """自定义端点优先，否则由 AccountID 推导 R2 端点。"""
    endpoint = str(cfg.get("endpoint", "") or "").strip()
    if endpoint:
        return endpoint
    account_id = str(cfg.get("account_id", "") or "").strip()
    if not account_id:
        raise NotConfiguredError("R2 备份未配置：请先填写 Account ID / Access Key / Secret Key / Bucket")
    return f"https://{account_id}.r2.cloudflarestorage.com"


def build_client(cfg: dict[str, Any]) -> tuple[Any, str]:
    """返回 (boto3 client, bucket)。cfg 需含 endpoint/ak/sk/bucket/region/force_path_style。"""
    endpoint = resolve_endpoint(cfg)
    access_key = str(cfg.get("access_key", "") or "").strip()
    secret_key = str(cfg.get("secret_key", "") or "").strip()
    bucket = str(cfg.get("bucket", "") or "").strip()
    if not (access_key and secret_key and bucket):
        raise NotConfiguredError("R2 备份未配置：请先填写 Account ID / Access Key / Secret Key / Bucket")
    if secret_key == SECRET_MASK:
        raise ValueError("R2 Secret Key 是掩码值；请重新保存真实密钥")

    parsed = urllib.parse.urlparse(endpoint)
    if not parsed.netloc:
        raise ValueError(f"R2 endpoint 无法解析: {endpoint}")
    region = str(cfg.get("region", "") or "").strip() or R2_REGION

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
        config=BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": "path" if cfg.get("force_path_style") else "auto"},
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 2},
        ),
    )
    return client, bucket


class R2BackupClient:
    """薄封装：对齐 Go 版 r2backup.Client 的方法面。"""

    def __init__(self, cfg: dict[str, Any]) -> None:
        self._client, self.bucket = build_client(cfg)

    def test(self) -> None:
        """连通性检查：head_bucket。"""
        self._client.head_bucket(Bucket=self.bucket)

    def put_file(self, key: str, path: str) -> None:
        self._client.upload_file(path, self.bucket, key,
                                 ExtraArgs={"ContentType": "application/octet-stream"})

    def put_bytes(self, key: str, body: bytes, content_type: str = "application/octet-stream") -> None:
        self._client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType=content_type)

    def list(self, prefix: str) -> list[dict[str, Any]]:
        """按前缀列出对象（key 升序）。"""
        objects: list[dict[str, Any]] = []
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                objects.append({
                    "key": obj["Key"],
                    "size": int(obj["Size"]),
                    "last_modified": obj["LastModified"],
                })
        objects.sort(key=lambda o: o["key"])
        return objects

    def get_to_file(self, key: str, path: str) -> None:
        self._client.download_file(self.bucket, key, path)

    def get_bytes(self, key: str) -> bytes:
        resp = self._client.get_object(Bucket=self.bucket, Key=key)
        return resp["Body"].read()

    def remove(self, key: str) -> None:
        self._client.delete_object(Bucket=self.bucket, Key=key)

    def remove_prefix(self, prefix: str) -> None:
        for obj in self.list(prefix):
            self.remove(obj["key"])

    def presign_url(self, key: str, expires_seconds: int = 3600) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires_seconds,
        )
