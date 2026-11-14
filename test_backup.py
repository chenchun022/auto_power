"""V1.3.3 R2/S3 备份功能测试：mock S3 全链路。

覆盖（对齐 CTA caa-v2 backup 语义）：
- 存储配置读写（SecretKey 掩码：不回传、留空沿用）
- 测试连接（bucket 存在性）
- 手动备份：VACUUM INTO 快照 + config 打包 → 上传 → 记录 completed
- 记录列表/轮询状态
- 恢复：下载 → SQLite 头校验 → 原子替换（留 .bak）→ config 还原
- 删除记录（含远端对象）
- 双重保留策略（retain_count/retain_days）
- 定时配置校验（cron 无效 422）
- 权限：未登录 401 / 普通用户 403
运行：python test_backup.py
"""
import io
import json
import re
import sqlite3
import sys
import tempfile
import threading
import time
import warnings
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="ap_bk_"))

import os

os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "AdminPass12345"

import authdb as _authdb

_authdb.CONFIG_DIR = TMP
_authdb.DB_PATH = TMP / "app.db"

import backup as _backup
import main as appmain
import security
from fastapi.testclient import TestClient

appmain.DB_PATH = TMP / "app.db"

# r2backup 默认 read_timeout=60s；测试用本地 mock 不受影响
client = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
client.__enter__()

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} :: {detail}")


# ---------------------------------------------------------------------------
# Mock S3：实现 boto3 用到的最小面（PUT/GET/DELETE/LIST + HEAD bucket）
# 内存对象存储：{key: bytes}
# ---------------------------------------------------------------------------
OBJECTS: dict[str, bytes] = {}
BUCKETS = {"test-bucket": True}


class MockS3Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静默
        pass

    def _send(self, code, body=b"", content_type="application/xml", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if parts and parts[0] in BUCKETS and len(parts) == 1:
            self._send(200)
        elif parts and parts[0] in BUCKETS and "/".join(parts[1:]) in OBJECTS:
            # Content-Length 由 _send 统一设置，勿重复（重复会导致 boto3 报 conflicting headers）
            self._send(200)
        else:
            self._send(404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2 or parts[0] not in BUCKETS:
            self._send(404)
            return
        key = "/".join(parts[1:])
        length = int(self.headers.get("Content-Length", 0))
        OBJECTS[key] = self.rfile.read(length)
        self._send(200)

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 1 and parts[0] in BUCKETS and "list-type=2" in (parsed.query or ""):
            prefix = ""
            if "prefix" in (parsed.query or ""):
                qs = parse_qs(parsed.query)
                prefix = qs.get("prefix", [""])[0]
            items = sorted(k for k in OBJECTS if k.startswith(prefix))
            body_rows = "".join(
                f"<Contents><Key>{k}</Key><Size>{len(v)}</Size><LastModified>2026-01-01T00:00:00Z</LastModified></Contents>"
                for k, v in ((k, OBJECTS[k]) for k in items)
            )
            xml = f'<?xml version="1.0"?><ListBucketResult>{body_rows}</ListBucketResult>'.encode()
            self._send(200, xml)
        elif len(parts) >= 2 and parts[0] in BUCKETS:
            key = "/".join(parts[1:])
            if key in OBJECTS:
                self._send(200, OBJECTS[key], content_type="application/octet-stream")
            else:
                self._send(404)
        else:
            self._send(404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2 and parts[0] in BUCKETS:
            OBJECTS.pop("/".join(parts[1:]), None)
            self._send(204)
        else:
            self._send(404)


server = ThreadingHTTPServer(("127.0.0.1", 0), MockS3Handler)
S3_PORT = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

print(f"== 0. 前置：登录管理员 ==")
r = client.post("/api/auth/login", json={"login": "admin", "password": "AdminPass12345"})
assert r.status_code == 200, r.text[:200]

print("== 1. 存储配置：读写掩码语义 ==")
r = client.get("/api/admin/backup/s3-config")
check("初始未配置", r.status_code == 200 and r.json().get("configured") is False, r.text[:150])

cfg_payload = {
    "endpoint": f"http://127.0.0.1:{S3_PORT}", "account_id": "", "region": "",
    "bucket": "test-bucket", "access_key": "AKIA-TEST", "secret_key": "SK-TEST-SECRET",
    "prefix": "backups/test", "force_path_style": True,
}
r = client.put("/api/admin/backup/s3-config", json=cfg_payload)
check("保存配置 200", r.status_code == 200, r.text[:200])
check("响应不回传 secret_key", r.json().get("secret_key", "x") == "", r.text[:200])
r = client.get("/api/admin/backup/s3-config")
check("读取也不回传 secret_key", r.json().get("secret_key", "x") == "" and r.json().get("bucket") == "test-bucket", r.text[:200])

# 留空沿用旧密钥
cfg2 = dict(cfg_payload)
cfg2["secret_key"] = ""
cfg2["prefix"] = "backups/v2"
r = client.put("/api/admin/backup/s3-config", json=cfg2)
saved_cfg = json.loads((_authdb.get_setting("backup_s3_config")))
check("留空保存沿用旧密钥", saved_cfg.get("secret_key") == "SK-TEST-SECRET" and saved_cfg.get("prefix") == "backups/v2",
      str({k: v for k, v in saved_cfg.items() if k != "secret_key"}))

print("== 2. 测试连接 ==")
r = client.post("/api/admin/backup/s3-config/test", json=cfg_payload)
check("测试连接成功", r.status_code == 200 and "成功" in r.json().get("message", ""), r.text[:200])
bad = dict(cfg_payload)
bad["bucket"] = "not-exist-bucket"
r = client.post("/api/admin/backup/s3-config/test", json=bad)
check("不存在的桶测试失败", r.status_code == 502, r.text[:200])

print("== 3. 手动备份全链路 ==")
# 先造一点数据：加一个用户、写 smtp.json
(TMP / "smtp.json").write_text('{"host":"smtp.test","port":465}', encoding="utf-8")
r = client.post("/api/admin/backup/records")
check("启动备份 202", r.status_code == 202 and r.json()["record"]["status"] == "running", r.text[:300])
record_id = r.json()["record"]["id"]

# 轮询到 completed
deadline = time.time() + 30
final = None
while time.time() < deadline:
    r = client.get(f"/api/admin/backup/records/{record_id}")
    final = r.json()
    if final["status"] != "running":
        break
    time.sleep(0.5)
check("备份完成", final and final["status"] == "completed", str(final)[:300])
check("记录含大小", final and final["size_bytes"] > 0, str(final)[:200])
check("s3_key 带日期前缀", final and re.match(r"backups/v2/\d{4}/\d{2}/\d{2}/autopower_\d{8}_\d{6}\.tar\.gz", final["s3_key"]), final.get("s3_key", ""))
check("对象已上传到 mock", final["s3_key"] in OBJECTS, str(list(OBJECTS)[:3]))
check("上传的是 gzip", OBJECTS.get(final["s3_key"], b"")[:2] == b"\x1f\x8b")

print("== 4. 恢复（改库 → 恢复 → 校验还原） ==")
# 破坏：删掉 admin 之外再插一个用户，模拟数据漂移
with _authdb.get_db() as conn:
    conn.execute("DELETE FROM users WHERE username != 'admin'")
    conn.execute("INSERT INTO users (username, email, password_hash, role, created_at) VALUES ('漂移用户', 'drift@test.com', 'x', 'user', '2026-01-01')")
(TMP / "smtp.json").unlink()

r = client.post(f"/api/admin/backup/records/{record_id}/restore")
check("启动恢复 202", r.status_code == 202, r.text[:200])
deadline = time.time() + 30
while time.time() < deadline:
    rec = client.get(f"/api/admin/backup/records/{record_id}").json()
    if rec.get("restore_status") not in ("running", ""):
        break
    time.sleep(0.5)
check("恢复完成", rec.get("restore_status") == "completed",
      f"status={rec.get('restore_status')} err={rec.get('restore_error', '')[:300]}")

# 校验：漂移用户消失（回到备份时点）、smtp.json 还原
import importlib

conn = sqlite3.connect(TMP / "app.db")
try:
    users_now = [row[0] for row in conn.execute("SELECT username FROM users").fetchall()]
finally:
    conn.close()
check("数据库回滚到备份点（漂移用户消失）", "漂移用户" not in users_now, str(users_now))
check("smtp.json 已还原", (TMP / "smtp.json").exists() and "smtp.test" in (TMP / "smtp.json").read_text(encoding="utf-8"))
baks = list(TMP.glob("app.db.bak-*"))
check("留有 .bak 后悔药", len(baks) == 1, str(baks))

print("== 5. 下载链接 ==")
r = client.get(f"/api/admin/backup/records/{record_id}/download-url")
check("生成预签名 URL", r.status_code == 200 and "url" in r.json(), r.text[:200])

print("== 6. 双重保留策略 ==")
# 再做 2 次备份（共 3 份），retain_count=2 → 最老的被清
for _ in range(2):
    security.api_ip_limiter._events.clear()
    client.post("/api/admin/backup/records")
    deadline = time.time() + 30
    while time.time() < deadline:
        recs = client.get("/api/admin/backup/records").json()["items"]
        if all(x["status"] != "running" for x in recs):
            break
        time.sleep(0.5)
r = client.put("/api/admin/backup/schedule", json={"enabled": False, "cron_expr": "", "retain_days": 0, "retain_count": 2})
check("保存保留份数=2", r.status_code == 200, r.text[:200])

_backup.get_service().cleanup_old_backups()
recs = client.get("/api/admin/backup/records").json()["items"]
completed = [x for x in recs if x["status"] == "completed"]
check("只保留 2 份", len(completed) == 2, f"剩 {len(completed)} 份")
# 远端对象同步清理：mock 里 completed 的 key 都在，被清的不在
for x in completed:
    check(f"保留对象在远端: {x['file_name'][:30]}", x["s3_key"] in OBJECTS)

print("== 7. 删除记录（含远端对象） ==")
victim = completed[0]
r = client.post(f"/api/admin/backup/records/{victim['id']}/delete")
check("删除 200", r.status_code == 200, r.text[:200])
check("远端对象已删", victim["s3_key"] not in OBJECTS)
check("记录已删", client.get(f"/api/admin/backup/records/{victim['id']}").status_code == 404)

print("== 8. 定时配置校验 ==")
r = client.put("/api/admin/backup/schedule", json={"enabled": True, "cron_expr": "", "retain_days": 30, "retain_count": 0})
check("启用但空 cron 拒绝 422", r.status_code == 422, r.text[:150])
r = client.put("/api/admin/backup/schedule", json={"enabled": True, "cron_expr": "bad-expr", "retain_days": 30, "retain_count": 0})
check("无效 cron 拒绝 422", r.status_code == 422, r.text[:150])
r = client.put("/api/admin/backup/schedule", json={"enabled": True, "cron_expr": "0 3 * * *", "retain_days": 30, "retain_count": 0})
check("合法 cron 保存", r.status_code == 200, r.text[:200])
r = client.get("/api/admin/backup/schedule")
check("定时配置可读回", r.json().get("enabled") is True and r.json().get("cron_expr") == "0 3 * * *", r.text[:150])

print("== 9. 未配置/权限 ==")
# 清掉配置后备份应被拒
saved = _authdb.get_setting("backup_s3_config")
_authdb.set_setting("backup_s3_config", "")
r = client.post("/api/admin/backup/records")
check("未配置时备份 400", r.status_code == 400 and "未配置" in r.json()["detail"], r.text[:200])
_authdb.set_setting("backup_s3_config", saved)

r2 = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
r = r2.get("/api/admin/backup/records")
check("未登录 401", r.status_code == 401, r.text[:150])

# 普通用户 403
with _authdb.get_db() as conn3:
    conn3.execute("INSERT INTO users (username, email, password_hash, role, created_at) VALUES ('普通甲', 'u@test.com', 'x', 'user', '2026-01-01')")
r = client.post("/api/auth/login", json={"login": "普通甲", "password": "whatever12345"})
# 密码是 'x' 的哈希——直接造一个真实用户更快
from security import hash_password

with _authdb.get_db() as conn3:
    conn3.execute("UPDATE users SET password_hash = ? WHERE username = '普通甲'", (hash_password("UserPass12345"),))
security.login_limiter.reset("普通甲")
r = client.post("/api/auth/login", json={"login": "普通甲", "password": "UserPass12345"})
assert r.status_code == 200, r.text[:150]
r = client.get("/api/admin/backup/records")
check("普通用户 403", r.status_code == 403, r.text[:150])

print("== 10. 中断记录恢复（启动钩子） ==")
svc = _backup.get_service()
svc.load_records().append({"id": "stale", "status": "running", "progress": "dumping", "started_at": 1})
svc.save_records([{"id": "stale", "status": "running", "progress": "dumping", "started_at": 1}])
svc.recover_stale_records()
records = svc.load_records()
stale = next((x for x in records if x["id"] == "stale"), {})
check("running 记录标记 failed", stale.get("status") == "failed" and "重启" in stale.get("error_message", ""), str(stale)[:200])

print(f"\n结果: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
