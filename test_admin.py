"""V1.3.2 管理员与门禁测试：种子管理员、全站拦截、SMTP 管理 API。

管理员由部署时的环境变量种子账号创建（ADMIN_USERNAME/ADMIN_PASSWORD），
不再有"空库首用户免验证码"通道（公网不安全且与种子机制冗余）。
运行：python test_admin.py
"""
import base64
import json
import re
import socket
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

BASE = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="ap_admin_"))

import os

os.environ["ADMIN_USERNAME"] = "首管理员"
os.environ["ADMIN_PASSWORD"] = "AdminPass12345"

import authdb as _authdb

_authdb.CONFIG_DIR = TMP
_authdb.DB_PATH = TMP / "app.db"

import mailer
import main as appmain
import security
from fastapi.testclient import TestClient

appmain.DB_PATH = TMP / "app.db"
mailer.SMTP_CONFIG_PATH = TMP / "smtp.json"

client = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
client.__enter__()  # lifespan：init_db + seed_bootstrap_admin

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} :: {detail}")


print("== 1. 引导状态（种子后） ==")
r = client.get("/api/auth/bootstrap-status")
check("bootstrap-status 200", r.status_code == 200, r.text[:200])
check("first_user_bootstrap 恒为 False（通道已移除）", r.json().get("first_user_bootstrap") is False, r.text)
check("SMTP 未配置", r.json().get("smtp_configured") is False, r.text)

print("== 2. 全站门禁（未登录） ==")
r = client.get("/", follow_redirects=False)
check("首页 302 跳登录", r.status_code == 302 and "/login" in r.headers.get("location", ""), f"{r.status_code} {r.headers.get('location')}")
r = client.get("/api/bootstrap")
check("API 未登录 401", r.status_code == 401, r.text[:150])
r = client.get("/api/projects")
check("项目列表 401", r.status_code == 401, r.text[:150])
r = client.post("/api/rebalance", json={"filters": {}, "load_factors": {}, "groups": {}})
check("重算 401", r.status_code == 401, r.text[:150])
r = client.get("/login")
check("登录页放行", r.status_code == 200)
r = client.get("/register")
check("注册页放行", r.status_code == 200)
r = client.get("/static/tailwind.local.js")
check("静态资源放行", r.status_code == 200)
r = client.get("/api/auth/me")
check("me 白名单放行", r.status_code == 200 and r.json().get("authenticated") is False, r.text[:150])

print("== 3. 种子管理员登录 ==")
r = client.post("/api/auth/login", json={"login": "首管理员", "password": "AdminPass12345"})
check("种子管理员登录", r.status_code == 200, r.text[:200])
r = client.get("/api/auth/me")
check("role=admin", r.json().get("authenticated") is True, r.text[:200])
r = client.get("/")
check("登录后首页放行", r.status_code == 200)

print("== 4. 自助注册必须验证码（免码通道已移除） ==")
security.register_ip_limiter._events.clear()
r = client.post("/api/auth/register/send-code", json={"email": "user2@test.com"})
check("SMTP 未配置发码 503", r.status_code == 503, r.text[:200])
r = client.post("/api/auth/register", json={
    "email": "user2@test.com", "username": "普通用户", "password": "UserPass12345",
    "verify_token": "", "verify_code": "000000",
})
check("空 token 注册被拒", r.status_code == 422, r.text[:200])

print("== 5. SMTP 管理 API 权限 ==")
r2 = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
r = r2.get("/api/admin/smtp")
check("未登录访问 SMTP 配置 401", r.status_code == 401, r.text[:150])
r = r2.put("/api/admin/smtp", json={"host": "x", "port": 1})
check("未登录写 SMTP 配置 401", r.status_code == 401, r.text[:150])

print("== 6. 管理员保存 + 读取 SMTP 配置 ==")
mock_store = []


class TinySmtp(threading.Thread):
    def __init__(self, port, store):
        super().__init__(daemon=True)
        self.port, self.store = port, store

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(4)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._h, args=(conn,), daemon=True).start()

    def _h(self, conn):
        buf = b""
        in_data = False
        mail = []

        def send(l):
            conn.sendall(l.encode() + b"\r\n")

        send("220 mock ESMTP")
        while True:
            try:
                chunk = conn.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                lb, buf = buf.split(b"\r\n", 1)
                line = lb.decode("utf-8", "replace")
                if in_data:
                    if line == ".":
                        in_data = False
                        self.store.append("\n".join(mail))
                        mail = []
                        send("250 OK")
                    else:
                        mail.append(line[1:] if line.startswith("..") else line)
                    continue
                u = line.upper()
                if u.startswith(("EHLO", "HELO")):
                    send("250-mock")
                    send("250 AUTH PLAIN")
                elif u.startswith("STARTTLS"):
                    send("454 no")
                elif u.startswith("AUTH"):
                    send("235 ok")
                elif u == "DATA":
                    in_data = True
                    send("354 go")
                elif u == "QUIT":
                    send("221 bye")
                    conn.close()
                    return
                else:
                    send("250 ok")
        conn.close()


TinySmtp(8898, mock_store).start()

r = client.put("/api/admin/smtp", json={
    "host": "127.0.0.1", "port": 8898, "username": "noreply@test.local",
    "password": "secret", "from_email": "noreply@test.local", "from_name": "测试", "use_tls": False,
})
check("管理员保存 SMTP 配置", r.status_code == 200, r.text[:200])
r = client.get("/api/admin/smtp")
check("读取配置（密码不回传）", r.status_code == 200 and r.json().get("host") == "127.0.0.1"
      and "password" not in r.json() and r.json().get("has_password") is True, r.text[:300])

r = client.put("/api/admin/smtp", json={
    "host": "127.0.0.1", "port": 8898, "username": "noreply@test.local",
    "password": "", "from_email": "noreply@test.local", "from_name": "改名", "use_tls": False,
})
saved = json.loads((TMP / "smtp.json").read_text(encoding="utf-8"))
check("密码留空沿用旧值", r.status_code == 200 and saved.get("password") == "secret", f"{r.text[:100]} pw={saved.get('password')}")

print("== 7. 测试邮件 + 第二用户邮箱验证注册 ==")
r = client.post("/api/admin/smtp/test")
time.sleep(1)
check("测试邮件接口 200", r.status_code == 200, r.text[:200])
check("测试邮件已投递", len(mock_store) >= 1, f"mails={len(mock_store)}")

security.register_ip_limiter._events.clear()
r = client.post("/api/auth/register/send-code", json={"email": "user2@test.com"})
check("配置后发码 200", r.status_code == 200, r.text[:200])
token = r.json().get("verify_token", "")


def latest_code(store):
    for raw in reversed(store):
        body = raw.split("\n\n", 1)[1] if "\n\n" in raw else raw
        compact = "".join(l for l in body.splitlines() if l.strip() and not l.startswith(("Content-", "MIME-", "Subject:", "From:", "To:")))
        try:
            dec = base64.b64decode(compact, validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        m = re.findall(r">(\d{6})<", dec)
        if m:
            return m[0]
    return None


time.sleep(1)
code = latest_code(mock_store)
check("验证码邮件送达", code is not None, f"mails={len(mock_store)}")

security.register_ip_limiter._events.clear()
r = client.post("/api/auth/register", json={
    "email": "user2@test.com", "username": "普通用户", "password": "UserPass12345",
    "verify_token": token, "verify_code": code or "000000",
})
check("第二用户验证码注册成功", r.status_code == 200, r.text[:300])
check("第二用户 role=user", r.json().get("role") == "user", r.text[:200])

with _authdb.get_db() as conn:
    row = conn.execute("SELECT role FROM users WHERE email = 'user2@test.com'").fetchone()
check("库里第二用户 role=user", row and row["role"] == "user", str(row))

print("== 8. 普通用户无权访问 SMTP 管理 ==")
r = client.get("/api/admin/smtp")
check("普通用户访问 SMTP 配置 403", r.status_code == 403, r.text[:150])
r = client.put("/api/admin/smtp", json={"host": "x", "port": 1})
check("普通用户写 SMTP 配置 403", r.status_code == 403, r.text[:150])

print("== 9. 用户管理与注册开关 ==")
# 当前 client 会话 = 普通用户（上一节注册的）。先验证普通用户 403，
# 再切回管理员做管理操作。
r = client.get("/api/admin/users")
check("普通用户访问用户列表 403", r.status_code == 403, r.text[:150])

security.login_limiter.reset("首管理员")
r = client.post("/api/auth/login", json={"login": "首管理员", "password": "AdminPass12345"})
assert r.status_code == 200, f"管理员重登失败: {r.text[:150]}"

# 管理员视角：列表 / 升降级 / 重置密码 / 删除
with _authdb.get_db() as conn:
    conn.execute(
        "INSERT OR IGNORE INTO users (username, email, password_hash, role, created_at) VALUES ('路人甲', 'p1@test.com', 'x', 'user', '2026-01-02')",
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, email, password_hash, role, created_at) VALUES ('路人乙', 'p2@test.com', 'x', 'user', '2026-01-03')",
    )
r = client.get("/api/admin/users")
users = {u["username"]: u for u in r.json().get("items", [])}
check("用户列表含全部用户", set(users) >= {"首管理员", "普通用户", "路人甲", "路人乙"}, str(list(users)))
check("列表含注册信息", all("created_at" in u and "email" in u for u in r.json()["items"]))
admin_id = users["首管理员"]["id"]
p1_id = users["路人甲"]["id"]

# 角色切换
r = client.put(f"/api/admin/users/{p1_id}/role", json={"role": "admin"})
check("升为管理员", r.status_code == 200, r.text[:150])
r = client.put(f"/api/admin/users/{p1_id}/role", json={"role": "user"})
check("降回普通用户", r.status_code == 200, r.text[:150])
r = client.put(f"/api/admin/users/{admin_id}/role", json={"role": "user"})
check("不能改自己角色 400", r.status_code == 400, r.text[:150])

# 重置密码（强密码校验）
r = client.put(f"/api/admin/users/{p1_id}/password", json={"new_password": "weak"})
check("重置弱密码被拒 422", r.status_code == 422, r.text[:150])
r = client.put(f"/api/admin/users/{p1_id}/password", json={"new_password": "ResetPass12345"})
check("重置密码成功", r.status_code == 200, r.text[:150])
r = client.put(f"/api/admin/users/{admin_id}/password", json={"new_password": "Whatever12345"})
check("不能重置自己密码 400", r.status_code == 400, r.text[:150])

# 重置后新密码可登录
security.login_limiter.reset("路人甲")
r = client.post("/api/auth/login", json={"login": "路人甲", "password": "ResetPass12345"})
check("重置后新密码可登录", r.status_code == 200, r.text[:150])

# 切回管理员做删除
security.login_limiter.reset("首管理员")
r = client.post("/api/auth/login", json={"login": "首管理员", "password": "AdminPass12345"})
assert r.status_code == 200, r.text[:150]
r = client.delete(f"/api/admin/users/{admin_id}")
check("不能删除自己 400", r.status_code == 400, r.text[:150])
r = client.delete(f"/api/admin/users/{p1_id}")
check("删除普通用户", r.status_code == 200, r.text[:150])
with _authdb.get_db() as conn:
    gone = conn.execute("SELECT 1 FROM users WHERE id = ?", (p1_id,)).fetchone() is None
    mem_gone = conn.execute("SELECT 1 FROM usage_memory WHERE user_id = ?", (p1_id,)).fetchone() is None
check("删除后用户与记忆级联清除", gone and mem_gone)

print("== 10. 注册开关 ==")
r = client.get("/api/admin/settings")
check("默认注册开放", r.json().get("registration_open") is True, r.text)
r = client.get("/api/auth/bootstrap-status")
check("状态接口默认开放", r.json().get("registration_open") is True, r.text)

r = client.put("/api/admin/settings/registration", json={"open": False})
check("关闭注册", r.status_code == 200 and r.json().get("registration_open") is False, r.text[:150])
r = client.get("/api/auth/bootstrap-status")
check("状态接口反映关闭", r.json().get("registration_open") is False, r.text)
security.register_ip_limiter._events.clear()
r = client.post("/api/auth/register/send-code", json={"email": "blocked@test.com"})
check("关闭后发码 403", r.status_code == 403 and "关闭" in r.json()["detail"], r.text[:150])
r = client.post("/api/auth/register", json={
    "email": "blocked@test.com", "username": "被拒用户", "password": "UserPass12345",
    "verify_token": "x" * 32, "verify_code": "123456",
})
check("关闭后注册 403", r.status_code == 403, r.text[:150])

r = client.put("/api/admin/settings/registration", json={"open": True})
check("重新开放注册", r.status_code == 200 and r.json().get("registration_open") is True, r.text[:150])

# 普通用户切开关 403
security.login_limiter.reset("普通用户")
r = client.post("/api/auth/login", json={"login": "普通用户", "password": "UserPass12345"})
assert r.status_code == 200, r.text[:150]
r = client.put("/api/admin/settings/registration", json={"open": False})
check("普通用户切开关 403", r.status_code == 403, r.text[:150])

print(f"\n结果: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
