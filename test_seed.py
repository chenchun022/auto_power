"""V1.3.2 种子管理员与账号设置测试。

覆盖：
- 空库启动自动创建管理员（环境变量指定 / 自动生成密码打日志）
- 幂等：重启不重复创建
- 改用户名（验证当前密码、撞名 409、格式 422）
- 改密码（验证旧密码、强密码校验、改密后全会话失效）
运行：python test_seed.py
"""
import io
import os
import re
import sys
import tempfile
import warnings
import contextlib
from pathlib import Path

warnings.filterwarnings("ignore")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="ap_seed_"))

# 环境变量种子：指定用户名与密码
os.environ["ADMIN_USERNAME"] = "运维老板"
os.environ["ADMIN_PASSWORD"] = "DeployPass12345"

import authdb as _authdb

_authdb.CONFIG_DIR = TMP
_authdb.DB_PATH = TMP / "app.db"

import main as appmain
import security
from fastapi.testclient import TestClient

appmain.DB_PATH = TMP / "app.db"

client = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
client.__enter__()  # lifespan 触发 init_db + seed_bootstrap_admin

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


print("== 1. 环境变量种子管理员 ==")
r = client.post("/api/auth/login", json={"login": "运维老板", "password": "DeployPass12345"})
check("环境变量种子管理员可登录", r.status_code == 200, r.text[:200])
check("登录会话有效", client.get("/api/auth/me").json().get("username") == "运维老板")

print("== 2. 改用户名 ==")
r = client.put("/api/profile/username", json={"password": "DeployPass12345", "new_username": "老板二号"})
check("改用户名成功", r.status_code == 200 and r.json().get("username") == "老板二号", r.text[:200])
r = client.put("/api/profile/username", json={"password": "错的密码", "new_username": "老板三号"})
check("密码错误拒绝改名 401", r.status_code == 401, r.text[:150])
r = client.put("/api/profile/username", json={"password": "DeployPass12345", "new_username": "x"})
check("格式非法拒绝 422", r.status_code == 422, r.text[:150])
security.login_limiter.reset("老板二号")
r = client.post("/api/auth/login", json={"login": "老板二号", "password": "DeployPass12345"})
check("新用户名可登录", r.status_code == 200, r.text[:150])

print("== 3. 改密码 ==")
r = client.put("/api/profile/password", json={"old_password": "DeployPass12345", "new_password": "weak"})
check("弱密码拒绝 422", r.status_code == 422, r.text[:150])
r = client.put("/api/profile/password", json={"old_password": "错的", "new_password": "NewPass123456"})
check("旧密码错误拒绝 401", r.status_code == 401, r.text[:150])
r = client.put("/api/profile/password", json={"old_password": "DeployPass12345", "new_password": "NewPass123456"})
check("改密码成功且要求重登录", r.status_code == 200 and r.json().get("relocated") is True, r.text[:200])
r = client.get("/api/auth/me")
check("改密后旧会话失效", r.json().get("authenticated") is False, r.text[:150])
r = client.get("/api/projects")
check("改密后旧会话 API 401", r.status_code == 401, r.text[:150])
security.login_limiter.reset("老板二号")
r = client.post("/api/auth/login", json={"login": "老板二号", "password": "NewPass123456"})
check("新密码可登录", r.status_code == 200, r.text[:150])
# 撞名 409：先在库里造第二个用户再试（用种子库直接插入）
with _authdb.get_db() as conn2:
    conn2.execute(
        "INSERT OR IGNORE INTO users (username, email, password_hash, role, created_at) VALUES ('别人', 'other@test.com', 'x', 'user', '2026-01-01')",
    )
r = client.put("/api/profile/username", json={"password": "NewPass123456", "new_username": "别人"})
check("撞名拒绝 409", r.status_code == 409, r.text[:150])

print("== 4. 幂等：库非空时不再创建 ==")
with contextlib.redirect_stdout(io.StringIO()) as buf:
    appmain.seed_bootstrap_admin()
check("重启不重复创建", "已按环境变量创建" not in buf.getvalue() and "首次部署" not in buf.getvalue(), buf.getvalue()[:100])

print("== 5. 未登录访问账号接口 ==")
r2 = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
r = r2.put("/api/profile/password", json={"old_password": "x", "new_password": "NewPass123456"})
check("未登录改密 401", r.status_code == 401, r.text[:150])
r = r2.put("/api/profile/username", json={"password": "x", "new_username": "y"})
check("未登录改名 401", r.status_code == 401, r.text[:150])

print("== 6. 自动生成密码模式（独立进程验证，避免污染本进程 DB 路径） ==")
TMP2 = Path(tempfile.mkdtemp(prefix="ap_seed2_"))
script = f"""
import contextlib, io, os, re, sys
os.environ["ADMIN_USERNAME"] = "auto-admin"
os.environ.pop("ADMIN_PASSWORD", None)
sys.path.insert(0, r"{BASE.as_posix()}")
from pathlib import Path
tmp = Path(r"{TMP2.as_posix()}")
import authdb as a
a.CONFIG_DIR = tmp; a.DB_PATH = tmp / "app.db"
a.init_auth_tables()
import main as m
m.DB_PATH = tmp / "app.db"
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.seed_bootstrap_admin()
log = buf.getvalue()
assert "初始密码" in log and "auto-admin" in log, log
match = re.search(r"初始密码: (\\S+)", log)
assert match and len(match.group(1)) == 16, log
from fastapi.testclient import TestClient
c = TestClient(m.app, headers={{"X-Requested-With": "fetch"}})
c.__enter__()
r = c.post("/api/auth/login", json={{"login": "auto-admin", "password": match.group(1)}})
assert r.status_code == 200, r.text[:150]
assert c.get("/api/auth/me").json().get("username") == "auto-admin"
# 幂等：再跑一次不重复
buf2 = io.StringIO()
with contextlib.redirect_stdout(buf2):
    m.seed_bootstrap_admin()
assert "首次部署" not in buf2.getvalue() and "初始密码" not in buf2.getvalue()
print("SUBPROCESS_OK")
"""
import subprocess

result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, cwd=str(BASE))
check("自动密码子进程全链路", "SUBPROCESS_OK" in result.stdout, (result.stdout + result.stderr)[-300:])

print(f"\n结果: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
