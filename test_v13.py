"""V1.3.0 集成测试：回路编号修复、注册登录安全链路、用途记忆、限流。

运行：python -I test_v13.py
（-I 隔离模式，不受当前目录植入模块影响）
"""
import json
import re
import sqlite3
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

BASE = Path(__file__).resolve().parent
# 测试用独立 DB：重定向 config 目录到临时目录，避免污染真实数据
TMP = Path(tempfile.mkdtemp(prefix="ap_test_"))
(BASE / "security.py").exists() or sys.exit("security.py missing")

import os

os.environ["AP_TEST_CONFIG_DIR"] = str(TMP)
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "SeedPass12345"

# 在导入 main 前重写 config 路径：main/authdb 都用 BASE/config，测试里直接打补丁
import authdb as _authdb

_authdb.CONFIG_DIR = TMP
_authdb.DB_PATH = TMP / "app.db"

import main as appmain
import security
from fastapi.testclient import TestClient

appmain.DB_PATH = TMP / "app.db"
# get_db 在 main 里闭包引用模块级 DB_PATH
security.TESTING = True

with appmain.get_db() as conn:
    pass  # 预热连接（建目录），真正的建表在 lifespan 的 init_db

client = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
# TestClient 需要用 with 语句触发 lifespan（init_db 建表在这里执行）
_client_ctx = client.__enter__()

# V1.3.2：管理员由种子账号创建（空库自动 seed），登录获得会话供后续业务接口使用
r = client.post("/api/auth/login", json={"login": "admin", "password": "SeedPass12345"})
assert r.status_code == 200, f"前置登录失败（首次运行请设置环境变量）: {r.text[:200]}"

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


print("== 1. 回路编号修复 ==")
# bootstrap
r = client.get("/api/bootstrap")
check("bootstrap 200", r.status_code == 200, r.text[:200])
active = r.json()["active_project"]
pid = active["id"]

# 新建项目：插入 3 行（模拟前端新行 sequence 从 0 的历史形态已不可能，但仍验证后端）
rows_n = [{"usage": "照明1", "capacity_kw": 1.5}, {"usage": "照明2", "capacity_kw": 2.5}, {"usage": "插座", "capacity_kw": 3}]
data = {
    "filters": {"breaker_brand": "", "wire_brand": ""},
    "load_factors": {"kx": 1, "cos": 0.8},
    "groups": {"N": rows_n, "P": [], "S": [], "WL": []},
}
r = client.put(f"/api/projects/{pid}", json={"name": "编号测试", "description": "", "data": data})
check("update project 200", r.status_code == 200, r.text[:300])
codes = [row["circuit_code"] for row in r.json()["project"]["data"]["groups"]["N"]]
seqs = [row["sequence"] for row in r.json()["project"]["data"]["groups"]["N"]]
check("回路编号 N1/N2/N3", codes == ["N1", "N2", "N3"], str(codes))
check("序号 1/2/3", seqs == [1, 2, 3], str(seqs))

# 恶意传入 sequence=0 / circuit_code 空：后端仍按位置重生成
rows_bad = [{"sequence": 0, "circuit_code": "", "usage": "a"}, {"sequence": 0, "circuit_code": "", "usage": "b"}]
data["groups"]["N"] = rows_bad
r = client.post("/api/rebalance", json=data)
codes = [row["circuit_code"] for row in r.json()["data"]["groups"]["N"]]
check("畸形 sequence=0 仍生成 N1/N2", codes == ["N1", "N2"], str(codes))

print("== 2. 注册登录安全链路 ==")
security.register_ip_limiter._events.clear()  # 前置注册已消耗配额，重置后再测
# SMTP 未配置：发码应 503
r = client.post("/api/auth/register/send-code", json={"email": "user@test.com"})
check("SMTP 未配置返回 503", r.status_code == 503, r.text[:200])

# 注入测试：邮箱/用户名带 SQL 注入载荷
r = client.post("/api/auth/register", json={
    "email": "a@b.com' OR '1'='1", "username": "admin'--", "password": "Abcdef12345",
    "verify_token": "x" * 32, "verify_code": "123456",
})
check("SQL 注入载荷被格式校验拒绝", r.status_code == 422, r.text[:200])

# 弱密码拒绝
r = client.post("/api/auth/register", json={
    "email": "weak@test.com", "username": "weakuser", "password": "abc123",
    "verify_token": "x" * 32, "verify_code": "123456",
})
check("弱密码被拒绝", r.status_code == 422 and "密码" in r.json()["detail"], r.text[:200])

# ---- 走真实注册流（mock SMTP：直接调用 authdb 生成验证码）----
EMAIL = "chen@test.com"
verification = _authdb.create_register_verification(EMAIL)
CODE = verification["code"]
TOKEN = verification["token"]
check("验证码为6位数字", re.fullmatch(r"\d{6}", CODE) is not None, CODE)

# 错误验证码 5 次后作废
r1 = client.post("/api/auth/register", json={
    "email": EMAIL, "username": "陈工", "password": "Abcdef12345",
    "verify_token": TOKEN, "verify_code": "000000",
})
check("错误验证码被拒", r1.status_code == 422, r1.text[:200])
for _ in range(4):
    client.post("/api/auth/register", json={
        "email": EMAIL, "username": "陈工", "password": "Abcdef12345",
        "verify_token": TOKEN, "verify_code": "000000",
    })
r2 = client.post("/api/auth/register", json={
    "email": EMAIL, "username": "陈工", "password": "Abcdef12345",
    "verify_token": TOKEN, "verify_code": CODE,  # 正确码但已作废
})
check("验证码错误5次后作废（licenserver 语义）", r2.status_code == 422, r2.text[:200])

# 重新发码后正确注册
verification = _authdb.create_register_verification(EMAIL)
r = client.post("/api/auth/register", json={
    "email": EMAIL, "username": "陈工", "password": "Abcdef12345X",
    "verify_token": verification["token"], "verify_code": verification["code"],
})
check("注册成功", r.status_code == 200, r.text[:300])
check("注册响应含 session cookie", "ap_session" in r.cookies or "__Host-ap_session" in r.cookies, str(dict(r.cookies)))

# 数据库中密码是 bcrypt 哈希（防泄露）
with _authdb.get_db() as conn:
    row = conn.execute("SELECT password_hash FROM users WHERE email = ?", (EMAIL,)).fetchone()
check("密码 bcrypt 哈希存储", row and row["password_hash"].startswith("$2b$"), str(row["password_hash"][:10]) if row else "none")
check("bcrypt cost=12", row and row["password_hash"].startswith("$2b$12$"), row["password_hash"][:10])

# 重复注册
security.register_ip_limiter.sweep()
security.register_ip_limiter._events.clear()  # 测试连发超出限额，重置后再验证
verification = _authdb.create_register_verification(EMAIL)
r = client.post("/api/auth/register", json={
    "email": EMAIL, "username": "别人", "password": "Abcdef12345X",
    "verify_token": verification["token"], "verify_code": verification["code"],
})
check("重复邮箱注册被拒 409", r.status_code == 409, r.text[:200])

# ---- 登录：用户名 / 邮箱均可 ----
r = client.post("/api/auth/login", json={"login": "陈工", "password": "Abcdef12345X"})
check("用户名登录", r.status_code == 200, r.text[:200])
r = client.post("/api/auth/login", json={"login": EMAIL, "password": "Abcdef12345X"})
check("邮箱登录", r.status_code == 200, r.text[:200])

# 错误密码 5 次 → 锁定
for i in range(5):
    client.post("/api/auth/login", json={"login": "陈工", "password": "Wrong" + str(i)})
r = client.post("/api/auth/login", json={"login": "陈工", "password": "Abcdef12345X"})
check("5次失败后账号锁定（防爆破）", r.status_code == 429 and "锁定" in r.json()["detail"], r.text[:200])

# 重置后正常
security.login_limiter.reset("陈工")
r = client.post("/api/auth/login", json={"login": "陈工", "password": "Abcdef12345X"})
check("解锁后可正常登录", r.status_code == 200, r.text[:200])
SESSION = r.cookies.get("ap_session") or r.cookies.get("__Host-ap_session")

# /api/auth/me
r = client.get("/api/auth/me")
check("me 返回已登录", r.json().get("authenticated") is True and r.json().get("username") == "陈工", r.text[:200])

print("== 3. 用途记忆 ==")
r = client.post("/api/usage-memory", json={"usage": "应急照明", "capacity_kw": "0.5"})
check("记忆用途", r.status_code == 200, r.text[:200])
for text, cap in [("照明插座", "1.5"), ("空调外机", "3.0"), ("厨房插座", "2.0")]:
    client.post("/api/usage-memory", json={"usage": text, "capacity_kw": cap})
r = client.get("/api/usage-memory")
items = {item["usage_text"]: item for item in r.json()["items"]}
check("记忆列表返回", set(items) >= {"应急照明", "照明插座"}, str(list(items)))

# 未登录不可用（V1.3.1 起未登录 GET 也被门禁拦截，同样 401）
r2 = TestClient(appmain.app).get("/api/usage-memory")
check("未登录记忆接口 401", r2.status_code == 401, r2.text[:200])

# 保存项目时自动沉淀用途
data["groups"]["N"] = [{"usage": "自动沉淀用途", "capacity_kw": 1.2}]
client.put(f"/api/projects/{pid}", json={"name": "编号测试", "description": "", "data": data}, cookies={"ap_session": SESSION} if SESSION else {})
r = client.get("/api/usage-memory")
check("保存项目自动沉淀用途", any(i["usage_text"] == "自动沉淀用途" for i in r.json()["items"]), r.text[:300])

print("== 4. 会话与登出 ==")
r = client.post("/api/auth/logout")
check("登出", r.status_code == 200)
r = client.get("/api/auth/me")
check("登出后未登录", r.json().get("authenticated") is False)
# 重新登录，供第 5 节继续使用
r = client.post("/api/auth/login", json={"login": "陈工", "password": "Abcdef12345X"})
check("重新登录", r.status_code == 200, r.text[:150])

print("== 5. 接口校验 ==")
# 项目名超长（登出前会话仍有效）
r = client.post("/api/projects", json={"name": "x" * 200, "description": "", "data": data})
check("项目名超长被拒 422", r.status_code == 422, r.text[:200])
# 配置分类不存在
r = client.post("/api/configs/not_exist", json={"label": "x"})
check("非法配置分类 404", r.status_code == 404, r.text[:200])
# CSRF 防护：写接口缺自定义头直接 403（跨站表单无法携带自定义头）
r = TestClient(appmain.app).post("/api/auth/login", json={"login": "x", "password": "y"})
check("缺 CSRF 头的写请求被拒 403", r.status_code == 403, r.text[:150])
# 登出后受保护接口 401（V1.3.1 全站门禁）
client.post("/api/auth/logout")
r = client.get("/api/projects")
check("登出后项目接口 401", r.status_code == 401, r.text[:150])

print(f"\n结果: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
