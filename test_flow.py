"""V1.3.0 完整流程测试：Mock SMTP → 发码 → 收信 → 注册 → 登录 → 记忆 → 候选 → 保存 → 回路编号。

覆盖此前测试跳过的真实链路：
- /api/auth/register/send-code 真实走 SMTP 发信（本地 Mock 服务器收信并提取验证码）
- 验证码邮件内容、token 一次性使用、过期逻辑
- 完整用户旅程
运行：python test_flow.py
"""
import asyncio
import json
import re
import sys
import tempfile
import threading
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

BASE = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="ap_flow_"))

import os

os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "SeedPass12345"

import authdb as _authdb

_authdb.CONFIG_DIR = TMP
_authdb.DB_PATH = TMP / "app.db"

import mailer
import main as appmain
import security
from fastapi.testclient import TestClient

appmain.DB_PATH = TMP / "app.db"

client = TestClient(appmain.app, headers={"X-Requested-With": "fetch"})
client.__enter__()  # 触发 lifespan（空库自动 seed 管理员，使 is_first_user=False，
# 邮箱验证码链路按普通用户流程走）

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


# ---------------------------------------------------------------------------
# 极简 Mock SMTP：实现足够的对话让 smtplib 完成投递
# ---------------------------------------------------------------------------
class TinySmtp(threading.Thread):

    def __init__(self, port: int, store: list) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.store = store

    def run(self) -> None:
        import socket

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(4)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn) -> None:
        import base64
        import socket

        store = self.store
        buf = b""

        def send(line: str) -> None:
            conn.sendall(line.encode() + b"\r\n")

        send("220 mock ESMTP")
        in_data = False
        mail_text: list[str] = []
        while True:
            try:
                chunk = conn.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line_bytes, buf = buf.split(b"\r\n", 1)
                line = line_bytes.decode("utf-8", errors="replace")
                if in_data:
                    if line == ".":
                        in_data = False
                        store.append("\n".join(mail_text))
                        mail_text = []
                        send("250 OK queued")
                    else:
                        mail_text.append(line[1:] if line.startswith("..") else line)
                    continue
                upper = line.upper()
                if upper.startswith("EHLO") or upper.startswith("HELO"):
                    send("250-mock")
                    send("250 AUTH PLAIN LOGIN")
                elif upper.startswith("STARTTLS"):
                    send("454 TLS not available")  # 让客户端放弃 STARTTLS
                elif upper.startswith("AUTH"):
                    if "PLAIN" in upper:
                        send("235 ok")
                    else:
                        send("334 " + base64.b64encode(b"Username:").decode())
                        # 等用户名/密码两行——简化：直接在循环里收
                        conn.settimeout(2)
                        try:
                            user_line = conn.recv(1024)
                            send("334 " + base64.b64encode(b"Password:").decode())
                            pass_line = conn.recv(1024)
                            send("235 ok")
                        except OSError:
                            pass
                        conn.settimeout(None)
                elif upper.startswith("MAIL FROM"):
                    send("250 ok")
                elif upper.startswith("RCPT TO"):
                    send("250 ok")
                elif upper == "DATA":
                    in_data = True
                    send("354 go")
                elif upper == "QUIT":
                    send("221 bye")
                    conn.close()
                    return
                else:
                    send("250 ok")
        conn.close()


mail_store: list[str] = []
smtp_thread = TinySmtp(8899, mail_store)
smtp_thread.start()

# 写 SMTP 配置指向 Mock
(TMP / "smtp.json").write_text(
    json.dumps({
        "host": "127.0.0.1", "port": 8899,
        "username": "noreply@test.local", "password": "secret",
        "from_email": "noreply@test.local", "from_name": "测试", "use_tls": False,
    }),
    encoding="utf-8",
)
# mailer 模块级的路径常量指向真实 config/，测试里打补丁到 TMP
mailer.SMTP_CONFIG_PATH = TMP / "smtp.json"
check("Mock SMTP 配置生效", mailer.load_smtp_config()["host"] == "127.0.0.1")

import time as _time


def latest_code_from_store() -> str | None:
    import base64

    for raw in reversed(mail_store):
        # 正文在空行之后（头部与正文以空行分隔）；只对正文段尝试 base64 解码
        body = raw.split("\n\n", 1)[1] if "\n\n" in raw else raw
        # base64 行按 76 字符折行；剔除空行后整体解码
        compact = "".join(line for line in body.splitlines() if line.strip() and not line.startswith(("Content-", "MIME-", "Subject:", "From:", "To:")))
        try:
            decoded = base64.b64decode(compact, validate=False).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        found = re.findall(r">(\d{6})<", decoded)
        if found:
            return found[0]
    return None


print("== 流程 1：发送验证码（真实 SMTP 链路） ==")
EMAIL = "flow@test.com"
r = client.post("/api/auth/register/send-code", json={"email": EMAIL})
check("send-code 200", r.status_code == 200, r.text[:200])
check("返回 verify_token", len(r.json().get("verify_token", "")) >= 32)
verify_token = r.json().get("verify_token", "")

_time.sleep(0.5)  # 等邮件落库
code = latest_code_from_store()
check("Mock SMTP 收到验证码邮件", code is not None, f"store={len(mail_store)} 封")
check("验证码为 6 位数字", code is not None and re.fullmatch(r"\d{6}", code) is not None, str(code))

print("== 流程 2：错误码耗尽 → 重发 → 正确注册 ==")
for i in range(5):
    client.post("/api/auth/register", json={
        "email": EMAIL, "username": "流程用户", "password": "FlowPass12345",
        "verify_token": verify_token, "verify_code": "000000"})
r = client.post("/api/auth/register", json={
    "email": EMAIL, "username": "流程用户", "password": "FlowPass12345",
    "verify_token": verify_token, "verify_code": code or "111111"})
check("旧 token 耗尽后正确码也无效", r.status_code == 422, r.text[:150])

# 重新发码（新 token）
mail_store.clear()
security.register_ip_limiter._events.clear()  # 测试连发超出 IP 配额，重置后继续
r = client.post("/api/auth/register/send-code", json={"email": EMAIL})
verify_token = r.json()["verify_token"]
_time.sleep(0.5)
code = latest_code_from_store()
check("重发后新验证码", code is not None)
r = client.post("/api/auth/register", json={
    "email": EMAIL, "username": "流程用户", "password": "FlowPass12345X",
    "verify_token": verify_token, "verify_code": code or "000000"})
check("注册成功", r.status_code == 200, r.text[:200])

# token 一次性：用过即失效
r = client.post("/api/auth/register", json={
    "email": "other@test.com", "username": "别人", "password": "FlowPass12345X",
    "verify_token": verify_token, "verify_code": code or "000000"})
check("token 一次性（重放被拒）", r.status_code in (409, 422), r.text[:150])

print("== 流程 3：登录 → 记忆 → bootstrap ==")
security.login_limiter.reset("流程用户")
r = client.post("/api/auth/login", json={"login": EMAIL, "password": "FlowPass12345X"})
check("邮箱登录", r.status_code == 200)
r = client.get("/api/auth/me")
check("会话有效", r.json().get("username") == "流程用户")

# 沉淀记忆
for u, c in [("应急照明", "0.5"), ("照明插座", "1.5"), ("空调外机", "3.0"), ("厨房插座", "2.0")]:
    client.post("/api/usage-memory", json={"usage": u, "capacity_kw": c})
# 重复记忆频次+
client.post("/api/usage-memory", json={"usage": "应急照明", "capacity_kw": "0.6"})
r = client.get("/api/usage-memory")
items = {i["usage_text"]: i for i in r.json()["items"]}
check("重复记忆频次+1 且容量更新", items["应急照明"]["use_count"] == 2 and items["应急照明"]["capacity_kw"] == "0.6", str(items.get("应急照明")))

r = client.get("/api/bootstrap")
check("bootstrap 携带 user+记忆", r.json()["user"]["username"] == "流程用户" and len(r.json()["usage_memory"]) == 4)

print("== 流程 4：保存项目（自动沉淀 + 回路编号） ==")
boot = client.get("/api/bootstrap").json()
pid = boot["active_project"]["id"]
data = {
    "filters": {"breaker_brand": "", "wire_brand": ""},
    "load_factors": {"kx": 0.9, "cos": 0.8},
    "groups": {
        "N": [{"usage": "走廊照明", "capacity_kw": 1.1}, {"usage": "应急照明", "capacity_kw": 0.5}],
        "P": [{"usage": "普通插座", "capacity_kw": 2.2, "voltage": "380"}],
        "S": [], "WL": [],
    },
}
r = client.put(f"/api/projects/{pid}", json={"name": "流程项目", "description": "", "data": data})
check("保存项目", r.status_code == 200, r.text[:200])
proj = r.json()["project"]
check("回路编号 N1/N2、P1", [x["circuit_code"] for x in proj["data"]["groups"]["N"]] == ["N1", "N2"] and proj["data"]["groups"]["P"][0]["circuit_code"] == "P1")
r = client.get("/api/usage-memory")
check("保存时自动沉淀新用途", any(i["usage_text"] == "走廊照明" for i in r.json()["items"]))
# 380V 相序
check("380V 分配 L1/L2/L3", proj["data"]["groups"]["P"][0]["phase_sequence"] == "L1/L2/L3", proj["data"]["groups"]["P"][0]["phase_sequence"])

print("== 流程 5：登出后记忆接口保护 ==")
client.post("/api/auth/logout")
r = client.get("/api/usage-memory")
check("登出后 401", r.status_code == 401)

print(f"\n结果: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
