"""安全基础设施：密码哈希、会话管理、登录限流、注册验证码。

设计对齐 D:\\python_tool\\licenserver 的注册逻辑：
- 验证码：6 位数字 + 24h 过期 + 5 次尝试上限 + bcrypt(cost=12) 存储 codeHash
- token：secrets.token_hex(32)，仅存 sha256(token) 哈希
- 密码：bcrypt cost=12
"""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import bcrypt

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"

BCRYPT_ROUNDS = 12
VERIFY_CODE_TTL_MINUTES = 24 * 60          # 验证码 24 小时有效（与 licenserver 一致）
VERIFY_CODE_MAX_ATTEMPTS = 5               # 验证码错误 5 次作废（与 licenserver 一致）
LOGIN_FAIL_WINDOW_SECONDS = 15 * 60        # 登录失败统计窗口 15 分钟
LOGIN_MAX_FAILS = 5                        # 窗口内 5 次失败后锁定
LOGIN_LOCK_SECONDS = 15 * 60               # 锁定 15 分钟
SESSION_TTL_HOURS = 7 * 24                 # 会话有效期 7 天

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fa5]{2,32}$")

# 强密码：>=10 位，必须含大写、小写、数字，允许特殊字符（与 licenserver 校验规则对齐并加长度）
STRONG_PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{10,128}$")


def validate_password_strength(password: str) -> str | None:
    """返回错误信息；合格返回 None。"""
    if not isinstance(password, str) or not STRONG_PASSWORD_RE.match(password):
        return "密码至少 10 位，且必须同时包含大写字母、小写字母和数字"
    return None


def validate_email(email: str) -> str | None:
    if not isinstance(email, str) or not EMAIL_RE.match(email) or len(email) > 254:
        return "邮箱格式不正确"
    return None


def validate_username(username: str) -> str | None:
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        return "用户名 2-32 位，仅限中英文、数字、下划线"
    return None


# ---------------------------------------------------------------------------
# 哈希工具
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def new_verify_token() -> str:
    return secrets.token_hex(32)


def new_verify_code() -> str:
    # 与 licenserver randomInt(100000, 1000000) 等价：6 位数字
    return str(secrets.randbelow(900000) + 100000)


def now_ts() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# 登录限流：内存滑动窗口 + 账号锁定（防密码爆破）
# 进程内实现已满足单实例部署；多实例部署时换 Redis 即可，接口不变。
# ---------------------------------------------------------------------------
class LoginRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def _key(self, identifier: str) -> str:
        return identifier.strip().lower()

    def is_locked(self, identifier: str) -> tuple[bool, int]:
        """返回 (是否锁定, 剩余秒数)。"""
        key = self._key(identifier)
        with self._lock:
            until = self._locked_until.get(key, 0)
            remaining = int(until - time.monotonic())
            if remaining > 0:
                return True, remaining
            self._locked_until.pop(key, None)
            return False, 0

    def record_failure(self, identifier: str) -> int:
        """记录一次失败，返回剩余可尝试次数；达到上限即锁定（锁检查与记录同一临界区，防并发越过阈值）。"""
        key = self._key(identifier)
        now = time.monotonic()
        with self._lock:
            if now < self._locked_until.get(key, 0):
                return 0  # 已锁定：并发请求不再累计
            fails = [t for t in self._fails.get(key, []) if now - t < LOGIN_FAIL_WINDOW_SECONDS]
            fails.append(now)
            self._fails[key] = fails
            if len(fails) >= LOGIN_MAX_FAILS:
                self._locked_until[key] = now + LOGIN_LOCK_SECONDS
                self._fails.pop(key, None)
                return 0
            return LOGIN_MAX_FAILS - len(fails)

    def reset(self, identifier: str) -> None:
        key = self._key(identifier)
        with self._lock:
            self._fails.pop(key, None)
            self._locked_until.pop(key, None)

    def sweep(self) -> None:
        """清理过期条目，防止内存缓慢增长。"""
        now = time.monotonic()
        with self._lock:
            for key in list(self._fails):
                if not any(now - t < LOGIN_FAIL_WINDOW_SECONDS for t in self._fails[key]):
                    self._fails.pop(key, None)
            for key, until in list(self._locked_until.items()):
                if now >= until:
                    self._locked_until.pop(key, None)


login_limiter = LoginRateLimiter()

# 时序防枚举：账号不存在时也执行一次等代价 bcrypt 校验，消除登录接口的可测时序差。
# 预生成一次 cost=12 哈希（进程内复用，校验耗时与真实哈希同量级）。
DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"timing-equalizer-dummy", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


# ---------------------------------------------------------------------------
# IP 级限流：注册/发码等高风险接口按 IP 限速（防脚本批量刷接口）
# ---------------------------------------------------------------------------
class IpRateLimiter:
    def __init__(self, max_events: int, window_seconds: int) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = {}

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            events = [t for t in self._events.get(ip, []) if now - t < self.window_seconds]
            if len(events) >= self.max_events:
                self._events[ip] = events
                return False
            events.append(now)
            self._events[ip] = events
            return True

    def sweep(self) -> None:
        now = time.monotonic()
        with self._lock:
            for key in list(self._events):
                kept = [t for t in self._events[key] if now - t < self.window_seconds]
                if kept:
                    self._events[key] = kept
                else:
                    self._events.pop(key, None)


# 注册发码：每 IP 每小时 10 次
register_ip_limiter = IpRateLimiter(max_events=10, window_seconds=3600)
# 登录尝试：每 IP 每分钟 30 次（账号级锁定之外的粗防线）
login_ip_limiter = IpRateLimiter(max_events=30, window_seconds=60)
# 通用 API：每 IP 每分钟 240 次
api_ip_limiter = IpRateLimiter(max_events=240, window_seconds=60)


def client_ip(request: Any) -> str:
    """取客户端 IP。仅信任 uvicorn 注入的直连地址，不信任可伪造的 XFF。"""
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


# ---------------------------------------------------------------------------
# CSRF：登录态写接口要求 X-Requested-With 自定义头（跨站表单无法携带）
# ---------------------------------------------------------------------------
def require_ajax_header(request: Any) -> bool:
    return request.headers.get("x-requested-with", "").lower() == "fetch"


# ---------------------------------------------------------------------------
# 请求体尺寸防御：拒收异常超大 JSON
# ---------------------------------------------------------------------------
MAX_BODY_BYTES = 256 * 1024


def dump_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, allow_nan=False)


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)
