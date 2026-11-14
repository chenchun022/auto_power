"""账号体系数据层：用户、会话、注册验证码、用途记忆。

所有 SQL 一律参数化（? 占位符），不存在字符串拼接 SQL —— 防数据库注入的结构性保证。
"""
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

from security import (
    SESSION_TTL_HOURS,
    VERIFY_CODE_MAX_ATTEMPTS,
    VERIFY_CODE_TTL_MINUTES,
    hash_password,
    new_session_token,
    new_verify_code,
    new_verify_token,
    now_ts,
    sha256_hex,
    to_iso,
    verify_password,
)

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
DB_PATH = CONFIG_DIR / "app.db"


@contextmanager
def get_db() -> Any:
    connection = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        yield connection
        if connection.in_transaction:
            connection.commit()
    finally:
        connection.close()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_auth_tables() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS register_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_regverify_email ON register_verifications(email, used)"
        )
        # 用途记忆：按用户维度沉淀候选
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                usage_text TEXT NOT NULL,
                capacity_kw TEXT NOT NULL DEFAULT '',
                use_count INTEGER NOT NULL DEFAULT 1,
                last_used_at TEXT NOT NULL,
                UNIQUE (user_id, usage_text)
            )
            """
        )
        # 存量库迁移：老 users 表没有 role 列时补上（首用户引导依赖它）
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        # 系统设置（键值）：注册开关等
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def get_setting(key: str, default: str = "") -> str:
    with get_db() as conn:
        row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, to_iso(now_ts())),
        )


def list_users() -> list[dict]:
    """管理后台用户列表（不含密码哈希）。"""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.role, u.created_at,
                   (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id
                     AND s.expires_at > ?) AS active_sessions,
                   (SELECT COUNT(*) FROM usage_memory m WHERE m.user_id = u.id) AS memory_count
            FROM users u ORDER BY u.id
            """,
            (to_iso(now_ts()),),
        ).fetchall()
    return [dict(row) for row in rows]


def set_user_role(user_id: int, role: str) -> bool:
    if role not in ("admin", "user"):
        return False
    with get_db() as conn:
        cursor = conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        return cursor.rowcount > 0


def admin_reset_user_password(user_id: int, new_password: str) -> bool:
    """管理员重置用户密码，同时销毁该用户全部会话（强制重登录）。"""
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )
        if cursor.rowcount == 0:
            return False
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        return True


def delete_user(user_id: int) -> bool:
    """删除用户（级联清会话与记忆）。"""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if cursor.rowcount == 0:
            return False
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM usage_memory WHERE user_id = ?", (user_id,))
        return True


def is_first_user() -> bool:
    """空库判定：没有任何用户时，下一个注册人即首用户（将成为管理员）。"""
    with get_db() as conn:
        return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None


def seed_admin(username: str, password: str) -> tuple[bool, str]:
    """部署引导：空库时创建种子管理员。

    返回 (是否创建, 提示信息)。库非空则跳过（幂等，重启不会重复创建）。
    """
    username = username.strip()
    if not username:
        return False, "用户名为空，跳过种子管理员创建"
    if not is_first_user():
        return False, ""  # 已有用户，正常启动
    create_user("admin@local.seed", username, password, role="admin")
    return True, username


# ---------------------------------------------------------------------------
# 注册验证码：复刻 licenserver invites 语义
# ---------------------------------------------------------------------------
def create_register_verification(email: str) -> dict[str, str]:
    """生成验证码记录，返回 {token, code, expires_at}（token/code 仅此一次明文返回）。"""
    token = new_verify_token()
    code = new_verify_code()
    created = now_ts()
    expires = created + timedelta(minutes=VERIFY_CODE_TTL_MINUTES)
    with get_db() as conn:
        # 同邮箱旧验证码全部作废
        conn.execute(
            "UPDATE register_verifications SET used = 1 WHERE email = ? AND used = 0",
            (email,),
        )
        conn.execute(
            """
            INSERT INTO register_verifications (email, token_hash, code_hash, attempts, used, created_at, expires_at)
            VALUES (?, ?, ?, 0, 0, ?, ?)
            """,
            (
                email.lower(),
                sha256_hex(token),
                hash_password(code),
                to_iso(created),
                to_iso(expires),
            ),
        )
    return {"token": token, "code": code, "expires_at": to_iso(expires)}


def check_register_verification(email: str, token: str, code: str) -> bool:
    """校验 token+验证码；错误累计 attempts，达到上限作废（与 licenserver 一致）。"""
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT * FROM register_verifications
            WHERE email = ? AND token_hash = ? AND used = 0
            ORDER BY id DESC LIMIT 1
            """,
            (email.lower(), sha256_hex(token)),
        ).fetchone()
        now = now_ts()
        if not row or row["attempts"] >= VERIFY_CODE_MAX_ATTEMPTS:
            return False
        expires_at = row["expires_at"]
        # ISO 字符串比较：都是 UTC offset 格式，可直接比较
        if to_iso(now) > expires_at:
            return False
        if not verify_password(code, row["code_hash"]):
            conn.execute(
                "UPDATE register_verifications SET attempts = attempts + 1 WHERE id = ?",
                (row["id"],),
            )
            return False
        conn.execute(
            "UPDATE register_verifications SET used = 1 WHERE id = ?",
            (row["id"],),
        )
        return True


# ---------------------------------------------------------------------------
# 用户与会话
# ---------------------------------------------------------------------------
def create_user(email: str, username: str, password: str, role: str = "user") -> int:
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, email.lower(), hash_password(password), role, to_iso(now_ts())),
        )
        return int(cursor.lastrowid)


def find_user_by_login(login: str) -> sqlite3.Row | None:
    """支持用户名或邮箱登录。"""
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1",
            (login, login.lower()),
        ).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def update_username(user_id: int, new_username: str) -> bool:
    """改用户名。撞名（UNIQUE）返回 False。"""
    with get_db() as conn:
        try:
            conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (new_username, user_id),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def update_password(user_id: int, new_password: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )


def user_exists(email: str, username: str) -> tuple[bool, bool]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT "
            "  EXISTS(SELECT 1 FROM users WHERE email = ? COLLATE NOCASE) AS email_taken, "
            "  EXISTS(SELECT 1 FROM users WHERE username = ? COLLATE NOCASE) AS username_taken",
            (email.lower(), username),
        ).fetchone()
    return bool(row["email_taken"]), bool(row["username_taken"])


def create_session(user_id: int) -> tuple[str, str]:
    """创建会话，返回 (明文 token, 过期时间)。库里只存 token 哈希。"""
    token = new_session_token()
    created = now_ts()
    expires = created + timedelta(hours=SESSION_TTL_HOURS)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (sha256_hex(token), user_id, to_iso(created), to_iso(expires)),
        )
    return token, to_iso(expires)


def resolve_session(token: str) -> sqlite3.Row | None:
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT s.token_hash, s.expires_at, u.id AS user_id, u.username, u.email, u.role
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (sha256_hex(token),),
        ).fetchone()
    if not row or to_iso(now_ts()) > row["expires_at"]:
        return None
    return row


def destroy_session(token: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (sha256_hex(token),))


# ---------------------------------------------------------------------------
# 用途记忆：记录 + 检索候选
# ---------------------------------------------------------------------------
def remember_usage(user_id: int, usage_text: str, capacity_kw: str = "") -> None:
    usage = usage_text.strip()[:300]
    if not usage:
        return
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO usage_memory (user_id, usage_text, capacity_kw, use_count, last_used_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(user_id, usage_text) DO UPDATE SET
                use_count = use_count + 1,
                capacity_kw = CASE WHEN excluded.capacity_kw != '' THEN excluded.capacity_kw ELSE usage_memory.capacity_kw END,
                last_used_at = excluded.last_used_at
            """,
            (user_id, usage, str(capacity_kw or "")[:32], to_iso(now_ts())),
        )


def list_usage_memory(user_id: int, limit: int = 200) -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT usage_text, capacity_kw, use_count, last_used_at
            FROM usage_memory WHERE user_id = ?
            ORDER BY use_count DESC, last_used_at DESC LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def purge_expired() -> None:
    """周期清理：过期会话、已用/过期验证码。由后台 sweeper 调用，防表无限膨胀。"""
    now = to_iso(now_ts())
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "DELETE FROM register_verifications WHERE used = 1 OR expires_at < ?",
            (now,),
        )
