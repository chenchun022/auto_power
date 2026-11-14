import asyncio
import json
import math
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from contextlib import contextmanager
from datetime import datetime
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import authdb
import backup
import mailer
import r2backup
from security import (
    DUMMY_PASSWORD_HASH,
    SESSION_TTL_HOURS,
    api_ip_limiter,
    client_ip,
    login_ip_limiter,
    login_limiter,
    register_ip_limiter,
    validate_email,
    validate_password_strength,
    validate_username,
    verify_password,
)


APP_TITLE = "电力负荷计算工具"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
DB_PATH = CONFIG_DIR / "app.db"
PHASES = ("L1", "L2", "L3")
GROUP_META = {
    "N": {"label": "N系列回路", "description": "灯具、开关电源回路"},
    "P": {"label": "P系列回路", "description": "插座回路"},
    "S": {"label": "S系列回路", "description": "24小时回路"},
    "WL": {"label": "WL系列回路", "description": "应急回路"},
}
CONFIG_CATEGORIES = {
    "breaker_options": {
        "label": "空气开关选项",
        "kind": "breaker",
        "defaults": [
            {
                "brand": "施耐德",
                "series": "iC65N",
                "poles": "2P",
                "ampere": "10A",
                "leakage": "vigi30mA",
                "note": "施耐德 Acti9 系列，两极 10A，带 30mA 漏保",
            },
            {
                "brand": "施耐德",
                "series": "iC65N",
                "poles": "2P",
                "ampere": "16A",
                "leakage": "vigi30mA",
                "note": "施耐德 Acti9 系列，两极 16A，带 30mA 漏保",
            },
        ],
    },
    "wire_options": {
        "label": "线型选择选项",
        "kind": "wire",
        "defaults": [
            {
                "brand": "WDZB-BYJ",
                "spec": "2×2.5mm²",
                "conduit": "KBG-D20",
                "note": "低烟无卤阻燃电线，双芯 2.5 平方，KBG-D20 管敷设",
            },
            {
                "brand": "WDZB-BYJ",
                "spec": "3×4mm²",
                "conduit": "KBG-D20",
                "note": "低烟无卤阻燃电线，三芯 4 平方，KBG-D20 管敷设",
            },
        ],
    },
    "socket_options": {
        "label": "插座类型选项",
        "kind": "simple",
        "defaults": [
            {"label": "10A五孔", "note": "常规办公插座"},
            {"label": "16A三孔", "note": "大功率设备插座"},
            {"label": "工业插座32A", "note": "工业设备专用插座"},
        ],
    },
}

SESSION_COOKIE = "ap_session"
# Cookie 名带上 __Host- 前缀：强制 Secure + Path=/ + 无 Domain（浏览器保证）
# 本地 http 调试时退化为普通名，避免 cookie 被浏览器拒收
SESSION_COOKIE_SECURE = "__Host-ap_session"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    seed_bootstrap_admin()
    # 备份服务：恢复中断记录 + 启动定时调度
    # 路径取 authdb 的重定向值（测试重定向 DB 时备份服务同步指向临时库，不污染真实数据）
    backup_service = backup.init_service(Path(authdb.DB_PATH), Path(authdb.CONFIG_DIR))
    backup_service.start_scheduler()
    # 限流表清理：每 10 分钟扫一次过期条目；同步清理过期会话与验证码
    async def sweeper() -> None:
        while True:
            await asyncio.sleep(600)
            login_limiter.sweep()
            login_ip_limiter.sweep()
            register_ip_limiter.sweep()
            api_ip_limiter.sweep()
            try:
                await run_in_threadpool(authdb.purge_expired)
            except Exception as error:  # noqa: BLE001
                print(f"[warn] 过期数据清理失败: {error}")

    task = asyncio.create_task(sweeper())
    yield
    task.cancel()


app = FastAPI(title=APP_TITLE, lifespan=lifespan)

os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# ---------------------------------------------------------------------------
# 中间件：全局限流 + 安全响应头
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    auth_strict_paths = ("/api/auth/login", "/api/auth/register")

    # CSRF 防护：API 写操作必须带自定义头 X-Requested-With: fetch。
    # 跨站表单/简单请求无法携带自定义头（需预检），从根本上阻断跨站写。
    if (
        request.method in ("POST", "PUT", "DELETE")
        and path.startswith("/api/")
        and request.headers.get("x-requested-with", "").lower() != "fetch"
    ):
        return JSONResponse({"detail": "非法的跨站请求"}, status_code=403)

    # 登录/发码接口有各自的更严限流，通用限流兜住其余 API（含 /api/auth/me、logout）
    if path.startswith("/api/") and not path.startswith(auth_strict_paths):
        if not api_ip_limiter.allow(client_ip(request)):
            return JSONResponse({"detail": "请求过于频繁，请稍后再试"}, status_code=429)

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


# ---------------------------------------------------------------------------
# 全站门禁：未登录一律拦截。
# 页面（非 /api）→ 302 跳登录页；API → 401。
# 白名单：登录/注册页与认证接口、静态资源、健康检查。
# 注意：此中间件在 security_middleware 之后注册 = 先于其执行（洋葱模型外层），
# 401/302 响应不经过 CSRF/限流逻辑，直接短路返回。
# ---------------------------------------------------------------------------
AUTH_ALLOW_PAGES = {"/login", "/register"}
AUTH_ALLOW_API_PREFIXES = (
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/auth/bootstrap-status",  # 注册页判断空库引导用
    "/static/",
    "/favicon.ico",
)


@app.middleware("http")
async def auth_gate_middleware(request: Request, call_next):
    path = request.url.path
    # 白名单直接放行
    if (
        path in AUTH_ALLOW_PAGES
        or path.startswith(AUTH_ALLOW_API_PREFIXES)
    ):
        return await call_next(request)
    # 已登录放行
    if current_user(request):
        return await call_next(request)
    # 页面请求 → 登录页；API 请求 → 401
    if path.startswith("/api/"):
        return JSONResponse({"detail": "请先登录"}, status_code=401)
    next_param = f"?next={path}" if path != "/" else ""
    return RedirectResponse(f"/login{next_param}", status_code=302)


def calculate_pjs(pe: float, kx: float) -> float:
    return round(pe * kx, 2)


def calculate_ljs(pjs: float, cos_phi: float) -> float:
    pjs_w = pjs * 1000
    ljs = pjs_w / (1.732 * 380 * cos_phi)
    return round(ljs, 2)


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


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
    columns = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def make_config_value(category: str, data: dict[str, Any]) -> str:
    kind = CONFIG_CATEGORIES[category]["kind"]
    if kind == "breaker":
        parts = [data.get("series", "").strip(), data.get("poles", "").strip(), data.get("ampere", "").strip()]
        base = "-".join([part for part in parts if part])
        leakage = data.get("leakage", "").strip()
        return f"{base}+{leakage}" if leakage else base
    if kind == "wire":
        brand = data.get("brand", "").strip()
        spec = data.get("spec", "").strip()
        conduit = data.get("conduit", "").strip()
        if brand and spec:
            return f"{brand}  {spec}{conduit}"
        return "".join([part for part in [brand, spec, conduit] if part])
    return data.get("label", "").strip()


def seed_config_item(category: str, item: dict[str, Any], sort_order: int) -> dict[str, Any]:
    note = item.get("note", "").strip()
    value = make_config_value(category, item)
    metadata = {
        key: value_text.strip()
        for key, value_text in item.items()
        if isinstance(value_text, str)
    }
    return {
        "category": category,
        "value": value,
        "note": note,
        "brand": item.get("brand", "").strip(),
        "series": item.get("series", "").strip(),
        "metadata": metadata,
        "sort_order": sort_order,
    }


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS config_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                value TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                brand TEXT NOT NULL DEFAULT '',
                series TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_column(conn, "config_items", "note", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "config_items", "brand", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "config_items", "series", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "config_items", "metadata_json", "TEXT NOT NULL DEFAULT '{}'")

        conn.execute(
            """
            DELETE FROM config_items
            WHERE (metadata_json IS NULL OR metadata_json = '' OR metadata_json = '{}')
              AND category IN ('breaker_options', 'wire_options', 'socket_options')
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                data_json TEXT NOT NULL,
                is_template INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_column(conn, "projects", "is_template", "INTEGER NOT NULL DEFAULT 0")

        for category, meta in CONFIG_CATEGORIES.items():
            existing_values = {
                row["value"]
                for row in conn.execute(
                    "SELECT value FROM config_items WHERE category = ?",
                    (category,),
                ).fetchall()
            }
            timestamp = now_iso()
            next_sort = conn.execute(
                "SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM config_items WHERE category = ?",
                (category,),
            ).fetchone()["max_sort"]
            for item in meta["defaults"]:
                seeded = seed_config_item(category, item, next_sort + 1)
                if seeded["value"] in existing_values:
                    continue
                conn.execute(
                    """
                    INSERT INTO config_items (
                        category, value, note, brand, series, metadata_json, sort_order, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        seeded["category"],
                        seeded["value"],
                        seeded["note"],
                        seeded["brand"],
                        seeded["series"],
                        json.dumps(seeded["metadata"], ensure_ascii=False),
                        seeded["sort_order"],
                        timestamp,
                        timestamp,
                    ),
                )
                existing_values.add(seeded["value"])
                next_sort += 1

        project_count = conn.execute(
            "SELECT COUNT(1) AS total FROM projects"
        ).fetchone()["total"]
        if not project_count:
            seed = default_project_payload(name="示例项目")
            conn.execute(
                """
                INSERT INTO projects (id, name, description, data_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    seed["id"],
                    seed["name"],
                    seed["description"],
                    json.dumps(seed["data"], ensure_ascii=False),
                    seed["created_at"],
                    seed["updated_at"],
                ),
            )

    authdb.init_auth_tables()


def default_groups() -> dict[str, list[dict[str, Any]]]:
    return {code: [] for code in GROUP_META}


def default_project_payload(name: str = "新项目") -> dict[str, Any]:
    project_id = uuid.uuid4().hex
    timestamp = now_iso()
    data = {
        "filters": {"breaker_brand": "", "wire_brand": ""},
        "load_factors": {"kx": 1.0, "cos": 0.8},
        "groups": default_groups(),
        "summary": {
            "phase_totals": {phase: 0 for phase in PHASES},
            "phase_difference": 0,
            "total_capacity_kw": 0,
            "pjs_kw": 0,
            "ijs_a": 0,
            "row_count": 0,
        },
    }
    return {
        "id": project_id,
        "name": name,
        "description": "",
        "data": data,
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def dump_project_data(data: dict[str, Any]) -> str:
    # allow_nan=False：历史毒化数据（Infinity/NaN）在此被拒绝而不是继续扩散
    return json.dumps(data, ensure_ascii=False, allow_nan=False)


def serialize_project_row(row: sqlite3.Row) -> dict[str, Any]:
    try:
        data = json.loads(row["data_json"])
        if not isinstance(data, dict):
            raise ValueError("data_json 不是对象")
    except (ValueError, TypeError) as error:
        print(f"[warn] 项目 {row['id']} 数据损坏，回退默认数据: {error}")
        data = default_project_payload()["data"]
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "is_template": bool(row["is_template"]) if "is_template" in row.keys() else False,
        "data": normalize_project_data(data),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_project_or_404(project_id: str) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="项目不存在")
    return serialize_project_row(row)


def normalize_row(row: dict[str, Any], group_code: str, index: int) -> dict[str, Any]:
    # 容错：非 dict 行（如恶意传入 [1,2]）回退为空行，避免 AttributeError 500
    if not isinstance(row, dict):
        row = {}
    capacity_value = row.get("capacity_kw", "")
    voltage = str(row.get("voltage", "220"))
    # 字符串字段限长，防止超大 payload 落库
    def clip(value: Any, limit: int = 300) -> str:
        return str(value or "")[:limit]

    return {
        "id": str(row.get("id") or uuid.uuid4().hex)[:64],
        "group_type": group_code,
        "sequence": index + 1,
        # BUG修复：回路编号在保存端强制按“组前缀+位置序号”重生成，
        # 客户端新增行的 sequence=0 不再影响编号生成（此前 index+1 恰好从 1 开始，
        # 但前端 createEmptyRow 的 circuit_code 为空且渲染依赖 sequence，
        # 导致序号列显示 0 且编号列为空）。编号从此只由数组位置决定。
        "circuit_code": f"{group_code}{index + 1}",
        "breaker_option": clip(row.get("breaker_option", "")),
        "wire_option": clip(row.get("wire_option", "")),
        "phase_sequence": clip(row.get("phase_sequence", ""), 16),
        "usage": clip(row.get("usage", "")),
        "capacity_kw": normalize_number(capacity_value, default=""),
        "voltage": "380" if voltage == "380" else "220",
        "socket_type": clip(row.get("socket_type", "")),
    }


def normalize_number(value: Any, default: Any = 0, keep_int: bool = False) -> Any:
    if value in (None, ""):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(number):
        # 拒绝 NaN/Infinity：否则会毒化 JSON 序列化，导致项目读取接口 500
        return default
    if keep_int and number.is_integer():
        return int(number)
    return round(number, 4)


def as_dict(value: Any) -> dict[str, Any]:
    """宽容取值：非 dict 一律回退空 dict，避免畸形输入触发 AttributeError"""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_project_data(data: dict[str, Any] | None) -> dict[str, Any]:
    safe_data = as_dict(data)
    input_groups = as_dict(safe_data.get("groups"))
    filters = as_dict(safe_data.get("filters"))
    load_factors = as_dict(safe_data.get("load_factors"))
    groups = default_groups()
    for group_code in GROUP_META:
        rows = as_list(input_groups.get(group_code))
        # 行数上限防御：异常超大 payload 截断
        normalized_rows = [
            normalize_row(row, group_code, index)
            for index, row in enumerate(rows[:500])
        ]
        groups[group_code] = normalized_rows

    result = {
        "filters": {
            "breaker_brand": str(filters.get("breaker_brand", "") or "")[:50],
            "wire_brand": str(filters.get("wire_brand", "") or "")[:50],
        },
        "load_factors": {
            "kx": normalize_number(load_factors.get("kx"), default=1),
            "cos": normalize_number(load_factors.get("cos"), default=0.8),
        },
        "groups": groups,
    }
    summary = rebalance_project_data(result)["summary"]
    result["summary"] = summary
    return result


def row_total_capacity(row: dict[str, Any]) -> float:
    capacity = normalize_number(row.get("capacity_kw"), default=0)
    return round(capacity, 4)


def rebalance_project_data(project_data: dict[str, Any]) -> dict[str, Any]:
    safe_data = as_dict(project_data)
    groups = as_dict(safe_data.get("groups"))
    normalized_groups = default_groups()
    phase_totals = {phase: 0.0 for phase in PHASES}
    total_capacity = 0.0
    row_count = 0
    load_factors = {
        "kx": normalize_number(as_dict(safe_data.get("load_factors")).get("kx"), default=1),
        "cos": normalize_number(as_dict(safe_data.get("load_factors")).get("cos"), default=0.8),
    }

    for group_code in GROUP_META:
        rows = as_list(groups.get(group_code))
        normalized_rows = [normalize_row(row, group_code, index) for index, row in enumerate(rows[:500])]
        normalized_groups[group_code] = normalized_rows

    single_phase_rows: list[tuple[str, int, float]] = []
    for group_code, rows in normalized_groups.items():
        for index, row in enumerate(rows):
            total_kw = row_total_capacity(row)
            total_capacity += total_kw
            row_count += 1
            if total_kw <= 0:
                row["phase_sequence"] = ""
                continue
            if row["voltage"] == "380":
                average = total_kw / 3
                for phase in PHASES:
                    phase_totals[phase] += average
                row["phase_sequence"] = "L1/L2/L3"
            else:
                single_phase_rows.append((group_code, index, total_kw))

    single_phase_rows.sort(key=lambda item: item[2], reverse=True)
    for group_code, row_index, total_kw in single_phase_rows:
        target_phase = min(PHASES, key=lambda phase: phase_totals[phase])
        normalized_groups[group_code][row_index]["phase_sequence"] = target_phase
        phase_totals[target_phase] += total_kw

    rounded_phase_totals = {phase: round(value, 2) for phase, value in phase_totals.items()}
    pjs_kw = calculate_pjs(total_capacity, load_factors["kx"])
    cos_phi = load_factors["cos"] if load_factors["cos"] not in (0, "", None) else 0.8
    ijs_a = calculate_ljs(pjs_kw, cos_phi) if pjs_kw > 0 and cos_phi > 0 else 0
    summary = {
        "phase_totals": rounded_phase_totals,
        "phase_difference": round(max(phase_totals.values()) - min(phase_totals.values()), 2),
        "total_capacity_kw": round(total_capacity, 2),
        "pjs_kw": round(pjs_kw, 2),
        "ijs_a": round(ijs_a, 2),
        "row_count": row_count,
    }
    return {
        "filters": {
            "breaker_brand": str(as_dict(safe_data.get("filters")).get("breaker_brand", "") or "")[:50],
            "wire_brand": str(as_dict(safe_data.get("filters")).get("wire_brand", "") or "")[:50],
        },
        "load_factors": load_factors,
        "groups": normalized_groups,
        "summary": summary,
    }


def fetch_all_configs() -> dict[str, Any]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, category, value, note, brand, series, metadata_json, sort_order
            FROM config_items
            ORDER BY category, sort_order, id
            """
        ).fetchall()

    grouped: dict[str, list[dict[str, Any]]] = {category: [] for category in CONFIG_CATEGORIES}
    for row in rows:
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
            if not isinstance(metadata, dict):
                raise ValueError("metadata_json 不是对象")
        except (ValueError, TypeError) as error:
            print(f"[warn] 配置项 {row['id']} metadata 损坏，回退空对象: {error}")
            metadata = {}
        grouped[row["category"]].append(
            {
                "id": row["id"],
                "value": row["value"],
                "note": row["note"],
                "brand": row["brand"],
                "series": row["series"],
                "metadata": metadata,
                "sort_order": row["sort_order"],
            }
        )

    categories = []
    for category, meta in CONFIG_CATEGORIES.items():
        brands = sorted({item["brand"] for item in grouped.get(category, []) if item["brand"]})
        categories.append(
            {
                "key": category,
                "label": meta["label"],
                "kind": meta["kind"],
                "brands": brands,
                "items": grouped.get(category, []),
            }
        )
    return {"categories": categories}


def fetch_project_list() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, name, description, is_template, created_at, updated_at
            FROM projects
            ORDER BY updated_at DESC
            """
        ).fetchall()
    return [
        {**dict(row), "is_template": bool(row["is_template"])}
        for row in rows
    ]


class BreakerConfigPayload(BaseModel):
    brand: str = Field(min_length=1, max_length=50)
    series: str = Field(min_length=1, max_length=50)
    poles: str = Field(min_length=1, max_length=20)
    ampere: str = Field(min_length=1, max_length=20)
    leakage: str = Field(default="", max_length=30)
    note: str = Field(default="", max_length=300)


class WireConfigPayload(BaseModel):
    brand: str = Field(min_length=1, max_length=50)
    spec: str = Field(min_length=1, max_length=50)
    conduit: str = Field(default="", max_length=50)
    note: str = Field(default="", max_length=300)


class SimpleConfigPayload(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=300)


class ProjectSavePayload(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=300)
    data: dict[str, Any]


def validate_config_payload(category: str, payload: dict[str, Any]) -> dict[str, Any]:
    kind = CONFIG_CATEGORIES.get(category, {}).get("kind")
    if not kind:
        raise HTTPException(status_code=404, detail="配置分类不存在")
    if kind == "breaker":
        return BreakerConfigPayload(**payload).model_dump()
    if kind == "wire":
        return WireConfigPayload(**payload).model_dump()
    return SimpleConfigPayload(**payload).model_dump()


def build_config_record(category: str, payload: dict[str, Any]) -> dict[str, Any]:
    value = make_config_value(category, payload)
    return {
        "value": value,
        "note": payload.get("note", "").strip(),
        "brand": payload.get("brand", "").strip(),
        "series": payload.get("series", "").strip(),
        "metadata_json": json.dumps(payload, ensure_ascii=False),
    }


# ---------------------------------------------------------------------------
# 会话辅助
# ---------------------------------------------------------------------------
def read_session_cookie(request: Request) -> str | None:
    raw = request.headers.get("cookie", "")
    cookie = SimpleCookie()
    try:
        cookie.load(raw)
    except Exception:  # noqa: BLE001 - 畸形 cookie 直接视为未登录
        return None
    for name in (SESSION_COOKIE_SECURE, SESSION_COOKIE):
        if name in cookie:
            return cookie[name].value
    return None


def current_user(request: Request) -> dict[str, Any] | None:
    token = read_session_cookie(request)
    if not token:
        return None
    row = authdb.resolve_session(token)
    if not row:
        return None
    return {
        "id": row["user_id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"] or "user",
    }


def require_user(request: Request) -> dict[str, Any]:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="请先登录")
    return user


def require_admin(request: Request) -> dict[str, Any]:
    user = require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


def set_session_cookie(response: JSONResponse, token: str) -> None:
    # __Host- 前缀要求 Secure；仅 https 请求下启用（本地 http 调试退化为普通名）
    use_secure = request_is_https.get()
    name = SESSION_COOKIE_SECURE if use_secure else SESSION_COOKIE
    response.set_cookie(
        name,
        token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        secure=use_secure,
        samesite="lax",
        path="/",
    )


# ContextVar 记录当前请求是否 https（set_session_cookie 用）
import contextvars  # noqa: E402

request_is_https = contextvars.ContextVar("request_is_https", default=False)


@app.middleware("http")
async def https_detect_middleware(request: Request, call_next):
    # 仅当直连方是本机/内网（即前面有反代的部署形态）才采信 X-Forwarded-Proto，
    # 防止公网直连客户端伪造该头让 cookie 带 Secure 被浏览器拒收（会话"登录即失效"）
    remote = request.client.host if request.client else ""
    trusted_proxy = (
        remote.startswith("127.")
        or remote.startswith("10.")
        or remote.startswith("192.168.")
        or remote.startswith("172.")
        or remote == "::1"
    )
    proto = request.headers.get("x-forwarded-proto", "") if trusted_proxy else request.url.scheme
    request_is_https.set(proto == "https")
    return await call_next(request)


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    context = {
        "app_title": APP_TITLE,
        "group_meta": GROUP_META,
    }
    return templates.TemplateResponse(request, "index.html", context)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    if current_user(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"app_title": APP_TITLE, "mode": "login"})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    if current_user(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"app_title": APP_TITLE, "mode": "register"})


@app.post("/calculate", response_class=HTMLResponse)
async def calculate(
    request: Request,
    pe: float = Form(...),
    kx: float = Form(...),
    cos: float = Form(...),
) -> HTMLResponse:
    pjs = calculate_pjs(pe, kx)
    ljs = calculate_ljs(pjs, cos)
    context = {
        "app_title": APP_TITLE,
        "group_meta": GROUP_META,
        "pe": pe,
        "kx": kx,
        "cos": cos,
        "pjs": pjs,
        "ljs": ljs,
    }
    return templates.TemplateResponse(request, "index.html", context)


# ===========================================================================
# 认证 API
# ===========================================================================
class RegisterSendCodePayload(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class RegisterPayload(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)
    verify_token: str = Field(min_length=0, max_length=128)
    verify_code: str = Field(min_length=6, max_length=6)


class LoginPayload(BaseModel):
    login: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def api_error(detail: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def seed_bootstrap_admin() -> None:
    """部署引导：空库时创建种子管理员。

    - 环境变量 ADMIN_USERNAME / ADMIN_PASSWORD 指定账号密码（compose 部署推荐）；
    - 缺省用户名 admin；密码未指定时自动生成 16 位随机密码并打进容器日志，
      部署者从 `docker logs` 获取后登录，再在网页「账号设置」里改成自己的；
    - 幂等：库非空直接跳过，重启不会重复创建或覆盖已有账号。
    """
    username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.environ.get("ADMIN_PASSWORD", "")
    generated = False
    if not password:
        # 随机密码：去掉易混淆字符，16 位
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
        password = "".join(secrets.choice(alphabet) for _ in range(16))
        generated = True
    created, info = authdb.seed_admin(username, password)
    if created:
        if generated:
            print("=" * 62)
            print("  首次部署：已自动创建管理员账号（仅此一次打印）")
            print(f"  用户名: {username}")
            print(f"  初始密码: {password}")
            print("  请立即登录，在「账号设置」中修改用户名与密码！")
            print("=" * 62)
        else:
            print(f"[info] 已按环境变量创建管理员账号: {username}")
    elif info:
        print(f"[warn] 种子管理员未创建: {info}")


@app.post("/api/auth/register/send-code")
async def api_register_send_code(payload: RegisterSendCodePayload, request: Request) -> JSONResponse:
    if not register_ip_limiter.allow(client_ip(request)):
        return api_error("发送过于频繁，请稍后再试", 429)

    if authdb.get_setting("registration_open", "1") != "1":
        return api_error("注册通道已关闭，请联系管理员", 403)

    if email_error := validate_email(payload.email):
        return api_error(email_error, 422)

    email_taken, _ = authdb.user_exists(payload.email, "_unused_")
    if email_taken:
        # 枚举防护：响应结构与成功分支完全一致（同样返回哑 token），
        # 攻击者无法凭 verify_token 有无/耗时差异探测邮箱是否已注册
        return JSONResponse({
            "ok": True,
            "verify_token": secrets.token_hex(32),
            "message": "若邮箱可用，验证码已发送，请查收",
        })

    try:
        verification = authdb.create_register_verification(payload.email)
        # P1修复：SMTP 是同步阻塞调用（最长 ~20s），放线程池避免冻结事件循环
        await run_in_threadpool(mailer.send_verify_code_mail, payload.email, verification["code"])
    except mailer.SmtpNotConfiguredError:
        return api_error("邮件服务未配置，请联系管理员配置 config/smtp.json", 503)
    except Exception as error:  # noqa: BLE001
        print(f"[error] 发送验证码失败: {error}")
        return api_error("验证码发送失败，请稍后重试", 502)

    return JSONResponse({
        "ok": True,
        "verify_token": verification["token"],
        "message": "验证码已发送，请查收邮件（24 小时内有效）",
    })


@app.get("/api/auth/bootstrap-status")
async def api_auth_bootstrap_status() -> JSONResponse:
    """注册页状态：SMTP 是否已配置、注册通道是否开放（管理员由部署种子账号引导）。"""
    return JSONResponse({
        "first_user_bootstrap": False,
        "smtp_configured": mailer.load_smtp_config() is not None,
        "registration_open": authdb.get_setting("registration_open", "1") == "1",
    })


@app.post("/api/auth/register")
async def api_register(payload: RegisterPayload, request: Request) -> JSONResponse:
    if not register_ip_limiter.allow(client_ip(request)):
        return api_error("操作过于频繁，请稍后再试", 429)

    if authdb.get_setting("registration_open", "1") != "1":
        return api_error("注册通道已关闭，请联系管理员", 403)

    if email_error := validate_email(payload.email):
        return api_error(email_error, 422)
    if username_error := validate_username(payload.username):
        return api_error(username_error, 422)
    if password_error := validate_password_strength(payload.password):
        return api_error(password_error, 422)

    # 所有自助注册均需邮箱验证码；管理员唯一来源是部署时的种子账号（环境变量/日志密码）
    if not payload.verify_code.isdigit():
        return api_error("验证码为 6 位数字", 422)
    if not authdb.check_register_verification(payload.email, payload.verify_token, payload.verify_code):
        return api_error("验证码错误或已失效", 422)

    email_taken, username_taken = authdb.user_exists(payload.email, payload.username)
    if email_taken:
        return api_error("该邮箱已注册", 409)
    if username_taken:
        return api_error("用户名已被使用", 409)

    try:
        role = "user"
        user_id = authdb.create_user(payload.email, payload.username, payload.password, role=role)
    except sqlite3.IntegrityError:
        # TOCTOU：并发双提交在 user_exists 检查后撞 UNIQUE 约束，回 409 而非 500
        return api_error("该邮箱或用户名已被注册", 409)
    token, _ = authdb.create_session(user_id)
    response = JSONResponse({"ok": True, "username": payload.username, "role": role})
    set_session_cookie(response, token)
    return response


@app.post("/api/auth/login")
async def api_login(payload: LoginPayload, request: Request) -> JSONResponse:
    if not login_ip_limiter.allow(client_ip(request)):
        return api_error("请求过于频繁，请稍后再试", 429)

    login_key = payload.login.strip().lower()
    locked, remaining = login_limiter.is_locked(login_key)
    if locked:
        return api_error(f"失败次数过多，账号已锁定，请 {remaining // 60 + 1} 分钟后再试", 429)

    user = authdb.find_user_by_login(payload.login.strip())
    # 统一错误文案 + 等时校验：账号不存在时也跑一次等代价 bcrypt，
    # 消除"账号存在与否"的可测时序差（防枚举）
    if not user:
        verify_password(payload.password, DUMMY_PASSWORD_HASH)
        tries_left = login_limiter.record_failure(login_key)
        if tries_left == 0:
            return api_error("失败次数过多，账号已锁定 15 分钟", 429)
        return api_error(f"账号或密码错误（剩余 {tries_left} 次尝试机会）", 401)
    if not verify_password(payload.password, user["password_hash"]):
        tries_left = login_limiter.record_failure(login_key)
        if tries_left == 0:
            return api_error("失败次数过多，账号已锁定 15 分钟", 429)
        return api_error(f"账号或密码错误（剩余 {tries_left} 次尝试机会）", 401)

    login_limiter.reset(login_key)
    token, _ = authdb.create_session(user["id"])
    response = JSONResponse({"ok": True, "username": user["username"]})
    set_session_cookie(response, token)
    return response


@app.post("/api/auth/logout")
async def api_logout(request: Request) -> JSONResponse:
    token = read_session_cookie(request)
    if token:
        authdb.destroy_session(token)
    response = JSONResponse({"ok": True})
    for name in (SESSION_COOKIE_SECURE, SESSION_COOKIE):
        response.delete_cookie(name, path="/")
    return response


@app.get("/api/auth/me")
async def api_me(request: Request) -> JSONResponse:
    user = current_user(request)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=200)
    return JSONResponse({"authenticated": True, "username": user["username"], "email": user["email"]})


# ===========================================================================
# 用途记忆 API（登录后可用）
# ===========================================================================
class UsageRememberPayload(BaseModel):
    usage: str = Field(min_length=1, max_length=300)
    capacity_kw: str = Field(default="", max_length=32)


@app.post("/api/usage-memory")
async def api_remember_usage(payload: UsageRememberPayload, request: Request) -> JSONResponse:
    user = require_user(request)
    authdb.remember_usage(user["id"], payload.usage, payload.capacity_kw)
    return JSONResponse({"ok": True})


@app.get("/api/usage-memory")
async def api_list_usage_memory(request: Request) -> JSONResponse:
    user = require_user(request)
    return JSONResponse({"items": authdb.list_usage_memory(user["id"])})


# ===========================================================================
# 管理员 API：SMTP 配置（首管理员在网页后台完成，不再依赖手工编辑文件）
# ===========================================================================
class SmtpConfigPayload(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    username: str = Field(default="", max_length=254)
    password: str = Field(default="", max_length=254)
    from_email: str = Field(default="", max_length=254)
    from_name: str = Field(default="", max_length=64)
    use_tls: bool = False


@app.get("/api/admin/smtp")
async def api_admin_get_smtp(request: Request) -> JSONResponse:
    require_admin(request)
    config = mailer.load_smtp_config()
    if not config:
        return JSONResponse({"configured": False})
    # 密码不回传前端，只回传是否已设置
    return JSONResponse({
        "configured": True,
        "host": config["host"],
        "port": config["port"],
        "username": config["username"],
        "from_email": config["from_email"],
        "from_name": config["from_name"],
        "use_tls": config["use_tls"],
        "has_password": bool(config["password"]),
    })


@app.put("/api/admin/smtp")
async def api_admin_put_smtp(payload: SmtpConfigPayload, request: Request) -> JSONResponse:
    require_admin(request)
    if payload.from_email and (email_error := validate_email(payload.from_email)):
        return api_error(f"发件邮箱格式不正确：{email_error}", 422)
    data = payload.model_dump()
    # 密码留空：沿用已保存的密码（前端不回传密码，避免明文往返）
    if not data["password"]:
        existing = mailer.load_smtp_config()
        if existing:
            data["password"] = existing["password"]
    mailer.save_smtp_config(data)
    return JSONResponse({"ok": True, "message": "SMTP 配置已保存"})


@app.post("/api/admin/smtp/test")
async def api_admin_test_smtp(request: Request) -> JSONResponse:
    """用刚提交（尚未保存）或已保存的配置发一封测试邮件到管理员自己的邮箱。"""
    admin = require_admin(request)
    config = mailer.load_smtp_config()
    if not config:
        return api_error("请先保存 SMTP 配置", 400)
    try:
        await run_in_threadpool(mailer.send_test_mail, admin["email"], config)
    except mailer.SmtpNotConfiguredError:
        return api_error("请先保存 SMTP 配置", 400)
    except Exception as error:  # noqa: BLE001 - 测试邮件要给管理员看具体失败原因
        return api_error(f"测试邮件发送失败：{error}", 502)
    return JSONResponse({"ok": True, "message": f"测试邮件已发送至 {admin['email']}，请查收"})


# ===========================================================================
# 账号设置：改用户名 / 改密码（需验证当前密码）
# ===========================================================================
class ProfileUsernamePayload(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    new_username: str = Field(min_length=1, max_length=32)


class ProfilePasswordPayload(BaseModel):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


@app.put("/api/profile/username")
async def api_profile_username(payload: ProfileUsernamePayload, request: Request) -> JSONResponse:
    user = require_user(request)
    record = authdb.get_user_by_id(user["id"])
    if not record or not verify_password(payload.password, record["password_hash"]):
        return api_error("当前密码不正确", 401)
    if error := validate_username(payload.new_username):
        return api_error(error, 422)
    if not authdb.update_username(user["id"], payload.new_username.strip()):
        return api_error("该用户名已被使用", 409)
    return JSONResponse({"ok": True, "username": payload.new_username.strip(), "message": "用户名已更新"})


@app.put("/api/profile/password")
async def api_profile_password(payload: ProfilePasswordPayload, request: Request) -> JSONResponse:
    user = require_user(request)
    record = authdb.get_user_by_id(user["id"])
    if not record or not verify_password(payload.old_password, record["password_hash"]):
        return api_error("当前密码不正确", 401)
    if error := validate_password_strength(payload.new_password):
        return api_error(error, 422)
    if payload.old_password == payload.new_password:
        return api_error("新密码不能与当前密码相同", 422)
    authdb.update_password(user["id"], payload.new_password)
    # 改密后销毁全部会话（含当前），前端收到 relocated 标记跳登录页重新登录
    with authdb.get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    response = JSONResponse({"ok": True, "relocated": True, "message": "密码已修改，请重新登录"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(SESSION_COOKIE_SECURE, path="/")
    return response


# ===========================================================================
# 管理员 API：用户管理 + 系统设置（注册开关）
# ===========================================================================
class UserRolePayload(BaseModel):
    role: str = Field(pattern="^(admin|user)$")


class AdminResetPasswordPayload(BaseModel):
    new_password: str = Field(min_length=1, max_length=128)


class RegistrationTogglePayload(BaseModel):
    open: bool


@app.get("/api/admin/users")
async def api_admin_list_users(request: Request) -> JSONResponse:
    require_admin(request)
    return JSONResponse({"items": authdb.list_users()})


@app.put("/api/admin/users/{user_id}/role")
async def api_admin_set_role(user_id: int, payload: UserRolePayload, request: Request) -> JSONResponse:
    admin = require_admin(request)
    if user_id == admin["id"]:
        return api_error("不能修改自己的角色", 400)
    if not authdb.set_user_role(user_id, payload.role):
        return api_error("用户不存在", 404)
    return JSONResponse({"ok": True, "message": "角色已更新"})


@app.put("/api/admin/users/{user_id}/password")
async def api_admin_reset_password(user_id: int, payload: AdminResetPasswordPayload, request: Request) -> JSONResponse:
    admin = require_admin(request)
    if user_id == admin["id"]:
        return api_error("不能在此重置自己的密码，请使用「账号设置」", 400)
    if error := validate_password_strength(payload.new_password):
        return api_error(error, 422)
    if not authdb.admin_reset_user_password(user_id, payload.new_password):
        return api_error("用户不存在", 404)
    return JSONResponse({"ok": True, "message": "密码已重置，该用户所有会话已失效"})


@app.delete("/api/admin/users/{user_id}")
async def api_admin_delete_user(user_id: int, request: Request) -> JSONResponse:
    admin = require_admin(request)
    if user_id == admin["id"]:
        return api_error("不能删除自己", 400)
    # 防呆：不允许删掉最后一个管理员
    users = authdb.list_users()
    target = next((u for u in users if u["id"] == user_id), None)
    if not target:
        return api_error("用户不存在", 404)
    if target["role"] == "admin" and sum(1 for u in users if u["role"] == "admin") <= 1:
        return api_error("系统至少需要保留一名管理员", 400)
    authdb.delete_user(user_id)
    return JSONResponse({"ok": True, "message": f"用户 {target['username']} 已删除"})


@app.get("/api/admin/settings")
async def api_admin_get_settings(request: Request) -> JSONResponse:
    require_admin(request)
    return JSONResponse({
        "registration_open": authdb.get_setting("registration_open", "1") == "1",
    })


@app.put("/api/admin/settings/registration")
async def api_admin_set_registration(payload: RegistrationTogglePayload, request: Request) -> JSONResponse:
    require_admin(request)
    authdb.set_setting("registration_open", "1" if payload.open else "0")
    return JSONResponse({"ok": True, "registration_open": payload.open,
                         "message": "注册通道已开放" if payload.open else "注册通道已关闭"})


# ===========================================================================
# 管理员 API：R2/S3 备份（移植自 CTA caa-v2 backup 模块）
# ===========================================================================
class BackupS3ConfigPayload(BaseModel):
    endpoint: str = Field(default="", max_length=512)
    account_id: str = Field(default="", max_length=128)
    region: str = Field(default="", max_length=64)
    bucket: str = Field(default="", max_length=128)
    access_key: str = Field(default="", max_length=254)
    secret_key: str = Field(default="", max_length=254)
    prefix: str = Field(default="", max_length=254)
    force_path_style: bool = False


class BackupSchedulePayload(BaseModel):
    enabled: bool = False
    cron_expr: str = Field(default="", max_length=128)
    retain_days: int = Field(default=0, ge=0, le=3650)
    retain_count: int = Field(default=0, ge=0, le=1000)


def _svc() -> backup.BackupService:
    return backup.get_service()


def _s3_config_out(cfg: dict[str, Any]) -> dict[str, Any]:
    out = dict(cfg)
    out["secret_key"] = ""  # 密钥不回传
    return out


@app.get("/api/admin/backup/s3-config")
async def api_backup_get_s3(request: Request) -> JSONResponse:
    require_admin(request)
    cfg = _svc().load_s3_config()
    return JSONResponse({"configured": bool(cfg), **(_s3_config_out(cfg) if cfg else {})})


@app.put("/api/admin/backup/s3-config")
async def api_backup_put_s3(payload: BackupS3ConfigPayload, request: Request) -> JSONResponse:
    require_admin(request)
    data = payload.model_dump()
    # secret_key 留空：沿用已保存的密钥（前端不回传，避免明文往返）
    if not data["secret_key"].strip():
        old = _svc().load_s3_config()
        if old:
            data["secret_key"] = old.get("secret_key", "")
    _svc().save_s3_config(data)
    return JSONResponse({"ok": True, "message": "存储配置已保存", **_s3_config_out(data)})


@app.post("/api/admin/backup/s3-config/test")
async def api_backup_test_s3(payload: BackupS3ConfigPayload, request: Request) -> JSONResponse:
    require_admin(request)
    data = payload.model_dump()
    if not data["secret_key"].strip():
        old = _svc().load_s3_config()
        if old:
            data["secret_key"] = old.get("secret_key", "")
    try:
        client = r2backup.R2BackupClient(data)
        await run_in_threadpool(client.test)
    except r2backup.NotConfiguredError as error:
        return api_error(str(error), 400)
    except Exception as error:  # noqa: BLE001 - 测试连接要给管理员看具体原因
        return api_error(f"连接失败: {error}", 502)
    return JSONResponse({"ok": True, "message": "连接成功，存储桶可访问"})


@app.get("/api/admin/backup/schedule")
async def api_backup_get_schedule(request: Request) -> JSONResponse:
    require_admin(request)
    return JSONResponse(_svc().load_schedule())


@app.put("/api/admin/backup/schedule")
async def api_backup_put_schedule(payload: BackupSchedulePayload, request: Request) -> JSONResponse:
    require_admin(request)
    data = payload.model_dump()
    if data["enabled"] and not data["cron_expr"].strip():
        return api_error("启用定时备份必须填写 cron 表达式", 422)
    if data["cron_expr"].strip():
        try:
            from croniter import croniter

            croniter(data["cron_expr"].strip())
        except (ValueError, KeyError):
            return api_error("cron 表达式无效（5 段式：分 时 日 月 周）", 422)
    _svc().save_schedule(data)
    _svc().apply_schedule()
    return JSONResponse({"ok": True, "message": "定时备份配置已保存", **data})


@app.get("/api/admin/backup/records")
async def api_backup_list_records(request: Request) -> JSONResponse:
    require_admin(request)
    records = sorted(_svc().load_records(), key=lambda r: r.get("started_at", 0), reverse=True)
    return JSONResponse({"items": records, "backing_up": _svc().backing_up, "restoring": _svc().restoring})


@app.post("/api/admin/backup/records")
async def api_backup_create(request: Request) -> JSONResponse:
    admin = require_admin(request)
    svc = _svc()
    if not svc.s3_configured(svc.load_s3_config()):
        return api_error("S3/R2 存储未配置：请先填写并保存存储配置", 400)
    try:
        record = await run_in_threadpool(svc.start_backup, f"manual:{admin['username']}")
    except backup.BackupError as error:
        return api_error(str(error), 409)
    except Exception as error:  # noqa: BLE001
        return api_error(f"启动备份失败: {error}", 500)
    return JSONResponse({"ok": True, "record": record}, status_code=202)


@app.get("/api/admin/backup/records/{record_id}")
async def api_backup_get_record(record_id: str, request: Request) -> JSONResponse:
    require_admin(request)
    record = _svc().find_record(record_id)
    if not record:
        return api_error("备份记录不存在", 404)
    return JSONResponse(record)


@app.post("/api/admin/backup/records/{record_id}/delete")
async def api_backup_delete_record(record_id: str, request: Request) -> JSONResponse:
    require_admin(request)
    svc = _svc()
    record = svc.find_record(record_id)
    if not record:
        return api_error("备份记录不存在", 404)
    if record["status"] == "running":
        return api_error("备份进行中，无法删除", 409)
    if record.get("restore_status") == "running":
        return api_error("恢复进行中，无法删除", 409)
    if record.get("s3_key"):
        cfg = svc.load_s3_config()
        if svc.s3_configured(cfg):
            try:
                client = r2backup.R2BackupClient(cfg)
                await run_in_threadpool(client.remove, record["s3_key"])
            except Exception as error:  # noqa: BLE001
                return api_error(f"删除存储对象失败，已保留记录: {error}", 502)
    with svc._records_lock:  # noqa: SLF001 - 同模块家族内的服务操作
        records = [r for r in svc.load_records() if r["id"] != record_id]
        svc.save_records(records)
    return JSONResponse({"ok": True, "message": "备份记录及存储对象已删除"})


@app.get("/api/admin/backup/records/{record_id}/download-url")
async def api_backup_download_url(record_id: str, request: Request) -> JSONResponse:
    require_admin(request)
    svc = _svc()
    record = svc.find_record(record_id)
    if not record:
        return api_error("备份记录不存在", 404)
    if record["status"] != "completed":
        return api_error("仅已完成的备份可下载", 400)
    try:
        client = r2backup.R2BackupClient(svc.load_s3_config())
        url = await run_in_threadpool(client.presign_url, record["s3_key"], 3600)
    except Exception as error:  # noqa: BLE001
        return api_error(f"生成下载链接失败: {error}", 502)
    return JSONResponse({"url": url})


@app.post("/api/admin/backup/records/{record_id}/restore")
async def api_backup_restore(record_id: str, request: Request) -> JSONResponse:
    require_admin(request)
    svc = _svc()
    record = svc.find_record(record_id)
    if not record:
        return api_error("备份记录不存在", 404)
    if record["status"] != "completed":
        return api_error("仅已完成的备份可恢复", 400)
    try:
        snapshot = await run_in_threadpool(svc.start_restore, record)
    except backup.BackupError as error:
        return api_error(str(error), 409)
    return JSONResponse({"ok": True, "record": snapshot, "message": "恢复已启动，完成后建议重启服务"}, status_code=202)


# ===========================================================================
# 业务 API（保持原有接口不变）
# ===========================================================================
@app.get("/api/bootstrap", response_class=JSONResponse)
async def api_bootstrap(request: Request) -> JSONResponse:
    projects = fetch_project_list()
    active_project = get_project_or_404(projects[0]["id"]) if projects else default_project_payload()
    user = current_user(request)
    usage_memory = authdb.list_usage_memory(user["id"]) if user else []
    return JSONResponse(
        {
            "configs": fetch_all_configs(),
            "projects": projects,
            "active_project": active_project,
            "group_meta": GROUP_META,
            "user": user,
            "usage_memory": usage_memory,
        }
    )


@app.get("/api/configs", response_class=JSONResponse)
async def api_get_configs() -> JSONResponse:
    return JSONResponse(fetch_all_configs())


@app.post("/api/configs/{category}", response_class=JSONResponse)
async def api_create_config_item(category: str, payload: dict[str, Any]) -> JSONResponse:
    validated = validate_config_payload(category, payload)
    record = build_config_record(category, validated)
    with get_db() as conn:
        max_sort = conn.execute(
            "SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM config_items WHERE category = ?",
            (category,),
        ).fetchone()["max_sort"]
        timestamp = now_iso()
        cursor = conn.execute(
            """
            INSERT INTO config_items (
                category, value, note, brand, series, metadata_json, sort_order, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                category,
                record["value"],
                record["note"],
                record["brand"],
                record["series"],
                record["metadata_json"],
                max_sort + 1,
                timestamp,
                timestamp,
            ),
        )
    return JSONResponse({"ok": True, "item_id": cursor.lastrowid, "configs": fetch_all_configs()})


@app.put("/api/configs/{item_id}", response_class=JSONResponse)
async def api_update_config_item(item_id: int, payload: dict[str, Any]) -> JSONResponse:
    with get_db() as conn:
        current = conn.execute(
            "SELECT category FROM config_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="配置项不存在")
        validated = validate_config_payload(current["category"], payload)
        record = build_config_record(current["category"], validated)
        conn.execute(
            """
            UPDATE config_items
            SET value = ?, note = ?, brand = ?, series = ?, metadata_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                record["value"],
                record["note"],
                record["brand"],
                record["series"],
                record["metadata_json"],
                now_iso(),
                item_id,
            ),
        )
    return JSONResponse({"ok": True, "configs": fetch_all_configs()})


@app.delete("/api/configs/{item_id}", response_class=JSONResponse)
async def api_delete_config_item(item_id: int) -> JSONResponse:
    with get_db() as conn:
        deleted = conn.execute("DELETE FROM config_items WHERE id = ?", (item_id,))
    if deleted.rowcount == 0:
        raise HTTPException(status_code=404, detail="配置项不存在")
    return JSONResponse({"ok": True, "configs": fetch_all_configs()})


@app.get("/api/projects", response_class=JSONResponse)
async def api_get_projects() -> JSONResponse:
    return JSONResponse({"projects": fetch_project_list()})


@app.get("/api/projects/{project_id}", response_class=JSONResponse)
async def api_get_project(project_id: str) -> JSONResponse:
    return JSONResponse(get_project_or_404(project_id))


@app.delete("/api/projects/{project_id}", response_class=JSONResponse)
async def api_delete_project(project_id: str) -> JSONResponse:
    with get_db() as conn:
        deleted = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        remaining = conn.execute(
            """
            SELECT id, name, description, created_at, updated_at
            FROM projects
            ORDER BY updated_at DESC
            """
        ).fetchall()
    if deleted.rowcount == 0:
        raise HTTPException(status_code=404, detail="项目不存在")
    projects = [dict(row) for row in remaining]
    active_project = get_project_or_404(projects[0]["id"]) if projects else None
    return JSONResponse({"ok": True, "projects": projects, "active_project": active_project})


@app.post("/api/projects", response_class=JSONResponse)
async def api_create_project(payload: ProjectSavePayload) -> JSONResponse:
    timestamp = now_iso()
    project_id = uuid.uuid4().hex
    normalized_data = rebalance_project_data(payload.data)
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO projects (id, name, description, data_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                payload.name.strip(),
                payload.description.strip(),
                dump_project_data(normalized_data),
                timestamp,
                timestamp,
            ),
        )
    return JSONResponse(
        {
            "ok": True,
            "project": get_project_or_404(project_id),
            "projects": fetch_project_list(),
        }
    )


@app.put("/api/projects/{project_id}", response_class=JSONResponse)
async def api_update_project(project_id: str, payload: ProjectSavePayload, request: Request) -> JSONResponse:
    user = current_user(request)
    normalized_data = rebalance_project_data(payload.data)
    # 用途记忆：保存项目时把非空用途沉淀为候选（异步友好：批量 upsert）
    if user:
        seen: set[str] = set()
        for group_rows in normalized_data["groups"].values():
            for row in group_rows:
                usage = row.get("usage", "").strip()
                if usage and usage not in seen:
                    seen.add(usage)
                    authdb.remember_usage(user["id"], usage, str(row.get("capacity_kw", "")))
    with get_db() as conn:
        updated = conn.execute(
            """
            UPDATE projects
            SET name = ?, description = ?, data_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                payload.name.strip(),
                payload.description.strip(),
                dump_project_data(normalized_data),
                now_iso(),
                project_id,
            ),
        )
    if updated.rowcount == 0:
        raise HTTPException(status_code=404, detail="项目不存在")
    return JSONResponse(
        {
            "ok": True,
            "project": get_project_or_404(project_id),
            "projects": fetch_project_list(),
        }
    )


@app.post("/api/projects/{project_id}/duplicate", response_class=JSONResponse)
async def api_duplicate_project(project_id: str) -> JSONResponse:
    source = get_project_or_404(project_id)
    # 截断到限长内再拼接后缀，避免源名接近 120 字符时 422
    base_name = source["name"][:110]
    duplicated_name = f"{base_name} - 副本"
    payload = ProjectSavePayload(
        name=duplicated_name,
        description=source["description"],
        data=source["data"],
    )
    return await api_create_project(payload)


@app.post("/api/projects/{project_id}/set-template", response_class=JSONResponse)
async def api_set_template(project_id: str, payload: dict[str, Any]) -> JSONResponse:
    is_template = bool(payload.get("is_template"))
    with get_db() as conn:
        updated = conn.execute(
            "UPDATE projects SET is_template = ?, updated_at = ? WHERE id = ?",
            (1 if is_template else 0, now_iso(), project_id),
        )
    if updated.rowcount == 0:
        raise HTTPException(status_code=404, detail="项目不存在")
    return JSONResponse(
        {
            "ok": True,
            "is_template": is_template,
            "projects": fetch_project_list(),
        }
    )


@app.post("/api/rebalance", response_class=JSONResponse)
async def api_rebalance(payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"ok": True, "data": rebalance_project_data(payload)})


if __name__ == "__main__":
    import uvicorn

    # 与 Dockerfile 一致：无热重载。reload 子进程会缓存旧代码（曾导致门禁不生效），
    # 且吞掉 lifespan 的 stdout（种子管理员初始密码打日志依赖它）
    uvicorn.run(app, host="0.0.0.0", port=8000)
