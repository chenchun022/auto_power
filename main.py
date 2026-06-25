import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field


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


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title=APP_TITLE, lifespan=lifespan)

os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


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
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
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
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

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


def serialize_project_row(row: sqlite3.Row) -> dict[str, Any]:
    data = json.loads(row["data_json"])
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
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
    capacity_value = row.get("capacity_kw", "")
    voltage = str(row.get("voltage", "220"))
    return {
        "id": row.get("id") or uuid.uuid4().hex,
        "group_type": group_code,
        "sequence": index + 1,
        "circuit_code": f"{group_code}{index + 1}",
        "breaker_option": str(row.get("breaker_option", "")),
        "wire_option": str(row.get("wire_option", "")),
        "phase_sequence": str(row.get("phase_sequence", "")),
        "usage": str(row.get("usage", "")),
        "capacity_kw": normalize_number(capacity_value, default=""),
        "voltage": "380" if voltage == "380" else "220",
        "socket_type": str(row.get("socket_type", "")),
    }


def normalize_number(value: Any, default: Any = 0, keep_int: bool = False) -> Any:
    if value in (None, ""):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if keep_int and number.is_integer():
        return int(number)
    return round(number, 4)


def normalize_project_data(data: dict[str, Any] | None) -> dict[str, Any]:
    groups = default_groups()
    input_groups = (data or {}).get("groups", {})
    for group_code in GROUP_META:
        rows = input_groups.get(group_code, [])
        normalized_rows = [
            normalize_row(row, group_code, index) for index, row in enumerate(rows)
        ]
        groups[group_code] = normalized_rows

    result = {
        "filters": {
            "breaker_brand": str((data or {}).get("filters", {}).get("breaker_brand", "")),
            "wire_brand": str((data or {}).get("filters", {}).get("wire_brand", "")),
        },
        "load_factors": {
            "kx": normalize_number((data or {}).get("load_factors", {}).get("kx"), default=1),
            "cos": normalize_number((data or {}).get("load_factors", {}).get("cos"), default=0.8),
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
    groups = project_data.get("groups", {})
    normalized_groups = default_groups()
    phase_totals = {phase: 0.0 for phase in PHASES}
    total_capacity = 0.0
    row_count = 0
    load_factors = {
        "kx": normalize_number(project_data.get("load_factors", {}).get("kx"), default=1),
        "cos": normalize_number(project_data.get("load_factors", {}).get("cos"), default=0.8),
    }

    for group_code in GROUP_META:
        rows = groups.get(group_code, [])
        normalized_rows = [normalize_row(row, group_code, index) for index, row in enumerate(rows)]
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
            "breaker_brand": str(project_data.get("filters", {}).get("breaker_brand", "")),
            "wire_brand": str(project_data.get("filters", {}).get("wire_brand", "")),
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
        metadata = json.loads(row["metadata_json"] or "{}")
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
            SELECT id, name, description, created_at, updated_at
            FROM projects
            ORDER BY updated_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


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


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    context = {
        "request": request,
        "app_title": APP_TITLE,
        "group_meta": GROUP_META,
    }
    return templates.TemplateResponse("index.html", context)


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
        "request": request,
        "app_title": APP_TITLE,
        "group_meta": GROUP_META,
        "pe": pe,
        "kx": kx,
        "cos": cos,
        "pjs": pjs,
        "ljs": ljs,
    }
    return templates.TemplateResponse("index.html", context)


@app.get("/api/bootstrap", response_class=JSONResponse)
async def api_bootstrap() -> JSONResponse:
    projects = fetch_project_list()
    active_project = get_project_or_404(projects[0]["id"]) if projects else default_project_payload()
    return JSONResponse(
        {
            "configs": fetch_all_configs(),
            "projects": projects,
            "active_project": active_project,
            "group_meta": GROUP_META,
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
                json.dumps(normalized_data, ensure_ascii=False),
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
async def api_update_project(project_id: str, payload: ProjectSavePayload) -> JSONResponse:
    normalized_data = rebalance_project_data(payload.data)
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
                json.dumps(normalized_data, ensure_ascii=False),
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
    duplicated_name = f"{source['name']} - 副本"
    payload = ProjectSavePayload(
        name=duplicated_name,
        description=source["description"],
        data=source["data"],
    )
    return await api_create_project(payload)


@app.post("/api/rebalance", response_class=JSONResponse)
async def api_rebalance(payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"ok": True, "data": rebalance_project_data(payload)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
