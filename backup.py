"""数据备份服务：SQLite 快照打包上传到 S3 兼容存储（R2/MinIO），支持恢复与定时。

移植自 CTA 项目 caa-v2/server/internal/caa/security/backup_http.go：
- S3 配置（endpoint/account_id/region/bucket/ak/sk/prefix/force_path_style）存 system_settings
- 定时配置（enabled + cron + retain_days + retain_count）
- 备份记录持久化（system_settings JSON，最多 200 条）
- 异步执行 + 进度（dumping/uploading），启动时恢复中断记录
- SQLite VACUUM INTO 一致性快照 + config 目录（smtp.json）打成一个 tar.gz
- 双重保留策略（按天数 + 按份数）自动清理
- 恢复：下载 → 校验 SQLite 头 → 原子替换 → 提示重启（本服务不自杀进程，
  由调用方决定；恢复后 SQLite 连接池里的旧连接由下次请求重新建立）
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import tarfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from croniter import croniter

import authdb
import r2backup
from r2backup import R2BackupClient

# system_settings 键
KEY_S3_CONFIG = "backup_s3_config"
KEY_SCHEDULE = "backup_schedule"
KEY_RECORDS = "backup_records"

MAX_RECORDS = 200
DEFAULT_RETAIN_DAYS = 30
SQLITE_HEADER = b"SQLite format 3\x00"


class BackupError(RuntimeError):
    pass


class BackupService:
    """进程内单例。所有公共方法线程安全。"""

    def __init__(self, db_path: Path, config_dir: Path) -> None:
        self.db_path = Path(db_path)
        self.config_dir = Path(config_dir)
        self._op_lock = threading.Lock()
        self._records_lock = threading.Lock()
        self.backing_up = False
        self.restoring = False
        self._timer: threading.Timer | None = None
        self._timer_lock = threading.Lock()

    # ---------- 配置读写 ----------

    def load_s3_config(self) -> dict[str, Any] | None:
        raw = authdb.get_setting(KEY_S3_CONFIG, "")
        if not raw.strip():
            return None
        try:
            cfg = json.loads(raw)
        except ValueError:
            return None
        return cfg if isinstance(cfg, dict) else None

    def save_s3_config(self, cfg: dict[str, Any]) -> None:
        authdb.set_setting(KEY_S3_CONFIG, json.dumps(cfg, ensure_ascii=False))

    @staticmethod
    def s3_configured(cfg: dict[str, Any] | None) -> bool:
        return bool(cfg) and all(str(cfg.get(k, "") or "").strip() for k in ("bucket", "access_key", "secret_key")) \
            and (str(cfg.get("endpoint", "") or "").strip() or str(cfg.get("account_id", "") or "").strip())

    def load_schedule(self) -> dict[str, Any]:
        raw = authdb.get_setting(KEY_SCHEDULE, "")
        try:
            cfg = json.loads(raw)
            return cfg if isinstance(cfg, dict) else {}
        except ValueError:
            return {}

    def save_schedule(self, cfg: dict[str, Any]) -> None:
        authdb.set_setting(KEY_SCHEDULE, json.dumps(cfg, ensure_ascii=False))

    # ---------- 记录持久化 ----------

    def load_records(self) -> list[dict[str, Any]]:
        raw = authdb.get_setting(KEY_RECORDS, "")
        try:
            records = json.loads(raw)
            return records if isinstance(records, list) else []
        except ValueError:
            return []

    def save_records(self, records: list[dict[str, Any]]) -> None:
        authdb.set_setting(KEY_RECORDS, json.dumps(records, ensure_ascii=False))

    def _save_record(self, record: dict[str, Any]) -> None:
        with self._records_lock:
            records = self.load_records()
            for i, r in enumerate(records):
                if r["id"] == record["id"]:
                    records[i] = record
                    break
            else:
                records.append(record)
            if len(records) > MAX_RECORDS:
                records = records[-MAX_RECORDS:]
            self.save_records(records)

    def find_record(self, record_id: str) -> dict[str, Any] | None:
        for r in self.load_records():
            if r["id"] == record_id:
                return r
        return None

    # ---------- 启动恢复 ----------

    def recover_stale_records(self) -> None:
        """启动时把重启前中断的 running 记录标记为 failed。"""
        with self._records_lock:
            records = self.load_records()
            changed = False
            now = int(time.time())
            for r in records:
                if r.get("status") == "running":
                    r["status"] = "failed"
                    r["error_message"] = "服务重启导致备份中断"
                    r["progress"] = ""
                    r["finished_at"] = now
                    changed = True
                if r.get("restore_status") == "running":
                    r["restore_status"] = "failed"
                    r["restore_error"] = "服务重启导致恢复中断"
                    changed = True
            if changed:
                self.save_records(records)

    # ---------- 定时调度 ----------

    def start_scheduler(self) -> None:
        self.recover_stale_records()
        self.apply_schedule()

    def apply_schedule(self) -> None:
        """按配置计算下次触发时间，安排一次性 Timer（无 cron 长驻线程）。"""
        with self._timer_lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            cfg = self.load_schedule()
            if not cfg.get("enabled"):
                return
            expr = str(cfg.get("cron_expr", "") or "").strip()
            if not expr:
                return
            try:
                cron = croniter(expr, datetime.now(timezone.utc))
                next_at = cron.get_next(float)
            except (ValueError, KeyError):
                print(f"[backup] 无效 cron 表达式，定时备份未生效: {expr}")
                return
            delay = max(next_at - time.time(), 1.0)
            self._timer = threading.Timer(delay, self._run_scheduled)
            self._timer.daemon = True
            self._timer.start()

    def _run_scheduled(self) -> None:
        try:
            self.start_backup("scheduled")
        except BackupError as error:
            if "正在进行" not in str(error):
                print(f"[backup] 定时备份失败: {error}")
        finally:
            self.apply_schedule()  # 重新安排下一次

    # ---------- 备份执行 ----------

    def start_backup(self, triggered_by: str) -> dict[str, Any]:
        """异步启动备份，立即返回记录（status=running）。"""
        with self._op_lock:
            if self.backing_up or self.restoring:
                raise BackupError("已有备份或恢复正在进行中")
            self.backing_up = True
        try:
            cfg = self.load_s3_config()
            if not self.s3_configured(cfg):
                raise BackupError("S3/R2 存储未配置：请先填写并保存存储配置")
            client = R2BackupClient(cfg)  # noqa: F841 - 提前校验凭据

            now = datetime.now(timezone.utc)
            schedule = self.load_schedule()
            retain_days = int(schedule.get("retain_days") or 0) or DEFAULT_RETAIN_DAYS
            record_id = now.strftime("%y%m%d%H%M%S") + f"-{now.microsecond % 10000:04d}"
            file_name = f"autopower_{now.strftime('%Y%m%d_%H%M%S')}.tar.gz"
            record = {
                "id": record_id,
                "status": "running",
                "backup_type": "sqlite",
                "file_name": file_name,
                "s3_key": self._build_s3_key(cfg, file_name, now),
                "size_bytes": 0,
                "triggered_by": triggered_by,
                "error_message": "",
                "started_at": int(now.timestamp()),
                "finished_at": 0,
                "expires_at": int((now + timedelta(days=retain_days)).timestamp()),
                "progress": "dumping",
                "restore_status": "",
                "restore_error": "",
                "restored_at": 0,
            }
            self._save_record(record)
        except Exception:
            with self._op_lock:
                self.backing_up = False
            raise

        worker = threading.Thread(target=self._execute_backup_safe, args=(record, cfg), daemon=True)
        worker.start()
        return record

    def _execute_backup_safe(self, record: dict[str, Any], cfg: dict[str, Any]) -> None:
        try:
            self._execute_backup(record, cfg)
            self.cleanup_old_backups()
        except Exception as error:  # noqa: BLE001 - 兜底，任何异常都要落记录
            record["status"] = "failed"
            record["error_message"] = f"internal error: {error}"
            record["progress"] = ""
            record["finished_at"] = int(time.time())
            self._save_record(record)
        finally:
            with self._op_lock:
                self.backing_up = False

    def _execute_backup(self, record: dict[str, Any], cfg: dict[str, Any]) -> None:
        client = R2BackupClient(cfg)
        with TemporaryDirectory(prefix="ap-backup-") as tmp:
            tmp_path = Path(tmp)
            # 1. SQLite VACUUM INTO 一致性快照
            record["progress"] = "dumping"
            self._save_record(record)
            snapshot = tmp_path / "app.db"
            self._sqlite_snapshot(snapshot)

            # 2. config 目录（smtp.json 等，排除 db 本体）
            config_dest = tmp_path / "config"
            config_dest.mkdir()
            for item in self.config_dir.glob("*"):
                if item.is_file() and item.name != "app.db" and not item.name.startswith("app.db-"):
                    (config_dest / item.name).write_bytes(item.read_bytes())

            # 3. 打包
            record["progress"] = "uploading"
            self._save_record(record)
            archive = tmp_path / "archive.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(snapshot, arcname="app.db")
                for item in config_dest.iterdir():
                    tar.add(item, arcname=f"config/{item.name}")
            size = archive.stat().st_size

            # 4. 上传（失败清理半成品）
            try:
                client.put_file(record["s3_key"], str(archive))
            except Exception as error:
                try:
                    client.remove(record["s3_key"])
                except Exception:  # noqa: BLE001
                    pass
                raise BackupError(f"上传失败: {error}") from error

            record["size_bytes"] = size
            record["status"] = "completed"
            record["progress"] = ""
            record["finished_at"] = int(time.time())
            self._save_record(record)

    def _sqlite_snapshot(self, output: Path) -> None:
        if not self.db_path.exists():
            raise BackupError(f"数据库文件不存在: {self.db_path}")
        uri = f"file:{self.db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("VACUUM INTO ?", (str(output),))
        finally:
            conn.close()

    @staticmethod
    def _build_s3_key(cfg: dict[str, Any], file_name: str, now: datetime) -> str:
        prefix = str(cfg.get("prefix", "") or "").strip(" /")
        if not prefix:
            prefix = "backups/autopower"
        return f"{prefix}/{now.strftime('%Y/%m/%d')}/{file_name}"

    # ---------- 恢复执行 ----------

    def start_restore(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._op_lock:
            if self.backing_up or self.restoring:
                raise BackupError("已有备份或恢复正在进行中")
            self.restoring = True
        record["restore_status"] = "running"
        record["restore_error"] = ""
        self._save_record(record)
        snapshot = dict(record)
        worker = threading.Thread(target=self._execute_restore_safe, args=(snapshot,), daemon=True)
        worker.start()
        return snapshot

    def _execute_restore_safe(self, record: dict[str, Any]) -> None:
        try:
            self._execute_restore(record)
        except Exception as error:  # noqa: BLE001
            record["restore_status"] = "failed"
            record["restore_error"] = str(error)
            self._save_record(record)
        finally:
            with self._op_lock:
                self.restoring = False

    def _execute_restore(self, record: dict[str, Any]) -> None:
        cfg = self.load_s3_config()
        client = R2BackupClient(cfg)
        with TemporaryDirectory(prefix="ap-restore-") as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "archive.tar.gz"
            try:
                client.get_to_file(record["s3_key"], str(archive))
            except Exception as error:
                raise BackupError(f"下载备份失败: {error}") from error
            with tarfile.open(archive, "r:gz") as tar:
                # 安全解包：拒绝路径穿越
                for member in tar.getmembers():
                    top = Path(member.name).parts[0] if member.name else ""
                    if member.name.startswith(("/", "\\")) or ".." in Path(member.name).parts or top not in ("app.db", "config"):
                        raise BackupError(f"备份包内含非法路径: {member.name}")
                tar.extractall(tmp_path)

            db_snapshot = tmp_path / "app.db"
            self._validate_sqlite_header(db_snapshot)
            # 替换线上库。Windows 下 rename 会因其他连接持有文件句柄失败
            # （WAL 句柄、sweeper 等），故用「备份→校验→SQLite backup API 覆写」：
            # 1) 先留 .bak 后悔药（复制，不动原文件 inode）
            bak = self.db_path.with_name(self.db_path.name + f".bak-{int(time.time())}")
            shutil.copyfile(self.db_path, bak)
            # 2) checkpoint + 关闭 WAL，把库收拢为单文件再覆写
            self._checkpoint_wal()
            # 3) 用 sqlite backup API 把快照覆写进目标库（对已存在库做逐页覆盖）
            try:
                src = sqlite3.connect(str(db_snapshot))
                dst = sqlite3.connect(str(self.db_path))
                src.backup(dst)
                dst.close()
                src.close()
            except sqlite3.Error as error:
                raise BackupError(f"覆写数据库失败: {error}") from error
            for suffix in ("-wal", "-shm"):
                p = self.db_path.with_name(self.db_path.name + suffix)
                p.unlink(missing_ok=True)
            # 恢复 config（smtp.json 等）
            config_src = tmp_path / "config"
            if config_src.is_dir():
                self.config_dir.mkdir(parents=True, exist_ok=True)
                for item in config_src.iterdir():
                    if item.is_file():
                        (self.config_dir / item.name).write_bytes(item.read_bytes())
            # 只保留最新一颗后悔药
            baks = sorted(self.config_dir.glob("app.db.bak-*"))
            for old in baks[:-1]:
                old.unlink(missing_ok=True)

        record["restore_status"] = "completed"
        record["restored_at"] = int(time.time())
        self._save_record(record)

    def _checkpoint_wal(self) -> None:
        """把 WAL 收拢进主库并切回 journal 模式，尽量释放 -wal/-shm 句柄。
        失败不阻断（Linux 上 replace 无锁问题，backup API 覆写也不依赖此步成功）。"""
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
        except sqlite3.Error:
            pass

    @staticmethod
    def _validate_sqlite_header(path: Path) -> None:
        try:
            with open(path, "rb") as f:
                header = f.read(16)
        except OSError as error:
            raise BackupError(f"读取恢复文件失败: {error}") from error
        if header != SQLITE_HEADER:
            raise BackupError("恢复文件不是有效的 SQLite 数据库")

    # ---------- 轮转 ----------

    def cleanup_old_backups(self) -> None:
        """双重保留策略：按份数 + 按天数，仅清理 completed 记录。"""
        schedule = self.load_schedule()
        retain_count = int(schedule.get("retain_count") or 0)
        retain_days = int(schedule.get("retain_days") or 0)
        if retain_count <= 0 and retain_days <= 0:
            return
        with self._records_lock:
            records = sorted(self.load_records(), key=lambda r: r.get("started_at", 0), reverse=True)
            now = int(time.time())
            keep: list[dict[str, Any]] = []
            victims: dict[str, dict[str, Any]] = {}
            for i, r in enumerate(records):
                should_delete = False
                if retain_count > 0 and i >= retain_count:
                    should_delete = True
                if retain_days > 0 and r.get("started_at", 0) > 0 and now - r["started_at"] > retain_days * 86400:
                    should_delete = True
                if should_delete and r.get("status") == "completed" and r.get("s3_key"):
                    victims[r["s3_key"]] = r
                else:
                    keep.append(r)
        if not victims:
            return
        cfg = self.load_s3_config()
        if not self.s3_configured(cfg):
            return
        try:
            client = R2BackupClient(cfg)
        except Exception:  # noqa: BLE001
            return
        for key, victim in victims.items():
            try:
                client.remove(key)
            except Exception:  # noqa: BLE001 - 删除失败保留记录便于重试
                keep.append(victim)
        with self._records_lock:
            self.save_records(keep)


# 进程内单例（main.py 启动时初始化）
service: BackupService | None = None


def init_service(db_path: Path, config_dir: Path) -> BackupService:
    global service
    if service is None:
        service = BackupService(db_path, config_dir)
    return service


def get_service() -> BackupService:
    if service is None:
        raise RuntimeError("备份服务未初始化")
    return service
