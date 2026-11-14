"""SMTP 发信：移植自 D:\\python_tool\\licenserver\\lib\\mail\\smtp.ts 的连接策略。

- useTls=true 优先隐式 TLS（465 语义），对端实为 STARTTLS 明文端口时自动改走
  "明文连接 + requireTLS"；useTls=false 明文连接，服务器支持则机会式升级
- SMTP 配置从 config/smtp.json 读取（对应 licenserver 的 adminSetting 表），
  未配置时抛 SmtpNotConfiguredError
"""
import json
import smtplib
import ssl
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
SMTP_CONFIG_PATH = BASE_DIR / "config" / "smtp.json"
DEFAULT_SMTP_PORT = 587
CONNECT_TIMEOUT = 10


class SmtpNotConfiguredError(RuntimeError):
    pass


def load_smtp_config() -> dict[str, Any] | None:
    if not SMTP_CONFIG_PATH.exists():
        return None
    try:
        raw = json.loads(SMTP_CONFIG_PATH.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if not isinstance(raw, dict) or not str(raw.get("host", "")).strip():
        return None
    port = raw.get("port")
    return {
        "host": str(raw["host"]).strip(),
        "port": int(port) if isinstance(port, (int, str)) and str(port).isdigit() and int(port) > 0 else DEFAULT_SMTP_PORT,
        "username": str(raw.get("username", "")).strip(),
        "password": str(raw.get("password", "")),
        "from_email": str(raw.get("from_email", "")).strip(),
        "from_name": str(raw.get("from_name", "")).strip(),
        "use_tls": bool(raw.get("use_tls", False)),
    }


def save_smtp_config(config: dict[str, Any]) -> None:
    """管理员后台保存 SMTP 配置（写回 config/smtp.json，权限收紧到本人可读）。"""
    SMTP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SMTP_CONFIG_PATH.write_text(
        json.dumps(
            {
                "host": str(config.get("host", "")).strip(),
                "port": config.get("port", DEFAULT_SMTP_PORT),
                "username": str(config.get("username", "")).strip(),
                "password": str(config.get("password", "")),
                "from_email": str(config.get("from_email", "")).strip(),
                "from_name": str(config.get("from_name", "")).strip(),
                "use_tls": bool(config.get("use_tls", False)),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    try:
        SMTP_CONFIG_PATH.chmod(0o600)
    except OSError:
        pass  # Windows 上 chmod 语义有限，忽略即可


def send_test_mail(to_email: str, config: dict[str, Any] | None = None) -> None:
    """管理员后台『发送测试邮件』：用指定（或当前）配置投递一封测试信。"""
    _send_with_config(
        config or load_smtp_config() or {},
        to_email,
        "电力负荷计算工具 · SMTP 配置测试",
        "<p>这是一封测试邮件。收到它说明 SMTP 配置正确，邮箱验证码功能可以正常工作。</p>",
    )


def _build_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _is_implicit_tls_mismatch(error: Exception) -> bool:
    message = str(error).lower()
    return any(
        marker in message
        for marker in ("wrong version number", "ssl", "greeting", "unexpected socket")
    )


def _base_login(smtp: smtplib.SMTP, config: dict[str, Any]) -> None:
    if config["username"]:
        smtp.login(config["username"], config["password"])


def _send_with_config(config: dict[str, Any], to_email: str, subject: str, html: str) -> None:
    sender = config["from_email"] or config["username"]
    from_name = config["from_name"].replace('"', "")
    message = MIMEText(html, "html", "utf-8")
    message["Subject"] = Header(subject, "utf-8")
    message["From"] = formataddr((str(Header(from_name, "utf-8")), sender)) if from_name else sender
    message["To"] = to_email

    if config["use_tls"]:
        try:
            with smtplib.SMTP_SSL(config["host"], config["port"], timeout=CONNECT_TIMEOUT, context=_build_ssl_context()) as smtp:
                _base_login(smtp, config)
                smtp.sendmail(sender, [to_email], message.as_string())
            return
        except Exception as error:  # noqa: BLE001 - 需要区分 TLS 不匹配
            if _is_implicit_tls_mismatch(error):
                with smtplib.SMTP(config["host"], config["port"], timeout=CONNECT_TIMEOUT) as smtp:
                    smtp.starttls(context=_build_ssl_context())
                    _base_login(smtp, config)
                    smtp.sendmail(sender, [to_email], message.as_string())
                return
            raise

    with smtplib.SMTP(config["host"], config["port"], timeout=CONNECT_TIMEOUT) as smtp:
        # 明文连接：服务器支持 STARTTLS 则机会式升级（licenserver useTls=false 行为）。
        # P0修复：has_extn() 依赖 ESMTP 特性表，而该表只在 ehlo() 后才填充——
        # 此前缺 ehlo() 导致 has_extn 恒 False，STARTTLS 永不升级、凭据明文外发。
        smtp.ehlo()
        if smtp.has_extn("starttls"):
            smtp.starttls(context=_build_ssl_context())
            smtp.ehlo()  # TLS 重置会话，需重新握手获取特性表
        _base_login(smtp, config)
        smtp.sendmail(sender, [to_email], message.as_string())


def send_mail(to_email: str, subject: str, html: str) -> None:
    config = load_smtp_config()
    if not config:
        raise SmtpNotConfiguredError("SMTP 未配置：请编辑 config/smtp.json")
    _send_with_config(config, to_email, subject, html)


VERIFY_CODE_MAIL = """\
<div style="max-width:480px;margin:0 auto;font-family:system-ui,-apple-system,'Segoe UI',sans-serif">
  <div style="padding:32px 28px;border:1px solid #e5e7eb;border-radius:12px">
    <h2 style="margin:0 0 8px;font-size:18px;color:#165DFF">电力负荷计算工具 · 邮箱验证</h2>
    <p style="margin:0 0 20px;font-size:14px;color:#4b5563">您的注册验证码为：</p>
    <div style="font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;padding:16px;background:#f5f7fa;border-radius:8px;color:#1d2129">{code}</div>
    <p style="margin:16px 0 0;font-size:13px;color:#6b7280">验证码 24 小时内有效，5 次尝试失败后将作废。若非本人操作请忽略此邮件。</p>
  </div>
</div>
"""


def send_verify_code_mail(to_email: str, code: str) -> None:
    send_mail(to_email, "注册验证码", VERIFY_CODE_MAIL.replace("{code}", code))
