# auto_power

一个基于 FastAPI 的电力负荷与电器系统图计算工具。

当前版本包含以下能力：

- 负荷计算：输入 `Pe / Kx / cos`，计算 `Pjs / Ijs`
- 电器系统图计算：
  - 按 `N / P / S / WL` 分组录入回路
  - 回路编号按组内位置自动生成（`N1、N2、…`），新增/删除/移动后自动重排
  - 自动相序平衡
  - 自动计算总容量、`Pjs`、`Ijs`
  - 项目草稿自动保存
  - SQLite 配置与项目库
- 账号体系（V1.3.0）：
  - 注册（邮箱强制验证 + 用户名 + 两次密码 + 强密码校验）
  - 登录（用户名或邮箱 + 密码错误次数锁定）
  - 会话使用 HttpOnly Cookie（HTTPS 下自动启用 `__Host-` 前缀）
- 用途智能记忆（V1.3.0）：
  - 录入过的"用途"自动沉淀为个人候选库
  - 支持汉字 / 全拼 / 拼音首字母 / 混合匹配（基于开源库 [pinyin-pro](https://github.com/pink-pink/pinyin-pro)）
  - 候选浮层：↑↓ 选择、Enter 选中、ESC 关闭；点击候选后容量列聚焦时自动带出容量建议

## 安全机制（V1.3.0）

| 威胁 | 防护 |
| --- | --- |
| 密码泄露 | bcrypt cost=12 哈希存储，库中无明文 |
| 密码爆破 | 账号 15 分钟内 5 次失败即锁定 15 分钟；IP 级限速 |
| 数据库注入 | 全量 SQL 参数化（`?` 占位符），无字符串拼接 |
| 逆向登录接口 | 统一错误文案（不区分账号不存在/密码错误）、邮箱注册枚举防护、验证码 5 次错误作废 |
| 明文传输 | 密码仅在 POST body 中一次性提交（不落 URL/日志）；生产部署应启用 HTTPS（Cookie 自动 Secure） |
| 跨站请求 | 会话 Cookie `HttpOnly + SameSite=Lax` |
| 接口滥用 | 全局 IP 限流（240 次/分钟）、注册发码 10 次/小时、登录 30 次/分钟 |

## 目录说明

- `main.py`：FastAPI 应用入口
- `security.py`：密码/会话/限流/校验安全基座
- `authdb.py`：用户、会话、验证码、用途记忆数据层
- `mailer.py`：SMTP 发信（465 隐式 TLS / STARTTLS 自适应）
- `templates/`：页面模板（`index.html` 主工具、`login.html` 登录注册）
- `static/pinyin-pro.local.js`：拼音匹配库（MIT，本地化运行，无外网 CDN 依赖）
- `static/tailwind.local.js`：Tailwind 运行时本地化副本
- `static/font-awesome.min.css` + `static/fonts/`：图标字体本地化副本
- `config/app.db`：SQLite 数据库
- `config/smtp.json.example`：SMTP 配置模板（也可由管理员登录后在网页「设置 → 邮箱服务」中在线配置，推荐后者）
- `test_v13.py`：集成测试（32 项断言）
- `test_flow.py`：完整流程测试（18 项断言，含 Mock SMTP 真实发信链路）
- `test_admin.py`：管理员/门禁/SMTP 管理测试（30 项断言）
- `test_seed.py`：种子管理员与账号设置测试（17 项断言）
- `Dockerfile`：容器构建文件
- `docker-compose.yaml`：容器编排文件

## 首次部署：管理员引导

> 另有「备份与恢复（R2/S3）」：管理员在用户菜单中配置 Cloudflare R2 / MinIO 等 S3 兼容存储，
> 支持手动/定时（cron）备份、双重保留策略自动清理、预签名下载、一键恢复（自动留 .bak 后悔药）。
> 备份内容 = SQLite VACUUM INTO 一致性快照 + config 目录（smtp.json 等）。见 `backup.py` / `r2backup.py`。

1. 启动容器（或本地运行）。空库时自动创建种子管理员，两种方式设定凭据：
   - **环境变量（推荐）**：compose 中设置 `ADMIN_USERNAME` / `ADMIN_PASSWORD`
   - **自动生成**：不设 `ADMIN_PASSWORD` 时生成 16 位随机密码并打进日志，用
     `docker logs auto_power | grep 初始密码`（或本地控制台输出）获取
2. 用种子凭据登录 → 头部「账号设置」修改用户名与密码（改密后全部会话失效，需重新登录）
3. 「设置 → 邮箱服务（SMTP）」配置邮件服务器并「发送测试邮件」验证，之后用户即可自助注册

种子账号仅在空库时创建一次；已有用户的库重启不会重复创建，环境变量也不会覆盖既有账号。

## 邮箱验证配置

推荐由管理员在网页「设置 → 邮箱服务（SMTP）」中在线配置并测试（密码不回传前端，留空保存沿用旧值）。
也可手工复制模板：

```powershell
copy config\smtp.json.example config\smtp.json
```

```json
{
  "host": "smtp.example.com",
  "port": 465,
  "username": "noreply@example.com",
  "password": "your-smtp-password",
  "from_email": "noreply@example.com",
  "from_name": "电力负荷计算工具",
  "use_tls": true
}
```

`use_tls: true` 走 465 隐式 TLS（对端实为 STARTTLS 端口时自动降级重试）；`false` 走明文连接并机会式 STARTTLS 升级。

## 本地开发

### 1. 创建并激活虚拟环境

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. 安装依赖

```powershell
pip install -r requirements.txt
```

### 3. 启动项目

```powershell
python main.py
```

启动后访问：

```text
http://127.0.0.1:8000
```

### 4. 运行测试

```powershell
python test_v13.py
```

## Docker 启动

### 构建并启动

```powershell
docker compose up -d --build
```

启动后访问：

```text
http://127.0.0.1:9548
```

### 停止容器

```powershell
docker compose down
```

## 数据持久化

项目数据和配置数据存放在：

```text
config/app.db
```

`docker-compose.yaml` 已将本地 `./config` 挂载到容器 `/app/config`，因此容器重建后数据仍会保留。

## 主要技术栈

- FastAPI
- Jinja2
- SQLite
- Gunicorn + Uvicorn Worker
- Tailwind CSS（本地化运行时，无外网依赖）

## 说明

- 应用已改为 `lifespan` 启动方式，不再使用已弃用的 `@app.on_event("startup")`
- 默认监听端口为 `8000`
- Docker 对外映射端口为 `9548`
