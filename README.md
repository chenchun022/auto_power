# auto_power

一个基于 FastAPI 的电力负荷与电器系统图计算工具。

当前版本包含两类能力：

- 负荷计算：输入 `Pe / Kx / cos`，计算 `Pjs / Ijs`
- 电器系统图计算：
  - 按 `N / P / S / WL` 分组录入回路
  - 自动相序平衡
  - 自动计算总容量、`Pjs`、`Ijs`
  - 项目草稿自动保存
  - SQLite 配置与项目库

## 目录说明

- `main.py`：FastAPI 应用入口
- `templates/`：页面模板
- `config/app.db`：SQLite 数据库
- `Dockerfile`：容器构建文件
- `docker-compose.yaml`：容器编排文件

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
- Tailwind CSS（CDN）

## 说明

- 应用已改为 `lifespan` 启动方式，不再使用已弃用的 `@app.on_event("startup")`
- 默认监听端口为 `8000`
- Docker 对外映射端口为 `9548`
