# auto_power
用于工装商业用电的有功功率以及电流的计算

version: '3.8'

services:
  # 服务名：自定义（与你的应用相关，如 power-calculator-app）
  power-calculator-app:
    # 关键：拉取 Docker Hub 上的远程镜像（替换 <DOCKERHUB_USERNAME> 为你的 Docker Hub 用户名）
    # 标签可选：latest（最新版）或具体版本（如 v1.0.1，更适合生产环境固定版本）
    image: chenchun022/auto-power:latest
    # 容器名称：固定名称，便于管理（如查看日志、停止容器）
    container_name: power-calculator-app
    # 端口映射：主机端口:容器端口（与你的应用一致：容器内 8000，主机用 9548，避免冲突）
    ports:
      - "9548:8000"
    # 重启策略：生产级配置（容器挂掉自动重启，开机也自动启动）
    restart: always
    # 环境变量：必要配置（如时区，避免日志时间错乱）
    environment:
      - TZ=Asia/Shanghai  # 与你的 Dockerfile 时区配置保持一致
    # 日志配置：限制日志大小，避免磁盘占满（复用你之前的配置逻辑）
    logging:
      driver: "json-file"  # 日志格式为 JSON，便于解析
      options:
        max-size: "10m"    # 单个日志文件最大 10MB
        max-file: "3"      # 最多保留 3 个日志文件（超过自动删除旧日志）
