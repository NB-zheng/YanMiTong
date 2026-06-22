# 研密通项目镜像
# 构建上下文：项目根目录（包含 backend/ 和 public/）
# 国内构建：base image / apt / pip 全部走镜像源

# DaoCloud 的 Docker Hub 公共镜像，国内拉取稳定
FROM docker.m.daocloud.io/library/python:3.12-slim

ENV TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
    PIP_TRUSTED_HOST=mirrors.aliyun.com

# 切换 apt 源到阿里云（兼容 bookworm 的 deb822 与旧 sources.list 两种格式），
# 安装 tzdata 使得容器内日志、文件 mtime 等系统时间也是北京时间
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends tzdata; \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime; \
    echo $TZ > /etc/timezone; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先单独 COPY 依赖描述并安装，利用层缓存：源码改动不会重装依赖
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# 应用源码（保持与开发期一致的目录结构，main.py 里相对路径才能找到 public 与 data）
COPY backend/src ./backend/src
COPY public ./public

# main.py 通过相对路径计算项目根：__file__ 在 /app/backend/src/main.py
# → 项目根 /app → 静态目录 /app/public、数据目录 /app/backend/data
WORKDIR /app/backend/src

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
