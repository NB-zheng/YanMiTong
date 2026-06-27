# 研密通

高校科研数据可信共享与审计平台

## 环境配置命令

建议**Python**版本: **3.12.10**

```bash
pip install -r backend/requirements.txt
```

## 终端启动命令（需先配置环境）

```bash
cd backend/src && uvicorn main:app --reload --port 8000
```

## Docker启动命令（无需配置环境）

```bash
#构建并启动
docker-compose up -d --build
```
