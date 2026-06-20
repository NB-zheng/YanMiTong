"""FastAPI 入口：注册路由 + CORS + 启动初始化 + 静态前端挂载。

调试入口：
- Swagger UI:    http://localhost:8000/docs
- ReDoc:         http://localhost:8000/redoc
- 极简前端:      http://localhost:8000/
- 健康检查:      http://localhost:8000/healthz
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from database import init_db
import crypto_adapter as crypto
from routers import api_auth, api_project, api_file, api_authz, api_audit


TAGS_METADATA = [
    {"name": "auth", "description": "用户注册 / 登录 / 改密码。登录后用 Authorization: Bearer <token> 访问其他接口。"},
    {"name": "project", "description": "项目与成员管理。角色不属于 User，而是属于 ProjectMember。"},
    {"name": "file", "description": "文件加密上传、授权下载（含水印）、泄露取证。"},
    {"name": "authz", "description": "细粒度授权与强撤销（重生成 K' + SM4 重加密 + SM2 重新封装）。"},
    {"name": "audit", "description": "SM3 哈希链日志 / 链完整性校验 / 异常告警。"},
]

APP_DESCRIPTION = """
**研密通后端** —— 面向高校科研数据的国产密码可信共享与审计平台。

### 核心能力
- **SM2 / SM3 / SM4 全栈国密**（队长 crypto_core 提供原语）
- **混合加密**：SM4 加密文件 + SM2 公钥封装文件密钥 K
- **细粒度授权 + 强撤销**：撤销时自动重生成 K' 并重新封装给剩余有效用户
- **数字指纹水印**：PDF / DOCX / 图片三类自动分发；泄露文件一键回溯下载者
- **SM3 哈希链审计**：每条日志含 prev_hash，篡改/删除即断链
- **异常告警**：撤销后访问、高频下载、签名校验失败、SM3 不匹配

### 演示账号
没有内置账号，请用 `/api/auth/register` 自行创建。

### Token 使用
登录返回 `token`。在 Swagger 右上角 **Authorize** 按钮里填 `Bearer <token>` 即可。
"""


app = FastAPI(
    title="研密通后端 API",
    description=APP_DESCRIPTION,
    version="0.2.0",
    openapi_tags=TAGS_METADATA,
    contact={"name": "郑志轩", "url": "https://github.com/"},
    swagger_ui_parameters={"persistAuthorization": True, "displayRequestDuration": True},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/healthz", tags=["meta"], summary="健康检查 + 国密内核状态")
def healthz():
    return {
        "status": "ok",
        "real_crypto_core": crypto.is_using_real_crypto(),
    }


app.include_router(api_auth.router)
app.include_router(api_project.router)
app.include_router(api_file.router)
app.include_router(api_authz.router)
app.include_router(api_audit.router)


# 极简前端：项目根 public/ 目录
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PUBLIC_DIR = os.path.join(_PROJECT_ROOT, "public")
if os.path.isdir(_PUBLIC_DIR):
    app.mount("/", StaticFiles(directory=_PUBLIC_DIR, html=True), name="public")
