"""数据总管：SQLAlchemy 引擎 + 8 张核心表 ORM 模型。

说明：
- 所有 datetime 字段统一使用北京时间（见 tools.now_bj）。
- User 表不存角色，角色挂在 ProjectMember 上（项目级身份）。
- 撤销策略：仅强撤销 —— 撤销时重新生成文件密钥 K'，重加密文件，
  对剩余有效授权重新封装，FileMeta.version 递增。
"""
import os
import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from tools import now_bj


Base = declarative_base()


class User(Base):
    """用户表：仅保存身份与 SM2 密钥，角色挂在 ProjectMember。"""
    __tablename__ = "user"

    user_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    username = sa.Column(sa.String(50), unique=True, nullable=False, index=True)
    password_hash = sa.Column(sa.String(128), nullable=False)
    organization = sa.Column(sa.String(100))

    # SM2 公钥 hex 字符串（注册时由 crypto_adapter.sm2_generate_keypair 生成）
    public_key = sa.Column(sa.Text, nullable=False)
    # SM4 加密后的 SM2 私钥（加密密钥 = SM3(password)）；数据库永不存明文私钥
    encrypted_private_key = sa.Column(sa.Text, nullable=False)

    created_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)


class Project(Base):
    """项目表。"""
    __tablename__ = "project"

    project_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    project_name = sa.Column(sa.String(100), nullable=False)
    owner_id = sa.Column(sa.Integer, sa.ForeignKey("user.user_id"), nullable=False)
    description = sa.Column(sa.Text)
    created_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)


class ProjectMember(Base):
    """项目成员表：用户在某个项目中的角色与状态。"""
    __tablename__ = "project_member"

    project_id = sa.Column(sa.Integer, sa.ForeignKey("project.project_id"), primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("user.user_id"), primary_key=True)
    # owner / member / auditor
    # - owner:   项目唯一负责人，拥有项目一切权利（含审计/取证）
    # - member:  只能下载被授权的文件
    # - auditor: 只能查看审计/告警/取证，可下载被授权的文件，不可上传
    role = sa.Column(sa.String(20), nullable=False)
    # active / removed
    status = sa.Column(sa.String(20), default="active", nullable=False)
    joined_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)


class FileMeta(Base):
    """文件元数据表：加密后科研数据。"""
    __tablename__ = "file_meta"

    file_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    project_id = sa.Column(sa.Integer, sa.ForeignKey("project.project_id"), nullable=False)
    uploader_id = sa.Column(sa.Integer, sa.ForeignKey("user.user_id"), nullable=False)

    original_filename = sa.Column(sa.String(255), nullable=False)
    # pdf / docx / image / zip / csv / other —— 决定水印器
    file_type = sa.Column(sa.String(20), nullable=False)
    file_size = sa.Column(sa.Integer, nullable=False)

    cipher_path = sa.Column(sa.String(255), nullable=False)
    sm3_hash = sa.Column(sa.String(64), nullable=False)        # SM3(明文) hex
    sm2_signature = sa.Column(sa.Text, nullable=False)          # SM2 上传者签名 hex

    # 强撤销时递增；旧 cipher_path 失效
    version = sa.Column(sa.Integer, default=1, nullable=False)
    created_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)


class Authorization(Base):
    """授权表 + SM2 封装的文件密钥。"""
    __tablename__ = "authorization"

    auth_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    file_id = sa.Column(sa.Integer, sa.ForeignKey("file_meta.file_id"), nullable=False)
    grantee_id = sa.Column(sa.Integer, sa.ForeignKey("user.user_id"), nullable=False)
    grantor_id = sa.Column(sa.Integer, sa.ForeignKey("user.user_id"), nullable=False)

    # base64 编码的 SM2_Encrypt(PK_grantee, K)
    encrypted_file_key = sa.Column(sa.Text, nullable=False)
    # 当前授权对应的文件版本（强撤销时旧版本仍可保留作历史）
    file_version = sa.Column(sa.Integer, nullable=False, default=1)

    # read / download / transfer
    permission = sa.Column(sa.String(20), default="download", nullable=False)
    expire_time = sa.Column(sa.DateTime, nullable=False)
    max_downloads = sa.Column(sa.Integer)                  # null = 不限
    used_downloads = sa.Column(sa.Integer, default=0, nullable=False)

    # valid / revoked / expired
    status = sa.Column(sa.String(20), default="valid", nullable=False)
    created_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)
    revoked_time = sa.Column(sa.DateTime)
    # 撤销模式：NULL=未撤销；"weak"=弱撤销（仅标记，可恢复）；"strong"=强撤销（重加密，不可恢复）
    revoke_mode = sa.Column(sa.String(10), nullable=True)


class WatermarkRecord(Base):
    """下载副本指纹映射，用于泄露取证。"""
    __tablename__ = "watermark_record"

    watermark_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    file_id = sa.Column(sa.Integer, sa.ForeignKey("file_meta.file_id"), nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("user.user_id"), nullable=False)

    fingerprint = sa.Column(sa.String(64), nullable=False, index=True)
    salt = sa.Column(sa.String(32), nullable=False)             # 取证时重算指纹用
    watermark_type = sa.Column(sa.String(20), nullable=False)   # pdf_meta / docx_prop / image_lsb...
    client_ip = sa.Column(sa.String(45))
    download_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)


class AuditLog(Base):
    """SM3 哈希链审计日志，按项目分链。

    user_id 不加 FK 防止级联删除截断链条；project_id 同理用裸 Integer，
    哪怕项目被删，旧日志仍可作为历史证据保留。
    系统级事件（注册/登录/改密码）不写入本表。
    """
    __tablename__ = "audit_log"

    log_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    project_id = sa.Column(sa.Integer, nullable=False, index=True)
    user_id = sa.Column(sa.Integer, nullable=False)
    operation = sa.Column(sa.String(50), nullable=False)
    object_type = sa.Column(sa.String(20))      # file / project / auth / member
    object_id = sa.Column(sa.String(50))
    result = sa.Column(sa.String(20), nullable=False)   # success / denied / failed
    detail = sa.Column(sa.Text)                  # JSON 字符串
    timestamp = sa.Column(sa.DateTime, default=now_bj, nullable=False)

    prev_hash = sa.Column(sa.String(64), nullable=False)
    current_hash = sa.Column(sa.String(64), nullable=False)


class Alert(Base):
    """异常访问告警，按项目划分。"""
    __tablename__ = "alert"

    alert_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    project_id = sa.Column(sa.Integer, nullable=False, index=True)
    user_id = sa.Column(sa.Integer)
    # high_freq_download / access_after_revoke / verify_fail / abnormal_ip
    alert_type = sa.Column(sa.String(30), nullable=False)
    severity = sa.Column(sa.String(10), default="medium", nullable=False)
    message = sa.Column(sa.Text)
    related_log_id = sa.Column(sa.Integer, sa.ForeignKey("audit_log.log_id"))
    created_time = sa.Column(sa.DateTime, default=now_bj, nullable=False)
    handled = sa.Column(sa.Boolean, default=False, nullable=False)


# ===== 引擎与 Session =====
_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(_DB_DIR, exist_ok=True)
os.makedirs(os.path.join(_DB_DIR, "storage"), exist_ok=True)

DB_URL = f"sqlite:///{os.path.join(_DB_DIR, 'yantong.db')}"
engine = sa.create_engine(DB_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """建表（已存在则跳过）。

    schema 有变更时直接删除 data/yantong.db 重启即可，不做在线迁移。
    """
    Base.metadata.create_all(engine)


def get_db():
    """FastAPI Depends 用：每个请求开一个 Session。"""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


STORAGE_DIR = os.path.join(_DB_DIR, "storage")
