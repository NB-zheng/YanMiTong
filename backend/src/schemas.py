"""Pydantic 数据契约：接口入参出参。

设计原则：
- 用户对外标识用 `username`，绝不暴露内部 user_id。
- 密码学内部细节（SM3 摘要、SM2 签名、密文路径、密钥包等）不出现在响应里。
"""
from __future__ import annotations

import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ===== Auth =====
class RegisterReq(BaseModel):
    username: str = Field(min_length=2, max_length=50)
    password: str = Field(min_length=6, max_length=64)
    organization: Optional[str] = None


class LoginReq(BaseModel):
    username: str
    password: str


class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str = Field(min_length=6, max_length=64)


class UpdateMeReq(BaseModel):
    username: Optional[str] = Field(default=None, min_length=2, max_length=50)
    organization: Optional[str] = Field(default=None, max_length=100)


class TokenResp(BaseModel):
    token: str
    username: str


# ===== User =====
class UserOut(BaseModel):
    username: str
    organization: Optional[str] = None
    created_time: datetime.datetime


# ===== Project =====
class ProjectCreateReq(BaseModel):
    project_name: str = Field(min_length=1, max_length=30)
    description: Optional[str] = Field(default=None, max_length=200)


class ProjectUpdateReq(BaseModel):
    project_name: Optional[str] = Field(default=None, min_length=1, max_length=30)
    description: Optional[str] = Field(default=None, max_length=200)


class ProjectOut(BaseModel):
    project_id: int
    project_name: str
    owner_username: str
    description: Optional[str] = None
    created_time: datetime.datetime
    # 当前访问者在本项目中的角色：owner / member / auditor / None（非成员）
    # 仅详情端点计算；列表端点恒为 None
    viewer_role: Optional[str] = None


class AddMemberReq(BaseModel):
    username: str
    # role 取值固定三个：owner / member / auditor。
    # owner 不允许通过 add_member 指定（项目唯一 owner 由创建者担任；转让功能本次未提供）。
    role: str = Field(pattern="^(member|auditor)$")


class ProjectMemberOut(BaseModel):
    project_id: int
    username: str
    role: str
    joined_time: datetime.datetime


# ===== File =====
class FileMetaOut(BaseModel):
    file_id: int
    project_id: int
    uploader_username: str
    original_filename: str
    file_type: str
    file_size: int
    version: int
    created_time: datetime.datetime


class UploadResp(BaseModel):
    file_id: int
    version: int


# ===== Authorization =====
class GrantReq(BaseModel):
    file_id: int
    grantee_username: str
    permission: str = Field(default="download", pattern="^(read|download|transfer)$")
    expire_minutes: int = Field(default=60 * 24 * 7, ge=1)
    max_downloads: Optional[int] = None


class RevokeReq(BaseModel):
    auth_id: int
    # mode:
    # - strong: 强撤销 —— 重生成 K'，重加密文件，重新封装剩余授权（默认）
    # - weak:   弱撤销 —— 仅标记 status=revoked，不重加密（适合临时协作到期）
    mode: str = Field(default="strong", pattern="^(strong|weak)$")


class RestoreReq(BaseModel):
    """恢复由弱撤销标记的授权（仅 owner 可调用）。"""
    auth_id: int


class AuthorizationOut(BaseModel):
    auth_id: int
    file_id: int
    grantee_username: str
    grantor_username: str
    permission: str
    expire_time: datetime.datetime
    max_downloads: Optional[int] = None
    used_downloads: int
    status: str
    file_version: int
    created_time: datetime.datetime
    revoked_time: Optional[datetime.datetime] = None
    # 撤销模式：NULL=未撤销 / "weak"=弱撤销（可恢复）/ "strong"=强撤销（不可恢复）
    revoke_mode: Optional[str] = None


# ===== Audit =====
class AuditLogOut(BaseModel):
    log_id: int
    project_id: int
    username: str
    operation: str
    object_type: Optional[str] = None
    object_label: Optional[str] = None
    result: str
    detail: Optional[str] = None
    timestamp: datetime.datetime


class ChainVerifyResp(BaseModel):
    ok: bool
    broken_at_log_id: int  # -1 表示无断裂
    total: int


# ===== Forensics =====
class ForensicsMatch(BaseModel):
    """单个指纹匹配结果"""
    username: str                      # 下载者用户名
    download_time: datetime.datetime   # 下载时间
    fingerprint: str                   # 指纹（64位hex，用于关联审计）
    client_ip: Optional[str] = None   # 下载时客户端IP
    file_id: int                      # 对应的文件ID


class ForensicsResp(BaseModel):
    matched: bool                                       # 是否有任何匹配
    matches: List[ForensicsMatch] = []                 # 所有匹配结果（按下载时间升序）
    total_count: int = 0                               # 匹配记录总数（包含同一人多次下载）
    leaker_count: int = 0                             # 泄露者人数（按用户去重）
    cross_project_count: int = 0                       # 属于其他项目的指纹数（无权查看）
    message: str


# ===== Alert =====
class AlertOut(BaseModel):
    alert_id: int
    project_id: int
    username: Optional[str] = None
    alert_type: str
    severity: str
    message: Optional[str] = None
    related_log_id: Optional[int] = None
    created_time: datetime.datetime
    handled: bool


# ===== 通用 =====
class OkResp(BaseModel):
    ok: bool = True
    message: str = "ok"
