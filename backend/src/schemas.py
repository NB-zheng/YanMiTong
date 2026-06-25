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


class AddMemberReq(BaseModel):
    username: str
    role: str = Field(pattern="^(owner|member|partner|auditor)$")


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
class ForensicsResp(BaseModel):
    matched: bool                                       # 命中且属于本项目
    cross_project: bool = False                         # 命中但属于其它项目（无权查看）
    username: Optional[str] = None                      # 仅在 matched=true 时返回
    download_time: Optional[datetime.datetime] = None   # 仅在 matched=true 时返回
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
