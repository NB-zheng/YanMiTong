"""认证 service：注册 / 登录 / 改密码 / Token 会话。

登录方案：
- 校验密码后，立即用密码派生出 SM2 私钥（SM3(pwd) 为 SM4 key 解出）放到内存会话表；
- 返回的 token 只对应当前进程内存中的私钥；进程重启需要重新登录。
"""
from __future__ import annotations

from typing import Optional
from sqlalchemy.orm import Session
from fastapi import Depends, Header, HTTPException, status

from database import User, get_db
from tools import gen_token, now_bj
import crypto_adapter as crypto


# 内存会话：token -> {user_id, username, sm2_private_key_hex}
_SESSIONS: dict[str, dict] = {}


def _pw_hash(password: str) -> str:
    """口令哈希：SM3(password)（占位用 SHA-256），加 salt 在 username 区分。"""
    return crypto.sm3_hash(password.encode("utf-8"))


def register(db: Session, username: str, password: str, organization: Optional[str]) -> User:
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "用户名已存在")

    priv_hex, pub_hex = crypto.sm2_generate_keypair()
    enc_priv = crypto.encrypt_private_key_with_password(priv_hex, password)

    u = User(
        username=username,
        password_hash=_pw_hash(password),
        organization=organization,
        public_key=pub_hex,
        encrypted_private_key=enc_priv,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def login(db: Session, username: str, password: str) -> tuple[str, User]:
    u = db.query(User).filter(User.username == username).first()
    if not u or u.password_hash != _pw_hash(password):
        raise HTTPException(401, "用户名或密码错误")

    # 派生 SM2 私钥进内存
    try:
        priv_hex = crypto.decrypt_private_key_with_password(u.encrypted_private_key, password)
    except Exception:
        raise HTTPException(500, "私钥解封失败，请联系管理员")

    token = gen_token()
    _SESSIONS[token] = {
        "user_id": u.user_id,
        "username": u.username,
        "sm2_private_key_hex": priv_hex,
        "login_time": now_bj(),
    }
    return token, u


def logout(token: str) -> None:
    _SESSIONS.pop(token, None)


def update_me(db: Session, user_id: int, new_username: Optional[str],
              new_organization: Optional[str], organization_provided: bool) -> User:
    """局部更新当前用户的资料字段。

    - username：传 None 表示不改；非 None 必须唯一
    - organization：通过 organization_provided 区分 "未传" 与 "显式置空"
      —— 显式传空字符串视为清空
    """
    u = db.query(User).get(user_id)
    if not u:
        raise HTTPException(404, "用户不存在")

    if new_username is not None and new_username != u.username:
        exists = db.query(User).filter(User.username == new_username).first()
        if exists:
            raise HTTPException(400, "用户名已存在")
        # 同步内存会话中的 username（其他字段不影响 session 有效性）
        for sess in _SESSIONS.values():
            if sess["user_id"] == u.user_id:
                sess["username"] = new_username
        u.username = new_username

    if organization_provided:
        u.organization = new_organization or None

    db.commit()
    db.refresh(u)
    return u


def change_password(db: Session, user_id: int, old_pwd: str, new_pwd: str) -> None:
    u = db.query(User).get(user_id)
    if not u:
        raise HTTPException(404, "用户不存在")
    if u.password_hash != _pw_hash(old_pwd):
        raise HTTPException(401, "原密码错误")
    # 用老密码解出私钥
    priv_hex = crypto.decrypt_private_key_with_password(u.encrypted_private_key, old_pwd)
    # 用新密码重新加密
    u.encrypted_private_key = crypto.encrypt_private_key_with_password(priv_hex, new_pwd)
    u.password_hash = _pw_hash(new_pwd)
    db.commit()


# ===== FastAPI 依赖 =====
def current_session(authorization: str = Header(default="")) -> dict:
    """从 Authorization: Bearer <token> 拿当前会话。"""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "缺少 Bearer Token")
    token = authorization[7:].strip()
    sess = _SESSIONS.get(token)
    if not sess:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token 无效或已过期")
    return sess


def current_user(sess: dict = Depends(current_session), db: Session = Depends(get_db)) -> User:
    u = db.query(User).get(sess["user_id"])
    if not u:
        raise HTTPException(401, "会话用户不存在")
    return u
