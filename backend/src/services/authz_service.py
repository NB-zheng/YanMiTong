"""授权 service：细粒度授权 + 撤销（强撤销 / 弱撤销）+ 恢复。

撤销权限：仅项目负责人 (owner) 可发起。
- 强撤销：重新生成 K'，重加密文件，重新封装剩余授权（密钥层彻底隔离）
- 弱撤销：仅标记 status=revoked，无密码学开销，可由 owner 恢复
"""
from __future__ import annotations

import os
from datetime import timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException

from database import Authorization, FileMeta, ProjectMember, User, STORAGE_DIR
from tools import now_bj, gen_uuid
import crypto_adapter as crypto
import services.audit_service as audit


def _load_auth_or_404(db: Session, auth_id: int) -> Authorization:
    auth = db.query(Authorization).get(auth_id)
    if not auth:
        raise HTTPException(404, "授权不存在")
    return auth


def _assert_owner_can_revoke(db: Session, grantor: User, auth: Authorization) -> FileMeta:
    """统一校验：调用方必须是项目负责人；目标授权不能是上传者自钥包；状态必须 valid。

    返回关联的 FileMeta 便于后续操作。
    """
    if auth.grantor_id == auth.grantee_id:
        # 上传者的自钥包是文件能被本人解密的物理前提，不允许撤销
        raise HTTPException(400, "不能撤销上传者的本人密钥")
    if auth.status != "valid":
        raise HTTPException(400, "该授权已非有效状态")

    fm = db.query(FileMeta).get(auth.file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")

    # 仅项目负责人 (owner) 可撤销
    grantor_pm = (
        db.query(ProjectMember)
        .filter_by(project_id=fm.project_id, user_id=grantor.user_id, status="active")
        .first()
    )
    if not grantor_pm or grantor_pm.role != "owner":
        audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                        operation="revoke", result="denied",
                        object_type="auth", object_id=str(auth.auth_id),
                        detail={"reason": "not project owner"})
        raise HTTPException(403, "仅项目负责人可撤销授权")

    return fm


def grant(db: Session, grantor: User, grantor_sm2_priv_hex: str,
          file_id: int, grantee_id: int, permission: str,
          expire_minutes: int, max_downloads):
    """发起授权：grantor 必须能解出当前文件密钥 K（自己有有效授权）。

    权限：仅项目负责人 (owner) 可发起授权。

    覆盖逻辑：
    - status="valid": 更新参数（覆盖）
    - status="revoked" + weak: 恢复 + 更新参数
    - status="revoked" + strong: 删除旧记录，创建新授权（用当前密钥）
    - status="expired": 删除旧记录，创建新授权
    """
    fm = db.query(FileMeta).get(file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")

    # 仅 owner 可发起授权（其它角色：member/auditor 都无权 grant）
    grantor_pm = (
        db.query(ProjectMember)
        .filter_by(project_id=fm.project_id, user_id=grantor.user_id, status="active")
        .first()
    )
    if not grantor_pm or grantor_pm.role != "owner":
        audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                        operation="grant", result="denied",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "not project owner"})
        raise HTTPException(403, "仅项目负责人可发起授权")

    if grantee_id == grantor.user_id:
        raise HTTPException(400, "不能授权给自己")
    grantee = db.query(User).get(grantee_id)
    if not grantee:
        raise HTTPException(404, "被授权用户不存在")

    # grantor 自己得有当前版本的有效授权（才能拿到 K）
    grantor_auth = (
        db.query(Authorization)
        .filter_by(file_id=file_id, grantee_id=grantor.user_id, status="valid",
                   file_version=fm.version)
        .first()
    )
    if not grantor_auth:
        audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                        operation="grant", result="denied",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "grantor has no current K"})
        raise HTTPException(403, "您本人对该文件没有有效授权，无法转授权")

    k = crypto.sm2_decrypt_key(grantor_sm2_priv_hex, grantor_auth.encrypted_file_key)
    enc_for_grantee = crypto.sm2_encrypt_key(grantee.public_key, k)
    new_expire_time = now_bj() + timedelta(minutes=expire_minutes)

    # 查询该用户对该文件的授权记录，优先取当前版本
    existing = (
        db.query(Authorization)
        .filter_by(file_id=file_id, grantee_id=grantee_id)
        .order_by(Authorization.file_version.desc())  # 优先当前版本
        .first()
    )

    if existing:
        if existing.status == "valid":
            # 有效授权：更新参数（覆盖）
            existing.encrypted_file_key = enc_for_grantee
            existing.permission = permission
            existing.expire_time = new_expire_time
            existing.max_downloads = max_downloads
            existing.revoke_mode = None
            existing.revoked_time = None
            db.commit()
            db.refresh(existing)
            auth = existing
        elif existing.status == "revoked" and existing.revoke_mode == "weak":
            # 弱撤销：恢复授权 + 更新参数
            existing.status = "valid"
            existing.encrypted_file_key = enc_for_grantee
            existing.permission = permission
            existing.expire_time = new_expire_time
            existing.max_downloads = max_downloads
            existing.revoke_mode = None
            existing.revoked_time = None
            db.commit()
            db.refresh(existing)
            auth = existing
        elif existing.status == "revoked" and existing.revoke_mode == "strong":
            # 强撤销：删除旧记录，创建新授权（用当前密钥）
            old_auth_id = existing.auth_id
            old_version = existing.file_version
            db.delete(existing)
            db.commit()
            auth = Authorization(
                file_id=file_id,
                grantee_id=grantee_id,
                grantor_id=grantor.user_id,
                encrypted_file_key=enc_for_grantee,
                file_version=fm.version,
                permission=permission,
                expire_time=new_expire_time,
                max_downloads=max_downloads,
                status="valid",
            )
            db.add(auth)
            db.commit()
            db.refresh(auth)
            audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                            operation="grant", result="success",
                            object_type="auth", object_id=str(auth.auth_id),
                            detail={"file_id": file_id, "grantee_id": grantee_id,
                                    "permission": permission, "max_downloads": max_downloads,
                                    "replaced_auth_id": old_auth_id, "replaced_version": old_version,
                                    "reason": "strong revoked replacement"})
            return auth
        elif existing.status == "expired":
            # 过期：删除旧记录，创建新授权
            old_auth_id = existing.auth_id
            old_version = existing.file_version
            db.delete(existing)
            db.commit()
            auth = Authorization(
                file_id=file_id,
                grantee_id=grantee_id,
                grantor_id=grantor.user_id,
                encrypted_file_key=enc_for_grantee,
                file_version=fm.version,
                permission=permission,
                expire_time=new_expire_time,
                max_downloads=max_downloads,
                status="valid",
            )
            db.add(auth)
            db.commit()
            db.refresh(auth)
            audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                            operation="grant", result="success",
                            object_type="auth", object_id=str(auth.auth_id),
                            detail={"file_id": file_id, "grantee_id": grantee_id,
                                    "permission": permission, "max_downloads": max_downloads,
                                    "replaced_auth_id": old_auth_id, "replaced_version": old_version,
                                    "reason": "expired replacement"})
            return auth
        else:
            # 其他状态：创建新授权
            auth = Authorization(
                file_id=file_id,
                grantee_id=grantee_id,
                grantor_id=grantor.user_id,
                encrypted_file_key=enc_for_grantee,
                file_version=fm.version,
                permission=permission,
                expire_time=new_expire_time,
                max_downloads=max_downloads,
                status="valid",
            )
            db.add(auth)
            db.commit()
            db.refresh(auth)
    else:
        # 无记录：创建新授权
        auth = Authorization(
            file_id=file_id,
            grantee_id=grantee_id,
            grantor_id=grantor.user_id,
            encrypted_file_key=enc_for_grantee,
            file_version=fm.version,
            permission=permission,
            expire_time=new_expire_time,
            max_downloads=max_downloads,
            status="valid",
        )
        db.add(auth)
        db.commit()
        db.refresh(auth)

    audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                    operation="grant", result="success",
                    object_type="auth", object_id=str(auth.auth_id),
                    detail={"file_id": file_id, "grantee_id": grantee_id,
                            "permission": permission, "max_downloads": max_downloads})
    return auth


def revoke(db: Session, grantor: User, grantor_sm2_priv_hex: str,
           auth_id: int, mode: str = "strong") -> Authorization:
    """撤销入口：根据 mode 走强/弱分支。

    - strong：重加密 + 重新封装（强隔离，密钥层不可恢复）
    - weak：仅标记 status=revoked（owner 可调 restore 恢复）
    """
    auth = _load_auth_or_404(db, auth_id)
    fm = _assert_owner_can_revoke(db, grantor, auth)

    if mode == "weak":
        return _do_revoke_weak(db, fm, auth, grantor)
    return _do_revoke_strong(db, fm, auth, grantor, grantor_sm2_priv_hex)


def _do_revoke_weak(db: Session, fm: FileMeta, auth: Authorization, grantor: User) -> Authorization:
    """弱撤销：仅标记状态，不重加密。"""
    auth.status = "revoked"
    auth.revoked_time = now_bj()
    auth.revoke_mode = "weak"
    db.commit()

    audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                    operation="revoke", result="success",
                    object_type="auth", object_id=str(auth.auth_id),
                    detail={"mode": "weak", "file_id": fm.file_id,
                            "grantee_id": auth.grantee_id})
    return auth


def _do_revoke_strong(db: Session, fm: FileMeta, auth: Authorization,
                      grantor: User, grantor_sm2_priv_hex: str) -> Authorization:
    """强撤销：重生成 K'，重加密文件，重新封装剩余授权。

    1) 把当前 auth 标 revoked（revoke_mode=strong）；
    2) grantor 必须有当前版本的有效授权解出 K；
    3) 生成新 K'，把文件用 SM4 重加密写到新 cipher 文件；
    4) 给"除被撤销者外"的当前版本所有 valid 授权 → 新版本 +1 + 用 K' 重新封装；
    5) FileMeta.version += 1，cipher_path 切到新文件，旧 cipher 文件删掉。
    """
    # 标记被撤销
    auth.status = "revoked"
    auth.revoked_time = now_bj()
    auth.revoke_mode = "strong"
    db.commit()

    # 强撤销重加密：grantor 必须有当前版本的有效授权解出 K
    grantor_cur = (
        db.query(Authorization)
        .filter_by(file_id=fm.file_id, grantee_id=grantor.user_id, status="valid",
                   file_version=fm.version)
        .first()
    )
    if not grantor_cur:
        # 极端情况：grantor 自己也被撤销了；只做软标记，无法重加密
        audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                        operation="revoke", result="success",
                        object_type="auth", object_id=str(auth.auth_id),
                        detail={"mode": "mark_only", "reason": "grantor has no current K"})
        return auth

    # 解旧 K
    _old_k = crypto.sm2_decrypt_key(grantor_sm2_priv_hex, grantor_cur.encrypted_file_key)
    # 取明文（解旧密文）
    plain = crypto.sm4_decrypt_bytes(_old_k, open(fm.cipher_path, "rb").read())

    # 校验明文哈希仍匹配
    if crypto.sm3_hash(plain) != fm.sm3_hash:
        raise HTTPException(500, "旧密文解密后 SM3 不匹配，撤销中止")

    # 新 K'，新文件
    new_k = crypto.gen_file_key()
    new_path = os.path.join(STORAGE_DIR, f"{gen_uuid()}.enc")
    with open(new_path, "wb") as f:
        f.write(crypto.sm4_encrypt_bytes(new_k, plain))

    new_version = fm.version + 1

    # 给剩余当前版本的 valid 授权（不含已撤销的 auth_id）重新封装到新版本
    survivors = (
        db.query(Authorization)
        .filter_by(file_id=fm.file_id, status="valid", file_version=fm.version)
        .all()
    )
    for s in survivors:
        grantee = db.query(User).get(s.grantee_id)
        new_auth = Authorization(
            file_id=fm.file_id,
            grantee_id=s.grantee_id,
            grantor_id=s.grantor_id,
            encrypted_file_key=crypto.sm2_encrypt_key(grantee.public_key, new_k),
            file_version=new_version,
            permission=s.permission,
            expire_time=s.expire_time,
            max_downloads=s.max_downloads,
            used_downloads=s.used_downloads,
            status="valid",
        )
        db.add(new_auth)
        # 旧版本的 valid 标记为 expired（语义：随版本切换失效）
        s.status = "expired"

    # 切换 FileMeta 指向新密文
    old_cipher_path = fm.cipher_path
    fm.cipher_path = new_path
    fm.version = new_version
    db.commit()

    # 删除旧密文文件
    try:
        os.remove(old_cipher_path)
    except OSError:
        pass

    audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                    operation="revoke", result="success",
                    object_type="auth", object_id=str(auth.auth_id),
                    detail={"mode": "strong", "file_id": fm.file_id,
                            "new_version": new_version, "rekeyed": len(survivors)})
    return auth


def restore(db: Session, grantor: User, auth_id: int) -> Authorization:
    """恢复弱撤销的授权：仅当 status=revoked 且 revoke_mode=weak 才允许。

    恢复后 status=valid, revoke_mode=NULL, revoked_time=NULL。
    强撤销的授权无法恢复（密码学层面 K' 已经封死）。
    """
    auth = _load_auth_or_404(db, auth_id)

    # 权限：必须是项目 owner
    fm = db.query(FileMeta).get(auth.file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")
    grantor_pm = (
        db.query(ProjectMember)
        .filter_by(project_id=fm.project_id, user_id=grantor.user_id, status="active")
        .first()
    )
    if not grantor_pm or grantor_pm.role != "owner":
        audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                        operation="restore_auth", result="denied",
                        object_type="auth", object_id=str(auth_id),
                        detail={"reason": "not project owner"})
        raise HTTPException(403, "仅项目负责人可恢复授权")

    if auth.status != "revoked":
        raise HTTPException(400, "该授权未被撤销，无需恢复")
    if auth.revoke_mode != "weak":
        raise HTTPException(400, "强撤销不可恢复（密码学层面已隔离），请重新发起授权")

    # 恢复：状态字段清零即可，文件密钥仍有效
    auth.status = "valid"
    auth.revoke_mode = None
    auth.revoked_time = None
    db.commit()

    audit.write_log(db, project_id=fm.project_id, user_id=grantor.user_id,
                    operation="restore_auth", result="success",
                    object_type="auth", object_id=str(auth.auth_id),
                    detail={"file_id": fm.file_id, "grantee_id": auth.grantee_id})
    return auth

