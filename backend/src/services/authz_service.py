"""授权 service：细粒度授权 + 强撤销（重加密 + 重新封装）。"""
from __future__ import annotations

import os
from datetime import timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException

from database import Authorization, FileMeta, User, STORAGE_DIR
from tools import now_bj, gen_uuid
import crypto_adapter as crypto
import services.audit_service as audit


def grant(db: Session, grantor: User, grantor_sm2_priv_hex: str,
          file_id: int, grantee_id: int, permission: str,
          expire_minutes: int, max_downloads):
    """发起授权：grantor 必须能解出当前文件密钥 K（自己有有效授权）。"""
    fm = db.query(FileMeta).get(file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")
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

    # 同一 (file_id, grantee_id, file_version) 若有 valid，更新即可，避免重复
    existing = (
        db.query(Authorization)
        .filter_by(file_id=file_id, grantee_id=grantee_id, status="valid",
                   file_version=fm.version)
        .first()
    )
    if existing:
        existing.encrypted_file_key = enc_for_grantee
        existing.permission = permission
        existing.expire_time = now_bj() + timedelta(minutes=expire_minutes)
        existing.max_downloads = max_downloads
        db.commit()
        db.refresh(existing)
        auth = existing
    else:
        auth = Authorization(
            file_id=file_id,
            grantee_id=grantee_id,
            grantor_id=grantor.user_id,
            encrypted_file_key=enc_for_grantee,
            file_version=fm.version,
            permission=permission,
            expire_time=now_bj() + timedelta(minutes=expire_minutes),
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


def revoke(db: Session, grantor: User, grantor_sm2_priv_hex: str, auth_id: int):
    """强撤销：
       1) 把当前 auth 标 revoked；
       2) 生成新 K'，把文件用 SM4 重加密写到新 cipher 文件；
       3) 把"除被撤销者外"的当前版本所有 valid 授权 → 新版本 +1 + 用 K' 重新封装；
       4) FileMeta.version += 1，cipher_path 切到新文件，旧 cipher 文件删掉。
    """
    auth = db.query(Authorization).get(auth_id)
    if not auth:
        raise HTTPException(404, "授权不存在")
    if auth.grantor_id == auth.grantee_id:
        # 上传者的自钥包是文件能被本人解密的物理前提，不允许撤销
        raise HTTPException(400, "不能撤销上传者的本人密钥")
    if auth.grantor_id != grantor.user_id:
        raise HTTPException(403, "只能撤销由本人发起的授权")
    if auth.status != "valid":
        raise HTTPException(400, "该授权已非有效状态")

    fm = db.query(FileMeta).get(auth.file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")

    # 标记被撤销
    auth.status = "revoked"
    auth.revoked_time = now_bj()
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
                        object_type="auth", object_id=str(auth_id),
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
                    object_type="auth", object_id=str(auth_id),
                    detail={"mode": "strong", "file_id": fm.file_id,
                            "new_version": new_version, "rekeyed": len(survivors)})
    return auth


def revoke_for_member_removal(db: Session, owner: User, owner_sm2_priv_hex: str,
                              removed_user_id: int, project_id: int) -> dict:
    """成员被移出项目时调用：对该成员在该项目所有文件上的有效授权执行强撤销。

    对每条 Authorization：
      1) 标记 revoked
      2) 若 owner 持有该文件当前版本的 K，则执行重生成 K' + 重加密 + 给剩余有效用户重新封装
      3) 若 owner 无 K（非上传者也未被授权），降级为 mark_only，写审计日志

    自钥包（grantor==grantee）不动。
    """
    auths = (
        db.query(Authorization)
        .join(FileMeta, FileMeta.file_id == Authorization.file_id)
        .filter(Authorization.grantee_id == removed_user_id,
                Authorization.grantor_id != Authorization.grantee_id,
                Authorization.status == "valid",
                FileMeta.project_id == project_id)
        .all()
    )

    stats = {"total": len(auths), "rekeyed": 0, "mark_only": 0, "failed": 0}

    for auth in auths:
        auth.status = "revoked"
        auth.revoked_time = now_bj()
        db.commit()

        fm = db.query(FileMeta).get(auth.file_id)
        if not fm:
            stats["failed"] += 1
            continue

        owner_cur = (
            db.query(Authorization)
            .filter_by(file_id=fm.file_id, grantee_id=owner.user_id,
                       status="valid", file_version=fm.version)
            .first()
        )
        if not owner_cur:
            stats["mark_only"] += 1
            audit.write_log(db, project_id=project_id, user_id=owner.user_id,
                            operation="revoke", result="success",
                            object_type="auth", object_id=str(auth.auth_id),
                            detail={"mode": "mark_only",
                                    "reason": "owner has no K for this file",
                                    "trigger": "member_removal"})
            continue

        try:
            old_k = crypto.sm2_decrypt_key(owner_sm2_priv_hex, owner_cur.encrypted_file_key)
            plain = crypto.sm4_decrypt_bytes(old_k, open(fm.cipher_path, "rb").read())
            if crypto.sm3_hash(plain) != fm.sm3_hash:
                stats["failed"] += 1
                audit.write_log(db, project_id=project_id, user_id=owner.user_id,
                                operation="revoke", result="failed",
                                object_type="auth", object_id=str(auth.auth_id),
                                detail={"reason": "sm3 mismatch",
                                        "trigger": "member_removal"})
                continue

            new_k = crypto.gen_file_key()
            new_path = os.path.join(STORAGE_DIR, f"{gen_uuid()}.enc")
            with open(new_path, "wb") as f:
                f.write(crypto.sm4_encrypt_bytes(new_k, plain))

            new_version = fm.version + 1
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
                s.status = "expired"

            old_cipher = fm.cipher_path
            fm.cipher_path = new_path
            fm.version = new_version
            db.commit()
            try:
                os.remove(old_cipher)
            except OSError:
                pass

            stats["rekeyed"] += 1
            audit.write_log(db, project_id=project_id, user_id=owner.user_id,
                            operation="revoke", result="success",
                            object_type="auth", object_id=str(auth.auth_id),
                            detail={"mode": "strong", "file_id": fm.file_id,
                                    "new_version": new_version,
                                    "trigger": "member_removal"})
        except Exception as ex:
            stats["failed"] += 1
            audit.write_log(db, project_id=project_id, user_id=owner.user_id,
                            operation="revoke", result="failed",
                            object_type="auth", object_id=str(auth.auth_id),
                            detail={"reason": str(ex)[:200],
                                    "trigger": "member_removal"})

    return stats
