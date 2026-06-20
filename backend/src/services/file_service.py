"""文件 service：上传加密、下载解密、水印分发、取证。"""
from __future__ import annotations

import os
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from database import FileMeta, User, Authorization, WatermarkRecord, ProjectMember, Project, STORAGE_DIR
from tools import now_bj, bj_str, gen_uuid, detect_file_type
import crypto_adapter as crypto
import services.audit_service as audit


# ===== 上传 =====
def upload_file(db: Session, uploader: User, uploader_sm2_priv_hex: str,
                project_id: int, filename: str, plain_bytes: bytes) -> FileMeta:
    # 校验上传者是项目成员
    pm = db.query(ProjectMember).filter_by(
        project_id=project_id, user_id=uploader.user_id, status="active"
    ).first()
    if not pm:
        audit.write_log(db, project_id=project_id, user_id=uploader.user_id,
                        operation="upload", result="denied",
                        object_type="file", object_id="-",
                        detail={"reason": "not a project member"})
        raise HTTPException(403, "不是该项目成员")

    # 生成文件密钥 K
    k = crypto.gen_file_key()

    # 计算明文 SM3
    sm3 = crypto.sm3_hash(plain_bytes)

    # SM2 上传者签名（对 SM3 摘要签）
    sig = crypto.sm2_sign(uploader_sm2_priv_hex, bytes.fromhex(sm3))

    # SM4 加密写盘
    uid = gen_uuid()
    cipher_path = os.path.join(STORAGE_DIR, f"{uid}.enc")
    with open(cipher_path, "wb") as f:
        f.write(crypto.sm4_encrypt_bytes(k, plain_bytes))

    fm = FileMeta(
        project_id=project_id,
        uploader_id=uploader.user_id,
        original_filename=filename,
        file_type=detect_file_type(filename),
        file_size=len(plain_bytes),
        cipher_path=cipher_path,
        sm3_hash=sm3,
        sm2_signature=sig,
        version=1,
    )
    db.add(fm)
    db.commit()
    db.refresh(fm)

    # 上传者自己同时获得一条永久授权（封装 K 给自己），便于后续他自己下载
    own_auth = Authorization(
        file_id=fm.file_id,
        grantee_id=uploader.user_id,
        grantor_id=uploader.user_id,
        encrypted_file_key=crypto.sm2_encrypt_key(uploader.public_key, k),
        file_version=fm.version,
        permission="download",
        expire_time=now_bj().replace(year=now_bj().year + 10),
        max_downloads=None,
        status="valid",
    )
    db.add(own_auth)
    db.commit()

    audit.write_log(db, project_id=project_id, user_id=uploader.user_id,
                    operation="upload", result="success",
                    object_type="file", object_id=str(fm.file_id),
                    detail={"filename": filename, "size": len(plain_bytes), "sm3": sm3})
    return fm


# ===== 下载 =====
def download_file(db: Session, requester: User, requester_sm2_priv_hex: str,
                  file_id: int, client_ip: Optional[str] = None) -> tuple[bytes, str, str]:
    """返回 (含水印的明文字节, original_filename, watermark_type)。"""
    fm = db.query(FileMeta).get(file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")

    # 找当前用户对当前 file_version 的有效授权
    auth = (
        db.query(Authorization)
        .filter_by(file_id=file_id, grantee_id=requester.user_id, status="valid",
                   file_version=fm.version)
        .first()
    )
    if not auth:
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="denied",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "no valid authorization"})
        # 撤销后访问 → 告警
        revoked = db.query(Authorization).filter_by(
            file_id=file_id, grantee_id=requester.user_id, status="revoked"
        ).first()
        if revoked:
            audit.raise_alert(db, project_id=fm.project_id, user_id=requester.user_id,
                              alert_type="access_after_revoke",
                              message=f"用户 {requester.username} 在授权撤销后仍尝试下载 file_id={file_id}",
                              severity="high")
        raise HTTPException(403, "无有效授权")

    # 校验有效期 / 下载次数
    if auth.expire_time < now_bj():
        auth.status = "expired"
        db.commit()
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="denied",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "expired"})
        raise HTTPException(403, "授权已过期")
    if auth.max_downloads is not None and auth.used_downloads >= auth.max_downloads:
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="denied",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "download quota exceeded"})
        raise HTTPException(403, "下载次数已用完")

    # 解出文件密钥 K
    k = crypto.sm2_decrypt_key(requester_sm2_priv_hex, auth.encrypted_file_key)

    # SM4 解密文件
    plain = crypto.sm4_decrypt_bytes(k, open(fm.cipher_path, "rb").read())

    # SM3 完整性校验
    sm3_now = crypto.sm3_hash(plain)
    if sm3_now != fm.sm3_hash:
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="failed",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "sm3 mismatch"})
        audit.raise_alert(db, project_id=fm.project_id, user_id=requester.user_id,
                          alert_type="verify_fail",
                          message=f"file_id={file_id} 解密后 SM3 不匹配", severity="high")
        raise HTTPException(500, "文件完整性校验失败")

    # SM2 验证上传者签名
    uploader = db.query(User).get(fm.uploader_id)
    if not crypto.sm2_verify(uploader.public_key, bytes.fromhex(fm.sm3_hash), fm.sm2_signature):
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="failed",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "sm2 signature invalid"})
        audit.raise_alert(db, project_id=fm.project_id, user_id=requester.user_id,
                          alert_type="verify_fail",
                          message=f"file_id={file_id} SM2 验签失败", severity="high")
        raise HTTPException(500, "上传者签名验证失败")

    # 嵌入水印
    salt = gen_uuid()
    download_time_str = bj_str()
    fingerprint = crypto.generate_fingerprint(requester.user_id, file_id, download_time_str, salt)
    marked_bytes, wm_type = _apply_watermark(fm.file_type, plain, fingerprint)

    # 记录水印映射
    wr = WatermarkRecord(
        file_id=file_id,
        user_id=requester.user_id,
        fingerprint=fingerprint,
        salt=salt,
        watermark_type=wm_type,
        client_ip=client_ip,
    )
    db.add(wr)
    auth.used_downloads += 1
    db.commit()

    audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                    operation="download", result="success",
                    object_type="file", object_id=str(file_id),
                    detail={"fingerprint": fingerprint, "watermark_type": wm_type})

    # 高频下载检测：同一用户在同一项目内 60 秒内 ≥ 5 次成功下载 → 告警
    _check_high_freq_download(db, requester, fm.project_id)

    return marked_bytes, fm.original_filename, wm_type


# ===== 删除 =====
def delete_file(db: Session, requester: User, file_id: int) -> None:
    """删除文件：仅上传者或项目 owner 可执行。

    级联清理：
    - Authorization 行全部删除（含自钥包与所有外部授权）
    - 加密密文从磁盘删除
    - FileMeta 行删除
    - WatermarkRecord 保留：水印是历史下载证据，文件删除不影响事后取证

    审计：写一条 delete 日志（按项目链）。
    """
    fm = db.query(FileMeta).get(file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")

    project = db.query(Project).get(fm.project_id)
    is_uploader = (fm.uploader_id == requester.user_id)
    is_owner = bool(project and project.owner_id == requester.user_id)
    if not (is_uploader or is_owner):
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="delete_file", result="denied",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "not uploader or owner"})
        raise HTTPException(403, "仅上传者或项目负责人可以删除文件")

    # 收集统计信息用于审计
    auth_count = db.query(Authorization).filter_by(file_id=file_id).count()
    filename = fm.original_filename
    cipher_path = fm.cipher_path

    # 删授权
    db.query(Authorization).filter_by(file_id=file_id).delete(synchronize_session=False)
    # 删文件元数据
    db.delete(fm)
    db.commit()

    # 删磁盘上的密文
    try:
        if cipher_path and os.path.exists(cipher_path):
            os.remove(cipher_path)
    except OSError:
        pass

    audit.write_log(db, project_id=project.project_id, user_id=requester.user_id,
                    operation="delete_file", result="success",
                    object_type="file", object_id=str(file_id),
                    detail={"filename": filename,
                            "by": "uploader" if is_uploader else "owner",
                            "cascaded_auth_rows": auth_count})


def _check_high_freq_download(db: Session, requester: User, project_id: int,
                              window_sec: int = 60, threshold: int = 5) -> None:
    from datetime import timedelta
    from database import AuditLog
    since = now_bj() - timedelta(seconds=window_sec)
    cnt = (
        db.query(AuditLog)
        .filter(AuditLog.project_id == project_id,
                AuditLog.user_id == requester.user_id,
                AuditLog.operation == "download",
                AuditLog.result == "success",
                AuditLog.timestamp >= since)
        .count()
    )
    if cnt >= threshold:
        audit.raise_alert(
            db, project_id=project_id, user_id=requester.user_id,
            alert_type="high_freq_download",
            message=f"用户 {requester.username} 在 {window_sec}s 内于该项目成功下载 {cnt} 次",
            severity="medium",
        )


def _apply_watermark(file_type: str, data: bytes, fingerprint: str) -> tuple[bytes, str]:
    """根据文件类型分发到对应 marker。

    若专用 marker 失败（文件实际不是声明的类型 / 损坏 / 格式异常），
    降级到通用 trailer_tag 方案以保证下载不中断；取证一侧仍可通过
    trailer_tag 提取指纹。
    """
    try:
        if file_type == "pdf":
            from watermark.pdf_marker import embed
            return embed(data, fingerprint), "pdf_meta"
        if file_type == "docx":
            from watermark.docx_marker import embed
            return embed(data, fingerprint), "docx_prop"
        if file_type == "image":
            from watermark.image_marker import embed
            return embed(data, fingerprint), "image_lsb"
    except Exception:
        # 专用 marker 失败 → 走通用 trailer_tag 方案
        pass
    # 其它类型 / 降级方案：追加隐蔽 trailer
    return data + f"\n<!--YMT-FP:{fingerprint}-->\n".encode("utf-8"), "trailer_tag"


# ===== 取证 =====
def forensics_analyze(db: Session, leaked_bytes: bytes, hint_file_id: Optional[int] = None) -> dict:
    """从泄露文件中提取指纹并匹配 WatermarkRecord。

    简单方案：扫描 trailer / metadata 中的指纹串，再到库里精确匹配。
    """
    fp = _extract_fingerprint(leaked_bytes)
    if not fp:
        return {"matched": False, "message": "未能提取到指纹"}

    wr = db.query(WatermarkRecord).filter_by(fingerprint=fp).first()
    if not wr:
        return {"matched": False, "fingerprint": fp, "message": "指纹未在下载记录中匹配到"}

    user = db.query(User).get(wr.user_id)
    fm = db.query(FileMeta).get(wr.file_id)
    if fm:
        audit.write_log(db, project_id=fm.project_id, user_id=wr.user_id,
                        operation="forensics", result="success",
                        object_type="file", object_id=str(wr.file_id),
                        detail={"fingerprint": fp})
    return {
        "matched": True,
        "fingerprint": fp,
        "username": user.username if user else None,
        "file_id": wr.file_id,
        "download_time": wr.download_time,
        "watermark_type": wr.watermark_type,
        "message": f"定位到下载者：{user.username if user else '(用户已删除)'}",
    }


def _extract_fingerprint(data: bytes) -> Optional[str]:
    """通用提取：先看 trailer，再交给具体 marker（演示版做简版）。"""
    import re
    m = re.search(rb"YMT-FP:([0-9a-f]{64})", data)
    if m:
        return m.group(1).decode("ascii")
    # PDF 元数据
    m = re.search(rb"/YMTFingerprint\s*\(([0-9a-f]{64})\)", data)
    if m:
        return m.group(1).decode("ascii")
    return None
