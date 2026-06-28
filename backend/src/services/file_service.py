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
    # 权限：仅项目负责人 (owner) 可上传文件
    pm = db.query(ProjectMember).filter_by(
        project_id=project_id, user_id=uploader.user_id, status="active"
    ).first()
    if not pm:
        audit.write_log(db, project_id=project_id, user_id=uploader.user_id,
                        operation="upload", result="denied",
                        object_type="file", object_id="-",
                        detail={"reason": "not a project member"})
        raise HTTPException(403, "不是该项目成员")
    if pm.role != "owner":
        audit.write_log(db, project_id=project_id, user_id=uploader.user_id,
                        operation="upload", result="denied",
                        object_type="file", object_id="-",
                        detail={"reason": "not project owner", "role": pm.role})
        raise HTTPException(403, "仅项目负责人可上传文件")

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
    try:
        k = crypto.sm2_decrypt_key(requester_sm2_priv_hex, auth.encrypted_file_key)
    except Exception as e:
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="failed",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "sm2 decapsulate failed",
                                "error": str(e)[:200]})
        audit.raise_alert(db, project_id=fm.project_id, user_id=requester.user_id,
                          alert_type="tamper_suspect",
                          message=f"file_id={file_id} 密钥封装数据异常（授权记录可能被篡改）",
                          severity="high")
        raise HTTPException(500, "授权数据异常，请联系项目负责人")

    # SM4 解密文件（密文损坏/被篡改会在此抛 ValueError）
    try:
        plain = crypto.sm4_decrypt_bytes(k, open(fm.cipher_path, "rb").read())
    except FileNotFoundError:
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="failed",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "cipher file missing",
                                "cipher_path": fm.cipher_path})
        audit.raise_alert(db, project_id=fm.project_id, user_id=requester.user_id,
                          alert_type="cipher_missing",
                          message=f"file_id={file_id} 密文文件丢失",
                          severity="high")
        raise HTTPException(500, "密文文件丢失，请联系项目负责人")
    except (ValueError, Exception) as e:
        audit.write_log(db, project_id=fm.project_id, user_id=requester.user_id,
                        operation="download", result="failed",
                        object_type="file", object_id=str(file_id),
                        detail={"reason": "sm4 decrypt failed (cipher tampered or corrupted)",
                                "error": str(e)[:200]})
        audit.raise_alert(db, project_id=fm.project_id, user_id=requester.user_id,
                          alert_type="cipher_tampered",
                          message=f"file_id={file_id} 密文异常（文件可能被篡改或损坏）",
                          severity="high")
        raise HTTPException(500, "文件密文异常，可能已被篡改或损坏，请联系项目负责人")

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
    # 注：按当前权限模型，只有 owner 能上传文件，因此 is_uploader 与 is_owner 等价。
    # 保留两分支仅为兼容历史数据与说明意图。

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
        if file_type == "doc":
            # .doc 二进制格式无法安全嵌入水印，走降级方案
            return data + f"\n<!--YMT-FP:{fingerprint}-->\n".encode("utf-8"), "doc_trailer"
        if file_type == "image":
            from watermark.image_marker import embed
            return embed(data, fingerprint), "image_lsb"
    except Exception:
        # 专用 marker 失败 → 走通用 trailer_tag 方案
        pass
    # 其它类型 / 降级方案：追加隐蔽 trailer
    return data + f"\n<!--YMT-FP:{fingerprint}-->\n".encode("utf-8"), "trailer_tag"


# ===== 取证 =====
def forensics_analyze(db: Session, requester: User, leaked_bytes: bytes,
                      project_id: int) -> dict:
    """从泄露文件中提取所有指纹并匹配 WatermarkRecord，必须项目内取证。

    安全约束：只回显本项目内文件的下载者；如果指纹属于其它项目的文件，
    只返回计数，不暴露任何下载者信息。

    返回：
        matched: 是否有任何匹配
        matches: 本项目内的匹配列表（按下载时间升序）
        total_count: 总匹配数
        cross_project_count: 属于其他项目的指纹数
        message: 说明信息
    """
    from schemas import ForensicsResp, ForensicsMatch

    # 1. 提取所有指纹
    fingerprints = _extract_all_fingerprints(leaked_bytes)
    if not fingerprints:
        return ForensicsResp(
            matched=False,
            matches=[],
            total_count=0,
            cross_project_count=0,
            message="未能从该文件中提取到指纹（可能未经平台下载或水印已被破坏）",
        ).model_dump(mode="json")

    # 2. 查询每个指纹的 WatermarkRecord（指纹已在 _extract_all_fingerprints 中去重）
    matched_records = []
    cross_project_count = 0

    for fp in fingerprints:
        wr = db.query(WatermarkRecord).filter_by(fingerprint=fp).first()
        if not wr:
            continue  # 指纹不在数据库中，跳过

        fm = db.query(FileMeta).get(wr.file_id)
        if not fm:
            continue  # 文件元数据已被清掉

        if fm.project_id != project_id:
            # 该文件不属于当前项目，只计数不披露
            cross_project_count += 1
            audit.write_log(db, project_id=project_id, user_id=requester.user_id,
                            operation="forensics", result="cross_project_hint",
                            object_type="file", object_id=str(wr.file_id),
                            detail={"reason": "cross_project",
                                    "actual_project_id": fm.project_id})
            continue

        # 属于本项目，添加到匹配列表
        user = db.query(User).get(wr.user_id)
        matched_records.append({
            "username": user.username if user else "(用户已删除)",
            "download_time": wr.download_time,
            "fingerprint": fp,
            "client_ip": wr.client_ip,
            "file_id": fm.file_id,
        })

    # 3. 按下载时间升序排序（同一用户多次下载都保留，按时间展示）
    sorted_matches = sorted(matched_records, key=lambda x: x["download_time"])

    # 4. 统计泄露者人数（按用户名去重）
    unique_leakers = set(m["username"] for m in sorted_matches)
    leaker_count = len(unique_leakers)

    # 5. 记录审计日志
    if sorted_matches:
        audit.write_log(db, project_id=project_id, user_id=requester.user_id,
                        operation="forensics", result="success",
                        object_type="file", object_id="-",
                        detail={"total_matches": len(sorted_matches),
                                "cross_project": cross_project_count})

    # 5. 构建响应
    matches = [ForensicsMatch(**m).model_dump(mode="json") for m in sorted_matches]
    total_count = len(sorted_matches) + cross_project_count

    if total_count == 0:
        message = "提取到的指纹未在平台下载记录中匹配到"
    elif cross_project_count > 0:
        message = f"共定位到 {leaker_count} 位泄露者（{total_count} 条匹配记录），另有 {cross_project_count} 个指纹属于其他项目"
    else:
        message = f"共定位到 {leaker_count} 位泄露者（{total_count} 条匹配记录）"

    return ForensicsResp(
        matched=len(sorted_matches) > 0,
        matches=matches,
        total_count=total_count,
        leaker_count=leaker_count,
        cross_project_count=cross_project_count,
        message=message,
    ).model_dump(mode="json")


# ===== 指纹提取：分格式实现 =====
def _extract_all_fingerprints(data: bytes) -> list[str]:
    """提取文件中所有指纹，返回去重后的指纹列表（按出现顺序）。"""
    import re
    fingerprints = set()

    # 1. trailer / 显式标记（兼容历史 trailer_tag）
    for pat in (rb"YMT-FP:([0-9a-f]{64})", rb"YMTFingerprint\(([0-9a-f]{64})\)"):
        for m in re.finditer(pat, data):  # finditer 找所有匹配
            fingerprints.add(m.group(1).decode("ascii"))

    # 2/3/4 顺序尝试，失败静默
    for extractor in (_extract_from_pdf, _extract_from_docx, _extract_from_image_lsb):
        fp = extractor(data)
        if fp:
            fingerprints.add(fp)

    return list(fingerprints)


def _extract_fingerprint(data: bytes) -> Optional[str]:
    """兼容旧接口：返回第一个指纹。"""
    fps = _extract_all_fingerprints(data)
    return fps[0] if fps else None


def _extract_from_pdf(data: bytes) -> Optional[str]:
    import re
    try:
        import fitz
        doc = fitz.open(stream=data, filetype="pdf")
        try:
            meta = doc.metadata or {}
            for key in ("keywords", "subject", "title", "author"):
                v = meta.get(key) or ""
                m = re.search(r"YMT(?:Fingerprint\(|-FP:)([0-9a-f]{64})", v)
                if m:
                    return m.group(1)
        finally:
            doc.close()
    except Exception:
        pass
    return None


def _extract_from_docx(data: bytes) -> Optional[str]:
    import re, io
    try:
        from docx import Document
        doc = Document(io.BytesIO(data))
        cp = doc.core_properties
        for v in (cp.keywords or "", cp.comments or "", cp.subject or ""):
            m = re.search(r"YMT(?:Fingerprint\(|-FP:)([0-9a-f]{64})", v)
            if m:
                return m.group(1)
        # 也扫描所有段落文本，捕获白色 1pt 隐藏段落
        for p in doc.paragraphs:
            m = re.search(r"YMT(?:Fingerprint\(|-FP:)([0-9a-f]{64})", p.text or "")
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _extract_from_image_lsb(data: bytes) -> Optional[str]:
    """从图像 R 通道最低位重组出 64 位 hex 指纹（与 image_marker.embed 对应）。"""
    import re, io
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("RGBA")
        pixels = img.load()
        w, h = img.size
        # 指纹 = 64 字符 hex（UTF-8 / ASCII 各 1 字节）+ 8 bit 终止符 = 520 bits
        target_bits = 65 * 8
        bits = []
        for y in range(h):
            for x in range(w):
                bits.append(pixels[x, y][0] & 1)
                if len(bits) >= target_bits:
                    break
            if len(bits) >= target_bits:
                break
        if len(bits) < target_bits:
            return None
        # 还原字节并以终止符 0x00 截断
        out = bytearray()
        for i in range(0, len(bits), 8):
            b = 0
            for j in range(8):
                b = (b << 1) | bits[i + j]
            if b == 0:
                break
            out.append(b)
        text = out.decode("ascii", errors="ignore")
        m = re.match(r"^([0-9a-f]{64})", text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None
