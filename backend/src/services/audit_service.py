"""审计 service：哈希链 按项目独立。

设计要点：
- 每个项目有独立的 prev_hash 序列（第一条从 GENESIS 起步）
- 仅 owner / auditor 角色（且 active）的成员能查看该项目的审计与告警
- 系统级事件（注册/登录/改密码）不写入本表
"""
from __future__ import annotations

import json
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from database import AuditLog, Alert, ProjectMember
from tools import now_bj, bj_str
import crypto_adapter as crypto


def _serialize_payload(project_id: int, user_id: int, operation: str,
                       object_type: Optional[str], object_id: Optional[str],
                       result: str, detail: Optional[dict], ts) -> dict:
    return {
        "project_id": project_id,
        "user_id": user_id,
        "operation": operation,
        "object_type": object_type,
        "object_id": object_id,
        "result": result,
        "detail": json.dumps(detail, sort_keys=True, ensure_ascii=False) if detail else None,
        "timestamp": bj_str(ts),
    }


def write_log(db: Session, *, project_id: int, user_id: int, operation: str, result: str,
              object_type: Optional[str] = None, object_id: Optional[str] = None,
              detail: Optional[dict] = None) -> AuditLog:
    """追加一条日志到指定项目的哈希链。"""
    last = (
        db.query(AuditLog)
        .filter(AuditLog.project_id == project_id)
        .order_by(AuditLog.log_id.desc())
        .first()
    )
    prev_hash = last.current_hash if last else crypto.GENESIS_HASH

    ts = now_bj()
    payload = _serialize_payload(project_id, user_id, operation, object_type, object_id, result, detail, ts)
    current = crypto.hash_chain_append(prev_hash, payload)

    log = AuditLog(
        project_id=project_id,
        user_id=user_id,
        operation=operation,
        object_type=object_type,
        object_id=object_id,
        result=result,
        detail=payload["detail"],
        timestamp=ts,
        prev_hash=prev_hash,
        current_hash=current,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def verify_chain(db: Session, project_id: int) -> tuple[bool, int, int]:
    """重算单个项目的哈希链。返回 (ok, broken_at_log_id, total)。"""
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.project_id == project_id)
        .order_by(AuditLog.log_id.asc())
        .all()
    )
    prev = crypto.GENESIS_HASH
    for r in rows:
        payload = _serialize_payload(
            r.project_id, r.user_id, r.operation, r.object_type, r.object_id,
            r.result, json.loads(r.detail) if r.detail else None, r.timestamp,
        )
        # detail 已是 JSON 字符串，重算时需保持一致
        payload["detail"] = r.detail
        expected = crypto.hash_chain_append(prev, payload)
        if expected != r.current_hash or r.prev_hash != prev:
            return False, r.log_id, len(rows)
        prev = r.current_hash
    return True, -1, len(rows)


def raise_alert(db: Session, *, project_id: int, user_id: Optional[int], alert_type: str,
                message: str, severity: str = "medium",
                related_log_id: Optional[int] = None) -> Alert:
    a = Alert(
        project_id=project_id,
        user_id=user_id,
        alert_type=alert_type,
        severity=severity,
        message=message,
        related_log_id=related_log_id,
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


# ===== 权限 =====
# 仅审计员可访问审计链与取证；owner 也无权（职责分离，防止 owner 自己掩盖痕迹）
AUDIT_ROLES = ("auditor",)


def can_audit(db: Session, user_id: int, project_id: int) -> bool:
    pm = (
        db.query(ProjectMember)
        .filter_by(project_id=project_id, user_id=user_id, status="active")
        .first()
    )
    return bool(pm and pm.role in AUDIT_ROLES)


def assert_can_audit(db: Session, user_id: int, project_id: int) -> None:
    if not can_audit(db, user_id, project_id):
        raise HTTPException(403, "无权访问审计与取证（仅项目审计员可用）")
