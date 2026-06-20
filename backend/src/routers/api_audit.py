"""审计 / 哈希链 / 告警 —— 全部按项目维度，并由 owner / auditor 角色把关。"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db, AuditLog, Alert, Project, ProjectMember, User
from services import auth_service, audit_service
from services.serializers import projects_out, logs_out, alerts_out
import schemas

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/auditable-projects", response_model=list[schemas.ProjectOut],
            summary="列出我可以审计的项目（owner 或 auditor 角色）")
def auditable_projects(me: User = Depends(auth_service.current_user),
                       db: Session = Depends(get_db)):
    pids = [
        m.project_id for m in db.query(ProjectMember)
        .filter(ProjectMember.user_id == me.user_id,
                ProjectMember.status == "active",
                ProjectMember.role.in_(audit_service.AUDIT_ROLES))
        .all()
    ]
    if not pids:
        return []
    return projects_out(db, db.query(Project).filter(Project.project_id.in_(pids)).all())


@router.get("/logs", response_model=list[schemas.AuditLogOut],
            summary="按项目查审计日志（游标分页：before_log_id 拿更早的）")
def list_logs(project_id: int = Query(..., description="目标项目 ID"),
              limit: int = Query(50, ge=1, le=200),
              before_log_id: int | None = Query(None, description="只返回 log_id 小于该值的（用于加载更早的页）"),
              me: User = Depends(auth_service.current_user),
              db: Session = Depends(get_db)):
    audit_service.assert_can_audit(db, me.user_id, project_id)
    q = db.query(AuditLog).filter(AuditLog.project_id == project_id)
    if before_log_id is not None:
        q = q.filter(AuditLog.log_id < before_log_id)
    rows = q.order_by(AuditLog.log_id.desc()).limit(limit).all()
    return logs_out(db, rows)


@router.get("/verify", response_model=schemas.ChainVerifyResp,
            summary="校验某项目的哈希链完整性")
def verify_chain(project_id: int = Query(...),
                 me: User = Depends(auth_service.current_user),
                 db: Session = Depends(get_db)):
    audit_service.assert_can_audit(db, me.user_id, project_id)
    ok, broken, total = audit_service.verify_chain(db, project_id)
    return schemas.ChainVerifyResp(ok=ok, broken_at_log_id=broken, total=total)


@router.get("/alerts", response_model=list[schemas.AlertOut],
            summary="按项目查异常告警（需 owner/auditor 角色）")
def list_alerts(project_id: int = Query(...),
                me: User = Depends(auth_service.current_user),
                db: Session = Depends(get_db)):
    audit_service.assert_can_audit(db, me.user_id, project_id)
    rows = (
        db.query(Alert)
        .filter(Alert.project_id == project_id)
        .order_by(Alert.alert_id.desc())
        .all()
    )
    return alerts_out(db, rows)


@router.post("/alerts/{alert_id}/handle", response_model=schemas.OkResp,
             summary="标记告警为已处理")
def handle_alert(alert_id: int,
                 me: User = Depends(auth_service.current_user),
                 db: Session = Depends(get_db)):
    a = db.query(Alert).get(alert_id)
    if not a:
        raise HTTPException(404, "告警不存在")
    audit_service.assert_can_audit(db, me.user_id, a.project_id)
    a.handled = True
    db.commit()
    return schemas.OkResp(message="已标记处理")


@router.delete("/alerts/{alert_id}", response_model=schemas.OkResp,
               summary="删除告警（需 owner/auditor 权限）")
def delete_alert(alert_id: int,
                 me: User = Depends(auth_service.current_user),
                 db: Session = Depends(get_db)):
    a = db.query(Alert).get(alert_id)
    if not a:
        raise HTTPException(404, "告警不存在")
    audit_service.assert_can_audit(db, me.user_id, a.project_id)
    db.delete(a)
    db.commit()
    return schemas.OkResp(message="告警已删除")
