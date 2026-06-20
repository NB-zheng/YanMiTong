"""项目管理路由。"""
import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, Project, ProjectMember, User, FileMeta, Authorization, Alert
from services import auth_service, audit_service, authz_service
from services.serializers import project_out, projects_out, member_out, members_out
import schemas

router = APIRouter(prefix="/api/project", tags=["project"])


@router.post("", response_model=schemas.ProjectOut)
def create_project(req: schemas.ProjectCreateReq,
                   me: User = Depends(auth_service.current_user),
                   db: Session = Depends(get_db)):
    p = Project(project_name=req.project_name, owner_id=me.user_id, description=req.description)
    db.add(p)
    db.commit()
    db.refresh(p)
    db.add(ProjectMember(project_id=p.project_id, user_id=me.user_id, role="owner"))
    db.commit()
    audit_service.write_log(db, project_id=p.project_id, user_id=me.user_id,
                            operation="create_project", result="success",
                            object_type="project", object_id=str(p.project_id),
                            detail={"name": p.project_name})
    return project_out(db, p)


@router.get("", response_model=list[schemas.ProjectOut])
def list_my_projects(me: User = Depends(auth_service.current_user),
                     db: Session = Depends(get_db)):
    ids = [m.project_id for m in db.query(ProjectMember).filter_by(
        user_id=me.user_id, status="active").all()]
    if not ids:
        return []
    return projects_out(db, db.query(Project).filter(Project.project_id.in_(ids)).all())


@router.get("/{project_id}", response_model=schemas.ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db),
                _me: User = Depends(auth_service.current_user)):
    p = db.query(Project).get(project_id)
    if not p:
        raise HTTPException(404, "项目不存在")
    return project_out(db, p)


@router.put("/{project_id}", response_model=schemas.ProjectOut,
            summary="修改项目名称和描述（仅 owner）")
def update_project(project_id: int, req: schemas.ProjectUpdateReq,
                   me: User = Depends(auth_service.current_user),
                   db: Session = Depends(get_db)):
    p = db.query(Project).get(project_id)
    if not p:
        raise HTTPException(404, "项目不存在")
    if p.owner_id != me.user_id:
        raise HTTPException(403, "只有项目负责人可以修改项目")

    changes = {}
    if req.project_name is not None and req.project_name != p.project_name:
        changes["project_name"] = {"from": p.project_name, "to": req.project_name}
        p.project_name = req.project_name
    if "description" in req.model_fields_set and req.description != p.description:
        changes["description"] = {"from": p.description, "to": req.description}
        p.description = req.description

    if changes:
        db.commit()
        db.refresh(p)
        audit_service.write_log(db, project_id=p.project_id, user_id=me.user_id,
                                operation="update_project", result="success",
                                object_type="project", object_id=str(p.project_id),
                                detail=changes)
    return project_out(db, p)


@router.delete("/{project_id}", response_model=schemas.OkResp,
               summary="删除项目（仅 owner，级联删除文件/授权/成员/告警；保留审计与水印）")
def delete_project(project_id: int,
                   me: User = Depends(auth_service.current_user),
                   db: Session = Depends(get_db)):
    p = db.query(Project).get(project_id)
    if not p:
        raise HTTPException(404, "项目不存在")
    if p.owner_id != me.user_id:
        raise HTTPException(403, "只有项目负责人可以删除项目")

    # 统计将被级联删除的数量
    files = db.query(FileMeta).filter_by(project_id=project_id).all()
    file_ids = [f.file_id for f in files]
    cipher_paths = [f.cipher_path for f in files]
    auth_count = (
        db.query(Authorization).filter(Authorization.file_id.in_(file_ids)).count()
        if file_ids else 0
    )
    member_count = db.query(ProjectMember).filter_by(project_id=project_id).count()
    alert_count = db.query(Alert).filter_by(project_id=project_id).count()
    project_name = p.project_name

    # 先写一条 delete_project 审计日志（在 chain 上留下证据，之后项目就消失了）
    audit_service.write_log(db, project_id=project_id, user_id=me.user_id,
                            operation="delete_project", result="success",
                            object_type="project", object_id=str(project_id),
                            detail={"name": project_name,
                                    "files_deleted": len(files),
                                    "auths_deleted": auth_count,
                                    "members_removed": member_count,
                                    "alerts_deleted": alert_count})

    # 级联删除（DB 层）：authz → file → member → alert → project
    if file_ids:
        db.query(Authorization).filter(Authorization.file_id.in_(file_ids))\
            .delete(synchronize_session=False)
    db.query(FileMeta).filter_by(project_id=project_id).delete(synchronize_session=False)
    db.query(ProjectMember).filter_by(project_id=project_id).delete(synchronize_session=False)
    db.query(Alert).filter_by(project_id=project_id).delete(synchronize_session=False)
    db.delete(p)
    db.commit()

    # 删除磁盘上的密文文件（DB 提交后再删，确保 DB 一致性优先）
    for cp in cipher_paths:
        try:
            if cp and os.path.exists(cp):
                os.remove(cp)
        except OSError:
            pass

    msg = (f"项目「{project_name}」已删除（清理 {len(files)} 个文件、"
           f"{auth_count} 条授权、{member_count} 个成员关系、{alert_count} 条告警；"
           f"审计日志与水印记录已保留）")
    return schemas.OkResp(message=msg)


@router.post("/{project_id}/members", response_model=schemas.ProjectMemberOut)
def add_member(project_id: int, req: schemas.AddMemberReq,
               me: User = Depends(auth_service.current_user),
               db: Session = Depends(get_db)):
    p = db.query(Project).get(project_id)
    if not p:
        raise HTTPException(404, "项目不存在")
    if p.owner_id != me.user_id:
        raise HTTPException(403, "只有项目负责人可以添加成员")
    target = db.query(User).filter_by(username=req.username).first()
    if not target:
        raise HTTPException(404, "目标用户不存在")

    existing = db.query(ProjectMember).filter_by(
        project_id=project_id, user_id=target.user_id).first()
    if existing:
        existing.role = req.role
        existing.status = "active"
        db.commit()
        db.refresh(existing)
        m = existing
    else:
        m = ProjectMember(project_id=project_id, user_id=target.user_id, role=req.role)
        db.add(m)
        db.commit()
        db.refresh(m)

    audit_service.write_log(db, project_id=project_id, user_id=me.user_id,
                            operation="add_member", result="success",
                            object_type="member", object_id=target.username,
                            detail={"target": target.username, "role": req.role})
    return member_out(db, m)


@router.delete("/{project_id}/members/{username}", response_model=schemas.OkResp)
def remove_member(project_id: int, username: str,
                  sess: dict = Depends(auth_service.current_session),
                  db: Session = Depends(get_db)):
    me = db.query(User).get(sess["user_id"])
    p = db.query(Project).get(project_id)
    if not p:
        raise HTTPException(404, "项目不存在")
    if p.owner_id != me.user_id:
        raise HTTPException(403, "只有项目负责人可以移除成员")
    target = db.query(User).filter_by(username=username).first()
    if not target:
        raise HTTPException(404, "目标用户不存在")
    if target.user_id == me.user_id:
        raise HTTPException(400, "不能移除自己")
    m = db.query(ProjectMember).filter_by(project_id=project_id, user_id=target.user_id).first()
    if not m:
        raise HTTPException(404, "成员不存在")

    # 先做强撤销：把该成员在本项目所有文件上的有效授权全部走重加密链路
    stats = authz_service.revoke_for_member_removal(
        db, me, sess["sm2_private_key_hex"], target.user_id, project_id,
    )

    # 再标记成员为 removed
    m.status = "removed"
    db.commit()

    audit_service.write_log(db, project_id=project_id, user_id=me.user_id,
                            operation="remove_member", result="success",
                            object_type="member", object_id=target.username,
                            detail={"target": target.username, "revoke_stats": stats})
    msg = f"成员已移除（强撤销 {stats['rekeyed']} 个授权，降级标记 {stats['mark_only']} 个）"
    return schemas.OkResp(message=msg)


@router.get("/{project_id}/members", response_model=list[schemas.ProjectMemberOut])
def list_members(project_id: int, db: Session = Depends(get_db),
                 _me: User = Depends(auth_service.current_user)):
    # 仅返回 active 成员；removed 成员仅作为审计历史保留在 DB 中
    rows = db.query(ProjectMember).filter_by(project_id=project_id, status="active").all()
    return members_out(db, rows)
