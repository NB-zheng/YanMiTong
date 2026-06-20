"""ORM → 响应 DTO 转换：统一在出口处把 user_id 解析为 username。

设计：每个 list 端点先批量查 username 映射，再逐行转换，避免 N+1。
"""
from __future__ import annotations

from typing import Iterable
from sqlalchemy.orm import Session

from database import User, Project, ProjectMember, FileMeta, Authorization, AuditLog, Alert
import schemas


def username_map(db: Session, user_ids: Iterable[int]) -> dict[int, str]:
    ids = {uid for uid in user_ids if uid is not None}
    if not ids:
        return {}
    rows = db.query(User.user_id, User.username).filter(User.user_id.in_(ids)).all()
    return {uid: name for uid, name in rows}


def _name(m: dict[int, str], uid: int | None) -> str | None:
    if uid is None:
        return None
    return m.get(uid) or f"#{uid}"  # 兜底：用户已删但日志仍在


def project_out(db: Session, p: Project) -> schemas.ProjectOut:
    m = username_map(db, [p.owner_id])
    return schemas.ProjectOut(
        project_id=p.project_id,
        project_name=p.project_name,
        owner_username=_name(m, p.owner_id),
        description=p.description,
        created_time=p.created_time,
    )


def projects_out(db: Session, ps: list[Project]) -> list[schemas.ProjectOut]:
    m = username_map(db, [p.owner_id for p in ps])
    return [
        schemas.ProjectOut(
            project_id=p.project_id,
            project_name=p.project_name,
            owner_username=_name(m, p.owner_id),
            description=p.description,
            created_time=p.created_time,
        ) for p in ps
    ]


def member_out(db: Session, pm: ProjectMember) -> schemas.ProjectMemberOut:
    m = username_map(db, [pm.user_id])
    return schemas.ProjectMemberOut(
        project_id=pm.project_id,
        username=_name(m, pm.user_id),
        role=pm.role,
        joined_time=pm.joined_time,
    )


def members_out(db: Session, pms: list[ProjectMember]) -> list[schemas.ProjectMemberOut]:
    m = username_map(db, [pm.user_id for pm in pms])
    return [
        schemas.ProjectMemberOut(
            project_id=pm.project_id,
            username=_name(m, pm.user_id),
            role=pm.role,
            joined_time=pm.joined_time,
        ) for pm in pms
    ]


def file_out(db: Session, f: FileMeta) -> schemas.FileMetaOut:
    m = username_map(db, [f.uploader_id])
    return schemas.FileMetaOut(
        file_id=f.file_id,
        project_id=f.project_id,
        uploader_username=_name(m, f.uploader_id),
        original_filename=f.original_filename,
        file_type=f.file_type,
        file_size=f.file_size,
        version=f.version,
        created_time=f.created_time,
    )


def files_out(db: Session, fs: list[FileMeta]) -> list[schemas.FileMetaOut]:
    m = username_map(db, [f.uploader_id for f in fs])
    return [
        schemas.FileMetaOut(
            file_id=f.file_id,
            project_id=f.project_id,
            uploader_username=_name(m, f.uploader_id),
            original_filename=f.original_filename,
            file_type=f.file_type,
            file_size=f.file_size,
            version=f.version,
            created_time=f.created_time,
        ) for f in fs
    ]


def authz_out(db: Session, a: Authorization) -> schemas.AuthorizationOut:
    m = username_map(db, [a.grantee_id, a.grantor_id])
    return schemas.AuthorizationOut(
        auth_id=a.auth_id,
        file_id=a.file_id,
        grantee_username=_name(m, a.grantee_id),
        grantor_username=_name(m, a.grantor_id),
        permission=a.permission,
        expire_time=a.expire_time,
        max_downloads=a.max_downloads,
        used_downloads=a.used_downloads,
        status=a.status,
        file_version=a.file_version,
        created_time=a.created_time,
        revoked_time=a.revoked_time,
    )


def authzs_out(db: Session, auths: list[Authorization]) -> list[schemas.AuthorizationOut]:
    ids = {a.grantee_id for a in auths} | {a.grantor_id for a in auths}
    m = username_map(db, ids)
    return [
        schemas.AuthorizationOut(
            auth_id=a.auth_id,
            file_id=a.file_id,
            grantee_username=_name(m, a.grantee_id),
            grantor_username=_name(m, a.grantor_id),
            permission=a.permission,
            expire_time=a.expire_time,
            max_downloads=a.max_downloads,
            used_downloads=a.used_downloads,
            status=a.status,
            file_version=a.file_version,
            created_time=a.created_time,
            revoked_time=a.revoked_time,
        ) for a in auths
    ]


def _resolve_object_labels(db: Session, logs: list[AuditLog]) -> dict[int, str]:
    """批量解析每条日志的 object_label：文件 ID 解为文件名（删除的从 detail 反查）；
    项目 ID 解为项目名；auth ID 解为对应文件名；member 直接用 object_id（已是 username）。
    """
    import json as _json
    file_ids: set[int] = set()
    project_ids: set[int] = set()
    auth_ids: set[int] = set()
    for l in logs:
        if l.object_id is None:
            continue
        try:
            oid = int(l.object_id)
        except (ValueError, TypeError):
            continue
        if l.object_type == "file":
            file_ids.add(oid)
        elif l.object_type == "project":
            project_ids.add(oid)
        elif l.object_type == "auth":
            auth_ids.add(oid)

    file_name = {f.file_id: f.original_filename for f in
                 db.query(FileMeta).filter(FileMeta.file_id.in_(file_ids)).all()} if file_ids else {}
    project_name = {p.project_id: p.project_name for p in
                    db.query(Project).filter(Project.project_id.in_(project_ids)).all()} if project_ids else {}
    auth_rows = db.query(Authorization).filter(Authorization.auth_id.in_(auth_ids)).all() if auth_ids else []
    # auth → file_id → name
    auth_file = {a.auth_id: a.file_id for a in auth_rows}
    extra_file_ids = {fid for fid in auth_file.values() if fid not in file_name}
    if extra_file_ids:
        file_name.update({f.file_id: f.original_filename for f in
                          db.query(FileMeta).filter(FileMeta.file_id.in_(extra_file_ids)).all()})

    result: dict[int, str] = {}
    for l in logs:
        if l.object_id is None or l.object_type is None:
            continue
        label = None
        if l.object_type == "file":
            try:
                fid = int(l.object_id)
                label = file_name.get(fid)
                if not label and l.detail:
                    try:
                        d = _json.loads(l.detail)
                        if isinstance(d, dict) and d.get("filename"):
                            label = d["filename"] + "（已删除）"
                    except Exception:
                        pass
                if not label:
                    label = f"已删除文件 #{fid}"
            except (ValueError, TypeError):
                pass
        elif l.object_type == "project":
            try:
                pid = int(l.object_id)
                label = project_name.get(pid) or f"已删除项目 #{pid}"
            except (ValueError, TypeError):
                pass
        elif l.object_type == "auth":
            try:
                aid = int(l.object_id)
                fid = auth_file.get(aid)
                if fid is not None:
                    label = file_name.get(fid, f"文件 #{fid}")
                else:
                    label = f"授权记录 #{aid}"
            except (ValueError, TypeError):
                pass
        elif l.object_type == "member":
            # object_id 已是 username
            label = l.object_id
        if label:
            result[l.log_id] = label
    return result


def log_out(db: Session, l: AuditLog) -> schemas.AuditLogOut:
    m = username_map(db, [l.user_id])
    labels = _resolve_object_labels(db, [l])
    return schemas.AuditLogOut(
        log_id=l.log_id,
        project_id=l.project_id,
        username=_name(m, l.user_id),
        operation=l.operation,
        object_type=l.object_type,
        object_label=labels.get(l.log_id),
        result=l.result,
        detail=l.detail,
        timestamp=l.timestamp,
    )


def logs_out(db: Session, ls: list[AuditLog]) -> list[schemas.AuditLogOut]:
    m = username_map(db, [l.user_id for l in ls])
    labels = _resolve_object_labels(db, ls)
    return [
        schemas.AuditLogOut(
            log_id=l.log_id,
            project_id=l.project_id,
            username=_name(m, l.user_id),
            operation=l.operation,
            object_type=l.object_type,
            object_label=labels.get(l.log_id),
            result=l.result,
            detail=l.detail,
            timestamp=l.timestamp,
        ) for l in ls
    ]


def alerts_out(db: Session, alerts: list[Alert]) -> list[schemas.AlertOut]:
    m = username_map(db, [a.user_id for a in alerts])
    return [
        schemas.AlertOut(
            alert_id=a.alert_id,
            project_id=a.project_id,
            username=_name(m, a.user_id),
            alert_type=a.alert_type,
            severity=a.severity,
            message=a.message,
            related_log_id=a.related_log_id,
            created_time=a.created_time,
            handled=a.handled,
        ) for a in alerts
    ]


def user_out(u: User) -> schemas.UserOut:
    return schemas.UserOut(
        username=u.username,
        organization=u.organization,
        created_time=u.created_time,
    )
