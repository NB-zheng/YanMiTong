"""授权 / 撤销 / 我的授权列表。"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db, Authorization, User
from services import auth_service, authz_service
from services.serializers import authz_out, authzs_out
import schemas

router = APIRouter(prefix="/api/authz", tags=["authz"])


@router.post("/grant", response_model=schemas.AuthorizationOut)
def grant(req: schemas.GrantReq,
          sess: dict = Depends(auth_service.current_session),
          db: Session = Depends(get_db)):
    me = db.query(User).get(sess["user_id"])
    grantee = db.query(User).filter_by(username=req.grantee_username).first()
    if not grantee:
        raise HTTPException(404, "被授权用户不存在")
    a = authz_service.grant(
        db, me, sess["sm2_private_key_hex"],
        req.file_id, grantee.user_id, req.permission,
        req.expire_minutes, req.max_downloads,
    )
    return authz_out(db, a)


@router.post("/revoke", response_model=schemas.AuthorizationOut)
def revoke(req: schemas.RevokeReq,
           sess: dict = Depends(auth_service.current_session),
           db: Session = Depends(get_db)):
    me = db.query(User).get(sess["user_id"])
    a = authz_service.revoke(db, me, sess["sm2_private_key_hex"], req.auth_id)
    return authz_out(db, a)


@router.get("/granted-by-me", response_model=list[schemas.AuthorizationOut])
def granted_by_me(me: User = Depends(auth_service.current_user),
                  db: Session = Depends(get_db)):
    # 过滤自钥包（grantor==grantee 的隐式记录）
    rows = (
        db.query(Authorization)
        .filter(Authorization.grantor_id == me.user_id,
                Authorization.grantor_id != Authorization.grantee_id)
        .all()
    )
    return authzs_out(db, rows)


@router.get("/granted-to-me", response_model=list[schemas.AuthorizationOut])
def granted_to_me(me: User = Depends(auth_service.current_user),
                  db: Session = Depends(get_db)):
    rows = (
        db.query(Authorization)
        .filter(Authorization.grantee_id == me.user_id,
                Authorization.grantor_id != Authorization.grantee_id)
        .all()
    )
    return authzs_out(db, rows)
