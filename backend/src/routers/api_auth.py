"""认证与用户路由：注册 / 登录 / 改密 / 用户列表。"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db, User
from services import auth_service
from services.serializers import user_out
import schemas

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=schemas.UserOut)
def register(req: schemas.RegisterReq, db: Session = Depends(get_db)):
    u = auth_service.register(db, req.username, req.password, req.organization)
    return user_out(u)


@router.post("/login", response_model=schemas.TokenResp)
def login(req: schemas.LoginReq, db: Session = Depends(get_db)):
    token, u = auth_service.login(db, req.username, req.password)
    return schemas.TokenResp(token=token, username=u.username)


@router.post("/logout", response_model=schemas.OkResp)
def logout(sess: dict = Depends(auth_service.current_session)):
    from services.auth_service import _SESSIONS
    for k, v in list(_SESSIONS.items()):
        if v["user_id"] == sess["user_id"]:
            _SESSIONS.pop(k, None)
    return schemas.OkResp(message="已退出登录")


@router.post("/change-password", response_model=schemas.OkResp)
def change_password(req: schemas.ChangePasswordReq,
                    me: User = Depends(auth_service.current_user),
                    db: Session = Depends(get_db)):
    auth_service.change_password(db, me.user_id, req.old_password, req.new_password)
    return schemas.OkResp(message="密码已更新，请重新登录")


@router.get("/me", response_model=schemas.UserOut)
def me(me: User = Depends(auth_service.current_user)):
    return user_out(me)


@router.put("/me", response_model=schemas.UserOut)
def update_me(req: schemas.UpdateMeReq,
              me: User = Depends(auth_service.current_user),
              db: Session = Depends(get_db)):
    # 用 model_fields_set 区分 "未传" 和 "显式 null"
    organization_provided = "organization" in req.model_fields_set
    updated = auth_service.update_me(
        db, me.user_id, req.username, req.organization, organization_provided,
    )
    return user_out(updated)
