"""文件上传 / 下载 / 列表 / 取证。"""
import asyncio
from urllib.parse import quote

from fastapi import APIRouter, Depends, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session


def _content_disposition(filename: str) -> str:
    """RFC 5987：同时给 ASCII 兜底名和 UTF-8 编码原名，兼容中文/特殊字符。"""
    ascii_fallback = filename.encode("ascii", "ignore").decode("ascii") or "download"
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(filename)}"

from database import get_db, FileMeta, User
from services import auth_service, file_service
from services.serializers import file_out, files_out
import schemas

router = APIRouter(prefix="/api/file", tags=["file"])


@router.post("/upload", response_model=schemas.UploadResp)
async def upload(project_id: int = Form(...),
                 file: UploadFile = File(...),
                 sess: dict = Depends(auth_service.current_session),
                 db: Session = Depends(get_db)):
    me = db.query(User).get(sess["user_id"])
    data = await file.read()
    # SM3 摘要 + SM4 加密整块明文是 CPU 密集且纯 Python 实现，
    # 放到默认线程池里跑，避免阻塞事件循环。
    fm = await asyncio.to_thread(
        file_service.upload_file,
        db, me, sess["sm2_private_key_hex"],
        project_id, file.filename or "unnamed", data,
    )
    return schemas.UploadResp(file_id=fm.file_id, version=fm.version)


@router.get("/list", response_model=list[schemas.FileMetaOut])
def list_files(project_id: int | None = None,
               _me: User = Depends(auth_service.current_user),
               db: Session = Depends(get_db)):
    q = db.query(FileMeta)
    if project_id is not None:
        q = q.filter(FileMeta.project_id == project_id)
    return files_out(db, q.order_by(FileMeta.created_time.desc()).all())


@router.get("/{file_id}/meta", response_model=schemas.FileMetaOut)
def get_meta(file_id: int, db: Session = Depends(get_db),
             _me: User = Depends(auth_service.current_user)):
    fm = db.query(FileMeta).get(file_id)
    if not fm:
        raise HTTPException(404, "文件不存在")
    return file_out(db, fm)


@router.delete("/{file_id}", response_model=schemas.OkResp,
               summary="删除文件（仅上传者或项目 owner，级联删授权 + 审计）")
def delete_file_route(file_id: int,
                      me: User = Depends(auth_service.current_user),
                      db: Session = Depends(get_db)):
    file_service.delete_file(db, me, file_id)
    return schemas.OkResp(message="文件已删除")


@router.get("/{file_id}/download")
def download(file_id: int, request: Request,
             sess: dict = Depends(auth_service.current_session),
             db: Session = Depends(get_db)):
    me = db.query(User).get(sess["user_id"])
    client_ip = request.client.host if request.client else None
    body, filename, wm_type = file_service.download_file(
        db, me, sess["sm2_private_key_hex"], file_id, client_ip
    )
    headers = {
        "Content-Disposition": _content_disposition(filename),
        "X-Watermark-Type": wm_type,
    }
    return Response(content=body, headers=headers, media_type="application/octet-stream")


