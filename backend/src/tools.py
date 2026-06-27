"""通用工具箱：时间、UUID、Token、文件类型判定。"""
import datetime
import secrets
import uuid as _uuid

_BJ_OFFSET = datetime.timezone(datetime.timedelta(hours=8))


def now_bj() -> datetime.datetime:
    """返回北京时间（naive datetime，方便 SQLite 存储）。

    全项目所有 datetime 字段、有效期判断、日志时间戳都应走这里。
    """
    return datetime.datetime.now(_BJ_OFFSET).replace(tzinfo=None)


def bj_str(dt: datetime.datetime | None = None) -> str:
    """北京时间字符串 YYYY-MM-DD HH:MM:SS。"""
    if dt is None:
        dt = now_bj()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def gen_uuid() -> str:
    """生成 32 位无横线 UUID（用于文件名、salt 等）。"""
    return _uuid.uuid4().hex


def gen_token(nbytes: int = 24) -> str:
    """生成会话 token（base64url-safe 字符串）。"""
    return secrets.token_urlsafe(nbytes)


_EXT_TYPE_MAP = {
    # 文档
    "pdf":      "pdf",
    "docx":     "docx",
    "doc":      "doc",
    # 图像
    "png":      "image", "jpg":      "image", "jpeg":     "image",
    "bmp":      "image", "gif":      "image", "webp":     "image",
    "svg":      "image", "tiff":     "image",
    # 代码 / 文本
    "txt":      "text",  "md":       "text",  "log":      "text",
    "rtf":      "text",  "tex":      "text",
    "py":       "code",  "js":       "code",  "ts":       "code",
    "tsx":      "code",  "jsx":      "code",  "java":     "code",
    "c":        "code",  "cpp":      "code",  "h":        "code",
    "hpp":      "code",  "rs":       "code",  "go":       "code",
    "rb":       "code",  "php":      "code",  "swift":    "code",
    "kt":       "code",  "sh":       "code",  "bash":     "code",
    "sql":      "code",  "html":     "code",  "css":      "code",
    "yaml":     "code",  "yml":      "code",  "toml":     "code",
    "json":     "code",  "xml":      "code",  "ini":      "code",
    # 表格 / 数据
    "csv":      "csv",
    "xlsx":     "excel", "xls":      "excel",
    "tsv":      "csv",
    "db":       "data",  "sqlite":   "data", "sqlite3":  "data",
    "parquet":  "data",
    # 演示文稿
    "pptx":     "ppt",   "ppt":      "ppt",
    # 视频
    "mp4":      "video", "mkv":      "video", "mov":      "video",
    "avi":      "video", "webm":     "video", "flv":      "video",
    # 音频
    "mp3":      "audio", "wav":      "audio", "flac":     "audio",
    "aac":      "audio", "ogg":      "audio", "m4a":      "audio",
    # 压缩
    "zip":      "zip",   "rar":      "zip",   "7z":       "zip",
    "tar":      "zip",   "gz":       "zip",   "bz2":      "zip",
    "xz":       "zip",
    # 可执行
    "exe":      "binary", "dll":     "binary", "so":      "binary",
    "dmg":      "binary", "iso":     "binary", "apk":     "binary",
}


def detect_file_type(filename: str) -> str:
    """根据文件名后缀分类，决定水印分发与 UI 标签。

    返回的类别名（如 pdf/docx/image/text/code/csv/excel/data/ppt/
    video/audio/zip/binary/other）会被前端展示为中文标签，并影响
    后端 _apply_watermark 选择哪个 marker。
    """
    name = filename.rsplit("/", 1)[-1].lower()
    if "." not in name:
        return "other"
    ext = name.rsplit(".", 1)[-1]
    return _EXT_TYPE_MAP.get(ext, "other")
