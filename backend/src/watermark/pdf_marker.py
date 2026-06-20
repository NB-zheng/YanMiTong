"""PDF 指纹嵌入：优先用 PyMuPDF 写元数据，缺失则追加 PDF Info 字段。"""
from __future__ import annotations

import io


def embed(pdf_bytes: bytes, fingerprint: str) -> bytes:
    """在 PDF 元数据中写入指纹；返回新的 PDF 字节流。

    比赛真用环境装了 PyMuPDF；若 import 失败则降级为追加注释，
    取证侧的正则同时认 /YMTFingerprint 和 YMT-FP: 两种格式。
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return pdf_bytes + f"\n%YMT-FP:{fingerprint}\n".encode("ascii")

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    # 空文档（损坏 / 非真实 PDF）：set_metadata 可能很快，但 doc[-1] 在 0 页 PDF
    # 上会让 MuPDF 进入很慢的页面解析路径甚至无限循环。直接降级到追加注释。
    if doc.page_count == 0:
        doc.close()
        return pdf_bytes + f"\n%YMT-FP:{fingerprint}\n".encode("ascii")

    meta = doc.metadata or {}
    meta["keywords"] = (meta.get("keywords") or "") + f" YMTFingerprint({fingerprint})"
    meta["subject"] = (meta.get("subject") or "") + f" /YMTFingerprint({fingerprint})"
    doc.set_metadata(meta)

    # 同时在末页加一行极小、近透明的水印，肉眼基本不可见
    try:
        page = doc[-1]
        rect = page.rect
        page.insert_text(
            (rect.width - 200, rect.height - 10),
            f"YMT-FP:{fingerprint}",
            fontsize=4,
            color=(0.95, 0.95, 0.95),
        )
    except Exception:
        pass

    out = io.BytesIO()
    doc.save(out)
    doc.close()
    return out.getvalue()
