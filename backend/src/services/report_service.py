"""取证 / 审计 PDF 报告生成。

reportlab 缺失时降级为纯文本，演示可用。
"""
from __future__ import annotations

import io
from typing import Optional

from tools import bj_str


def render_forensics_pdf(result: dict) -> tuple[bytes, str]:
    """返回 (bytes, content_type)。"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import os

        bio = io.BytesIO()
        c = canvas.Canvas(bio, pagesize=A4)
        # 尽量找一个中文字体；找不到就用默认（中文会变方框，演示可接受）
        font_name = "Helvetica"
        for fp in ["/System/Library/Fonts/PingFang.ttc",
                   "/System/Library/Fonts/STHeiti Light.ttc",
                   "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"]:
            if os.path.exists(fp):
                try:
                    pdfmetrics.registerFont(TTFont("CN", fp))
                    font_name = "CN"
                    break
                except Exception:
                    pass

        w, h = A4
        y = h - 60
        c.setFont(font_name, 18)
        c.drawString(50, y, "研密通 · 泄露取证报告")
        y -= 30
        c.setFont(font_name, 11)
        c.drawString(50, y, f"生成时间：{bj_str()}")
        y -= 24

        lines = [
            f"匹配结果：{'已定位到下载者' if result.get('matched') else '未匹配'}",
            f"提取的指纹：{result.get('fingerprint') or '-'}",
            f"责任用户：{result.get('username') or '-'} (user_id={result.get('user_id')})",
            f"关联文件：file_id={result.get('file_id') or '-'}",
            f"下载时间：{result.get('download_time') or '-'}",
            f"水印类型：{result.get('watermark_type') or '-'}",
            f"说明：{result.get('message') or ''}",
        ]
        for line in lines:
            c.drawString(50, y, line)
            y -= 20

        c.showPage()
        c.save()
        return bio.getvalue(), "application/pdf"
    except ImportError:
        # 降级为文本
        text = "研密通 · 泄露取证报告\n" + bj_str() + "\n\n"
        for k, v in result.items():
            text += f"{k}: {v}\n"
        return text.encode("utf-8"), "text/plain; charset=utf-8"
