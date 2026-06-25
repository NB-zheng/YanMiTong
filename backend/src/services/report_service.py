"""取证 / 审计 PDF 报告生成。

reportlab 缺失时降级为纯文本，演示可用。
"""
from __future__ import annotations

import io
from typing import Optional

from tools import bj_str


def render_forensics_pdf(result: dict, filename: str | None = None) -> tuple[bytes, str]:
    """返回 (bytes, content_type)。filename 为送检的疑似泄露文件名。"""
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
        y -= 20
        c.drawString(50, y, f"取证文件：{filename or '-'}")
        y -= 24

        if result.get("matched"):
            status_text = "已定位到下载者"
        elif result.get("cross_project"):
            status_text = "命中但属于其它项目（无权查看下载者）"
        else:
            status_text = "未匹配"

        lines = [f"匹配结果：{status_text}"]
        if result.get("matched"):
            lines += [
                f"下载用户：{result.get('username') or '-'}",
                f"下载时间：{result.get('download_time') or '-'}",
            ]
        if result.get("message"):
            lines.append(f"说明：{result['message']}")

        for line in lines:
            c.drawString(50, y, line)
            y -= 20

        c.showPage()
        c.save()
        return bio.getvalue(), "application/pdf"
    except ImportError:
        # 降级为文本（同样不暴露指纹/水印类型等内部细节）
        lines = ["研密通 · 泄露取证报告", bj_str(), f"取证文件：{filename or '-'}", ""]
        if result.get("matched"):
            lines += ["匹配结果：已定位到下载者",
                      f"下载用户：{result.get('username') or '-'}",
                      f"下载时间：{result.get('download_time') or '-'}"]
        elif result.get("cross_project"):
            lines.append("匹配结果：命中但属于其它项目（无权查看下载者）")
        else:
            lines.append("匹配结果：未匹配")
        if result.get("message"):
            lines.append(f"说明：{result['message']}")
        return ("\n".join(lines) + "\n").encode("utf-8"), "text/plain; charset=utf-8"
