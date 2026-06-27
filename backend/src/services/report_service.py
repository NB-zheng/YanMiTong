"""取证 / 审计 PDF 报告生成。

reportlab 缺失时降级为纯文本，演示可用。

中文字体策略：
- 项目内嵌 backend/assets/fonts/NotoSansSC-Regular.ttf（Noto Sans SC 的 Variable TTF）
- TTFont 走 TrueType outlines，reportlab 会把用到的字形子集嵌入 PDF
- 跨平台一致：Windows / macOS / Linux（含 Docker 容器）打开都不乱码
- 文件不在则降级到 Helvetica（中文会变方框但不崩）
"""
from __future__ import annotations

import io
import os
from typing import Optional

from tools import bj_str


# 项目内嵌的中文字体路径
_FONT_PATH = os.path.normpath(os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "assets", "fonts", "NotoSansSC-Regular.ttf",
))
_FONT_NAME = "NotoSC"


def _try_register_cn_font() -> Optional[str]:
    """尝试注册中文字体并返回字体名；不可用则返回 None。"""
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:
        return None
    if not os.path.isfile(_FONT_PATH):
        return None
    try:
        pdfmetrics.registerFont(TTFont(_FONT_NAME, _FONT_PATH))
        return _FONT_NAME
    except Exception:
        return None


def render_forensics_pdf(result: dict, filename: str | None = None) -> tuple[bytes, str]:
    """返回 (bytes, content_type)。filename 为送检的疑似泄露文件名。

    支持多个匹配结果：
        - result.matches: list[dict] - 所有匹配项
        - result.total_count: int - 总匹配数
        - result.cross_project_count: int - 属于其他项目的指纹数
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        bio = io.BytesIO()
        c = canvas.Canvas(bio, pagesize=A4)

        # 优先用项目内嵌的中文字体；不可用时降级到 Helvetica
        font_name = _try_register_cn_font() or "Helvetica"
        font_name_bold = font_name  # reportlab 不区分粗细，用同一字体

        w, h = A4
        margin_left = 50
        y = h - 60

        # === 标题 ===
        c.setFont(font_name, 18)
        c.drawString(margin_left, y, "研密通 · 泄露取证报告")
        y -= 30

        # === 基本信息 ===
        c.setFont(font_name, 11)
        c.drawString(margin_left, y, f"生成时间：{bj_str()}")
        y -= 20
        c.drawString(margin_left, y, f"取证文件：{filename or '-'}")
        y -= 24

        # === 匹配结果汇总 ===
        leaker_count = result.get("leaker_count", 0)
        total_count = result.get("total_count", 0)
        cross_project = result.get("cross_project_count", 0)

        if leaker_count > 0:
            status_text = f"已定位到 {leaker_count} 位泄露者（{total_count} 条匹配记录）"
        elif cross_project > 0:
            status_text = "命中但属于其它项目（无权查看下载者）"
        else:
            status_text = "未匹配"

        c.drawString(margin_left, y, f"匹配结果：{status_text}")
        y -= 20

        # 如果有跨项目计数
        if cross_project > 0:
            c.drawString(margin_left, y, f"（另有 {cross_project} 个指纹属于其他项目，无法查看）")
            y -= 20

        y -= 10

        # === 详细匹配列表 ===
        matches = result.get("matches", [])
        if matches:
            # 表头
            c.setFont(font_name_bold, 10)
            c.drawString(margin_left, y, "序号")
            c.drawString(margin_left + 40, y, "下载用户")
            c.drawString(margin_left + 160, y, "下载时间")
            c.drawString(margin_left + 330, y, "客户端IP")
            y -= 5
            # 下划线
            c.line(margin_left, y, w - 50, y)
            y -= 18

            # 数据行
            c.setFont(font_name, 10)
            for i, m in enumerate(matches, 1):
                # 检查是否需要换页
                if y < 80:
                    c.showPage()
                    y = h - 60
                    c.setFont(font_name, 10)

                c.drawString(margin_left, y, str(i))
                c.drawString(margin_left + 40, y, m.get('username', '-'))
                c.drawString(margin_left + 160, y, str(m.get('download_time', '-')[:19] if m.get('download_time') else '-'))
                c.drawString(margin_left + 330, y, m.get('client_ip', '-') or '-')
                y -= 18

        y -= 10

        # === 说明 ===
        if result.get("message"):
            c.setFont(font_name, 9)
            c.drawString(margin_left, y, f"说明：{result['message']}")

        c.showPage()
        c.save()
        return bio.getvalue(), "application/pdf"
    except ImportError:
        # 降级为文本
        lines = ["研密通 · 泄露取证报告", bj_str(), f"取证文件：{filename or '-'}", ""]

        matches = result.get("matches", [])
        leaker_count = result.get("leaker_count", 0)
        total_count = result.get("total_count", 0)
        cross_project = result.get("cross_project_count", 0)

        if leaker_count > 0:
            lines += [f"匹配结果：已定位到 {leaker_count} 位泄露者（{total_count} 条匹配记录）", ""]
            if cross_project > 0:
                lines.append(f"（另有 {cross_project} 个指纹属于其他项目）")
                lines.append("")
            lines.append("详细列表：")
            for i, m in enumerate(matches, 1):
                lines.append(f"  {i}. {m.get('username', '-')}  |  {m.get('download_time', '-')}  |  {m.get('client_ip', '-') or '-'}")
        elif cross_project > 0:
            lines.append("匹配结果：命中但属于其它项目（无权查看下载者）")
        else:
            lines.append("匹配结果：未匹配")

        if result.get("message"):
            lines.append(f"说明：{result['message']}")
        return ("\n".join(lines) + "\n").encode("utf-8"), "text/plain; charset=utf-8"
