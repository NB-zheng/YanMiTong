"""图片指纹嵌入：Pillow LSB 写入；缺失时追加 trailer。"""
from __future__ import annotations

import io


def embed(image_bytes: bytes, fingerprint: str) -> bytes:
    try:
        from PIL import Image
    except ImportError:
        return image_bytes + f"\nYMT-FP:{fingerprint}\n".encode("ascii")

    bio = io.BytesIO(image_bytes)
    img = Image.open(bio).convert("RGBA")
    pixels = img.load()
    bits = "".join(f"{b:08b}" for b in fingerprint.encode("utf-8"))
    bits += "00000000"  # 终止符

    w, h = img.size
    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= len(bits):
                break
            r, g, b, a = pixels[x, y]
            r = (r & ~1) | int(bits[idx])
            pixels[x, y] = (r, g, b, a)
            idx += 1
        if idx >= len(bits):
            break

    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()
