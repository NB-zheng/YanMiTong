"""防腐层：业务层只认这一层 API；底层切到队长的 crypto_core 后所有业务代码零改动。

设计要点：
- crypto_core 提供 SM2/SM3 文件摘要/哈希链；本适配器额外补 SM4 字节级 API
  （crypto_core 仅暴露文件级 SM4，业务侧需要内存级用于私钥加解封）。
- SM4 字节级 = 16B 随机 IV || SM4-CBC(K, PKCS#7(plain))，与 crypto_core 的
  文件级 SM4 格式保持一致（IV 前缀 + CBC 主体）。
- SM2 密文统一使用 hex 字符串（crypto_core 风格），数据库 Text 字段存。
- 哈希链 log 内容统一为 canonical_json（业务层传 dict，由本层串行化）。
"""
from __future__ import annotations

import json
import os
import secrets
from typing import Tuple

from gmssl import func, sm3
from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT

try:
    import crypto_core as _core
    _USE_REAL = True
except Exception:
    _core = None
    _USE_REAL = False


GENESIS_HASH = "0" * 64


# ===== SM3 =====
def sm3_hash(data: bytes) -> str:
    """计算 SM3 摘要，返回 64 字符 hex。"""
    return sm3.sm3_hash(func.bytes_to_list(data))


def sm3_file_hash(path: str) -> str:
    if _USE_REAL:
        return _core.sm3_file_hash(path)
    with open(path, "rb") as f:
        return sm3_hash(f.read())


# ===== SM2 =====
def sm2_generate_keypair() -> Tuple[str, str]:
    """返回 (private_key_hex 64, public_key_hex 128)。"""
    if _USE_REAL:
        return _core.sm2_generate_keypair()
    # 不该走到这里；adapter 必须有 crypto_core
    raise RuntimeError("crypto_core 未加载")


def sm2_sign(private_key_hex: str, message: bytes) -> str:
    if _USE_REAL:
        return _core.sm2_sign(private_key_hex, message)
    raise RuntimeError("crypto_core 未加载")


def sm2_verify(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    if _USE_REAL:
        return _core.sm2_verify(public_key_hex, message, signature_hex)
    return False


def sm2_encrypt_key(public_key_hex: str, sym_key: bytes) -> str:
    """SM2 封装 SM4 文件密钥 K，返回 hex 字符串。"""
    if _USE_REAL:
        return _core.sm2_encrypt_key(public_key_hex, sym_key)
    raise RuntimeError("crypto_core 未加载")


def sm2_decrypt_key(private_key_hex: str, cipher_hex: str) -> bytes:
    """解封装出 16 字节 SM4 文件密钥。"""
    if _USE_REAL:
        return _core.sm2_decrypt_key(private_key_hex, cipher_hex)
    raise RuntimeError("crypto_core 未加载")


# ===== SM4 字节级（业务侧需要内存加解密：私钥保护、强撤销等） =====
def sm4_encrypt_bytes(key: bytes, plain: bytes) -> bytes:
    """16B 随机 IV || SM4-CBC(PKCS#7(plain))。"""
    if len(key) != 16:
        raise ValueError("SM4 密钥必须 16 字节")
    iv = os.urandom(16)
    crypt = CryptSM4()
    crypt.set_key(key, SM4_ENCRYPT)
    cipher = crypt.crypt_cbc(iv, plain)  # gmssl 自动 PKCS#7
    return iv + cipher


def sm4_decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("SM4 密钥必须 16 字节")
    if len(blob) < 32 or len(blob) % 16 != 0:
        raise ValueError("SM4 密文长度不合法")
    iv, cipher = blob[:16], blob[16:]
    crypt = CryptSM4()
    crypt.set_key(key, SM4_DECRYPT)
    return crypt.crypt_cbc(iv, cipher)


# ===== SM4 文件级（直接转交 crypto_core） =====
def sm4_encrypt_file(key: bytes, src_path: str, dst_path: str) -> None:
    if _USE_REAL:
        return _core.sm4_encrypt_file(src_path, dst_path, key)
    raise RuntimeError("crypto_core 未加载")


def sm4_decrypt_file_to_path(key: bytes, src_path: str, dst_path: str) -> None:
    if _USE_REAL:
        return _core.sm4_decrypt_file(src_path, dst_path, key)
    raise RuntimeError("crypto_core 未加载")


# ===== 私钥保护（业务侧用密码派生 SM4 密钥加密 SM2 私钥） =====
def _sm4_key_from_password(password: str) -> bytes:
    return bytes.fromhex(sm3_hash(password.encode("utf-8")))[:16]


def encrypt_private_key_with_password(private_key_hex: str, password: str) -> str:
    """返回 hex 字符串，存数据库 User.encrypted_private_key。"""
    k = _sm4_key_from_password(password)
    return sm4_encrypt_bytes(k, private_key_hex.encode("ascii")).hex()


def decrypt_private_key_with_password(enc_hex: str, password: str) -> str:
    k = _sm4_key_from_password(password)
    plain = sm4_decrypt_bytes(k, bytes.fromhex(enc_hex))
    return plain.decode("ascii")


# ===== 文件密钥 =====
def gen_file_key() -> bytes:
    """128-bit 随机 SM4 文件密钥 K。"""
    return secrets.token_bytes(16)


# ===== 指纹 =====
def generate_fingerprint(user_id, file_id, ts: str, salt: str) -> str:
    """报告 4.3 公式：SM3(user_id || file_id || time || salt)。"""
    if _USE_REAL:
        return _core.generate_fingerprint(str(user_id), str(file_id), str(ts), str(salt))
    payload = f"{user_id}{file_id}{ts}{salt}".encode("utf-8")
    return sm3_hash(payload)


# ===== 哈希链 =====
def _canonical_log(payload: dict) -> str:
    """业务 dict 转规范字符串，确保每次序列化一致。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def hash_chain_append(prev_hash: str, log_payload: dict) -> str:
    """current_hash = SM3(canonical_log(payload) || prev_hash)。

    业务侧总是传 dict；本层做规范序列化后调 crypto_core.hash_chain_append。
    """
    content = _canonical_log(log_payload)
    if _USE_REAL:
        return _core.hash_chain_append(content, prev_hash)
    return sm3_hash(content.encode("utf-8") + prev_hash.encode("ascii"))


def hash_chain_verify(records: list[dict]) -> tuple[bool, int]:
    """逐条重算；返回 (ok, broken_at_log_id 或 -1)。

    自有实现是因为 crypto_core.hash_chain_verify 只返回 bool，
    本接口需要精确定位断裂位置便于前端审计大屏标红。
    """
    prev = GENESIS_HASH
    for r in records:
        payload = {
            "user_id": r["user_id"],
            "operation": r["operation"],
            "object_type": r.get("object_type"),
            "object_id": r.get("object_id"),
            "result": r["result"],
            "detail": r.get("detail"),
            "timestamp": r["timestamp"],
        }
        expected = hash_chain_append(prev, payload)
        if expected != r["current_hash"] or r["prev_hash"] != prev:
            return False, r["log_id"]
        prev = r["current_hash"]
    return True, -1


def is_using_real_crypto() -> bool:
    return _USE_REAL
