"""
configclient - Lightweight configuration center client library.

Standard library only.
"""

import os
import sys
import json
import time
import re
import base64
import threading
import hashlib
import urllib.request
import urllib.error
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple

__version__ = "1.0.0"

EXIT_OK = 0
EXIT_ARG_ERROR = 1
EXIT_REMOTE_ERROR = 2
EXIT_VALIDATION_ERROR = 3
EXIT_PERMISSION_ERROR = 4
EXIT_IO_ERROR = 5

KEY_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")
ENC_PREFIX = "enc://"
ENC_VERSION_PREFIX = "v1:"
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0


def _log(level: str, message: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    sys.stderr.write(f"[{ts}] [{level.upper()}] {message}\n")
    sys.stderr.flush()


def log_info(msg: str) -> None:
    _log("info", msg)


def log_warn(msg: str) -> None:
    _log("warn", msg)


def log_error(msg: str) -> None:
    _log("error", msg)


def _derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def _get_crypto_key() -> Optional[bytes]:
    key = os.environ.get("CONFIG_KEY")
    if key is None:
        return None
    if not key:
        return None
    return _derive_key(key)


def require_crypto_key() -> bytes:
    key = _get_crypto_key()
    if key is None:
        log_error("Environment variable CONFIG_KEY is not set or empty. Refusing to run with empty key.")
        sys.exit(EXIT_ARG_ERROR)
    return key


_AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

_AES_INV_SBOX = bytes([
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
])

_AES_RCON = bytes([
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
    0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a,
])


def _aes_sub_word(w: bytes) -> bytes:
    return bytes(_AES_SBOX[b] for b in w)


def _aes_rot_word(w: bytes) -> bytes:
    return bytes([w[1], w[2], w[3], w[0]])


def _aes_key_expansion_256(key: bytes) -> List[bytes]:
    nk = 8
    nr = 14
    nb = 4
    total = nb * (nr + 1)
    w: List[bytes] = [bytes(4)] * total
    for i in range(nk):
        w[i] = bytes(key[4*i : 4*i+4])
    for i in range(nk, total):
        temp = w[i-1]
        if i % nk == 0:
            temp = _aes_sub_word(_aes_rot_word(temp))
            temp = bytes([temp[0] ^ _AES_RCON[i // nk]]) + temp[1:]
        elif nk > 6 and (i % nk) == 4:
            temp = _aes_sub_word(temp)
        w[i] = bytes(a ^ b for a, b in zip(w[i-nk], temp))
    return w


def _aes_add_round_key(state: List[List[int]], round_key: List[bytes]) -> None:
    for c in range(4):
        col = round_key[c]
        for r in range(4):
            state[r][c] ^= col[r]


def _aes_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _AES_SBOX[state[r][c]]


def _aes_inv_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _AES_INV_SBOX[state[r][c]]


def _aes_shift_rows(state: List[List[int]]) -> None:
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]


def _aes_inv_shift_rows(state: List[List[int]]) -> None:
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _aes_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2 ^ s3
        state[1][c] = s0 ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
        state[2][c] = s0 ^ s1 ^ _gmul(s2, 2) ^ _gmul(s3, 3)
        state[3][c] = _gmul(s0, 3) ^ s1 ^ s2 ^ _gmul(s3, 2)


def _aes_inv_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = _gmul(s0, 14) ^ _gmul(s1, 11) ^ _gmul(s2, 13) ^ _gmul(s3, 9)
        state[1][c] = _gmul(s0, 9) ^ _gmul(s1, 14) ^ _gmul(s2, 11) ^ _gmul(s3, 13)
        state[2][c] = _gmul(s0, 13) ^ _gmul(s1, 9) ^ _gmul(s2, 14) ^ _gmul(s3, 11)
        state[3][c] = _gmul(s0, 11) ^ _gmul(s1, 13) ^ _gmul(s2, 9) ^ _gmul(s3, 14)


def _aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    w = _aes_key_expansion_256(key)
    state: List[List[int]] = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = block[c*4 + r]
    nr = 14
    round0_key = [w[0], w[1], w[2], w[3]]
    _aes_add_round_key(state, round0_key)
    for rnd in range(1, nr):
        _aes_sub_bytes(state)
        _aes_shift_rows(state)
        _aes_mix_columns(state)
        rk = [w[rnd*4], w[rnd*4+1], w[rnd*4+2], w[rnd*4+3]]
        _aes_add_round_key(state, rk)
    _aes_sub_bytes(state)
    _aes_shift_rows(state)
    last_rk = [w[nr*4], w[nr*4+1], w[nr*4+2], w[nr*4+3]]
    _aes_add_round_key(state, last_rk)
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c*4 + r] = state[r][c]
    return bytes(out)


def _aes_ctr_xor(key: bytes, nonce: bytes, data: bytes, initial_counter: int = 2) -> bytes:
    result = bytearray(len(data))
    counter_block = bytearray(16)
    if len(nonce) == 12:
        counter_block[0:12] = nonce
        ctr = initial_counter
        for i in range(3, -1, -1):
            counter_block[12 + i] = (ctr >> (8 * (3 - i))) & 0xFF
    else:
        counter_block[0:len(nonce)] = nonce[:16]
        ctr = initial_counter
        for i in range(4):
            counter_block[15 - i] ^= ((ctr >> (8 * i)) & 0xFF)
    offset = 0
    total = len(data)
    while offset < total:
        keystream = _aes_encrypt_block(key, bytes(counter_block))
        chunk_len = min(16, total - offset)
        for i in range(chunk_len):
            result[offset + i] = data[offset + i] ^ keystream[i]
        offset += chunk_len
        if len(nonce) == 12:
            ctr += 1
            for i in range(3, -1, -1):
                counter_block[12 + i] = (ctr >> (8 * (3 - i))) & 0xFF
        else:
            for i in range(15, -1, -1):
                counter_block[i] = (counter_block[i] + 1) & 0xFF
                if counter_block[i] != 0:
                    break
    return bytes(result)


def _aes_gcm_derive_hash_subkey(key: bytes) -> bytes:
    return _aes_encrypt_block(key, b"\x00" * 16)


def _gcm_mul_block(x: bytes, y: bytes) -> bytes:
    x_int = int.from_bytes(x, "big")
    y_int = int.from_bytes(y, "big")
    mask = (1 << 128) - 1
    r_poly = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1
    z = 0
    v = y_int
    for i in range(128):
        if x_int & (1 << (127 - i)):
            z ^= v
        v_lsb = v & 1
        v = (v >> 1) & mask
        if v_lsb:
            v ^= (r_poly & mask)
    return z.to_bytes(16, "big")


def _ghash_correct(h: bytes, data: bytes) -> bytes:
    if not data:
        return b"\x00" * 16
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    last = blocks[-1]
    if len(last) < 16:
        blocks[-1] = last + b"\x00" * (16 - len(last))
    y = b"\x00" * 16
    for blk in blocks:
        xored = bytes(a ^ b for a, b in zip(y, blk))
        y = _gcm_mul_block(xored, h)
    return y


def _aes_gcm_encrypt_pure(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    h = _aes_gcm_derive_hash_subkey(key)
    if len(nonce) == 12:
        j0_pre = nonce + b"\x00\x00\x00\x01"
    else:
        padded = nonce
        if len(padded) % 16 != 0:
            padded = padded + b"\x00" * (16 - (len(padded) % 16))
        len_block = (len(nonce) * 8).to_bytes(16, "big")
        j0_pre = _ghash_correct(h, padded + len_block)
    ciphertext = _aes_ctr_xor(key, nonce, plaintext, initial_counter=2)
    auth_block = b""
    if aad:
        auth_block += aad
        rem = len(aad) % 16
        if rem != 0:
            auth_block += b"\x00" * (16 - rem)
    if ciphertext:
        auth_block += ciphertext
        rem = len(ciphertext) % 16
        if rem != 0:
            auth_block += b"\x00" * (16 - rem)
    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    auth_block += len_block.to_bytes(16, "big")
    ghash_result = _ghash_correct(h, auth_block)
    enc_j0 = _aes_encrypt_block(key, j0_pre)
    tag = bytes(a ^ b for a, b in zip(ghash_result, enc_j0))
    return ciphertext, tag


def _aes_gcm_decrypt_pure(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, expected_tag: bytes) -> Optional[bytes]:
    if len(expected_tag) != 16:
        return None
    h = _aes_gcm_derive_hash_subkey(key)
    if len(nonce) == 12:
        j0_pre = nonce + b"\x00\x00\x00\x01"
    else:
        padded = nonce
        if len(padded) % 16 != 0:
            padded = padded + b"\x00" * (16 - (len(padded) % 16))
        len_block = (len(nonce) * 8).to_bytes(16, "big")
        j0_pre = _ghash_correct(h, padded + len_block)
    auth_block = b""
    if aad:
        auth_block += aad
        rem = len(aad) % 16
        if rem != 0:
            auth_block += b"\x00" * (16 - rem)
    if ciphertext:
        auth_block += ciphertext
        rem = len(ciphertext) % 16
        if rem != 0:
            auth_block += b"\x00" * (16 - rem)
    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    auth_block += len_block.to_bytes(16, "big")
    ghash_result = _ghash_correct(h, auth_block)
    enc_j0 = _aes_encrypt_block(key, j0_pre)
    computed_tag = bytes(a ^ b for a, b in zip(ghash_result, enc_j0))
    diff = 0
    for a, b in zip(computed_tag, expected_tag):
        diff |= a ^ b
    if diff != 0:
        return None
    plaintext = _aes_ctr_xor(key, nonce, ciphertext, initial_counter=2)
    return plaintext


def aes_gcm_encrypt(plaintext: str, key: bytes) -> str:
    try:
        nonce = os.urandom(NONCE_LEN)
        ct, tag = _aes_gcm_encrypt_pure(key, nonce, plaintext.encode("utf-8"), b"")
        raw = nonce + ct + tag
        b64 = base64.b64encode(raw).decode("ascii")
        return ENC_PREFIX + ENC_VERSION_PREFIX + b64
    except Exception as e:
        log_warn(f"AES-GCM encrypt failed: {e}")
        return ""


def aes_gcm_decrypt(enc_value: str, key: Optional[bytes] = None) -> Optional[str]:
    if not enc_value.startswith(ENC_PREFIX):
        log_warn(f"Value does not start with {ENC_PREFIX}")
        return None
    rest = enc_value[len(ENC_PREFIX):]
    if not rest.startswith(ENC_VERSION_PREFIX):
        log_warn(f"Unknown encryption version prefix, expected {ENC_VERSION_PREFIX!r}")
        return None
    b64part = rest[len(ENC_VERSION_PREFIX):]
    try:
        raw = base64.b64decode(b64part)
    except Exception as e:
        log_warn(f"Base64 decode failed: {e}")
        return None
    if len(raw) < NONCE_LEN + TAG_LEN:
        log_warn("Ciphertext too short")
        return None
    nonce = raw[:NONCE_LEN]
    ct = raw[NONCE_LEN:-TAG_LEN]
    tag = raw[-TAG_LEN:]
    if key is None:
        key = _get_crypto_key()
        if key is None:
            log_warn("CONFIG_KEY not set, cannot decrypt")
            return None
    try:
        pt = _aes_gcm_decrypt_pure(key, nonce, ct, b"", tag)
        if pt is None:
            log_warn("Tag verification failed during decryption")
            return None
        return pt.decode("utf-8")
    except Exception as e:
        log_warn(f"AES-GCM decrypt failed: {e}")
        return None


def cache_dir() -> Path:
    return Path.home() / ".configcache"


def cache_path() -> Path:
    return cache_dir() / "cache.json"


def history_path(version: int) -> Path:
    return cache_dir() / f"cache.{version}.json"


def list_history_versions() -> List[int]:
    d = cache_dir()
    if not d.exists():
        return []
    versions = []
    for p in d.glob("cache.*.json"):
        try:
            v = int(p.stem.split(".", 1)[1])
            versions.append(v)
        except (ValueError, IndexError):
            continue
    versions.sort(reverse=True)
    return versions


def _ensure_cache_dir() -> None:
    d = cache_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        log_error(f"Permission denied creating cache directory: {d}")
        sys.exit(EXIT_PERMISSION_ERROR)
    except OSError as e:
        log_error(f"Failed to create cache directory {d}: {e}")
        sys.exit(EXIT_IO_ERROR)


def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors = []
    if not isinstance(config, dict):
        errors.append("Root config must be a JSON object")
        return False, errors
    if "version" not in config:
        errors.append("Missing required field: version")
    else:
        if not isinstance(config["version"], int) or isinstance(config["version"], bool):
            errors.append("Field 'version' must be an integer")
    if "updated_at" not in config:
        errors.append("Missing required field: updated_at")
    else:
        ua = config["updated_at"]
        if not isinstance(ua, str):
            errors.append("Field 'updated_at' must be an ISO 8601 string")
        else:
            try:
                datetime.fromisoformat(ua.replace("Z", "+00:00"))
            except ValueError:
                errors.append("Field 'updated_at' is not a valid ISO 8601 string")
    for k, v in config.items():
        if k in ("version", "updated_at"):
            continue
        if not KEY_PATTERN.match(k):
            errors.append(f"Invalid key name: {k!r}. Must match [a-zA-Z0-9._-]+")
        ok, e = _validate_value(v, f"value for key {k!r}")
        if not ok:
            errors.extend(e)
    return len(errors) == 0, errors


def _validate_value(v: Any, ctx: str) -> Tuple[bool, List[str]]:
    errs = []
    if v is None:
        return True, errs
    if isinstance(v, bool):
        return True, errs
    if isinstance(v, (int, float)):
        return True, errs
    if isinstance(v, str):
        return True, errs
    if isinstance(v, list):
        for i, item in enumerate(v):
            ok, e = _validate_value(item, f"{ctx}[{i}]")
            if not ok:
                errs.extend(e)
        return len(errs) == 0, errs
    if isinstance(v, dict):
        for k, item in v.items():
            if not KEY_PATTERN.match(str(k)):
                errs.append(f"Invalid nested key: {k!r} in {ctx}. Must match [a-zA-Z0-9._-]+")
            ok, e = _validate_value(item, f"{ctx}.{k}")
            if not ok:
                errs.extend(e)
        return len(errs) == 0, errs
    errs.append(f"Invalid type in {ctx}: {type(v).__name__}. Allowed: string, number, boolean, null, object, array")
    return False, errs


def fetch_remote(url: str, etag: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """Fetch config from remote HTTP endpoint.

    Returns: (config_dict_or_none, error_message_or_none, new_etag_or_none)
    If remote returns 304 Not Modified, config is None and error is None.
    """
    try:
        req = urllib.request.Request(url, method="GET")
        if etag:
            req.add_header("If-None-Match", etag)
        resp = urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT)
        try:
            sock = getattr(resp, "fp", None)
            if sock and hasattr(sock, "_sock"):
                raw_sock = sock._sock
                if hasattr(raw_sock, "settimeout"):
                    raw_sock.settimeout(READ_TIMEOUT)
            raw = resp.read()
        except socket.timeout:
            try:
                resp.close()
            except Exception:
                pass
            return None, "Read timeout while reading remote response", None
        except Exception as e:
            try:
                resp.close()
            except Exception:
                pass
            return None, f"Failed to read remote response: {e}", None
        code = resp.getcode()
        new_etag = resp.headers.get("ETag") if hasattr(resp, "headers") else None
        if code == 304:
            return None, None, new_etag
        try:
            cfg = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as e:
            return None, f"Remote response is not valid JSON: {e}", new_etag
        except Exception as e:
            return None, f"Failed to parse remote response: {e}", new_etag
        return cfg, None, new_etag
    except urllib.error.HTTPError as e:
        if e.code == 304:
            new_etag = e.headers.get("ETag") if e.headers else None
            return None, None, new_etag
        return None, f"Remote HTTP error: {e.code} {e.reason}", None
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.timeout):
            return None, f"Connection timeout to {url}", None
        return None, f"Remote unreachable: {reason}", None
    except socket.timeout:
        return None, f"Connection timeout to {url}", None
    except ssl.SSLError as e:
        return None, f"SSL error: {e}", None
    except PermissionError:
        return None, "Permission denied while connecting to remote", None
    except OSError as e:
        return None, f"OS error connecting to remote: {e}", None
    except Exception as e:
        return None, f"Unexpected error fetching remote: {e}", None


def push_remote(url: str, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    try:
        body = json.dumps(config, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="PUT")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT)
        try:
            resp.read()
        except Exception:
            pass
        return True, None
    except urllib.error.HTTPError as e:
        return False, f"Remote HTTP error during PUT: {e.code} {e.reason}"
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.timeout):
            return False, f"Connection timeout pushing to {url}"
        return False, f"Remote unreachable during push: {reason}"
    except socket.timeout:
        return False, f"Connection timeout pushing to {url}"
    except ssl.SSLError as e:
        return False, f"SSL error during push: {e}"
    except PermissionError:
        return False, "Permission denied while pushing to remote"
    except OSError as e:
        return False, f"OS error pushing to remote: {e}"
    except Exception as e:
        return False, f"Unexpected error pushing to remote: {e}"


def load_cache() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    p = cache_path()
    if not p.exists():
        return None, None
    try:
        raw = p.read_text(encoding="utf-8")
    except PermissionError:
        return None, f"Permission denied reading cache file {p}"
    except OSError as e:
        return None, f"IO error reading cache file {p}: {e}"
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, f"Cache file is not valid JSON: {e}"
    return cfg, None


def save_cache(config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    _ensure_cache_dir()
    p = cache_path()
    try:
        p.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    except PermissionError:
        return False, f"Permission denied writing cache file {p}"
    except OSError as e:
        return False, f"IO error writing cache file {p}: {e}"
    return True, None


def save_history(config: Dict[str, Any]) -> None:
    _ensure_cache_dir()
    v = config.get("version")
    if not isinstance(v, int) or isinstance(v, bool):
        return
    p = history_path(v)
    if p.exists():
        return
    try:
        p.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        log_warn(f"Failed to save history version {v}: {e}")
    _prune_history()


def _prune_history() -> None:
    versions = list_history_versions()
    if len(versions) <= 20:
        return
    for v in versions[20:]:
        try:
            history_path(v).unlink(missing_ok=True)
        except Exception:
            pass


def load_history(version: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    p = history_path(version)
    if not p.exists():
        return None, f"History version {version} not found"
    try:
        raw = p.read_text(encoding="utf-8")
    except PermissionError:
        return None, f"Permission denied reading history file {p}"
    except OSError as e:
        return None, f"IO error reading history file {p}: {e}"
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, f"History file is not valid JSON: {e}"
    return cfg, None


def banner(version_source: str) -> None:
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.write(f"  configclient v{__version__}\n")
    sys.stderr.write(f"  Config source: {version_source}\n")
    sys.stderr.write("=" * 60 + "\n")
    sys.stderr.flush()


class ConfigClient:
    def __init__(self, remote_url: Optional[str] = None, dry_run: bool = False):
        self._lock = threading.RLock()
        self._config: Dict[str, Any] = {}
        self._loaded = False
        self._source = "none"
        self._remote_url = remote_url
        self._dry_run = dry_run
        self._etag: Optional[str] = None
        self._last_version: Optional[int] = None
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_stop = threading.Event()
        self._async_load_thread: Optional[threading.Thread] = None
        self._allow_push = False
        self._local_modified = False
        self._fail_count = 0
        self._watch_interval_normal = 30.0
        self._watch_interval_degraded = 300.0

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def config_source(self) -> str:
        return self._source

    def version(self) -> Optional[int]:
        with self._lock:
            v = self._config.get("version")
            if isinstance(v, int) and not isinstance(v, bool):
                return v
            return None

    def get(self, key: str, decrypt: bool = False) -> Optional[Any]:
        if not KEY_PATTERN.match(key):
            return None
        with self._lock:
            if not self._loaded:
                return None
            parts = key.split(".")
            cur: Any = self._config
            for p in parts:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    return None
            if isinstance(cur, str) and cur.startswith(ENC_PREFIX) and decrypt:
                decrypted = aes_gcm_decrypt(cur)
                if decrypted is None:
                    return None
                return decrypted
            return cur

    def set(self, key: str, value: Any) -> None:
        if not KEY_PATTERN.match(key):
            raise ValueError(f"Invalid key: {key!r}")
        with self._lock:
            parts = key.split(".")
            cur: Any = self._config
            for p in parts[:-1]:
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
            cur[parts[-1]] = value
            cur_v = self._config.get("version")
            if isinstance(cur_v, int) and not isinstance(cur_v, bool):
                self._config["version"] = cur_v + 1
            self._config["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            self._local_modified = True
            snapshot = dict(self._config)
        ok, err = save_cache(snapshot)
        if not ok and err:
            log_warn(f"Failed to persist local change to cache: {err}")

    def _apply_config(self, config: Dict[str, Any], source: str) -> bool:
        if self._dry_run:
            log_info(f"[dry-run] Would load config from {source}, version={config.get('version')}")
            log_info(f"[dry-run] Config preview: {json.dumps(config, ensure_ascii=False)[:500]}")
            with self._lock:
                self._loaded = True
                self._source = source
            return False
        with self._lock:
            old_ver = self._config.get("version")
            new_ver = config.get("version")
            if self._loaded and isinstance(old_ver, int) and isinstance(new_ver, int) and not isinstance(old_ver, bool) and not isinstance(new_ver, bool):
                if new_ver <= old_ver and not self._local_modified:
                    return False
            self._config = config
            self._loaded = True
            self._source = source
        return True

    def load_from_cache(self) -> Tuple[bool, Optional[str]]:
        cfg, err = load_cache()
        if err:
            return False, err
        if cfg is None:
            return False, None
        ok, verrs = validate_config(cfg)
        if not ok:
            for e in verrs:
                log_warn(f"Cache validation warning: {e}")
            return False, "Cache validation failed"
        self._apply_config(cfg, "cache")
        return True, None

    def load_from_remote(self, save_history_flag: bool = True) -> Tuple[bool, Optional[str]]:
        if not self._remote_url:
            return False, "No remote URL configured"
        with self._lock:
            current_etag = self._etag
        cfg, err, new_etag = fetch_remote(self._remote_url, etag=current_etag)
        if err:
            return False, err
        if cfg is None:
            if new_etag:
                with self._lock:
                    self._etag = new_etag
            return True, None
        if new_etag:
            with self._lock:
                self._etag = new_etag
        ok, verrs = validate_config(cfg)
        if not ok:
            for e in verrs:
                log_warn(f"Remote validation warning: {e}")
            return False, "Remote config validation failed, keeping previous config"
        new_ver = cfg.get("version")
        with self._lock:
            old_ver = self._last_version
        if (isinstance(old_ver, int) and not isinstance(old_ver, bool)
            and isinstance(new_ver, int) and not isinstance(new_ver, bool)
            and new_ver == old_ver):
            return True, None
        changed = self._apply_config(cfg, "remote")
        if changed and save_history_flag:
            save_history(cfg)
            ok_save, e_save = save_cache(cfg)
            if not ok_save and e_save:
                log_warn(f"Failed to update local cache after remote fetch: {e_save}")
        elif self._loaded:
            ok_save, e_save = save_cache(cfg)
            if not ok_save and e_save:
                log_warn(f"Failed to update local cache: {e_save}")
        if isinstance(new_ver, int) and not isinstance(new_ver, bool):
            with self._lock:
                self._last_version = new_ver
        return True, None

    def start_watch(self, allow_push: bool = False) -> None:
        if self._watch_thread is not None and self._watch_thread.is_alive():
            return
        self._allow_push = allow_push
        self._watch_stop.clear()
        self._watch_thread = threading.Thread(target=self._watch_loop, name="configclient-watch", daemon=True)
        self._watch_thread.start()
        log_info(f"Watch mode started (interval={int(self._watch_interval_normal)}s, allow_push={allow_push})")

    def load_from_remote_async(self, save_history_flag: bool = True) -> None:
        if self._async_load_thread is not None and self._async_load_thread.is_alive():
            return
        self._async_load_thread = threading.Thread(
            target=self._async_load_worker,
            args=(save_history_flag,),
            name="configclient-async-load",
            daemon=True,
        )
        self._async_load_thread.start()

    def _async_load_worker(self, save_history_flag: bool) -> None:
        ok, err = self.load_from_remote(save_history_flag=save_history_flag)
        if ok:
            with self._lock:
                v = self._config.get("version")
            log_info(f"Async remote load complete, version={v}")
        else:
            log_warn(f"Async remote load failed: {err}")

    def stop_watch(self) -> None:
        self._watch_stop.set()
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=2.0)
        self._watch_thread = None

    def _watch_loop(self) -> None:
        while not self._watch_stop.is_set():
            interval = self._watch_interval_degraded if self._fail_count >= 3 else self._watch_interval_normal
            if self._watch_stop.wait(interval):
                break
            try:
                self._do_watch_tick()
            except Exception as e:
                log_warn(f"Watch tick error: {e}")

    def _do_watch_tick(self) -> None:
        if self._allow_push and self._local_modified:
            if self._remote_url:
                with self._lock:
                    snapshot = dict(self._config)
                ok, err = push_remote(self._remote_url, snapshot)
                if ok:
                    log_info("Local modifications pushed to remote successfully")
                    with self._lock:
                        self._local_modified = False
                    save_history(snapshot)
                    okc, errc = save_cache(snapshot)
                    if not okc and errc:
                        log_warn(f"Failed to update cache after push: {errc}")
                else:
                    log_warn(f"Failed to push local modifications to remote: {err}")
            else:
                log_warn("allow_push is set but no remote URL, cannot push")
                self._local_modified = False
        if self._remote_url:
            ok, err = self.load_from_remote()
            if ok:
                self._fail_count = 0
                with self._lock:
                    v = self._config.get("version")
                log_info(f"Config refreshed from remote, version={v}")
            else:
                self._fail_count += 1
                if self._fail_count >= 3:
                    log_warn(f"Remote fetch failed ({self._fail_count} consecutive times, degrading to 5-min interval): {err}")
                else:
                    log_warn(f"Remote fetch failed: {err}")

    def get_all(self) -> Dict[str, Any]:
        with self._lock:
            if not self._loaded:
                return {}
            return dict(self._config)


_client_instance: Optional[ConfigClient] = None
_client_instance_lock = threading.Lock()


def get_client(remote_url: Optional[str] = None, dry_run: bool = False) -> ConfigClient:
    global _client_instance
    with _client_instance_lock:
        if _client_instance is None:
            _client_instance = ConfigClient(remote_url=remote_url, dry_run=dry_run)
        return _client_instance


def get(key: str, decrypt: bool = False) -> Optional[Any]:
    return get_client().get(key, decrypt=decrypt)
