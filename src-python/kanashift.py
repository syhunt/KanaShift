# kanashift.py
# KanaShift 2.x — Base Library (Python port of HTML demo)
# ROT500K2 / KAN500K2 family (stealth framing update)
# Author: Felipe Daragon
# https://github.com/syhunt/kanashift
#
# Latest 2.x patch notes (HTML parity):
#  1) Per-message nonce ("tweak") mixed into PBKDF2 salt => prevents keystream reuse across messages
#  2) Verified modes derive MAC key via PBKDF2 (domain-separated, nonce-aware) => avoids fast HMAC oracle
#  3) Stealth wire format (no fixed separators, no ASCII prefix, no «」 wrappers):
#        <HDR4><NONCE16><PAYLOAD...>
#     where HDR4 encodes 3 bytes -> 4 kana64 chars with masked ver/mode bits.
#
# Families:
#   family=0 => Skin (Latin/PT -> kana render)
#   family=1 => JP-native (JP -> JP + ASCII shifting)
#
# Modes:
#   isT=False => base (no verification)
#   isT=True  => token-verified (KT)

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


# ============================================================
# KANA64 (fixed 64-char alphabet) + codec
# Must be exactly 64 chars, each 1 code unit (no surrogate pairs)
# ============================================================

KANA64 = (
    "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよ"
    "らりるれろわをん"
    "アイウエオカキクケコサシスセソタチツ"
)
if len(KANA64) != 64:
    raise RuntimeError(f"KANA64 must be exactly 64 chars (got {len(KANA64)})")

_KANA64_INV = {ch: i for i, ch in enumerate(KANA64)}


def kana64_encode(data: bytes) -> str:
    """Encodes bytes to kana64 (base64-like, no '=' padding)."""
    out: List[str] = []
    acc = 0
    acc_bits = 0

    for b in data:
        acc = (acc << 8) | (b & 0xFF)
        acc_bits += 8
        while acc_bits >= 6:
            acc_bits -= 6
            v = (acc >> acc_bits) & 0x3F
            out.append(KANA64[v])

    if acc_bits > 0:
        v = (acc << (6 - acc_bits)) & 0x3F
        out.append(KANA64[v])

    return "".join(out)


def kana64_decode(s: str) -> bytes:
    """Decodes kana64 string into bytes (accepts non-padded length)."""
    acc = 0
    acc_bits = 0
    out = bytearray()

    for ch in s:
        v = _KANA64_INV.get(ch)
        if v is None:
            raise ValueError(f"Invalid kana64 char: {ch!r}")
        acc = (acc << 6) | v
        acc_bits += 6
        while acc_bits >= 8:
            acc_bits -= 8
            out.append((acc >> acc_bits) & 0xFF)

    return bytes(out)


# ============================================================
# Stealth framing: <HDR4><NONCE16><PAYLOAD...>
# ============================================================

VER = 2
HEADER_LEN = 4
NONCE_LEN_BYTES = 12
NONCE_LEN_KANA = 16  # 12 bytes -> 16 kana64 chars (since 12*8/6=16)

FAMILY_SKIN = 0
FAMILY_JP = 1


def _gen_nonce_kana() -> str:
    nb = secrets.token_bytes(NONCE_LEN_BYTES)
    s = kana64_encode(nb)
    if len(s) != NONCE_LEN_KANA:
        raise RuntimeError(f"Nonce kana length mismatch: expected {NONCE_LEN_KANA}, got {len(s)}")
    return s


def _header_encode_kana4(family: int, is_t: bool) -> str:
    """
    3 bytes -> kana64(4 chars)
    b0 random
    meta = family(3 bits) | (T<<3) | (ver<<4)
    b1 = meta XOR b0   (masks mode bits)
    b2 random
    """
    family &= 0x07
    t = 1 if is_t else 0
    meta = (family & 0x07) | ((t & 0x01) << 3) | ((VER & 0x0F) << 4)

    b0 = secrets.randbelow(256)
    b1 = (meta ^ b0) & 0xFF
    b2 = secrets.randbelow(256)

    k4 = kana64_encode(bytes([b0, b1, b2]))
    if len(k4) != 4:
        raise RuntimeError("Header kana64 must be exactly 4 chars.")
    return k4


def _header_decode_kana4(hdr4: str) -> Optional[Tuple[int, bool, int]]:
    if not isinstance(hdr4, str) or len(hdr4) != 4:
        return None
    try:
        raw = kana64_decode(hdr4)
    except Exception:
        return None
    if len(raw) != 3:
        return None

    b0 = raw[0] & 0xFF
    b1 = raw[1] & 0xFF
    meta = (b1 ^ b0) & 0xFF

    family = meta & 0x07
    is_t = ((meta >> 3) & 1) == 1
    ver = (meta >> 4) & 0x0F

    if ver != VER:
        return None
    if family not in (FAMILY_SKIN, FAMILY_JP):
        return None

    return (family, is_t, ver)


def _pack_ciphertext(hdr4: str, nonce_kana: str, payload: str) -> str:
    return f"{hdr4}{nonce_kana}{payload}"


def _unpack_ciphertext_strict(s: str) -> Optional[Tuple[int, bool, str, str]]:
    """
    Returns (family, isT, nonce_kana, payload) or None.
    Strict: must validate header and nonce decode length.
    """
    if not isinstance(s, str):
        return None
    if len(s) <= (HEADER_LEN + NONCE_LEN_KANA):
        return None

    hdr4 = s[:HEADER_LEN]
    meta = _header_decode_kana4(hdr4)
    if not meta:
        return None
    family, is_t, _ver = meta

    nonce_kana = s[HEADER_LEN : HEADER_LEN + NONCE_LEN_KANA]
    try:
        nb = kana64_decode(nonce_kana)
    except Exception:
        return None
    if len(nb) != NONCE_LEN_BYTES:
        return None

    payload = s[HEADER_LEN + NONCE_LEN_KANA :]
    if payload == "":
        return None

    return (family, is_t, nonce_kana, payload)


def _unpack_ciphertext_tolerant(
    s: str,
    expected_family: Optional[int] = None,
    expected_is_t: Optional[bool] = None,
    scan_limit: int = 512
) -> Optional[Tuple[int, bool, str, str]]:
    """
    Tolerant scan: find a valid KanaShift stealth frame anywhere inside the string.
    Returns (family, isT, nonce_kana, payload) or None.

    - Scans up to scan_limit chars (like the JS tolerant scan approach)
    - Tries to validate a strict frame at each position:
        <HDR4><NONCE16><PAYLOAD...>
    - Optionally filters by expected_family / expected_is_t
    """
    if not isinstance(s, str) or len(s) <= (HEADER_LEN + NONCE_LEN_KANA):
        return None

    limit = min(len(s), scan_limit)

    # Need at least a full header+nonce after the start position
    max_start = min(limit, len(s) - (HEADER_LEN + NONCE_LEN_KANA) - 1)

    for i in range(max_start + 1):
        sub = s[i:]
        u = _unpack_ciphertext_strict(sub)
        if not u:
            continue

        family, is_t, nonce_kana, payload = u

        if expected_family is not None and family != expected_family:
            continue
        if expected_is_t is not None and is_t != expected_is_t:
            continue

        return u

    return None


def _unpack_ciphertext_tolerant_base(s: str, expected_family: int) -> Optional[Tuple[int, bool, str, str]]:
    # Convenience: tolerant + base-only (isT=False)
    return _unpack_ciphertext_tolerant(s, expected_family=expected_family, expected_is_t=False)

def _dsalt(base_salt: str, nonce_kana: str, domain: str) -> str:
    # Matches HTML dsalt(baseSalt, nonce, domain) => `${baseSalt}|${domain}|n=${nonce}`
    return f"{base_salt}|{domain}|n={nonce_kana}"


# ============================================================
# Helpers
# ============================================================

def is_separator(ch: str) -> bool:
    return ch in (" ", "-", "'")

def is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"

def is_fullwidth_digit(ch: str) -> bool:
    return "０" <= ch <= "９"

def is_ascii_upper(ch: str) -> bool:
    return "A" <= ch <= "Z"

def is_ascii_lower(ch: str) -> bool:
    return "a" <= ch <= "z"

def to_lower_ascii(ch: str) -> str:
    if is_ascii_upper(ch):
        return chr(ord(ch) | 0x20)
    return ch

def effective_shift(shift: int, set_size: int) -> int:
    if set_size <= 1:
        return 0
    m = shift % set_size
    if m == 0:
        m = 1 if shift >= 0 else -1
    return m

def rotate_in_set_no_zero(set_chars: str, ch: str, shift: int) -> str:
    n = len(set_chars)
    idx = set_chars.find(ch)
    if idx < 0:
        return ch
    eff = effective_shift(shift, n)
    j = (idx + eff) % n
    return set_chars[j]

def rotate_in_set_allow_zero(set_chars: str, ch: str, shift: int) -> str:
    n = len(set_chars)
    idx = set_chars.find(ch)
    if idx < 0:
        return ch
    m = shift % n
    j = (idx + m) % n
    return set_chars[j]


# ============================================================
# PBKDF2 + MAC key derivation (nonce-aware, domain-separated)
# ============================================================

def pbkdf2_keystream(password: str, salt: str, iterations: int, need_bytes: int) -> bytes:
    if need_bytes < 32:
        need_bytes = 32
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        max(1, int(iterations)),
        dklen=need_bytes,
    )

def _derive_hmac_key(password: str, base_salt: str, iterations: int, nonce_kana: str, domain: str) -> bytes:
    # Mirrors HTML: PBKDF2-derived HMAC key from dsalt(baseSalt, nonce, "HMACKey:" + domain)
    salt = _dsalt(base_salt, nonce_kana, "HMACKey:" + domain)
    return pbkdf2_keystream(password, salt, iterations, 32)

def hmac_sha256_bytes(key_bytes: bytes, msg_str: str) -> bytes:
    return hmac.new(key_bytes, msg_str.encode("utf-8"), hashlib.sha256).digest()


# ============================================================
# Punctuation translation (ASCII <-> JP fullwidth)
# ============================================================

_PUNCT_ENC_MAP = {
    "?": "？",
    "!": "！",
    ",": "、",
    ".": "。",
    ":": "：",
    ";": "；",
    "(": "（",
    ")": "）",
    "[": "［",
    "]": "］",
    "{": "｛",
    "}": "｝",
    '"': "＂",
}
_PUNCT_DEC_MAP = {v: k for k, v in _PUNCT_ENC_MAP.items()}

def punct_translate(s: str, direction: int) -> str:
    if not s:
        return s
    mp = _PUNCT_ENC_MAP if direction > 0 else _PUNCT_DEC_MAP
    return "".join(mp.get(c, c) for c in s)


# ============================================================
# Keyed JP punctuation shifting (glyph sets) — nonce-aware
# ============================================================

P_END = "！？"
P_MID = "、。・"

def _is_shift_punct(ch: str) -> bool:
    return (ch in P_END) or (ch in P_MID)

def punct_shift_apply(s: str, password: str, iterations: int, salt: str, direction: int, nonce_kana: str) -> str:
    if not s:
        return s

    need = sum(1 for c in s if _is_shift_punct(c))
    if need == 0:
        return s

    ks_salt = _dsalt(salt, nonce_kana, "PunctShiftJP:v2")
    ks = pbkdf2_keystream(password, ks_salt, iterations, need + 64)
    kpos = 0

    out = list(s)
    for i, c in enumerate(out):
        if not _is_shift_punct(c):
            continue
        shift = (ks[kpos] & 0xFF) * direction
        kpos += 1
        if kpos >= len(ks):
            kpos = 0

        if c in P_END:
            out[i] = rotate_in_set_no_zero(P_END, c, shift)
        else:
            out[i] = rotate_in_set_no_zero(P_MID, c, shift)

    return "".join(out)


# ============================================================
# FAMILY A: Skin (Latin/PT -> kana render) — nonce-aware
# ============================================================

def _skin_transform(text: str, password: str, iterations: int, salt: str, direction: int, nonce_kana: str) -> str:
    P_VOW_LO = "aeiou"
    P_VOW_UP = "AEIOU"
    P_CON_LO = "bcdfghjklmnpqrstvwxyz"
    P_CON_UP = "BCDFGHJKLMNPQRSTVWXYZ"

    P_VOW_LO_PT = "áàâãäéèêëíìîïóòôõöúùûü"
    P_VOW_UP_PT = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ"

    C_CED_LO = "ゞ"
    C_CED_UP = "ヾ"

    C_VOW_LO = "あいうえお"
    C_CON_LO = "さしすせそたちつてとなにぬねのはひふへほま"

    C_VOW_UP = "アイウエオ"
    C_CON_UP = "サシスセソタチツテトナニヌネノハヒフヘホマ"

    C_ACC_LO = "かきくけこみむめもやゆよらりるれろわをんゐゑゔゝ"
    C_ACC_UP = "カキクケコミムメモヤユヨラリルレロワヲンヰヱヴヽ"

    if not text:
        return text

    ks_salt = _dsalt(salt, nonce_kana, "SkinCore:v2")
    ks = pbkdf2_keystream(password, ks_salt, iterations, len(text) + 64)
    kpos = 0

    def map_rotate(plain_set: str, cipher_set: str, ch: str, shift: int, dirn: int) -> Optional[str]:
        n = len(plain_set)
        if n <= 1:
            return None
        idx = (plain_set.find(ch) if dirn > 0 else cipher_set.find(ch))
        if idx < 0:
            return None
        j = (idx + (shift % n)) % n
        return (cipher_set[j] if dirn > 0 else plain_set[j])

    out: List[str] = []
    for c in text:
        if is_separator(c):
            out.append(c)
            continue

        shift = ((ks[kpos] & 0xFF) + 1) * direction
        kpos += 1
        if kpos >= len(ks):
            kpos = 0

        if direction > 0:
            if is_digit(c):
                d = ord(c) - 48
                nd = (d + (shift % 10) + 10) % 10
                out.append(chr(ord("０") + nd))
                continue
        else:
            if is_digit(c) or is_fullwidth_digit(c):
                d = (ord(c) - 48) if is_digit(c) else (ord(c) - ord("０"))
                nd = (d + (shift % 10) + 10) % 10
                out.append(chr(48 + nd))
                continue

        if direction > 0:
            if c in P_VOW_LO:
                out.append(map_rotate(P_VOW_LO, C_VOW_LO, c, shift, +1) or c); continue
            if c in P_CON_LO:
                out.append(map_rotate(P_CON_LO, C_CON_LO, c, shift, +1) or c); continue

            if c in P_VOW_UP:
                out.append(map_rotate(P_VOW_UP, C_VOW_UP, c, shift, +1) or c); continue
            if c in P_CON_UP:
                out.append(map_rotate(P_CON_UP, C_CON_UP, c, shift, +1) or c); continue

            if c in P_VOW_LO_PT:
                out.append(map_rotate(P_VOW_LO_PT, C_ACC_LO, c, shift, +1) or c); continue
            if c in P_VOW_UP_PT:
                out.append(map_rotate(P_VOW_UP_PT, C_ACC_UP, c, shift, +1) or c); continue

            if c == "ç":
                out.append(C_CED_LO); continue
            if c == "Ç":
                out.append(C_CED_UP); continue

            out.append(c)
        else:
            if c in C_VOW_LO:
                out.append(map_rotate(P_VOW_LO, C_VOW_LO, c, shift, -1) or c); continue
            if c in C_CON_LO:
                out.append(map_rotate(P_CON_LO, C_CON_LO, c, shift, -1) or c); continue

            if c in C_VOW_UP:
                out.append(map_rotate(P_VOW_UP, C_VOW_UP, c, shift, -1) or c); continue
            if c in C_CON_UP:
                out.append(map_rotate(P_CON_UP, C_CON_UP, c, shift, -1) or c); continue

            if c in C_ACC_LO:
                out.append(map_rotate(P_VOW_LO_PT, C_ACC_LO, c, shift, -1) or c); continue
            if c in C_ACC_UP:
                out.append(map_rotate(P_VOW_UP_PT, C_ACC_UP, c, shift, -1) or c); continue

            if c == C_CED_LO:
                out.append("ç"); continue
            if c == C_CED_UP:
                out.append("Ç"); continue

            out.append(c)

    return "".join(out)


def kanashift2_skin_encrypt(
    text: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
    nonce_kana: Optional[str] = None,
) -> str:
    nonce_kana = nonce_kana or _gen_nonce_kana()
    hdr4 = _header_encode_kana4(FAMILY_SKIN, False)

    r = _skin_transform(text, password, iterations, salt, +1, nonce_kana)
    r = punct_translate(r, +1)
    if shift_punctuation:
        r = punct_shift_apply(r, password, iterations, salt, +1, nonce_kana)

    return _pack_ciphertext(hdr4, nonce_kana, r)


def kanashift2_skin_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
) -> str:
    u = _unpack_ciphertext_tolerant_base(obfuscated, FAMILY_SKIN)
    if not u:
        raise ValueError("Invalid/legacy ciphertext.")
    family, is_t, nonce_kana, payload = u
    # family/is_t already filtered, but keep sanity:
    if family != FAMILY_SKIN or is_t:
        raise ValueError("Ciphertext is not Skin base mode.")

    s = payload
    if shift_punctuation:
        s = punct_shift_apply(s, password, iterations, salt, -1, nonce_kana)
    s = punct_translate(s, -1)
    return _skin_transform(s, password, iterations, salt, -1, nonce_kana)


# ============================================================
# FAMILY B: JP-native (JP -> JP) + ASCII shifting — nonce-aware
# ============================================================

def is_kanji(ch: str) -> bool:
    cp = ord(ch)
    return 0x4E00 <= cp <= 0x9FFF

def rotate_codepoint_range_no_zero(ch: str, shift: int, lo: int, hi: int) -> str:
    cp = ord(ch)
    if cp < lo or cp > hi:
        return ch
    n = (hi - lo + 1)
    eff = effective_shift(shift, n)
    idx = cp - lo
    j = (idx + eff) % n
    return chr(lo + j)

def build_kana_set(from_cp: int, to_cp: int) -> str:
    return "".join(chr(cp) for cp in range(from_cp, to_cp + 1))

JP_HIRA = build_kana_set(0x3041, 0x3096)
JP_KATA = build_kana_set(0x30A1, 0x30FA)

def is_hiragana(ch: str) -> bool:
    cp = ord(ch)
    return 0x3041 <= cp <= 0x3096

def is_katakana(ch: str) -> bool:
    cp = ord(ch)
    return 0x30A1 <= cp <= 0x30FA

def is_stable_jp_mark(ch: str) -> bool:
    return ch in ("ー", "々", "ゝ", "ゞ", "ヽ", "ヾ")


def rotate_ascii_alpha_phono(ch: str, shift: int) -> str:
    V = "aeiou"
    C = "bcdfghjklmnpqrstvwxyz"

    if is_ascii_upper(ch):
        low = to_lower_ascii(ch)
        if low in V:
            return rotate_in_set_allow_zero(V, low, shift).upper()
        if low in C:
            return rotate_in_set_allow_zero(C, low, shift).upper()
        return ch

    if is_ascii_lower(ch):
        if ch in V:
            return rotate_in_set_allow_zero(V, ch, shift)
        if ch in C:
            return rotate_in_set_allow_zero(C, ch, shift)
        return ch

    return ch


def _jp_native_transform(text: str, password: str, iterations: int, salt: str, direction: int, nonce_kana: str) -> str:
    if not text:
        return text

    ks_salt = _dsalt(salt, nonce_kana, "JPNative:v2|AsciiShift")
    ks = pbkdf2_keystream(password, ks_salt, iterations, len(text) + 64)
    kpos = 0

    out: List[str] = []
    for c in text:
        if is_separator(c):
            out.append(c); continue
        if is_stable_jp_mark(c):
            out.append(c); continue

        shift = (ks[kpos] & 0xFF) * direction
        kpos += 1
        if kpos >= len(ks):
            kpos = 0

        if is_ascii_upper(c) or is_ascii_lower(c):
            out.append(rotate_ascii_alpha_phono(c, shift))
            continue

        if direction > 0:
            if is_digit(c):
                d = ord(c) - 48
                eff = effective_shift(shift, 10)
                nd = (d + eff + 10) % 10
                out.append(chr(ord("０") + nd))
                continue
            if is_fullwidth_digit(c):
                d = ord(c) - ord("０")
                eff = effective_shift(shift, 10)
                nd = (d + eff + 10) % 10
                out.append(chr(ord("０") + nd))
                continue
        else:
            if is_digit(c) or is_fullwidth_digit(c):
                d = (ord(c) - 48) if is_digit(c) else (ord(c) - ord("０"))
                eff = effective_shift(shift, 10)
                nd = (d + eff + 10) % 10
                out.append(chr(48 + nd))
                continue

        if is_hiragana(c):
            out.append(rotate_in_set_no_zero(JP_HIRA, c, shift)); continue
        if is_katakana(c):
            out.append(rotate_in_set_no_zero(JP_KATA, c, shift)); continue
        if is_kanji(c):
            out.append(rotate_codepoint_range_no_zero(c, shift, 0x4E00, 0x9FFF)); continue

        out.append(c)

    return "".join(out)


def kanashift2_jp_encrypt(
    text: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
    nonce_kana: Optional[str] = None,
) -> str:
    nonce_kana = nonce_kana or _gen_nonce_kana()
    hdr4 = _header_encode_kana4(FAMILY_JP, False)

    r = _jp_native_transform(text, password, iterations, salt, +1, nonce_kana)
    r = punct_translate(r, +1)
    if shift_punctuation:
        r = punct_shift_apply(r, password, iterations, salt, +1, nonce_kana)

    return _pack_ciphertext(hdr4, nonce_kana, r)


def kanashift2_jp_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
) -> str:
    u = _unpack_ciphertext_tolerant_base(obfuscated, FAMILY_JP)
    if not u:
        raise ValueError("Invalid/legacy ciphertext.")
    family, is_t, nonce_kana, payload = u
    if family != FAMILY_JP or is_t:
        raise ValueError("Ciphertext is not JP base mode.")

    s = payload
    if shift_punctuation:
        s = punct_shift_apply(s, password, iterations, salt, -1, nonce_kana)
    s = punct_translate(s, -1)
    return _jp_native_transform(s, password, iterations, salt, -1, nonce_kana)


# ============================================================
# KT Token Verification (shared) — PBKDF2-derived MAC key + nonce
# ============================================================

def is_token_sep(ch: str) -> bool:
    return ch in (
        " ", "　", "-", "'", ".", ",", "!", "?", ":", ";",
        "。", "、", "！", "？", "：", "；", "・",
        "「", "」", "『", "』", "（", "）", "［", "］", "｛", "｝",
        "\t", "\n", "\r"
    )

def is_all_digits_str_anywidth(s: str) -> bool:
    if not s:
        return False
    for c in s:
        if not (is_digit(c) or is_fullwidth_digit(c)):
            return False
    return True

def make_token_check(kind: str, mac: bytes, check_chars_per_token: int) -> str:
    n = max(1, int(check_chars_per_token))
    KANA_CHK = "さしすせそたちつてとなにぬねのはひふへほま"
    out = []
    for i in range(n):
        b = mac[(i * 7) & 31]
        if kind == "digits":
            out.append(chr(ord("０") + (b % 10)))
        else:
            out.append(KANA_CHK[b % len(KANA_CHK)])
    return "".join(out)

# Match HTML “Tok2” names (since the MAC scheme is now PBKDF2-derived-key)
TOK_DOMAIN_SKIN = "KanaShiftTok2"
TOK_DOMAIN_JP   = "KanaShiftTokJP2"

def token_digest(mac_key: bytes, salt: str, iterations: int, token_index: int, token_plain: str, domain: str) -> bytes:
    # Match HTML: `${domain}|${salt}|${iterations}|${tokenIndex}|${tokenPlain}`
    msg = f"{domain}|{salt}|{iterations}|{token_index}|{token_plain}"
    return hmac_sha256_bytes(mac_key, msg)

def build_plain_token_checks(
    plain: str,
    mac_key: bytes,
    salt: str,
    iterations: int,
    check_chars_per_token: int,
    domain: str,
    norm_fn: Optional[Callable[[str], str]] = None,
) -> List[str]:
    checks: List[str] = []
    tok: List[str] = []
    tok_idx = 0

    def flush():
        nonlocal tok_idx
        if not tok:
            return
        t = "".join(tok)
        tok.clear()

        kind = "digits" if is_all_digits_str_anywidth(t) else "alpha"
        tnorm = norm_fn(t) if norm_fn else t
        mac = token_digest(mac_key, salt, iterations, tok_idx, tnorm, domain)
        checks.append(make_token_check(kind, mac, check_chars_per_token))
        tok_idx += 1

    for c in plain:
        if is_token_sep(c):
            flush()
        else:
            tok.append(c)
    flush()

    return checks

def attach_checks_to_cipher(cipher: str, checks: List[str]) -> str:
    out: List[str] = []
    tok: List[str] = []
    tok_idx = 0

    def flush():
        nonlocal tok_idx
        if not tok:
            return
        if tok_idx >= len(checks):
            raise ValueError("TokenTagged: token/check count mismatch.")
        out.append("".join(tok) + checks[tok_idx])
        tok_idx += 1
        tok.clear()

    for c in cipher:
        if is_token_sep(c):
            flush()
            out.append(c)
        else:
            tok.append(c)
    flush()

    if tok_idx != len(checks):
        raise ValueError("TokenTagged: unused checks remain.")
    return "".join(out)

def strip_checks_from_tagged(tagged: str, check_chars_per_token: int) -> Optional[Tuple[str, List[str]]]:
    n = max(1, int(check_chars_per_token))

    base: List[str] = []
    given: List[str] = []
    tok: List[str] = []

    def flush() -> bool:
        if not tok:
            return True
        t = "".join(tok)
        tok.clear()
        if len(t) <= n:
            return False
        given.append(t[-n:])
        base.append(t[:-n])
        return True

    for c in tagged:
        if is_token_sep(c):
            if not flush():
                return None
            base.append(c)
        else:
            tok.append(c)

    if not flush():
        return None

    return ("".join(base), given)

@dataclass
class VerifiedResult:
    ok: bool
    value: str

def norm_token_skin(tok: str) -> str:
    return tok

def norm_token_identity(tok: str) -> str:
    return tok


def _family_token_tagged_encrypt(
    plain: str,
    password: str,
    iterations: int,
    salt: str,
    check_chars_per_token: int,
    shift_punctuation: bool,
    core_transform_fn: Callable[[str, str, int, str, int, str], str],
    tok_domain: str,
    family: int,
    norm_fn: Optional[Callable[[str], str]] = None,
    nonce_kana: Optional[str] = None,
) -> str:
    nonce_kana = nonce_kana or _gen_nonce_kana()
    hdr4 = _header_encode_kana4(family, True)

    cipher = core_transform_fn(plain, password, iterations, salt, +1, nonce_kana)

    mac_key = _derive_hmac_key(password, salt, iterations, nonce_kana, tok_domain)
    checks = build_plain_token_checks(plain, mac_key, salt, iterations, check_chars_per_token, tok_domain, norm_fn)

    out = attach_checks_to_cipher(cipher, checks)

    out = punct_translate(out, +1)
    if shift_punctuation:
        out = punct_shift_apply(out, password, iterations, salt, +1, nonce_kana)

    return _pack_ciphertext(hdr4, nonce_kana, out)


def _family_token_tagged_decrypt(
    tagged: str,
    password: str,
    iterations: int,
    salt: str,
    check_chars_per_token: int,
    shift_punctuation: bool,
    core_transform_fn: Callable[[str, str, int, str, int, str], str],
    tok_domain: str,
    expected_family: int,
    norm_fn: Optional[Callable[[str], str]] = None,
) -> VerifiedResult:
    u = _unpack_ciphertext_strict(tagged)
    if not u:
        return VerifiedResult(False, "")
    family, is_t, nonce_kana, payload = u
    if family != expected_family or not is_t:
        return VerifiedResult(False, "")

    s = payload
    if shift_punctuation:
        s = punct_shift_apply(s, password, iterations, salt, -1, nonce_kana)
    s = punct_translate(s, -1)

    stripped = strip_checks_from_tagged(s, check_chars_per_token)
    if not stripped:
        return VerifiedResult(False, "")

    base_cipher, given_checks = stripped
    plain = core_transform_fn(base_cipher, password, iterations, salt, -1, nonce_kana)

    mac_key = _derive_hmac_key(password, salt, iterations, nonce_kana, tok_domain)
    expected = build_plain_token_checks(plain, mac_key, salt, iterations, check_chars_per_token, tok_domain, norm_fn)

    if len(expected) != len(given_checks):
        return VerifiedResult(False, "")
    for a, b in zip(expected, given_checks):
        if a != b:
            return VerifiedResult(False, "")

    return VerifiedResult(True, plain)


# ============================================================
# Public Token-Verified wrappers (v2.x stealth)
# ============================================================

def kanashift2_skin_token_encrypt(
    text: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
    nonce_kana: Optional[str] = None,
) -> str:
    return _family_token_tagged_encrypt(
        text, password, iterations, salt, check_chars_per_token, shift_punctuation,
        _skin_transform, TOK_DOMAIN_SKIN, FAMILY_SKIN, norm_token_skin, nonce_kana
    )

def kanashift2_skin_token_decrypt(
    tagged: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> VerifiedResult:
    return _family_token_tagged_decrypt(
        tagged, password, iterations, salt, check_chars_per_token, shift_punctuation,
        _skin_transform, TOK_DOMAIN_SKIN, FAMILY_SKIN, norm_token_skin
    )

def kanashift2_jp_token_encrypt(
    text: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
    nonce_kana: Optional[str] = None,
) -> str:
    return _family_token_tagged_encrypt(
        text, password, iterations, salt, check_chars_per_token, shift_punctuation,
        _jp_native_transform, TOK_DOMAIN_JP, FAMILY_JP, norm_token_identity, nonce_kana
    )

def kanashift2_jp_token_decrypt(
    tagged: str,
    password: str,
    iterations: int = 500000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> VerifiedResult:
    return _family_token_tagged_decrypt(
        tagged, password, iterations, salt, check_chars_per_token, shift_punctuation,
        _jp_native_transform, TOK_DOMAIN_JP, FAMILY_JP, norm_token_identity
    )