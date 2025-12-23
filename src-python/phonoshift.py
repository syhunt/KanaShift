# phonoshift.py
# ROT500K2 Family / PhonoShift — Base Library (Python port)
# PhonoShift 2.x - ROT500K2 family
# Author: Felipe Daragon
# https://github.com/syhunt/kanashift
#
# Python port of the JS demo, including stealth framing v4:
#  - No visible "ROT500K2:" / nonce / ":" headers
#  - Per-message nonce mixed into PBKDF2 salt (prevents keystream reuse across messages)
#  - Verified modes derive MAC key via PBKDF2 (domain-separated) to avoid fast HMAC-only oracle
#  - Deterministic stealth header decode:
#      header bytes = rotByte(1) + padLen(1) + modeId(1) + nonce(12) + pad(0..7)
#      first syllable encodes rotByte unrotated; remaining bytes rotated by rotByte
#
# NOTE: This is NOT intended to be "strong encryption". It's an obfuscation / FPE-like transform.

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ============================================================
# Core helpers (match JS logic)
# ============================================================

def is_separator(ch: str) -> bool:
    return ch in (" ", "-", "'")


def is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def is_ascii_upper(ch: str) -> bool:
    return "A" <= ch <= "Z"


def is_ascii_lower(ch: str) -> bool:
    return "a" <= ch <= "z"


def to_lower_ascii(ch: str) -> str:
    return chr(ord(ch) | 0x20) if is_ascii_upper(ch) else ch


def to_upper_ascii(ch: str) -> str:
    return chr(ord(ch) & ~0x20) if is_ascii_lower(ch) else ch


def is_latin_letter(ch: str) -> bool:
    o = ord(ch)
    return (65 <= o <= 90) or (97 <= o <= 122)


def effective_shift(shift: int, set_size: int) -> int:
    if set_size <= 1:
        return 0
    m = shift % set_size
    if m == 0:
        m = 1 if shift >= 0 else -1
    return m


def rotate_in_set_no_zero(set_chars: str, ch: str, shift: int) -> str:
    idx = set_chars.find(ch)
    if idx < 0:
        return ch
    n = len(set_chars)
    eff = effective_shift(shift, n)
    j = (idx + eff) % n
    return set_chars[j]


def derive_keystream(password: str, salt: str, iterations: int, need_bytes: int) -> bytes:
    if need_bytes < 32:
        need_bytes = 32
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        max(1, int(iterations)),
        dklen=int(need_bytes),
    )


# ============================================================
# base64url helpers (nonce handling)
# ============================================================

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# ============================================================
# Domain-separated salt builder (nonce-aware)
# ============================================================

def dsalt(base_salt: str, nonce_b64u: str, domain: str) -> str:
    return f"{base_salt}|{domain}|n={nonce_b64u}"


# ============================================================
# Pronounceable syllable codec for header bytes (3-letter syllables)
# ============================================================

H_CSET = "bcdfghjklmnpqrstvwxyz"  # 21
H_VSET = "aeiou"                  # 5
H_END  = "nrls"                   # 4

# 21*5*4 = 420 combos; we take first 256 for a perfect byte alphabet
BYTE_SYL: List[str] = []
SYL_TO_BYTE: Dict[str, int] = {}

def _build_header_alphabet() -> None:
    global BYTE_SYL, SYL_TO_BYTE
    if BYTE_SYL:
        return
    for ci in range(len(H_CSET)):
        for vi in range(len(H_VSET)):
            for ei in range(len(H_END)):
                if len(BYTE_SYL) >= 256:
                    break
                syl = H_CSET[ci] + H_VSET[vi] + H_END[ei]
                BYTE_SYL.append(syl)
            if len(BYTE_SYL) >= 256:
                break
        if len(BYTE_SYL) >= 256:
            break
    SYL_TO_BYTE = {syl: i for i, syl in enumerate(BYTE_SYL)}

_build_header_alphabet()


def encode_header_bytes_to_letters(header_bytes: bytes) -> str:
    """
    v4: first byte (rotByte) encoded unrotated; remainder encoded with +rotByte.
    Output is lowercase ASCII letters only (3 per byte).
    """
    if not header_bytes:
        return ""
    rot = header_bytes[0] & 0xFF
    out = [BYTE_SYL[rot]]  # raw rotByte
    for b in header_bytes[1:]:
        out.append(BYTE_SYL[((b + rot) & 0xFF)])
    return "".join(out)


def decode_header_letters_to_bytes(letters_lower: str, total_bytes: int) -> Optional[bytes]:
    need_letters = total_bytes * 3
    if len(letters_lower) < need_letters:
        return None

    # first syllable: raw rotByte
    syl0 = letters_lower[0:3]
    if syl0 not in SYL_TO_BYTE:
        return None
    rot = SYL_TO_BYTE[syl0] & 0xFF
    out = bytearray(total_bytes)
    out[0] = rot

    for i in range(1, total_bytes):
        syl = letters_lower[i * 3 : i * 3 + 3]
        v = SYL_TO_BYTE.get(syl)
        if v is None:
            return None
        out[i] = (v - rot + 256) & 0xFF

    return bytes(out)


# ============================================================
# Header formatting (human-ish, matches JS behavior)
# ============================================================

MAX_SYL_PER_WORD = 3  # <= 9 letters before internal breaks

def pick_sep(b: int) -> str:
    r = b % 100
    if r < 70:
        return " "
    if r < 86:
        return ", "
    if r < 95:
        return " — "
    return "; "


def cap_first_word(w: str) -> str:
    if not w:
        return w
    return w[0].upper() + w[1:]


def choose_word_syl(rem: int, seed_byte: int) -> int:
    mx = min(MAX_SYL_PER_WORD, rem)
    if mx <= 1:
        return 1

    r = seed_byte % 100
    if r < 15:
        want = 1
    elif r < 60:
        want = 2
    else:
        want = 3

    want = min(want, mx)

    # avoid leaving a 1-syllable tail if possible
    if rem - want == 1 and rem > 1:
        if want > 1:
            want -= 1
        else:
            want = min(2, mx)

    return want


def maybe_add_internal_breaks(word: str, syl_count: int, seed_byte: int) -> str:
    if syl_count < 2:
        return word
    r = seed_byte % 100
    do_break = (r < 70) if syl_count == 3 else (r < 35)
    if not do_break:
        return word

    break_char = "-" if (seed_byte & 1) else "'"

    if syl_count == 2:
        return word[:3] + break_char + word[3:]

    pos = 3 if (seed_byte % 2) else 6
    return word[:pos] + break_char + word[pos:]


def format_header_from_letters(header_letters_lower: str, seed_bytes: bytes) -> str:
    # split to syllables
    syls = [header_letters_lower[i:i+3] for i in range(0, len(header_letters_lower), 3)]
    total_syl = len(syls)

    min_words = (total_syl + MAX_SYL_PER_WORD - 1) // MAX_SYL_PER_WORD
    max_words = total_syl

    target = 6 + (seed_bytes[0] % 7)  # 6..12
    target = max(target, min_words)
    target = min(target, max_words)

    # build sizes summing to total_syl
    sizes: List[int] = []
    rem = total_syl
    for wi in range(target):
        words_left = target - wi
        min_here = max(1, rem - (words_left - 1) * MAX_SYL_PER_WORD)
        max_here = min(MAX_SYL_PER_WORD, rem - (words_left - 1) * 1)

        want = choose_word_syl(rem, seed_bytes[(7 + wi) & 31])
        want = max(want, min_here)
        want = min(want, max_here)

        sizes.append(want)
        rem -= want

    while rem > 0:
        sizes.append(min(MAX_SYL_PER_WORD, rem))
        rem -= sizes[-1]

    # materialize words (+ internal breaks)
    words: List[str] = []
    p = 0
    for i, sz in enumerate(sizes):
        w = "".join(syls[p:p+sz])
        p += sz
        w = maybe_add_internal_breaks(w, sz, seed_bytes[(19 + i) & 31])
        if w:
            words.append(w)

    # stitch with varied separators and occasional dot
    out = ""
    for i, w in enumerate(words):
        if not out:
            out = cap_first_word(w)
            continue
        spr = "." if (seed_bytes[(21 + i) & 31] % 29) == 0 else ""
        out += spr + pick_sep(seed_bytes[(3 + i) & 31]) + w

    # end joiner to payload
    end_style = seed_bytes[2] % 5
    if end_style == 0:
        out += " "
    elif end_style == 1:
        out += ", "
    elif end_style == 2:
        out += " — "
    elif end_style == 3:
        out += "; "
    else:
        out += " "

    return out


# ============================================================
# Stealth frame pack/unpack (v4)
# ============================================================

NONCE_LEN = 12
PAD_MAX = 7

MODE_ID: Dict[str, int] = {"ROT500K2": 0, "ROT500K2V": 1, "ROT500K2T": 2, "ROT500K2P": 3}
MODE_FROM_ID: Dict[int, str] = {v: k for k, v in MODE_ID.items()}

def make_nonce_bytes() -> bytes:
    return secrets.token_bytes(NONCE_LEN)

def build_stealth_frame(mode_str: str, nonce_bytes: bytes) -> str:
    pad_len = secrets.randbelow(PAD_MAX + 1)  # 0..7
    pad = secrets.token_bytes(pad_len) if pad_len else b""

    mode_id = MODE_ID.get(mode_str)
    if mode_id is None:
        raise ValueError("Unknown mode for framing.")

    rot_byte = secrets.randbelow(256)

    # bytes = rotByte + padLen + modeId + nonce + pad
    header_bytes = bytes([rot_byte, pad_len & 0xFF, mode_id & 0xFF]) + nonce_bytes + pad

    header_letters = encode_header_bytes_to_letters(header_bytes)

    # seed from header bytes (cheap, deterministic)
    seed = bytearray(32)
    L = len(header_bytes)
    for i in range(32):
        seed[i] = (
            header_bytes[(i * 7) % L] ^
            header_bytes[(i * 13 + 1) % L] ^
            ((i * 29) & 0xFF)
        ) & 0xFF

    return format_header_from_letters(header_letters, bytes(seed))


def parse_stealth_frame_and_payload(s: str) -> Optional[Tuple[str, str, str]]:
    """
    Returns (modeStr, nonceB64u, payload) or None.
    """
    if not isinstance(s, str) or len(s) < 12:
        return None

    def is_joiner_char(ch: str) -> bool:
        return ch in (" ", "\t", "\n", "\r", ",", ";", "-", "—")

    def collect_letters(max_letters: int) -> Tuple[str, int]:
        letters = []
        payload_start = -1
        cnt = 0
        for j, ch in enumerate(s):
            if is_latin_letter(ch):
                letters.append(to_lower_ascii(ch))
                cnt += 1
                if cnt == max_letters:
                    payload_start = j + 1
                    break
        return ("".join(letters), payload_start)

    # need first 3 bytes => 9 letters
    first_letters, first_end = collect_letters(9)
    if len(first_letters) < 9:
        return None

    first3 = decode_header_letters_to_bytes(first_letters, 3)
    if not first3:
        return None

    pad_len = first3[1]
    mode_id = first3[2]
    mode_str = MODE_FROM_ID.get(mode_id)
    if mode_str is None:
        return None
    if pad_len > PAD_MAX:
        return None

    total_bytes = 1 + 1 + 1 + NONCE_LEN + pad_len
    need_letters = total_bytes * 3

    full_letters, full_end = collect_letters(need_letters)
    if full_end < 0:
        return None

    header_bytes = decode_header_letters_to_bytes(full_letters, total_bytes)
    if not header_bytes:
        return None

    # validate critical fields (avoid false positives)
    if header_bytes[1] != pad_len:
        return None
    if header_bytes[2] != mode_id:
        return None

    nonce_bytes = header_bytes[3 : 3 + NONCE_LEN]
    nonce_b64u = b64url_encode(nonce_bytes)

    # skip joiners between header and payload
    ps = full_end
    while ps < len(s) and is_joiner_char(s[ps]):
        ps += 1

    payload = s[ps:]
    if not payload:
        return None

    return (mode_str, nonce_b64u, payload)


def parse_stealth_frame_and_payload_tolerant(s: str, expected_mode: Optional[str] = None) -> Optional[Tuple[str, str, str]]:
    """
    Tolerant scan: find a valid stealth frame anywhere inside the string.
    If expected_mode is provided, only accept frames with that mode.
    Mirrors JS parseStealthFrameAndPayloadTolerant (bounded scan).
    """
    if not isinstance(s, str) or len(s) < 12:
        return None

    limit = min(len(s), 512)  # bounded to avoid pathological scanning

    for i in range(limit):
        if not is_latin_letter(s[i]):
            continue
        u = parse_stealth_frame_and_payload(s[i:])  # strict-from-here
        if not u:
            continue
        mode, nonce_b64u, payload = u
        if expected_mode and mode != expected_mode:
            continue
        return (mode, nonce_b64u, payload)

    return None

# ============================================================
# PhonoShift core transform (nonce-aware)
# ============================================================

PT_VOW_LO = "áàâãäéèêëíìîïóòôõöúùûü"
PT_VOW_UP = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ"
PT_CON_LO = "ç"
PT_CON_UP = "Ç"

VOW_LO = "aeiou"

# split consonants into human-looking vs rare (patch you added)
CON_COMMON = "bcdfghklmnprstvwy"
CON_RARE   = "jqxz"

def _pick_con_set(lc: str) -> Optional[str]:
    if lc in CON_COMMON:
        return CON_COMMON
    if lc in CON_RARE:
        return CON_RARE
    return None


def transform_name_name_like_fpe(
    s: str,
    password: str,
    iterations: int,
    salt: str,
    nonce_b64u: str,
    direction: int,
) -> str:
    if not s:
        return s

    core_salt = dsalt(salt, nonce_b64u, "Core:v2")
    ks = derive_keystream(password, core_salt, iterations, len(s) + 64)
    kpos = 0

    out: List[str] = []
    for c in s:
        if is_separator(c):
            out.append(c)
            continue

        shift = (ks[kpos] + 1) * direction
        kpos += 1
        if kpos >= len(ks):
            kpos = 0

        if is_digit(c):
            d = ord(c) - 48
            nd = (d + (shift % 10) + 10) % 10
            out.append(chr(48 + nd))
            continue

        upper = is_ascii_upper(c) or (c in PT_VOW_UP) or (c in PT_CON_UP)

        lc = c
        if is_ascii_upper(lc):
            lc = to_lower_ascii(lc)

        if lc in VOW_LO:
            ch = rotate_in_set_no_zero(VOW_LO, lc, shift)
            out.append(to_upper_ascii(ch) if upper else ch)
            continue

        con_set = _pick_con_set(lc)
        if con_set is not None:
            ch = rotate_in_set_no_zero(con_set, lc, shift)
            out.append(to_upper_ascii(ch) if upper else ch)
            continue

        # PT vowels / cedilla
        if c in PT_VOW_LO:
            out.append(rotate_in_set_no_zero(PT_VOW_LO, c, shift))
            continue
        if c in PT_VOW_UP:
            out.append(rotate_in_set_no_zero(PT_VOW_UP, c, shift))
            continue
        if c in PT_CON_LO:
            out.append(rotate_in_set_no_zero(PT_CON_LO, c, shift))
            continue
        if c in PT_CON_UP:
            out.append(rotate_in_set_no_zero(PT_CON_UP, c, shift))
            continue

        out.append(c)

    return "".join(out)


# ============================================================
# Optional punctuation shifting (only ¿¡ and !?), nonce-aware
# ============================================================

P_OPEN = "¿¡"
P_END = "!?"

def is_shift_punct(ch: str) -> bool:
    return (ch in P_OPEN) or (ch in P_END)

def punct_shift_apply(
    s: str,
    password: str,
    iterations: int,
    salt: str,
    nonce_b64u: str,
    direction: int,
) -> str:
    if not s:
        return s

    need = sum(1 for c in s if is_shift_punct(c))
    if need == 0:
        return s

    punct_salt = dsalt(salt, nonce_b64u, "PunctShift:v2")
    ks = derive_keystream(password, punct_salt, iterations, need + 64)

    out = list(s)
    kpos = 0
    for i, c in enumerate(out):
        if not is_shift_punct(c):
            continue

        shift = (ks[kpos] + 1) * direction
        kpos += 1
        if kpos >= len(ks):
            kpos = 0

        if c in P_OPEN:
            out[i] = rotate_in_set_no_zero(P_OPEN, c, shift)
        else:
            out[i] = rotate_in_set_no_zero(P_END, c, shift)

    return "".join(out)


# ============================================================
# Verified modes: PBKDF2-derived HMAC key (nonce-aware)
# ============================================================

def derive_mac_key_bytes(password: str, base_salt: str, iterations: int, nonce_b64u: str, domain: str) -> bytes:
    # domain-separated from keystream
    mac_salt = dsalt(base_salt, nonce_b64u, "HMACKey:" + domain)
    return derive_keystream(password, mac_salt, iterations, 32)  # 256-bit key

def hmac_sha256_bytes(key_bytes: bytes, msg_str: str) -> bytes:
    return hmac.new(key_bytes, msg_str.encode("utf-8"), hashlib.sha256).digest()


# ============================================================
# ROT500K2T (token-verified)
# ============================================================

def is_token_sep(ch: str) -> bool:
    return ch in (" ", "-", "'", ".", ",", "!", "?", ":", ";", "\t", "\n", "\r")

def is_all_digits_str(s: str) -> bool:
    return bool(s) and all(is_digit(c) for c in s)

def is_all_upper_ascii(s: str) -> bool:
    has_letter = False
    for c in s:
        if "a" <= c <= "z":
            return False
        if "A" <= c <= "Z":
            has_letter = True
    return has_letter

CONSET = "bcdfghjklmnpqrstvwxyz"
TOK_DOMAIN = "PhonoShiftTok2"

def token_digest(mac_key: bytes, salt: str, iterations: int, token_index: int, token_plain: str, nonce_b64u: str) -> bytes:
    msg = f"{TOK_DOMAIN}|{salt}|{iterations}|n={nonce_b64u}|{token_index}|{token_plain}"
    return hmac_sha256_bytes(mac_key, msg)

def make_token_check(token_plain: str, kind: str, mac_bytes: bytes, check_chars_per_token: int) -> str:
    n = max(1, int(check_chars_per_token))
    upper_mode = (kind == "alpha") and is_all_upper_ascii(token_plain)
    out = []
    for i in range(n):
        b = mac_bytes[(i * 7) & 31]
        if kind == "digits":
            out.append(chr(48 + (b % 10)))
        else:
            ch = CONSET[b % len(CONSET)]
            out.append(ch.upper() if upper_mode else ch)
    return "".join(out)

def build_plain_token_checks(plain: str, mac_key: bytes, salt: str, iterations: int, check_chars_per_token: int, nonce_b64u: str) -> List[str]:
    checks: List[str] = []
    tok = []
    tok_idx = 0

    def flush():
        nonlocal tok_idx
        if not tok:
            return
        t = "".join(tok)
        tok.clear()
        kind = "digits" if is_all_digits_str(t) else "alpha"
        mac = token_digest(mac_key, salt, iterations, tok_idx, t, nonce_b64u)
        checks.append(make_token_check(t, kind, mac, check_chars_per_token))
        tok_idx += 1

    for c in plain:
        if is_token_sep(c):
            flush()
        else:
            tok.append(c)
    flush()
    return checks

def attach_checks_to_cipher(cipher: str, checks: List[str]) -> str:
    out = []
    tok = []
    tok_idx = 0

    def flush():
        nonlocal tok_idx
        if not tok:
            return
        if tok_idx >= len(checks):
            raise ValueError("ROT500K2T: token/check count mismatch.")
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
        raise ValueError("ROT500K2T: unused checks remain.")
    return "".join(out)

def strip_checks_from_tagged(tagged: str, check_chars_per_token: int) -> Optional[Tuple[str, List[str]]]:
    n = max(1, int(check_chars_per_token))
    base = []
    given = []
    tok = []

    def flush() -> bool:
        if not tok:
            return True
        t = "".join(tok)
        tok.clear()
        if len(t) <= n:
            return False
        chk = t[-n:]
        base_tok = t[:-n]
        given.append(chk)
        base.append(base_tok)
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


# ============================================================
# ROT500K2P (prefix-verified)
# ============================================================

TAG_DOMAIN = "PhonoShiftTag2"

PT_LETTERS = PT_VOW_LO + PT_VOW_UP + PT_CON_LO + PT_CON_UP

def only_letters_ascii_or_pt(c: str) -> bool:
    return ("A" <= c <= "Z") or ("a" <= c <= "z") or (c in PT_LETTERS)

def detect_case_style(plain: str) -> str:
    has_letter = False
    any_upper = False
    any_lower = False
    for c in plain:
        if not only_letters_ascii_or_pt(c):
            continue
        has_letter = True
        if "A" <= c <= "Z":
            any_upper = True
        elif "a" <= c <= "z":
            any_lower = True
        else:
            any_upper = True
            any_lower = True

    if not has_letter:
        return "title"
    if any_upper and not any_lower:
        return "upper"
    if any_lower and not any_upper:
        return "lower"
    return "title"

def apply_case_style_to_word(w: str, style: str) -> str:
    if not w:
        return w
    if style == "upper":
        return w.upper()
    if style == "lower":
        return w.lower()
    low = w.lower()
    return low[:1].upper() + low[1:]

def apply_case_style_to_phrase(phrase: str, style: str) -> str:
    return " ".join(apply_case_style_to_word(p, style) for p in phrase.split(" "))

def make_pronounceable_word_from_bytes(mac: bytes, offset: int, syllables: int) -> str:
    CSet = "bcdfghjklmnpqrstvwxyz"
    VSet = "aeiou"
    out = []
    for i in range(syllables):
        x = mac[(offset + i) & 31]
        c_idx = x % len(CSet)
        v_idx = (x // len(CSet)) % len(VSet)
        out.append(CSet[c_idx] + VSet[v_idx])
    return "".join(out)

def pick_punct_from_bytes(mac: bytes) -> str:
    puncts = ["? ", "! "]
    return puncts[mac[0] % len(puncts)]

def build_tag_prefix_for_plaintext(plain: str, password: str, iterations: int, salt: str, nonce_b64u: str) -> str:
    hmac_key = derive_mac_key_bytes(password, salt, iterations, nonce_b64u, TAG_DOMAIN)
    msg = f"{TAG_DOMAIN}|{salt}|{iterations}|n={nonce_b64u}|{plain}"
    mac = hmac_sha256_bytes(hmac_key, msg)

    w1 = make_pronounceable_word_from_bytes(mac, 1, 3)
    w2 = make_pronounceable_word_from_bytes(mac, 4, 3)
    phrase = f"{w1} {w2}"

    punct = pick_punct_from_bytes(mac)
    style = detect_case_style(plain)
    phrase = apply_case_style_to_phrase(phrase, style)
    return phrase + punct  # ends with space

def split_tagged_prefix(tagged: str) -> Optional[Tuple[str, str]]:
    for i in range(len(tagged) - 1):
        if tagged[i] in ("?", "!") and tagged[i + 1] == " ":
            prefix = tagged[: i + 1]   # includes punct, no trailing space
            cipher = tagged[i + 2 :]   # after "<punct><space>"
            return (prefix, cipher) if cipher else None
    return None


# ============================================================
# Public APIs: Encrypt / Decrypt
# ============================================================

def rot500k2_encrypt(
    plaintext: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
) -> str:
    nonce_bytes = make_nonce_bytes()
    nonce_b64u = b64url_encode(nonce_bytes)

    payload = transform_name_name_like_fpe(plaintext, password, iterations, salt, nonce_b64u, +1)
    if shift_punctuation:
        payload = punct_shift_apply(payload, password, iterations, salt, nonce_b64u, +1)

    header = build_stealth_frame("ROT500K2", nonce_bytes)
    return header + payload


def rot500k2_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
) -> str:
    parsed = parse_stealth_frame_and_payload_tolerant(obfuscated, expected_mode="ROT500K2")
    if not parsed:
        raise ValueError("Invalid/legacy ciphertext (expected ROT500K2 stealth frame).")

    _, nonce_b64u, payload = parsed

    s = payload
    if shift_punctuation:
        s = punct_shift_apply(s, password, iterations, salt, nonce_b64u, -1)
    return transform_name_name_like_fpe(s, password, iterations, salt, nonce_b64u, -1)


def rot500k2t_encrypt(
    plaintext: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> str:
    nonce_bytes = make_nonce_bytes()
    nonce_b64u = b64url_encode(nonce_bytes)

    cipher = transform_name_name_like_fpe(plaintext, password, iterations, salt, nonce_b64u, +1)

    hmac_key = derive_mac_key_bytes(password, salt, iterations, nonce_b64u, TOK_DOMAIN)
    checks = build_plain_token_checks(plaintext, hmac_key, salt, iterations, check_chars_per_token, nonce_b64u)

    payload = attach_checks_to_cipher(cipher, checks)
    if shift_punctuation:
        payload = punct_shift_apply(payload, password, iterations, salt, nonce_b64u, +1)

    header = build_stealth_frame("ROT500K2T", nonce_bytes)
    return header + payload


def rot500k2t_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> VerifiedResult:
    parsed = parse_stealth_frame_and_payload(obfuscated)
    if not parsed or parsed[0] != "ROT500K2T":
        raise ValueError("Invalid/legacy ciphertext (expected ROT500K2T stealth frame).")

    _, nonce_b64u, payload = parsed

    s = payload
    if shift_punctuation:
        s = punct_shift_apply(s, password, iterations, salt, nonce_b64u, -1)

    stripped = strip_checks_from_tagged(s, check_chars_per_token)
    if not stripped:
        return VerifiedResult(False, "")

    base_cipher, given_checks = stripped
    plain = transform_name_name_like_fpe(base_cipher, password, iterations, salt, nonce_b64u, -1)

    hmac_key = derive_mac_key_bytes(password, salt, iterations, nonce_b64u, TOK_DOMAIN)
    expected = build_plain_token_checks(plain, hmac_key, salt, iterations, check_chars_per_token, nonce_b64u)

    if len(expected) != len(given_checks):
        return VerifiedResult(False, "")
    for a, b in zip(expected, given_checks):
        if a != b:
            return VerifiedResult(False, "")

    return VerifiedResult(True, plain)


def rot500k2p_encrypt(
    plaintext: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
) -> str:
    nonce_bytes = make_nonce_bytes()
    nonce_b64u = b64url_encode(nonce_bytes)

    cipher = transform_name_name_like_fpe(plaintext, password, iterations, salt, nonce_b64u, +1)
    prefix = build_tag_prefix_for_plaintext(plaintext, password, iterations, salt, nonce_b64u)

    payload = prefix + cipher
    if shift_punctuation:
        payload = punct_shift_apply(payload, password, iterations, salt, nonce_b64u, +1)

    header = build_stealth_frame("ROT500K2P", nonce_bytes)
    return header + payload


def rot500k2p_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    shift_punctuation: bool = True,
) -> VerifiedResult:
    parsed = parse_stealth_frame_and_payload(obfuscated)
    if not parsed or parsed[0] != "ROT500K2P":
        raise ValueError("Invalid/legacy ciphertext (expected ROT500K2P stealth frame).")

    _, nonce_b64u, payload = parsed

    s = payload
    if shift_punctuation:
        s = punct_shift_apply(s, password, iterations, salt, nonce_b64u, -1)

    pr = split_tagged_prefix(s)
    if not pr:
        return VerifiedResult(False, "")
    prefix_given, cipher = pr

    plain = transform_name_name_like_fpe(cipher, password, iterations, salt, nonce_b64u, -1)
    expected = build_tag_prefix_for_plaintext(plain, password, iterations, salt, nonce_b64u)
    expected_no_space = expected[:-1]  # strip trailing space

    if expected_no_space != prefix_given:
        return VerifiedResult(False, "")

    return VerifiedResult(True, plain)


# ============================================================
# ROT500K2V (auto verified): frame says V, payload is T-style or P-style
# ============================================================

def contains_structured_delimiters(s: str) -> bool:
    return any(c in "{}[]\"\\<> =:" for c in s)

def count_tokens_simple(s: str) -> int:
    count = 0
    in_tok = False
    for c in s:
        if is_token_sep(c):
            in_tok = False
        elif not in_tok:
            count += 1
            in_tok = True
    return count

def min_token_len_simple(s: str) -> int:
    min_len = math.inf
    cur = 0
    in_tok = False
    for c in s:
        if is_token_sep(c):
            if in_tok:
                min_len = min(min_len, cur)
            cur = 0
            in_tok = False
        else:
            in_tok = True
            cur += 1
    if in_tok:
        min_len = min(min_len, cur)
    return 0 if min_len is math.inf else int(min_len)

def should_use_token_tagged(plain: str, check_chars_per_token: int) -> bool:
    n = max(1, int(check_chars_per_token))
    if contains_structured_delimiters(plain):
        return False
    tok_count = count_tokens_simple(plain)
    min_len = min_token_len_simple(plain)
    return tok_count >= 2 and min_len > n and len(plain) >= 6

def rot500k2v_encrypt(
    plaintext: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> str:
    # adaptive hardening for short strings (same spirit as JS)
    eff = max(1, int(check_chars_per_token))
    if len(plaintext) < 12:
        eff = max(eff, 2)
    if len(plaintext) < 6:
        eff = max(eff, 3)

    nonce_bytes = make_nonce_bytes()
    nonce_b64u = b64url_encode(nonce_bytes)

    if should_use_token_tagged(plaintext, eff):
        # Build T-style payload but frame as V
        cipher = transform_name_name_like_fpe(plaintext, password, iterations, salt, nonce_b64u, +1)
        hmac_key = derive_mac_key_bytes(password, salt, iterations, nonce_b64u, TOK_DOMAIN)
        checks = build_plain_token_checks(plaintext, hmac_key, salt, iterations, eff, nonce_b64u)
        payload = attach_checks_to_cipher(cipher, checks)
        if shift_punctuation:
            payload = punct_shift_apply(payload, password, iterations, salt, nonce_b64u, +1)
    else:
        # Build P-style payload but frame as V
        cipher = transform_name_name_like_fpe(plaintext, password, iterations, salt, nonce_b64u, +1)
        prefix = build_tag_prefix_for_plaintext(plaintext, password, iterations, salt, nonce_b64u)
        payload = prefix + cipher
        if shift_punctuation:
            payload = punct_shift_apply(payload, password, iterations, salt, nonce_b64u, +1)

    header = build_stealth_frame("ROT500K2V", nonce_bytes)
    return header + payload


def rot500k2v_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> VerifiedResult:
    parsed = parse_stealth_frame_and_payload(obfuscated)
    if not parsed or parsed[0] != "ROT500K2V":
        return VerifiedResult(False, "")

    _, nonce_b64u, payload = parsed

    # try T
    try:
        s = payload
        if shift_punctuation:
            s = punct_shift_apply(s, password, iterations, salt, nonce_b64u, -1)

        stripped = strip_checks_from_tagged(s, check_chars_per_token)
        if stripped:
            base_cipher, given_checks = stripped
            plain = transform_name_name_like_fpe(base_cipher, password, iterations, salt, nonce_b64u, -1)

            hmac_key = derive_mac_key_bytes(password, salt, iterations, nonce_b64u, TOK_DOMAIN)
            expected = build_plain_token_checks(plain, hmac_key, salt, iterations, check_chars_per_token, nonce_b64u)

            if len(expected) == len(given_checks) and all(a == b for a, b in zip(expected, given_checks)):
                return VerifiedResult(True, plain)
    except Exception:
        pass

    # try P
    try:
        s = payload
        if shift_punctuation:
            s = punct_shift_apply(s, password, iterations, salt, nonce_b64u, -1)

        pr = split_tagged_prefix(s)
        if pr:
            prefix_given, cipher = pr
            plain = transform_name_name_like_fpe(cipher, password, iterations, salt, nonce_b64u, -1)

            expected = build_tag_prefix_for_plaintext(plain, password, iterations, salt, nonce_b64u)
            if expected[:-1] == prefix_given:
                return VerifiedResult(True, plain)
    except Exception:
        pass

    return VerifiedResult(False, "")


# ============================================================
# Small convenience: "decode-by-frame" (auto picks correct decrypt)
# ============================================================

def rot500k2_any_decrypt(
    obfuscated: str,
    password: str,
    iterations: int = 500_000,
    salt: str = "NameFPE:v1",
    check_chars_per_token: int = 1,
    shift_punctuation: bool = True,
) -> Tuple[str, bool]:
    """
    Returns (plaintext, verified_ok_flag).
    - ROT500K2: verified_ok_flag=False (no verification)
    - ROT500K2T/ROT500K2P/ROT500K2V: verified_ok_flag=True iff verification passed
    """
    parsed = parse_stealth_frame_and_payload(obfuscated)
    if not parsed:
        raise ValueError("Input is not a valid stealth-framed ROT500K2 ciphertext.")
    mode, _, _ = parsed

    if mode == "ROT500K2":
        return (rot500k2_decrypt(obfuscated, password, iterations, salt, shift_punctuation), False)
    if mode == "ROT500K2T":
        r = rot500k2t_decrypt(obfuscated, password, iterations, salt, check_chars_per_token, shift_punctuation)
        return (r.value, r.ok)
    if mode == "ROT500K2P":
        r = rot500k2p_decrypt(obfuscated, password, iterations, salt, shift_punctuation)
        return (r.value, r.ok)
    if mode == "ROT500K2V":
        r = rot500k2v_decrypt(obfuscated, password, iterations, salt, check_chars_per_token, shift_punctuation)
        return (r.value, r.ok)

    raise ValueError("Unknown mode in frame.")


# ============================================================
# Minimal self-test
# ============================================================

if __name__ == "__main__":
    pw = "correct horse battery staple"
    txt = "Vamos lá, ver se isso funciona mesmo!"

    c0 = rot500k2_encrypt(txt, pw)
    p0 = rot500k2_decrypt(c0, pw)
    assert p0 == txt

    cT = rot500k2t_encrypt(txt, pw, check_chars_per_token=1)
    rT = rot500k2t_decrypt(cT, pw, check_chars_per_token=1)
    assert rT.ok and rT.value == txt

    cP = rot500k2p_encrypt(txt, pw)
    rP = rot500k2p_decrypt(cP, pw)
    assert rP.ok and rP.value == txt

    cV = rot500k2v_encrypt(txt, pw, check_chars_per_token=1)
    rV = rot500k2v_decrypt(cV, pw, check_chars_per_token=1)
    assert rV.ok and rV.value == txt

    print("OK")