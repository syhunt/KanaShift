window.PhonoShift = (() => {
  const te = new TextEncoder();
  const td = new TextDecoder();

  const PUBLIC_SHARE_BASE = "https://syhunt.github.io/KanaShift/src/phonoshiftqr.html";

  const DEFAULT_ITERATIONS = 500000;
  const DEFAULT_SALT = "NameFPE:v1";
  const DEFAULT_CHECKCHARS = 1;
  const DEFAULT_SHIFT_PUNCT = true;

  const NONCE_LEN = 12;
  const PAD_MAX = 7;

  const MODE_ID = {
    ROT500K2: 0,
    ROT500K2V: 1,
    ROT500K2T: 2,
    ROT500K2P: 3,
  };
  const MODE_FROM_ID = Object.fromEntries(Object.entries(MODE_ID).map(([k, v]) => [v, k]));

  const H_CSET = "bcdfghjklmnpqrstvwxyz";
  const H_VSET = "aeiou";
  const H_END = "nrls";
  const BYTE_SYL = [];
  const SYL_TO_BYTE = new Map();

  const P_OPEN = "¿¡";
  const P_END = "!?";
  const CONSET = "bcdfghjklmnpqrstvwxyz";
  const TOK_DOMAIN = "PhonoShiftTok2";
  const TAG_DOMAIN = "PhonoShiftTag2";
  const MAX_SYL_PER_WORD = 3;

  (function buildAlphabet() {
    for (let ci = 0; ci < H_CSET.length; ci++) {
      for (let vi = 0; vi < H_VSET.length; vi++) {
        for (let ei = 0; ei < H_END.length; ei++) {
          if (BYTE_SYL.length >= 256) break;
          const syl = H_CSET[ci] + H_VSET[vi] + H_END[ei];
          BYTE_SYL.push(syl);
        }
        if (BYTE_SYL.length >= 256) break;
      }
      if (BYTE_SYL.length >= 256) break;
    }
    for (let i = 0; i < BYTE_SYL.length; i++) SYL_TO_BYTE.set(BYTE_SYL[i], i);
  })();

  function $(id) {
    return document.getElementById(id);
  }

  function b64urlEncode(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    const b64 = btoa(bin);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64urlDecode(s) {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8ToB64url(str) {
    return b64urlEncode(te.encode(str));
  }

  function b64urlToUtf8(s) {
    return td.decode(b64urlDecode(s));
  }

  function makeNonceBytes() {
    const n = new Uint8Array(NONCE_LEN);
    crypto.getRandomValues(n);
    return n;
  }

  function dsalt(baseSalt, nonceB64u, domain) {
    return `${baseSalt}|${domain}|n=${nonceB64u}`;
  }

  function isSeparator(ch) { return ch === " " || ch === "-" || ch === "'"; }
  function isDigit(ch) { return ch >= "0" && ch <= "9"; }
  function isAsciiUpper(ch) { return ch >= "A" && ch <= "Z"; }
  function isAsciiLower(ch) { return ch >= "a" && ch <= "z"; }
  function toLowerASCII(ch) { return isAsciiUpper(ch) ? String.fromCharCode(ch.charCodeAt(0) | 0x20) : ch; }
  function toUpperASCII(ch) { return isAsciiLower(ch) ? String.fromCharCode(ch.charCodeAt(0) & ~0x20) : ch; }

  function isLatinLetter(ch) {
    const c = ch.charCodeAt(0);
    return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
  }

  function effectiveShift(shift, setSize) {
    if (setSize <= 1) return 0;
    let m = shift % setSize;
    if (m === 0) m = (shift >= 0) ? 1 : -1;
    return m;
  }

  function rotateInSetNoZero(setChars, ch, shift) {
    const n = setChars.length;
    const idx = setChars.indexOf(ch);
    if (idx < 0) return ch;
    const eff = effectiveShift(shift, n);
    const j = (idx + eff) % n;
    const jj = (j + n) % n;
    return setChars.charAt(jj);
  }

  function ensureWebCrypto() {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Web Crypto unavailable. Open via HTTPS or localhost.");
    }
  }

  async function deriveKeyStream(password, salt, iterations, needBytes) {
    ensureWebCrypto();

    if (needBytes < 32) needBytes = 32;
    const pwBytes = te.encode(password);
    const saltBytes = te.encode(salt);

    const baseKey = await crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iterations },
      baseKey,
      needBytes * 8
    );
    return new Uint8Array(bits);
  }

  function encodeHeaderBytesToLetters(bytes) {
    let out = BYTE_SYL[bytes[0] & 0xff];
    const rot = bytes[0] & 0xff;
    for (let i = 1; i < bytes.length; i++) out += BYTE_SYL[(bytes[i] + rot) & 0xff];
    return out;
  }

  function decodeHeaderLettersToBytes(lettersLower, totalBytes) {
    const needLetters = totalBytes * 3;
    if (lettersLower.length < needLetters) return null;

    const out = new Uint8Array(totalBytes);

    const syl0 = lettersLower.slice(0, 3);
    const v0 = SYL_TO_BYTE.get(syl0);
    if (v0 === undefined) return null;
    out[0] = v0 & 0xff;

    const rot = out[0] & 0xff;

    for (let i = 1; i < totalBytes; i++) {
      const syl = lettersLower.slice(i * 3, i * 3 + 3);
      const v = SYL_TO_BYTE.get(syl);
      if (v === undefined) return null;
      out[i] = (v - rot + 256) & 0xff;
    }
    return out;
  }

  function pickSep(b) {
    const r = b % 100;
    if (r < 70) return " ";
    if (r < 86) return ", ";
    if (r < 95) return " — ";
    return "; ";
  }

  function capFirstWord(w) {
    if (!w) return w;
    return w.charAt(0).toUpperCase() + w.slice(1);
  }

  function chooseWordSyl(rem, seedByte) {
    const max = Math.min(MAX_SYL_PER_WORD, rem);
    if (max <= 1) return 1;

    const r = seedByte % 100;
    let want;
    if (r < 15) want = 1;
    else if (r < 60) want = 2;
    else want = 3;

    want = Math.min(want, max);

    if (rem - want === 1 && rem > 1) {
      if (want > 1) want -= 1;
      else want = Math.min(2, max);
    }
    return want;
  }

  function maybeAddInternalBreaks(word, sylCount, seedByte) {
    if (sylCount < 2) return word;

    const r = seedByte % 100;
    const doBreak = (sylCount === 3) ? (r < 70) : (r < 35);
    if (!doBreak) return word;

    const breakChar = (seedByte & 1) ? "-" : "'";
    if (sylCount === 2) return word.slice(0, 3) + breakChar + word.slice(3);

    const pos = (seedByte % 2) ? 3 : 6;
    return word.slice(0, pos) + breakChar + word.slice(pos);
  }

  function formatHeaderFromLetters(headerLettersLower, seedBytes) {
    const syls = [];
    for (let i = 0; i < headerLettersLower.length; i += 3) syls.push(headerLettersLower.slice(i, i + 3));

    const totalSyl = syls.length;
    const minWords = Math.ceil(totalSyl / MAX_SYL_PER_WORD);
    const maxWords = totalSyl;

    let target = 6 + (seedBytes[0] % 7);
    if (target < minWords) target = minWords;
    if (target > maxWords) target = maxWords;

    const sizes = [];
    let rem = totalSyl;
    for (let wi = 0; wi < target; wi++) {
      const wordsLeft = target - wi;
      const minHere = Math.max(1, rem - (wordsLeft - 1) * MAX_SYL_PER_WORD);
      const maxHere = Math.min(MAX_SYL_PER_WORD, rem - (wordsLeft - 1));

      let want = chooseWordSyl(rem, seedBytes[(7 + wi) & 31]);
      if (want < minHere) want = minHere;
      if (want > maxHere) want = maxHere;

      sizes.push(want);
      rem -= want;
    }
    while (rem > 0) {
      sizes.push(Math.min(MAX_SYL_PER_WORD, rem));
      rem -= sizes[sizes.length - 1];
    }

    const words = [];
    let p = 0;
    for (let i = 0; i < sizes.length; i++) {
      let w = "";
      for (let k = 0; k < sizes[i]; k++) w += syls[p++];
      w = maybeAddInternalBreaks(w, sizes[i], seedBytes[(19 + i) & 31]);
      if (w) words.push(w);
    }

    let out = "";
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      if (!out) {
        out = capFirstWord(w);
        continue;
      }
      const spr = (seedBytes[(21 + i) & 31] % 29) === 0 ? "." : "";
      out += spr + pickSep(seedBytes[(3 + i) & 31]) + w;
    }

    const endStyle = seedBytes[2] % 5;
    if (endStyle === 0) out += " ";
    else if (endStyle === 1) out += ", ";
    else if (endStyle === 2) out += " — ";
    else if (endStyle === 3) out += "; ";
    else out += " ";

    return out;
  }

  function buildStealthFrame(modeStr, nonceBytes) {
    const padLen = Math.floor(Math.random() * (PAD_MAX + 1));
    const pad = new Uint8Array(padLen);
    if (padLen) crypto.getRandomValues(pad);

    const modeId = MODE_ID[modeStr];
    if (modeId === undefined) throw new Error("Unknown mode for framing.");

    const rotArr = new Uint8Array(1);
    crypto.getRandomValues(rotArr);
    const rotByte = rotArr[0] & 0xff;

    const bytes = new Uint8Array(1 + 1 + 1 + NONCE_LEN + padLen);
    bytes[0] = rotByte;
    bytes[1] = padLen & 0xff;
    bytes[2] = modeId & 0xff;
    bytes.set(nonceBytes, 3);
    if (padLen) bytes.set(pad, 3 + NONCE_LEN);

    const headerLetters = encodeHeaderBytesToLetters(bytes);

    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] =
        bytes[(i * 7) % bytes.length] ^
        bytes[(i * 13 + 1) % bytes.length] ^
        ((i * 29) & 0xff);
    }

    return formatHeaderFromLetters(headerLetters, seed);
  }

  function parseStealthFrameAndPayloadStrict(s) {
    if (typeof s !== "string" || s.length < 12) return null;

    function isJoinerChar(ch) {
      return (
        ch === " " || ch === "\t" || ch === "\n" || ch === "\r" ||
        ch === "," || ch === ";" || ch === "-" || ch === "—"
      );
    }

    function collectLetters(maxLetters) {
      let letters = "";
      let payloadStart = -1;
      for (let j = 0; j < s.length; j++) {
        const ch = s.charAt(j);
        if (isLatinLetter(ch)) letters += toLowerASCII(ch);
        if (letters.length === maxLetters) {
          payloadStart = j + 1;
          break;
        }
      }
      return { letters, payloadStart };
    }

    const first = collectLetters(9);
    if (first.letters.length < 9) return null;

    const first3 = decodeHeaderLettersToBytes(first.letters, 3);
    if (!first3) return null;

    const padLen = first3[1];
    const modeId = first3[2];
    const modeStr = MODE_FROM_ID[modeId];
    if (!modeStr) return null;
    if (padLen > PAD_MAX) return null;

    const totalBytes = 1 + 1 + 1 + NONCE_LEN + padLen;
    const needLetters = totalBytes * 3;

    const full = collectLetters(needLetters);
    if (full.payloadStart < 0) return null;

    const headerBytes = decodeHeaderLettersToBytes(full.letters, totalBytes);
    if (!headerBytes) return null;

    if (headerBytes[1] !== padLen) return null;
    if (headerBytes[2] !== modeId) return null;

    const nonceBytes = headerBytes.slice(3, 3 + NONCE_LEN);
    const nonceB64u = b64urlEncode(nonceBytes);

    let ps = full.payloadStart;
    while (ps < s.length && isJoinerChar(s.charAt(ps))) ps++;

    const payload = s.slice(ps);
    if (!payload) return null;

    return { modeStr, nonceB64u, payload };
  }

  function parseStealthFrameAndPayload(s) {
    return parseStealthFrameAndPayloadStrict(s);
  }

  function parseStealthFrameAndPayloadTolerant(s, expectedModeStr) {
    if (typeof s !== "string" || s.length < 12) return null;

    const limit = Math.min(s.length, 512);

    for (let i = 0; i < limit; i++) {
      if (!isLatinLetter(s.charAt(i))) continue;

      const u = parseStealthFrameAndPayloadStrict(s.slice(i));
      if (!u) continue;
      if (expectedModeStr && u.modeStr !== expectedModeStr) continue;
      return u;
    }
    return null;
  }

  async function transformNameNameLikeFPE(s, password, iterations, salt, nonceB64u, direction) {
    const VOW_LO = "aeiou";
    const CON_COMMON = "bcdfghklmnprstvwy";
    const CON_RARE = "jqxz";

    function pickConSet(lc) {
      if (CON_COMMON.includes(lc)) return CON_COMMON;
      if (CON_RARE.includes(lc)) return CON_RARE;
      return null;
    }

    const VOW_LO_PT = "áàâãäéèêëíìîïóòôõöúùûü";
    const VOW_UP_PT = "ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜ";
    const CON_LO_PT = "ç";
    const CON_UP_PT = "Ç";

    if (!s) return s;

    const coreSalt = dsalt(salt, nonceB64u, "Core:v2");
    const ks = await deriveKeyStream(password, coreSalt, iterations, s.length + 64);
    let kpos = 0;

    let out = "";
    for (let i = 0; i < s.length; i++) {
      const c = s.charAt(i);
      if (isSeparator(c)) {
        out += c;
        continue;
      }

      const shift = ((ks[kpos] | 0) + 1) * direction;
      kpos++;
      if (kpos >= ks.length) kpos = 0;

      if (isDigit(c)) {
        const d = c.charCodeAt(0) - 48;
        const nd = (d + (shift % 10) + 10) % 10;
        out += String.fromCharCode(48 + nd);
        continue;
      }

      const upper = isAsciiUpper(c) || (VOW_UP_PT.includes(c) || CON_UP_PT.includes(c));
      let lc = c;
      if (isAsciiUpper(lc)) lc = toLowerASCII(lc);

      if (VOW_LO.includes(lc)) {
        let ch = rotateInSetNoZero(VOW_LO, lc, shift);
        if (upper) ch = toUpperASCII(ch);
        out += ch;
        continue;
      }

      const conSet = pickConSet(lc);
      if (conSet) {
        let ch = rotateInSetNoZero(conSet, lc, shift);
        if (upper) ch = toUpperASCII(ch);
        out += ch;
        continue;
      }

      if (VOW_LO_PT.includes(c)) { out += rotateInSetNoZero(VOW_LO_PT, c, shift); continue; }
      if (VOW_UP_PT.includes(c)) { out += rotateInSetNoZero(VOW_UP_PT, c, shift); continue; }
      if (CON_LO_PT.includes(c)) { out += rotateInSetNoZero(CON_LO_PT, c, shift); continue; }
      if (CON_UP_PT.includes(c)) { out += rotateInSetNoZero(CON_UP_PT, c, shift); continue; }

      out += c;
    }
    return out;
  }

  function isShiftPunct(ch) {
    return P_OPEN.includes(ch) || P_END.includes(ch);
  }

  async function punctShiftApply(s, password, iterations, salt, nonceB64u, direction) {
    if (!s) return s;

    let need = 0;
    for (let i = 0; i < s.length; i++) if (isShiftPunct(s.charAt(i))) need++;
    if (need === 0) return s;

    const punctSalt = dsalt(salt, nonceB64u, "PunctShift:v2");
    const ks = await deriveKeyStream(password, punctSalt, iterations, need + 64);
    let kpos = 0;

    const out = s.split("");
    for (let i = 0; i < out.length; i++) {
      const c = out[i];
      if (!isShiftPunct(c)) continue;

      const shift = ((ks[kpos] | 0) + 1) * direction;
      kpos++;
      if (kpos >= ks.length) kpos = 0;

      if (P_OPEN.includes(c)) out[i] = rotateInSetNoZero(P_OPEN, c, shift);
      else out[i] = rotateInSetNoZero(P_END, c, shift);
    }
    return out.join("");
  }

  async function deriveHmacKeyFromPassword(password, baseSalt, iterations, nonceB64u, domain) {
    ensureWebCrypto();

    const pwBytes = te.encode(password);
    const saltBytes = te.encode(dsalt(baseSalt, nonceB64u, "HMACKey:" + domain));
    const baseKey = await crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iterations },
      baseKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );
  }

  async function hmacSha256BytesWithKey(hmacKey, msgStr) {
    ensureWebCrypto();
    const msgBytes = te.encode(msgStr);
    const sig = await crypto.subtle.sign("HMAC", hmacKey, msgBytes);
    return new Uint8Array(sig);
  }

  function isTokenSep(ch) {
    return (
      ch === " " || ch === "-" || ch === "'" ||
      ch === "." || ch === "," || ch === "!" || ch === "?" ||
      ch === ":" || ch === ";" ||
      ch === "\t" || ch === "\n" || ch === "\r"
    );
  }

  function isAllDigitsStr(s) {
    if (!s) return false;
    for (let i = 0; i < s.length; i++) if (!isDigit(s.charAt(i))) return false;
    return true;
  }

  function isAllUpperASCII(s) {
    let hasLetter = false;
    for (let i = 0; i < s.length; i++) {
      const c = s.charAt(i);
      if (c >= "a" && c <= "z") return false;
      if (c >= "A" && c <= "Z") hasLetter = true;
    }
    return hasLetter;
  }

  async function tokenDigest(hmacKey, salt, iterations, tokenIndex, tokenPlain, nonceB64u) {
    const msg = `${TOK_DOMAIN}|${salt}|${iterations}|n=${nonceB64u}|${tokenIndex}|${tokenPlain}`;
    return hmacSha256BytesWithKey(hmacKey, msg);
  }

  function makeTokenCheck(tokenPlain, kind, macBytes, checkCharsPerToken) {
    const n = Math.max(1, checkCharsPerToken | 0);
    const upperMode = (kind === "alpha") && isAllUpperASCII(tokenPlain);

    let out = "";
    for (let i = 0; i < n; i++) {
      const b = macBytes[(i * 7) & 31];
      if (kind === "digits") out += String.fromCharCode(48 + (b % 10));
      else {
        let ch = CONSET.charAt(b % CONSET.length);
        if (upperMode) ch = ch.toUpperCase();
        out += ch;
      }
    }
    return out;
  }

  async function buildPlainTokenChecks(plain, hmacKey, salt, iterations, checkCharsPerToken, nonceB64u) {
    const checks = [];
    let tok = "";
    let tokIdx = 0;

    for (let i = 0; i < plain.length; i++) {
      const c = plain.charAt(i);
      if (isTokenSep(c)) {
        if (tok) {
          const kind = isAllDigitsStr(tok) ? "digits" : "alpha";
          const mac = await tokenDigest(hmacKey, salt, iterations, tokIdx, tok, nonceB64u);
          checks.push(makeTokenCheck(tok, kind, mac, checkCharsPerToken));
          tokIdx++;
          tok = "";
        }
      } else {
        tok += c;
      }
    }

    if (tok) {
      const kind = isAllDigitsStr(tok) ? "digits" : "alpha";
      const mac = await tokenDigest(hmacKey, salt, iterations, tokIdx, tok, nonceB64u);
      checks.push(makeTokenCheck(tok, kind, mac, checkCharsPerToken));
    }

    return checks;
  }

  function attachChecksToCipher(cipher, checks) {
    let out = "";
    let tok = "";
    let tokIdx = 0;

    for (let i = 0; i < cipher.length; i++) {
      const c = cipher.charAt(i);
      if (isTokenSep(c)) {
        if (tok) {
          if (tokIdx >= checks.length) throw new Error("ROT500K2T: token/check count mismatch.");
          out += tok + checks[tokIdx];
          tokIdx++;
          tok = "";
        }
        out += c;
      } else {
        tok += c;
      }
    }

    if (tok) {
      if (tokIdx >= checks.length) throw new Error("ROT500K2T: token/check count mismatch.");
      out += tok + checks[tokIdx];
      tokIdx++;
    }
    if (tokIdx !== checks.length) throw new Error("ROT500K2T: unused checks remain.");

    return out;
  }

  function stripChecksFromTagged(tagged, checkCharsPerToken) {
    const n = Math.max(1, checkCharsPerToken | 0);

    let baseCipher = "";
    const givenChecks = [];
    let tok = "";

    for (let i = 0; i < tagged.length; i++) {
      const c = tagged.charAt(i);
      if (isTokenSep(c)) {
        if (tok) {
          if (tok.length <= n) return null;
          const chk = tok.slice(-n);
          const baseTok = tok.slice(0, -n);
          givenChecks.push(chk);
          baseCipher += baseTok;
          tok = "";
        }
        baseCipher += c;
      } else {
        tok += c;
      }
    }

    if (tok) {
      if (tok.length <= n) return null;
      const chk = tok.slice(-n);
      const baseTok = tok.slice(0, -n);
      givenChecks.push(chk);
      baseCipher += baseTok;
    }

    return { baseCipher, givenChecks };
  }

  function onlyLettersASCIIOrPT(c) {
    const pt = "áàâãäéèêëíìîïóòôõöúùûüÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜçÇ";
    return (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || pt.includes(c);
  }

  function detectCaseStyle(plain) {
    let hasLetter = false, anyUpper = false, anyLower = false;
    for (let i = 0; i < plain.length; i++) {
      const c = plain.charAt(i);
      if (!onlyLettersASCIIOrPT(c)) continue;
      hasLetter = true;
      if (c >= "A" && c <= "Z") anyUpper = true;
      else if (c >= "a" && c <= "z") anyLower = true;
      else { anyUpper = true; anyLower = true; }
    }
    if (!hasLetter) return "title";
    if (anyUpper && !anyLower) return "upper";
    if (anyLower && !anyUpper) return "lower";
    return "title";
  }

  function applyCaseStyleToWord(w, style) {
    if (!w) return w;
    if (style === "upper") return w.toUpperCase();
    if (style === "lower") return w.toLowerCase();
    const low = w.toLowerCase();
    return low.charAt(0).toUpperCase() + low.slice(1);
  }

  function applyCaseStyleToPhrase(phrase, style) {
    return phrase.split(" ").map(p => applyCaseStyleToWord(p, style)).join(" ");
  }

  function makePronounceableWordFromBytes(bytes, offset, syllables) {
    const CSet = "bcdfghjklmnpqrstvwxyz";
    const VSet = "aeiou";
    let out = "";
    for (let i = 0; i < syllables; i++) {
      const x = bytes[(offset + i) & 31];
      const cIdx = x % CSet.length;
      const vIdx = Math.floor(x / CSet.length) % VSet.length;
      out += CSet.charAt(cIdx) + VSet.charAt(vIdx);
    }
    return out;
  }

  function pickPunctFromBytes(bytes) {
    const puncts = ["? ", "! "];
    return puncts[bytes[0] % puncts.length];
  }

  async function buildTagPrefixForPlaintext(plain, password, iterations, salt, nonceB64u) {
    const hmacKey = await deriveHmacKeyFromPassword(password, salt, iterations, nonceB64u, TAG_DOMAIN);
    const msg = `${TAG_DOMAIN}|${salt}|${iterations}|n=${nonceB64u}|${plain}`;
    const mac = await hmacSha256BytesWithKey(hmacKey, msg);

    const w1 = makePronounceableWordFromBytes(mac, 1, 3);
    const w2 = makePronounceableWordFromBytes(mac, 4, 3);
    let phrase = `${w1} ${w2}`;

    const punct = pickPunctFromBytes(mac);
    const style = detectCaseStyle(plain);
    phrase = applyCaseStyleToPhrase(phrase, style);

    return phrase + punct;
  }

  function splitTaggedPrefix(tagged) {
    for (let i = 0; i < tagged.length - 1; i++) {
      const c = tagged.charAt(i);
      if ((c === "?" || c === "!") && tagged.charAt(i + 1) === " ") {
        const prefix = tagged.slice(0, i + 1);
        const cipher = tagged.slice(i + 2);
        return cipher ? { prefix, cipher } : null;
      }
    }
    return null;
  }

  async function ROT500K2_Encrypt(name, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const nonceBytes = makeNonceBytes();
    const nonceB64u = b64urlEncode(nonceBytes);

    let r = await transformNameNameLikeFPE(name, password, iterations, salt, nonceB64u, +1);
    if (shiftPunctuation) r = await punctShiftApply(r, password, iterations, salt, nonceB64u, +1);

    const header = buildStealthFrame("ROT500K2", nonceBytes);
    return header + r;
  }

  async function ROT500K2_Decrypt(obfuscated, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const u = parseStealthFrameAndPayloadTolerant(obfuscated, "ROT500K2");
    if (!u) throw new Error("Invalid/legacy ciphertext (expected ROT500K2 stealth frame).");

    let s = u.payload;
    if (shiftPunctuation) s = await punctShiftApply(s, password, iterations, salt, u.nonceB64u, -1);
    return transformNameNameLikeFPE(s, password, iterations, salt, u.nonceB64u, -1);
  }

  async function ROT500K2T_Encrypt(name, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, checkCharsPerToken = DEFAULT_CHECKCHARS, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const nonceBytes = makeNonceBytes();
    const nonceB64u = b64urlEncode(nonceBytes);

    const cipher = await transformNameNameLikeFPE(name, password, iterations, salt, nonceB64u, +1);
    const hmacKey = await deriveHmacKeyFromPassword(password, salt, iterations, nonceB64u, TOK_DOMAIN);
    const checks = await buildPlainTokenChecks(name, hmacKey, salt, iterations, checkCharsPerToken, nonceB64u);

    let out = attachChecksToCipher(cipher, checks);
    if (shiftPunctuation) out = await punctShiftApply(out, password, iterations, salt, nonceB64u, +1);

    const header = buildStealthFrame("ROT500K2T", nonceBytes);
    return header + out;
  }

  async function ROT500K2T_Decrypt(tagged, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, checkCharsPerToken = DEFAULT_CHECKCHARS, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const u = parseStealthFrameAndPayload(tagged);
    if (!u || u.modeStr !== "ROT500K2T") throw new Error("Invalid/legacy ciphertext (expected ROT500K2T stealth frame).");

    let s = u.payload;
    if (shiftPunctuation) s = await punctShiftApply(s, password, iterations, salt, u.nonceB64u, -1);

    const stripped = stripChecksFromTagged(s, checkCharsPerToken);
    if (!stripped) return { ok: false, value: "" };

    const plain = await transformNameNameLikeFPE(stripped.baseCipher, password, iterations, salt, u.nonceB64u, -1);
    const hmacKey = await deriveHmacKeyFromPassword(password, salt, iterations, u.nonceB64u, TOK_DOMAIN);
    const expected = await buildPlainTokenChecks(plain, hmacKey, salt, iterations, checkCharsPerToken, u.nonceB64u);

    if (expected.length !== stripped.givenChecks.length) return { ok: false, value: "" };
    for (let i = 0; i < expected.length; i++) {
      if (expected[i] !== stripped.givenChecks[i]) return { ok: false, value: "" };
    }

    return { ok: true, value: plain };
  }

  async function ROT500K2P_Encrypt(name, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const nonceBytes = makeNonceBytes();
    const nonceB64u = b64urlEncode(nonceBytes);

    const cipher = await transformNameNameLikeFPE(name, password, iterations, salt, nonceB64u, +1);
    const prefix = await buildTagPrefixForPlaintext(name, password, iterations, salt, nonceB64u);

    let out = prefix + cipher;
    if (shiftPunctuation) out = await punctShiftApply(out, password, iterations, salt, nonceB64u, +1);

    const header = buildStealthFrame("ROT500K2P", nonceBytes);
    return header + out;
  }

  async function ROT500K2P_Decrypt(tagged, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const u = parseStealthFrameAndPayload(tagged);
    if (!u || u.modeStr !== "ROT500K2P") throw new Error("Invalid/legacy ciphertext (expected ROT500K2P stealth frame).");

    let s = u.payload;
    if (shiftPunctuation) s = await punctShiftApply(s, password, iterations, salt, u.nonceB64u, -1);

    const parsed = splitTaggedPrefix(s);
    if (!parsed) return { ok: false, value: "" };

    const plain = await transformNameNameLikeFPE(parsed.cipher, password, iterations, salt, u.nonceB64u, -1);
    const expected = await buildTagPrefixForPlaintext(plain, password, iterations, salt, u.nonceB64u);

    const expectedPrefixNoSpace = expected.slice(0, expected.length - 1);
    if (expectedPrefixNoSpace !== parsed.prefix) return { ok: false, value: "" };

    return { ok: true, value: plain };
  }

  function containsStructuredDelimiters(s) {
    for (let i = 0; i < s.length; i++) {
      const c = s.charAt(i);
      if (c === "{" || c === "}" || c === "[" || c === "]" || c === '"' ||
          c === "\\" || c === "<" || c === ">" || c === "=" || c === ":") {
        return true;
      }
    }
    return false;
  }

  function countTokensSimple(s) {
    let count = 0;
    let inTok = false;
    for (let i = 0; i < s.length; i++) {
      if (isTokenSep(s.charAt(i))) inTok = false;
      else if (!inTok) { count++; inTok = true; }
    }
    return count;
  }

  function minTokenLenSimple(s) {
    let min = Infinity;
    let cur = 0;
    let inTok = false;
    for (let i = 0; i < s.length; i++) {
      const c = s.charAt(i);
      if (isTokenSep(c)) {
        if (inTok) min = Math.min(min, cur);
        cur = 0;
        inTok = false;
      } else {
        inTok = true;
        cur++;
      }
    }
    if (inTok) min = Math.min(min, cur);
    return min === Infinity ? 0 : min;
  }

  function shouldUseTokenTagged(plain, checkCharsPerToken) {
    const n = Math.max(1, checkCharsPerToken | 0);
    if (containsStructuredDelimiters(plain)) return false;
    const tokCount = countTokensSimple(plain);
    const minLen = minTokenLenSimple(plain);
    return tokCount >= 2 && minLen > n && plain.length >= 6;
  }

  async function ROT500K2V_SafeEncrypt(name, password, iterations, salt, checkCharsPerToken, shiftPunctuation) {
    if (shouldUseTokenTagged(name, checkCharsPerToken)) {
      const nonceBytes = makeNonceBytes();
      const nonceB64u = b64urlEncode(nonceBytes);

      const cipher = await transformNameNameLikeFPE(name, password, iterations, salt, nonceB64u, +1);
      const hmacKey = await deriveHmacKeyFromPassword(password, salt, iterations, nonceB64u, TOK_DOMAIN);
      const checks = await buildPlainTokenChecks(name, hmacKey, salt, iterations, checkCharsPerToken, nonceB64u);

      let out = attachChecksToCipher(cipher, checks);
      if (shiftPunctuation) out = await punctShiftApply(out, password, iterations, salt, nonceB64u, +1);

      const header = buildStealthFrame("ROT500K2V", nonceBytes);
      return header + out;
    }

    const nonceBytes = makeNonceBytes();
    const nonceB64u = b64urlEncode(nonceBytes);

    const cipher = await transformNameNameLikeFPE(name, password, iterations, salt, nonceB64u, +1);
    const prefix = await buildTagPrefixForPlaintext(name, password, iterations, salt, nonceB64u);

    let out = prefix + cipher;
    if (shiftPunctuation) out = await punctShiftApply(out, password, iterations, salt, nonceB64u, +1);

    const header = buildStealthFrame("ROT500K2V", nonceBytes);
    return header + out;
  }

  async function ROT500K2V_SafeDecrypt(obfuscated, password, iterations, salt, checkCharsPerToken, shiftPunctuation) {
    const u = parseStealthFrameAndPayload(obfuscated);
    if (!u || u.modeStr !== "ROT500K2V") return { ok: false, value: "" };

    try {
      let s = u.payload;
      if (shiftPunctuation) s = await punctShiftApply(s, password, iterations, salt, u.nonceB64u, -1);

      const stripped = stripChecksFromTagged(s, checkCharsPerToken);
      if (stripped) {
        const plain = await transformNameNameLikeFPE(stripped.baseCipher, password, iterations, salt, u.nonceB64u, -1);
        const hmacKey = await deriveHmacKeyFromPassword(password, salt, iterations, u.nonceB64u, TOK_DOMAIN);
        const expected = await buildPlainTokenChecks(plain, hmacKey, salt, iterations, checkCharsPerToken, u.nonceB64u);

        if (expected.length === stripped.givenChecks.length) {
          let ok = true;
          for (let i = 0; i < expected.length; i++) {
            if (expected[i] !== stripped.givenChecks[i]) { ok = false; break; }
          }
          if (ok) return { ok: true, value: plain };
        }
      }
    } catch {}

    try {
      let s = u.payload;
      if (shiftPunctuation) s = await punctShiftApply(s, password, iterations, salt, u.nonceB64u, -1);

      const parsed = splitTaggedPrefix(s);
      if (!parsed) return { ok: false, value: "" };

      const plain = await transformNameNameLikeFPE(parsed.cipher, password, iterations, salt, u.nonceB64u, -1);
      const expected = await buildTagPrefixForPlaintext(plain, password, iterations, salt, u.nonceB64u);

      const expectedPrefixNoSpace = expected.slice(0, expected.length - 1);
      if (expectedPrefixNoSpace === parsed.prefix) return { ok: true, value: plain };
    } catch {}

    return { ok: false, value: "" };
  }

  async function ROT500K2V(name, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, checkCharsPerToken = DEFAULT_CHECKCHARS, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    const u = parseStealthFrameAndPayload(name);
    if (u && u.modeStr === "ROT500K2V") {
      const r = await ROT500K2V_SafeDecrypt(name, password, iterations, salt, checkCharsPerToken, shiftPunctuation);
      if (r.ok) return r.value;
    }

    let eff = Math.max(1, checkCharsPerToken | 0);
    if (name.length < 12) eff = Math.max(eff, 2);
    if (name.length < 6) eff = Math.max(eff, 3);

    return ROT500K2V_SafeEncrypt(name, password, iterations, salt, eff, shiftPunctuation);
  }

  async function ROT500K2V_Decrypt(obfuscated, password, iterations = DEFAULT_ITERATIONS, salt = DEFAULT_SALT, checkCharsPerToken = DEFAULT_CHECKCHARS, shiftPunctuation = DEFAULT_SHIFT_PUNCT) {
    return ROT500K2V_SafeDecrypt(obfuscated, password, iterations, salt, checkCharsPerToken, shiftPunctuation);
  }

  function modeToShort(mode) {
    if (mode === "ROT500K2") return "2";
    if (mode === "ROT500K2V") return "2V";
    if (mode === "ROT500K2T") return "2T";
    if (mode === "ROT500K2P") return "2P";
    return "2";
  }

  function shortToMode(m) {
    const s = String(m || "").trim().toUpperCase();
    if (s === "2" || s === "ROT500K2") return "ROT500K2";
    if (s === "2V" || s === "ROT500K2V") return "ROT500K2V";
    if (s === "2T" || s === "ROT500K2T") return "ROT500K2T";
    if (s === "2P" || s === "ROT500K2P") return "ROT500K2P";
    return null;
  }

  function getBaseShareUrl() {
    return PUBLIC_SHARE_BASE;
  }

  function buildShareUrlFromCiphertext(mode, ciphertext) {
    const m = modeToShort(mode);
    const d = utf8ToB64url(ciphertext);
    return `${getBaseShareUrl()}#m=${encodeURIComponent(m)}&d=${encodeURIComponent(d)}`;
  }

  function parseHashParams() {
    const raw = (location.hash || "").replace(/^#/, "");
    if (!raw) return null;

    const sp = new URLSearchParams(raw);
    const m = sp.get("m") || sp.get("mode");
    const d = sp.get("d") || sp.get("data");
    if (!m || !d) return null;

    return { m, d };
  }

  function bindTabs() {
    document.querySelectorAll(".tabbtn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tabbtn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(btn.dataset.tab).classList.add("active");
      });
    });
  }

  function statusSetter(el) {
    return (msg, ok = null) => {
      if (!el) return;
      if (ok === true) el.innerHTML = `<span class="ok">${msg}</span>`;
      else if (ok === false) el.innerHTML = `<span class="bad">${msg}</span>`;
      else el.textContent = msg;
    };
  }

  async function initDemoPage() {
    const btnEnc = $("btnEnc");
    const btnDec = $("btnDec");
    const btnSwap = $("btnSwap");
    const btnQR = $("btnQR");
    const btnCopyLink = $("btnCopyLink");
    const statusEl = $("status");
    const qrStatusEl = $("qrStatus");
    const qrPreviewEl = $("qrPreview");
    const shareUrlEl = $("shareUrl");

    const status = statusSetter(statusEl);
    const qrStatus = statusSetter(qrStatusEl);

    if (!window.crypto || !window.crypto.subtle) {
      statusEl.innerHTML = '<span class="bad">Web Crypto is unavailable in this context. Encode/Decode require HTTPS or localhost. QR generation alone can still work for already-produced output.</span>';
    }

    function setBusy(b) {
      btnEnc.disabled = b;
      btnDec.disabled = b;
      btnSwap.disabled = b;
      btnQR.disabled = b;
      btnCopyLink.disabled = b;
    }

    function getParams() {
      const mode = $("mode").value;
      const name = $("name").value;
      const pw = $("password").value;
      const it = Math.max(1, parseInt($("iterations").value || "1", 10));
      const salt = $("salt").value || DEFAULT_SALT;
      const cc = Math.max(1, parseInt($("checkChars").value || "1", 10));
      const sp = $("shiftPunct").checked;
      return { mode, name, pw, it, salt, cc, sp };
    }

    async function generateQrForOutput() {
      const mode = $("mode").value;
      const out = $("out").value || "";

      if (!out.trim()) {
        shareUrlEl.value = "";
        qrPreviewEl.textContent = "No output to encode.";
        qrStatus("Nothing in Output yet.", false);
        return;
      }

      const shareUrl = buildShareUrlFromCiphertext(mode, out);
      shareUrlEl.value = shareUrl;
      qrPreviewEl.innerHTML = "";

      try {
        if (!window.QRCode || !QRCode.toDataURL) {
          throw new Error("QRCode library not loaded.");
        }

        const img = document.createElement("img");
        img.alt = "QR code";

        const dataUrl = await QRCode.toDataURL(shareUrl, {
          errorCorrectionLevel: "L",
          margin: 1,
          width: 220
        });

        img.src = dataUrl;
        qrPreviewEl.appendChild(img);
        qrStatus(`QR generated successfully. URL length: ${shareUrl.length} chars.`, true);
      } catch (e) {
        qrPreviewEl.textContent = "QR could not be generated.";
        qrStatus("QR generation failed: " + (e && e.message ? e.message : String(e)), false);
        console.error(e);
      }
    }

    async function copyShareLink() {
      const s = shareUrlEl.value || "";
      if (!s) {
        qrStatus("Generate the QR/share link first.", false);
        return;
      }
      try {
        await navigator.clipboard.writeText(s);
        qrStatus("Share URL copied to clipboard.", true);
      } catch (e) {
        qrStatus("Could not copy the share URL.", false);
        console.error(e);
      }
    }

    async function doEncode() {
      const { mode, name, pw, it, salt, cc, sp } = getParams();
      if (mode === "ROT500K2") return ROT500K2_Encrypt(name, pw, it, salt, sp);
      if (mode === "ROT500K2P") return ROT500K2P_Encrypt(name, pw, it, salt, sp);
      if (mode === "ROT500K2T") return ROT500K2T_Encrypt(name, pw, it, salt, cc, sp);
      return ROT500K2V(name, pw, it, salt, cc, sp);
    }

    async function doDecode() {
      const { mode, name, pw, it, salt, cc, sp } = getParams();

      if (mode === "ROT500K2") {
        const dec = await ROT500K2_Decrypt(name, pw, it, salt, sp);
        return { ok: true, value: dec, verified: false };
      }
      if (mode === "ROT500K2P") {
        const r = await ROT500K2P_Decrypt(name, pw, it, salt, sp);
        return { ok: r.ok, value: r.value, verified: true };
      }
      if (mode === "ROT500K2T") {
        const r = await ROT500K2T_Decrypt(name, pw, it, salt, cc, sp);
        return { ok: r.ok, value: r.value, verified: true };
      }
      const r = await ROT500K2V_Decrypt(name, pw, it, salt, cc, sp);
      return { ok: r.ok, value: r.value, verified: true };
    }

    btnEnc.addEventListener("click", async () => {
      try {
        setBusy(true);
        status("Encoding… (PBKDF2/HMAC can take a moment)");
        const t0 = performance.now();
        const enc = await doEncode();
        const t1 = performance.now();
        $("out").value = enc;
        status(`Done in ${Math.round(t1 - t0)} ms.`, true);
        await generateQrForOutput();
      } catch (e) {
        console.error(e);
        status("Error: " + (e && e.message ? e.message : String(e)), false);
      } finally {
        setBusy(false);
      }
    });

    btnDec.addEventListener("click", async () => {
      try {
        setBusy(true);
        status("Decoding…");
        const t0 = performance.now();
        const r = await doDecode();
        const t1 = performance.now();

        $("out").value = r.value || "";

        shareUrlEl.value = "";
        qrPreviewEl.textContent = "QR is generated from encoded Output only.";
        qrStatus("Decoded output is plaintext, so QR generation is not refreshed automatically.", null);

        if (!r.verified) {
          status(`Done in ${Math.round(t1 - t0)} ms. (No verification in ROT500K2)`, true);
        } else {
          status(`Done in ${Math.round(t1 - t0)} ms. Verified: ${r.ok ? "OK" : "FAILED"}`, r.ok);
        }
      } catch (e) {
        console.error(e);
        status("Error: " + (e && e.message ? e.message : String(e)), false);
      } finally {
        setBusy(false);
      }
    });

    btnSwap.addEventListener("click", () => {
      const a = $("name").value;
      $("name").value = $("out").value;
      $("out").value = a;
      status("Swapped.");
      shareUrlEl.value = "";
      qrPreviewEl.textContent = "Generate QR again if needed.";
      qrStatus("Output changed after swap.", null);
    });

    btnQR.addEventListener("click", async () => {
      try {
        setBusy(true);
        await generateQrForOutput();
      } finally {
        setBusy(false);
      }
    });

    btnCopyLink.addEventListener("click", async () => {
      try {
        setBusy(true);
        if (!shareUrlEl.value && $("out").value.trim()) {
          await generateQrForOutput();
        }
        await copyShareLink();
      } finally {
        setBusy(false);
      }
    });

    bindTabs();

    async function initFromHash() {
      const hp = parseHashParams();
      if (!hp) return;

      const mode = shortToMode(hp.m);
      if (!mode) {
        status("Hash payload found, but mode is invalid.", false);
        return;
      }

      let ciphertext = "";
      try {
        ciphertext = b64urlToUtf8(hp.d);
      } catch (e) {
        console.error(e);
        status("Hash payload found, but ciphertext could not be decoded from base64url.", false);
        return;
      }

      document.querySelectorAll(".tabbtn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      document.querySelector('.tabbtn[data-tab="demo"]').classList.add("active");
      document.getElementById("demo").classList.add("active");

      $("mode").value = mode;
      $("name").value = ciphertext;

      const pw = window.prompt("Enter the password to decode this message:", "") || "";
      $("password").value = pw;

      if (!pw) {
        status("A shared message was loaded from the URL. Enter the password and click Decode.", null);
        return;
      }

      try {
        setBusy(true);
        status("Shared message detected. Decoding…");
        const t0 = performance.now();
        const r = await doDecode();
        const t1 = performance.now();

        $("out").value = r.value || "";
        shareUrlEl.value = `${getBaseShareUrl()}#m=${encodeURIComponent(modeToShort(mode))}&d=${encodeURIComponent(hp.d)}`;
        qrPreviewEl.textContent = "This page was opened from a shared QR/link.";

        if (!r.verified) {
          status(`Shared message decoded in ${Math.round(t1 - t0)} ms. (No verification in ROT500K2)`, true);
        } else {
          status(`Shared message decoded in ${Math.round(t1 - t0)} ms. Verified: ${r.ok ? "OK" : "FAILED"}`, r.ok);
        }
      } catch (e) {
        console.error(e);
        status("Error while decoding shared message: " + (e && e.message ? e.message : String(e)), false);
      } finally {
        setBusy(false);
      }
    }

    await initFromHash();
  }

  async function initDecoderPage() {
    const outEl = $("out");
    const statusEl = $("status");
    const status = statusSetter(statusEl);

    if (!window.crypto || !window.crypto.subtle) {
      status("Web Crypto is unavailable in this context. Open via HTTPS or localhost.", false);
      return;
    }

    const hp = parseHashParams();
    if (!hp) {
      status("No shared payload found in URL hash.", false);
      return;
    }

    const mode = shortToMode(hp.m);
    if (!mode) {
      status("Hash payload found, but mode is invalid.", false);
      return;
    }

    let ciphertext = "";
    try {
      ciphertext = b64urlToUtf8(hp.d);
    } catch (e) {
      status("Hash payload found, but ciphertext could not be decoded.", false);
      return;
    }

    const password = window.prompt("Enter the password to decode this message:", "") || "";
    if (!password) {
      status("No password provided.", false);
      return;
    }

    try {
      status("Decoding…");
      const t0 = performance.now();

      if (mode === "ROT500K2") {
        const plain = await ROT500K2_Decrypt(ciphertext, password);
        outEl.value = plain;
        status(`Decoded in ${Math.round(performance.now() - t0)} ms.`, true);
        return;
      }

      if (mode === "ROT500K2P") {
        const r = await ROT500K2P_Decrypt(ciphertext, password);
        outEl.value = r.value || "";
        status(`Decoded in ${Math.round(performance.now() - t0)} ms. Verified: ${r.ok ? "OK" : "FAILED"}`, r.ok);
        return;
      }

      if (mode === "ROT500K2T") {
        const r = await ROT500K2T_Decrypt(ciphertext, password);
        outEl.value = r.value || "";
        status(`Decoded in ${Math.round(performance.now() - t0)} ms. Verified: ${r.ok ? "OK" : "FAILED"}`, r.ok);
        return;
      }

      if (mode === "ROT500K2V") {
        const r = await ROT500K2V_Decrypt(ciphertext, password);
        outEl.value = r.value || "";
        status(`Decoded in ${Math.round(performance.now() - t0)} ms. Verified: ${r.ok ? "OK" : "FAILED"}`, r.ok);
        return;
      }

      status("Unsupported mode.", false);
    } catch (e) {
      console.error(e);
      status("Error: " + (e && e.message ? e.message : String(e)), false);
    }
  }

  return {
    initDemoPage,
    initDecoderPage,
    buildShareUrlFromCiphertext,
    parseHashParams,
    shortToMode,
    modeToShort
  };
})();