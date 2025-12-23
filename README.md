![cover-v5-optimized](./kanashift-cover.gif)

# KanaShift & PhonoShift

**Password-derived, format-preserving text transformation with a Japanese visual skin. Looks Japanese, translates to something else, decodes back to the truth.**

## Overview

KanaShift is a password-based, reversible text transformation scheme for Latin and Japanese text that preserves length, spacing, punctuation, and token boundaries.
Conceptually, it operates as a character-by-character, password-derived, format-preserving transformation.

It can be understood as a stream-based, password-derived variant of format-preserving encryption (FPE), optimized for structured text and short tokens rather than free-form natural language.

Like its sibling **PhonoShift (ROT500K)**, also included in this repository, KanaShift is intentionally hardened using cryptographic primitives to make reversal without the correct password computationally costly, while remaining deterministic and fully reversible with the secret.

Internally, ROT500K derives a keystream using **PBKDF2-HMAC-SHA256 with 500,000 iterations** (“500K”), deliberately slowing each password-guess attempt. Unlike ROT13, which can be reversed instantly by anyone, reversal here requires guessing the correct password and paying the full key-derivation cost.

The name “ROT500K” is a deliberate nod to ROT13—partly as a joke and partly to underline the contrast:
this is **not** ROT13 repeated many times, but a keyed design where reversal without the secret is no longer trivial.

KanaShift applies the same mechanics with a different visual skin, rendering text using Japanese writing systems (kana and kanji) instead of Latin letters. The design works best for **access codes, identifiers, logs, UI strings, and other structured text**, and is not intended to provide semantic security for arbitrary free-form prose.

Initial implementations of PhonoShift and KanaShift are provided as:
- a standalone HTML/JavaScript reference implementation (`src/`)
- a Python port with Gradio (`src-python/`)
- a cross-platform Rust application

The browser implementation serves as the reference design; other implementations aim to match it byte-for-byte.

## Live Demos

[![ KanaShift – JP skin ](https://img.shields.io/badge/demo-live-green)](https://syhunt.github.io/KanaShift/src/kanashift.html)

[![ PhonoShift – Latin ](https://img.shields.io/badge/demo-live-green)](https://syhunt.github.io/KanaShift/src/phonoshift.html)

----

### Example Outputs with Default Settings — “Rio”

| Family  | Scheme        | Input | Output                                                                 |
|---------|---------------|-------|------------------------------------------------------------------------|
| Kana    | KAN500K2      | Rio   | まによわやるんチえひふみけちなタひケんきセえお           |
| Kana    | KAN500K2T     | Rio   | セをはむたコはちぬクスすとケちめセとウエソおえな           |
| Kana JP | KAN500K2JP    | リオ  | てらをならよむぬすきをかくるはイうきのるブダ               |
| Kana JP | KAN500K2JPT   | リオ  | んれタすとはかふつるまみおうひつかうしさクゲす               |
| Phono   | ROT500K2      | Rio   | Curcuscur dur'bel culpin; ken-leskon; pas canjol hal jon kan; kus; Vae   |
| Phono   | ROT500K2T     | Rio   | Karker kasnar hus'mir bel'cus mon-pen leshes'con gun-merfun jol mer; bon — Beuk |
| Phono   | ROT500K2P     | Rio   | Nen-ninnes — mon fel. mol'nes., lanker jer der honmes ken-dolhes kaldelmer Soyobu Rerofo? Kee |

Verified variants (KT, KJPT, KP) append additional characters to enable detection of incorrect passwords during decoding.

The output looks like Japanese text, even though its meaning is hidden.
For example, “Anna” may encode to イつてう, which Google Translate renders as “It’s good”, while only the correct password recovers the original.
Latin text becomes Japanese-looking, and Japanese text remains Japanese-looking but unreadable to native speakers.

The salt value (e.g. `NameFPE:v1`) acts as a domain and version separator rather than a per-message secret, ensuring keystreams are bound to this specific algorithm and version.

---

## Version Note — ROT500K2 / KAN500K2 (V2)

> This project uses a V2 generation format (`ROT500K2`, `KAN500K2`, and variants).  
> Earlier `ROT500K / KAN500K` formats are considered legacy.

### What’s new in V2

- **Per-message nonce**  
  Prevents keystream reuse across messages encrypted with the same password.

- **PBKDF2-derived HMAC keys (verified modes)**  
  Verification no longer uses a fast HMAC directly on the password, preventing oracle attacks that bypass PBKDF2 cost.

- **Stealth framing**  
  No fixed headers, colons, or magic strings.  
  Mode and nonce are encoded as pronounceable, human-looking text.

- **Strict decoding by default**  
  Verified modes require an exact `ROT500K2 / KAN500K2` frame; base modes allow tolerant frame detection.

> Recommendation: use `ROT500K2 / KAN500K2` for all new data.

### Acknowledgment

Thanks to **Sea-Cardiologist-954** for identifying a critical weakness in v1. KAN500K2 / ROT500K2 addresses keystream-reuse attacks present in v1 by introducing a per-message random nonce that is mixed into PBKDF2 salt derivation. As a result, chosen-plaintext or known-plaintext observations from one message do not apply to any other message encrypted with the same password.

---

## What This Is (and Is Not)

KanaShift is not a replacement for authenticated encryption (e.g., AES-GCM),
nor does it aim to provide semantic security for natural language.

It is designed for reversible masking of structured text where format preservation,
visual disguise, and password-based recovery matter.

## Performance and Tuning

KanaShift derives its keystream using PBKDF2 to impose a configurable cost per password guess.
The default iteration count (500,000) is chosen for short strings and interactive use.

For longer-form text or batch processing, the iteration count can be tuned down substantially,
trading brute-force resistance for throughput while preserving full reversibility
and format stability.

### Security posture and Use cases

KanaShift uses real cryptographic primitives to make reversal expensive, while intentionally preserving text structure and usability. With a strong 16-character password, guessing becomes extremely impractical.

KanaShift is designed for reversible masking of human-readable text in UIs, logs, demos, and identifiers, where stable tokenization, copy/paste friendliness, and visually plausible output matter.
The PBKDF2 500K setting increases the cost of password guessing, but does not turn the output into conventional ciphertext.

As an open-source project, its strength comes from scrutiny rather than secrecy; any weaknesses are expected to surface through review rather than obscurity.

### Calibration

The default 500,000-iteration setting was calibrated on a macOS Mac mini (M4 Pro),
where it produces an encode/decode time of about 200 ms in a browser environment.
This targets a “slow but usable” cost comparable in wall-clock time to common bcrypt
deployments (for example, cost factor 12), without claiming the same security properties.

---

## Shared Core

- Keyed and reversible (`password + salt + iterations`)
- Format-preserving (keeps `space`, `-`, `'`)
- Class-preserving rotation (no cross-class mapping, no zero-shifts)
- PBKDF2-HMAC-SHA256 keystream
- Optional verification (decode can return OK / FAILED)

---

## PhonoShift (ROT500K)

![cover-v5-optimized](./phonoshift-cover.gif)

- Stays in Latin / ASCII
- Phonetic rotation
  - vowels rotate within vowels
  - consonants rotate within consonants
  - case preserved
- Digits stay digits
- Optional punctuation swapping (role-sets, position-preserving)

**Modes:**  
`ROT500K2` (base), `ROT500K2T` (token-verified), `ROT500K2P` (prefix-verified), `ROT500K2V` (auto)

---

## KanaShift (KAN500K)

![cover-v5-optimized](./kanashift-cover.gif)

- Switches to Japanese scripts for visual disguise

**Families**
- **Skin (Latin → Kana)**  
  lowercase → hiragana, uppercase → katakana, digits → fullwidth
- **JP-native (JP → JP)**  
  kana stay kana, kanji stay kanji-like; embedded ASCII also obfuscated

**Modes:**  
`KAN500K2`, `KAN500K2T`, `KAN500K2JP`, `KAN500K2JPT`

---

## Key Differences

| Aspect         | PhonoShift (ROT500K) | KanaShift (KAN500K) |
|----------------|----------------------|----------------------|
| Visual script  | Latin / ASCII        | Japanese (kana/kanji) |
| Main goal     | Subtle scrambling    | Visual disguise      |
| Case handling | Upper/lower preserved | Uppercase via katakana |
| Digits        | ASCII digits 0–9     | Fullwidth digits ０–９ |
| JP support    | No                   | Yes                  |
| Best use      | IDs, logs, UI text   | JP text, strong masking |

---

## Usage

- **Browser:** open the HTML file in `src/` or use the hosted GitHub Pages link.
- **Rust:** get it from https://github.com/DaragonTech/KanaShift-RS. Build with `cargo build -p kanashift_app --release` and run the binary from `target/release/`.
- **Python:** install Gradio (`pip install gradio`) and run `python kanashift_app.py`.

For the Rust implementation, performance measurements assume a release build, as debug builds can significantly slow down encoding and decoding.

### Quick Pick

- Stay Latin → PhonoShift / ROT500K
- Need verification → ROT500KV
- Want strong visual disguise → KanaShift
- Mixed JP + EN text → KAN500KJP

---
Authored by the cybersecurity professional and programmer Felipe Daragon, with AI assistance.
This project is experimental, not production-ready, and is shared for learning, testing, and review.
This code has not been formally audited and should not be considered cryptographically bulletproof.
Independent review by cryptography experts is encouraged.

Released under the **a 3-clause BSD license** for research and experimental use - see the LICENSE file for details.