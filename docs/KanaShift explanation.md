# KanaShift (KAN500K2): Keyed, format-preserving obfuscation with Japanese “skins” and optional verification

## Abstract

KanaShift is a **keyed, reversible text obfuscation scheme** designed to transform input strings into **Japanese-looking output** (Skin family) or **Japanese-preserving output** (JP-native family) while keeping key structural properties intact: token boundaries, separators, and character “classes” (letters stay letter-like, digits stay digit-like, kana stays kana-like, etc.). KanaShift is _not_ encryption in the conventional “binary ciphertext” sense; it is a **format-preserving obfuscation layer** intended for cases where you want to hide meaning while keeping text visually plausible, copy/paste-friendly, and structurally stable.

The default **500K2** configuration uses **PBKDF2-SHA-256 with 500,000 iterations** to derive keystream material from a password+salt. **KAN500K2 also introduces a per-message nonce (“tweak”) embedded in the ciphertext framing**, mixed into all PBKDF2 salt derivations to prevent keystream reuse across messages.

A small offline demo UI exists only as a convenience wrapper (encode/decode fields, mode selector, and a verification indicator). The core is the transform itself.

___

## Design goals

KanaShift is built around a few practical goals:

1.  **Reversible with a password**  
    Given the same _(password, salt, iterations)_, decode returns the original text.
    
2.  **Format-preserving behavior**  
    Deliberately keeps separators such as **space**, **\-**, and **'** fixed so token boundaries remain stable (useful for logs, IDs, UI labels, filenames, etc., where delimiters matter).
    
3.  **Class preservation instead of “random bytes”**  
    Letters map to kana (Skin family), digits map to digits (often fullwidth), kana stays kana (JP-native family), and punctuation can be converted to Japanese fullwidth equivalents without moving punctuation positions.
    
4.  **Uniform scrambling in mixed text**  
    In JP-native mode, embedded ASCII segments are also obfuscated so you don’t end up with obvious “plaintext islands” inside a Japanese sentence.
    
5.  **Per-message nonce to prevent keystream reuse (2.x)**  
    Each encryption uses a fresh nonce embedded in the output, and the nonce is mixed into PBKDF2 salt derivation (domain-separated) so two messages don’t share the same keystream even under identical parameters.
    

___

## Core primitive: keystream-driven rotation (nonce-aware)

At the heart of KanaShift is a simple structure:

-   Derive a keystream (2.x: **nonce-aware + domain-separated**):  
    `keystream = PBKDF2_SHA256(password, dsalt(baseSalt, nonce, domain), iterations)`
    
-   For each character `c` (except fixed separators), take a byte `k` and compute a **shift**.
    
-   Rotate `c` inside an appropriate **set** (alphabet) determined by its class:
    
    -   vowels rotate within vowels
        
    -   consonants within consonants
        
    -   digits within digits
        
    -   hiragana within hiragana
        
    -   katakana within katakana
        
    -   kanji within a CJK range (JP-native)
        
-   Apply the inverse (negative shift) to decode.
    

Two notable implementation choices appear in the code:

### 1) “No-zero rotation” for many sets

Some transforms enforce “never rotate by 0” (via an `effectiveShift` rule), meaning a character typically won’t map to itself under correct operation. This avoids outputs that leak unchanged characters too often (especially in short strings), while remaining invertible because decode uses the exact opposite rotation.

### 2) Separators are intentionally stable

A small set of characters is treated as **structural separators** (space, hyphen, apostrophe). These are never rotated. This is a major part of what makes the scheme “format-preserving” in a human sense (tokenization survives).

___

## Stealth framing (KAN500K2 wire format)

KAN500K2 ciphertexts are wrapped in a **stealth frame** with **no fixed ASCII prefix**, designed to be “kana-only” and easy to embed in text.

**Wire format (2.x stealth):**

```
<HDR4><NONCE16><PAYLOAD...>
```

-   `HDR4` is **4 Kana64 characters** encoding 3 bytes with masked mode/version bits.
    
-   `NONCE16` is **16 Kana64 characters** (12 bytes / 96-bit nonce).
    
-   `PAYLOAD...` is the transformed text (kana-looking), appended as-is.
    

**Tolerant decoding (base modes):**  
Base-mode decoders may optionally **scan the input** to find a valid stealth frame anywhere inside a larger string (useful if the ciphertext is pasted into surrounding text). Verified modes typically remain strict.

___

## Two families (two philosophies)

### Family A — “Japanese-looking skin” (KAN500K2)

This family is meant for Latin/Portuguese text and produces output that _looks_ Japanese.

**Key properties**

-   **Lowercase Latin letters → hiragana**
    
-   **Uppercase Latin letters → katakana** (case preservation via script choice)
    
-   **Digits → fullwidth digits** (０–９), still rotated
    
-   **Portuguese accented vowels** handled via dedicated sets
    
-   **Cedilla (ç/Ç)** maps to distinct kana marks (ゞ / ヾ), reversible
    
-   **Separators remain unchanged**: `space`, `-`, `'`
    

In short: it is a _skin_—you get kana output, but the mapping is class-aware so text remains consistent and reversible.

### Family B — JP-native (KAN500K2JP)

This family is meant for text that is already Japanese (or mixed JP+EN). It tries to keep Japanese looking Japanese.

**Key properties**

-   **Hiragana rotates within the hiragana block**
    
-   **Katakana rotates within the katakana block**
    
-   **Kanji rotates within a CJK Unified Ideographs range** (0x4E00–0x9FFF) so it stays “kanji-like”
    
-   **Embedded ASCII letters are still obfuscated** (vowels within vowels, consonants within consonants, case preserved)
    
-   **Digits rotate and normalize**, commonly into fullwidth on encode
    

The goal is: if you start with Japanese, you don’t end with obvious Latin artifacts or script changes—everything stays in its native visual domain.

___

## Punctuation handling (two layers)

KanaShift treats punctuation as a separate, optional concern:

### 1) Punctuation translation (ASCII ⇄ JP fullwidth)

A reversible mapping converts punctuation glyphs without changing punctuation positions:

-   `? ! , . : ; ( ) [ ] { } "`  
    become their Japanese fullwidth or Japanese-style equivalents:
    
-   `？ ！ 、 。 ： ； （ ） ［ ］ ｛ ｝ ＂`
    

The transform **does not translate** `-` or `'` because those are treated as separators with structural meaning.

### 2) Optional keyed shifting of JP punctuation glyphs

KanaShift can also rotate among small sets of Japanese punctuation:

-   end marks: `！？`
    
-   mid marks: `、。・`
    

This step is:

-   keyed (PBKDF2-derived keystream under a punct-specific domain, **nonce-aware**)
    
-   reversible
    
-   position-preserving
    

So punctuation stays punctuation, stays in place, but becomes less predictable.

___

## KT: Token verification (KAN500K2T / KAN500K2JPT)

Base modes are deterministic and reversible, but **they do not inherently tell you whether the password/salt/iterations were correct**. If you decode with a wrong password, you’ll still get _something_—just not the original.

The **KT** variant adds a verification signal by appending **check characters per token**:

1.  Split plaintext into tokens using a broad set of token separators (spaces, punctuation, JP punctuation, brackets, newlines, etc.).
    
2.  Derive a **MAC key via PBKDF2** (2.x: **domain-separated and nonce-aware**), rather than using the raw password directly.
    
3.  For each token, compute an **HMAC-SHA-256** digest over:
    
    -   domain label (separates Skin vs JP-native)
        
    -   salt
        
    -   iterations
        
    -   token index
        
    -   token content (optionally normalized)
        
4.  Convert digest bytes into **1+ check characters**:
    
    -   digit tokens get fullwidth digit checks
        
    -   other tokens get kana checks from a fixed kana set
        
5.  Append the check characters to each cipher token.
    

On decode:

-   strip the last N check chars from each token
    
-   decode the underlying text
    
-   recompute expected checks from the decoded plaintext (under the same nonce-aware MAC key)
    
-   compare checks
    
-   return **Verified: OK/FAILED**
    

This gives KanaShift something it otherwise lacks: a **definitive wrong-key detection mechanism**, tunable via `checkCharsPerToken` (more chars → lower false-OK probability).

___

## Security posture (what it is, and what it is not)

KanaShift is best understood as **keyed obfuscation / format-preserving scrambling** with optional integrity-like verification (KT). It is intentionally human-text-shaped and predictable in structure.

That implies:

-   It is **not** a drop-in replacement for authenticated encryption (AEAD) for high-stakes secrecy.
    
-   It **is** useful when you need:
    
    -   reversible masking of strings in UIs/logs/demos
        
    -   stable tokenization and copy/paste friendliness
        
    -   output that looks like plausible Japanese text rather than base64/hex
        
    -   optional “wrong password” detection (KT)
        

The PBKDF2 500K setting is there to make **key guessing more expensive**, not to convert the design into conventional ciphertext.

___

## Practical mode summary

-   **KAN500K2**: Latin/PT → kana “skin”; no verification signal.
    
-   **KAN500K2T**: same skin + per-token appended check chars; decode reports OK/FAILED.
    
-   **KAN500K2JP**: JP-native rotation (kana/kanji preserved) + ASCII obfuscation; no verification.
    
-   **KAN500K2JPT**: JP-native + token verification.
    

___

## Implementation notes reflected in the code

A few choices in the implementation are intentional “engineering” decisions:

-   **Per-message nonce (2.x)** is embedded in the stealth frame and mixed into all PBKDF2 salt derivations to prevent keystream reuse across messages.
    
-   **Domain-separated salts** (e.g., `|PunctShiftJP:v2`, `|JPNative:v2|AsciiShift`, `HMACKey:<domain>`) prevent accidental cross-reuse of derived material across sub-operations.
    
-   **Case preservation** in Skin mode is achieved without storing metadata: uppercase letters are mapped into katakana sets.
    
-   **Token checks** are bound to token position (`tokenIndex`) to reduce ambiguity in repeated tokens.