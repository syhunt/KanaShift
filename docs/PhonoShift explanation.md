# ROT500K2 Family (PhonoShift): Keyed, format-preserving obfuscation with adaptive verification

## Abstract

**PhonoShift**, implemented as the **ROT500K2 family**, is a keyed, reversible, **format-preserving obfuscation** scheme for human-readable text. ROT500K2 applies **polyalphabetic, class-preserving rotations** to characters using keystream material derived from **PBKDF2-HMAC-SHA-256** (default **500,000 iterations**, hence “500K”).

Version **2.x** introduces a **per-message nonce embedded in a stealth frame**, mixed into all PBKDF2 salt derivations. This prevents keystream reuse across messages, even when the same password, salt, and iteration count are reused.

The result is text that remains structurally usable (same delimiters, similar readability properties) while hiding meaning in a deterministic, password-controlled way. Verified variants embed a **verification signal** so decode can return a definitive **OK / FAILED** result under incorrect parameters (**ROT500K2V**, **ROT500K2T**, **ROT500K2P**).

A small offline demo UI exists as a wrapper around these modes, but the design is independent of any UI.

___

## Design goals

ROT500K2 targets scenarios where you want “scrambled but still text-like” output:

1.  **Reversible, keyed obfuscation**  
    The same _(password, salt, iterations)_ produces correct decoding.
    
2.  **Format preservation**  
    Separators such as **space**, **\-**, and **'** remain fixed so token boundaries are stable.
    
3.  **Class preservation**  
    Digits remain digits, letters remain letters, and case is preserved for ASCII letters.
    
4.  **Pronounceability-aware rotation (PhonoShift)**  
    ASCII letters rotate in **phonetic classes** rather than across the whole alphabet:
    
    -   vowels rotate within vowels
        
    -   consonants rotate within consonants  
        This avoids outputs that look like random noise and preserves a “word-like” texture.
        
5.  **Nonce-aware keystream derivation (2.x)**  
    Every message uses a fresh nonce embedded in the ciphertext framing and mixed into PBKDF2 salt derivation, preventing keystream reuse across messages.
    
6.  **Optional punctuation hiding without moving punctuation**  
    A reversible punctuation swap can reduce semantic cues (e.g., question vs exclamation) while keeping punctuation positions unchanged.
    

___

## Core primitive: PBKDF2 keystream + non-zero rotations (nonce-aware)

### Keystream derivation

For an input string `s`, ROT500K2 derives a byte stream:

```
ks = PBKDF2_SHA256(
  password,
  dsalt(baseSalt, nonce, domain),
  iterations,
  needBytes
)

```

Key points:

-   A **per-message nonce** is embedded in the ciphertext and included in the salt.
    
-   Different sub-operations (core transform, punctuation shifting, verification) use **domain-separated salts**.
    

### Non-zero rotation rule

To avoid leaking unchanged characters, the transform forces shifts to never be zero:

```
shift = (ks[i] + 1) * direction
```

-   Encrypt uses `direction = +1`
    
-   Decrypt uses `direction = -1`
    

That `+1` guarantees every affected character changes (for sets larger than 1), while preserving perfect invertibility.

### Separator invariance

Characters used as structural separators are not transformed:

-   space `" "`
    
-   hyphen `"-"`
    
-   apostrophe `"'"`
    

This ensures that token boundaries and formatting survive the transformation.

___

## ROT500K2 base mode (length-preserving)

**ROT500K2** is the minimal, length-preserving transform.

### What it transforms

-   **Digits (0–9)**: rotated within digits → still digits
    
-   **ASCII letters**:
    
    -   vowels rotate within `aeiou`
        
    -   consonants rotate within `bcdfghjklmnpqrstvwxyz`
        
    -   case is preserved
        
-   **Portuguese accented vowels**: rotated within dedicated sets
    
-   **Portuguese ç / Ç**: handled in dedicated sets, reversible
    

### What it leaves alone

-   separators (space, `-`, `'`)
    
-   characters outside handled sets (symbols, emojis, etc.) pass through unchanged unless punctuation shifting is enabled
    

**Key property:** output length equals input length.

___

## Optional punctuation shifting

ROT500K2 includes an optional, reversible punctuation swap that **does not move punctuation positions**.

In the reference implementation:

-   opening marks: `¿¡`
    
-   ending marks: `!?`
    

Each punctuation character rotates within its own small set using a **nonce-aware, domain-separated keystream**.

**Purpose:** hide semantic cues like “question vs exclamation” while keeping text readable and layout-stable.

___

## Stealth framing (ROT500K2 wire format)

ROT500K2 ciphertexts are wrapped in a **stealth frame** with **no fixed ASCII signature**, designed to blend naturally into text.

High-level behavior:

-   The frame embeds:
    
    -   mode identifier
        
    -   per-message nonce
        
    -   optional padding
        
-   The header is encoded as **pronounceable syllables**
    
-   The payload immediately follows the header
    

### Strict vs tolerant decoding

-   **Verified modes (T / P / V)** use **strict frame parsing**.
    
-   **Base ROT500K2 decode** may optionally use **tolerant detection**, scanning text to locate a valid stealth frame embedded inside a larger string.
    

This makes base decoding robust when ciphertext is pasted into surrounding prose, logs, or messages.

___

## The verification problem: why verified modes exist

A pure reversible obfuscation transform has a classic issue:

> Decoding with the wrong password still produces _some_ output, and it may look plausible.

ROT500K2 addresses this with verified variants that embed a **keyed authenticity signal**, allowing decode to return **OK / FAILED**.

___

## Verified family overview

### ROT500K2T — Token-verified (adds chars per token)

**Idea:** append `N` verification characters to every token.

1.  Split plaintext into tokens.
    
2.  Derive an **HMAC key via PBKDF2** (nonce-aware, domain-separated).
    
3.  For each token `t` at index `i`, compute:
    
    ```
mac = HMAC_SHA256(domain | salt | iterations | nonce | i | t)
    ```
    
4.  Convert MAC bytes into `N` check characters:
    
    -   digit tokens → digits
        
    -   other tokens → consonant letters (case-aware)
        
5.  Append the check characters to each cipher token.
    

On decode:

-   strip checks
    
-   decode base cipher
    
-   recompute checks from decoded plaintext
    
-   compare → **OK / FAILED**
    

**Traits**

-   Stealthy (no visible header)
    
-   Best for medium/long token-rich text
    
-   Length increases by `N × tokenCount`
    

___

### ROT500K2P — Prefix-verified (adds a word-like prefix)

**Idea:** prepend a short, human-looking tag derived from the plaintext.

1.  Compute a MAC over the entire plaintext (nonce-aware).
    
2.  Generate a **pronounceable prefix** (e.g., two pseudo-words).
    
3.  Append punctuation and a space, then the ciphertext.
    

On decode:

-   parse prefix
    
-   decode remainder
    
-   recompute expected prefix
    
-   compare → **OK / FAILED**
    

**Traits**

-   Best for **very short** strings
    
-   Fixed, visible overhead
    
-   More obvious than KT
    

___

### ROT500K2V — Verified auto (adaptive)

**ROT500K2V** automatically selects the best strategy:

-   Uses **ROT500K2T** for suitable multi-token text
    
-   Falls back to **ROT500K2P** for short or unsuitable inputs
    
-   May increase verification strength automatically for very short messages
    

On decode, it tries **token-verified first**, then **prefix-verified**.

___

## Comparison to ROT13

ROT13 is:

-   fixed and unkeyed
    
-   trivially recognizable
    
-   trivially reversible
    

ROT500K2 is:

-   **keyed**
    
-   **polyalphabetic**
    
-   nonce-hardened against keystream reuse
    
-   expensive to brute-force due to PBKDF2 cost
    
-   optionally **verifiable**, enabling definitive wrong-key detection
    

___

## Practical guidance

-   Use **ROT500K2** when you must preserve length exactly and don’t need verification.
    
-   Use **ROT500K2V** as a safe default with adaptive verification.
    
-   Use **ROT500K2T** explicitly for stealthy verification on token-rich text.
    
-   Use **ROT500K2P** explicitly for very short inputs where KT is ineffective.
    

___

## Security posture (what it is and isn’t)

ROT500K2 is **format-preserving obfuscation**, not conventional ciphertext. It is optimized for human-text workflows: stable separators, readable structure, deterministic reversal, nonce-hardened keystreams, and optional verification signals.

For high-stakes confidentiality of arbitrary data, use standard authenticated encryption.  
For “scramble this text but keep it text-shaped,” ROT500K2 is purpose-built.