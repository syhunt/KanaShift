# phonoshift_app.py
# ROT500K2 Family / PhonoShift — Gradio UI (compat: no Blocks(css=...))
# PhonoShift 2.x - ROT500K2 family
# Author: Felipe Daragon
# https://github.com/syhunt/kanashift

import gradio as gr
import phonoshift as ps

ABOUT_MD = r"""
## About the ROT500K2 Family

**ROT500K2** is a keyed, format-preserving *rotation-based* obfuscation scheme.
It preserves separators (`space`, `-`, `'`) and character classes (digits remain digits, letters remain letters),
and is fully reversible with the same **password + salt + PBKDF2 iterations**.

While the **payload** transformation itself preserves length, all ROT500K2 variants now prepend a **stealth frame**.
This frame slightly increases total output length, but is designed to look like natural, human-written text
rather than a fixed cryptographic header.

**ROT500K2V** is the “verified” variant. In addition to the stealth frame, it embeds a keyed verification signal
so decryption can return a definitive **true / false** result when parameters are incorrect.
It automatically selects the most appropriate verification style:
- **ROT500K2T** (token verification): appends a small number of characters per token (stealthy, robust)
- **ROT500K2P** (prefix verification): adds a short word-like prefix (best for very short inputs)

**Punctuation shifting (optional):** only rotates within `¿¡` and `!?` (does not move punctuation positions).

---

**Stealth framing:** outputs begin with a variable, pronounceable text segment that encodes
`mode + nonce + padding` internally. There are no fixed markers, delimiters, or repeated signatures
(no `ROT500K2:`, no colons, no constant layout). Each encoding produces a different-looking header,
even for identical inputs.
"""

CSS = """
<style>
#title { margin-bottom: 0.25rem; }
.small { opacity: 0.85; font-size: 0.9rem; }
</style>
"""

def do_encode(mode: str, text_in: str, password: str, iterations: int, salt: str, check_chars: int, shift_punct: bool):
    try:
        iterations = max(1, int(iterations))
        check_chars = max(1, int(check_chars))
        salt = salt or "NameFPE:v1"

        if mode == "ROT500K2":
            enc = ps.rot500k2_encrypt(text_in, password, iterations, salt, shift_punct)
            # Optional sanity check (since base mode has no verification)
            dec = ps.rot500k2_decrypt(enc, password, iterations, salt, shift_punct)
            ok = (dec == text_in)
            return enc, f"Encoded. Self-check (ROT500K2 only): {'OK' if ok else 'FAILED'}"

        if mode == "ROT500K2P":
            enc = ps.rot500k2p_encrypt(text_in, password, iterations, salt, shift_punct)
            return enc, "Encoded (ROT500K2P)."

        if mode == "ROT500K2T":
            enc = ps.rot500k2t_encrypt(text_in, password, iterations, salt, check_chars, shift_punct)
            return enc, "Encoded (ROT500K2T)."

        # ROT500K2V
        enc = ps.rot500k2v_encrypt(text_in, password, iterations, salt, check_chars, shift_punct)
        return enc, "Encoded (ROT500K2V)."

    except Exception as e:
        return "", f"Error: {e}"


def do_decode(mode: str, text_in: str, password: str, iterations: int, salt: str, check_chars: int, shift_punct: bool):
    try:
        iterations = max(1, int(iterations))
        check_chars = max(1, int(check_chars))
        salt = salt or "NameFPE:v1"

        if mode == "ROT500K2":
            dec = ps.rot500k2_decrypt(text_in, password, iterations, salt, shift_punct)
            return dec, "Decoded. (No verification in ROT500K2)"

        if mode == "ROT500K2P":
            r = ps.rot500k2p_decrypt(text_in, password, iterations, salt, shift_punct)
            return r.value, f"Decoded. Verified: {'OK' if r.ok else 'FAILED'}"

        if mode == "ROT500K2T":
            r = ps.rot500k2t_decrypt(text_in, password, iterations, salt, check_chars, shift_punct)
            return r.value, f"Decoded. Verified: {'OK' if r.ok else 'FAILED'}"

        # ROT500K2V
        r = ps.rot500k2v_decrypt(text_in, password, iterations, salt, check_chars, shift_punct)
        return r.value, f"Decoded. Verified: {'OK' if r.ok else 'FAILED'}"

    except Exception as e:
        return "", f"Error: {e}"


def do_swap(text_in: str, text_out: str):
    return text_out, text_in, "Swapped."


def build_app():
    # No css= kwarg for old Gradio
    with gr.Blocks(title="ROT500K2 Family / PhonoShift — Gradio Demo") as demo:
        gr.HTML(CSS)

        gr.Markdown("# ROT500K2 Family (aka *PhonoShift*) — Gradio Demo", elem_id="title")
        gr.Markdown(
            "**PhonoShift (ROT500K2)** is a keyed, format-preserving obfuscation scheme that applies polyalphabetic, "
            "class-preserving rotations driven by a PBKDF2-derived keystream. Default is **500,000 PBKDF2 iterations**.",
            elem_classes=["small"],
        )
        gr.Markdown(
            "**V2:** outputs include a per-message nonce (safe reuse of the same password across messages), "
            "verified modes derive their MAC key via PBKDF2, and framing is now **stealth** (no fixed signature).",
            elem_classes=["small"],
        )

        with gr.Tabs():
            with gr.TabItem("Demo"):
                with gr.Row():
                    mode = gr.Dropdown(
                        choices=["ROT500K2", "ROT500K2V", "ROT500K2T", "ROT500K2P"],
                        value="ROT500K2",
                        label="Mode",
                    )
                    check_chars = gr.Number(
                        value=1,
                        precision=0,
                        label="Token check chars (ROT500K2T / ROT500K2V)",
                        minimum=1,
                    )

                shift_punct = gr.Checkbox(value=True, label="Shift punctuation (optional) — only ¿¡ and !?")

                text_in = gr.Textbox(
                    label="Input (plaintext or obfuscated)",
                    lines=4,
                    value="Vamos lá, ver se isso funciona mesmo!",
                )

                with gr.Row():
                    password = gr.Textbox(label="Password", value="correct horse battery staple")
                    iterations = gr.Number(label="PBKDF2 iterations", value=500000, precision=0, minimum=1)
                    salt = gr.Textbox(label="Salt", value="NameFPE:v1")

                with gr.Row():
                    btn_enc = gr.Button("Encode")
                    btn_dec = gr.Button("Decode")
                    btn_swap = gr.Button("Swap ↔")

                text_out = gr.Textbox(label="Output", lines=4)
                status = gr.Markdown(
                    "Tip: **Encode** writes to Output. **Decode** reads from Input. "
                    "Verified modes can detect wrong parameters. Base mode can’t (no MAC)."
                )

                btn_enc.click(
                    do_encode,
                    inputs=[mode, text_in, password, iterations, salt, check_chars, shift_punct],
                    outputs=[text_out, status],
                )
                btn_dec.click(
                    do_decode,
                    inputs=[mode, text_in, password, iterations, salt, check_chars, shift_punct],
                    outputs=[text_out, status],
                )
                btn_swap.click(
                    do_swap,
                    inputs=[text_in, text_out],
                    outputs=[text_in, text_out, status],
                )

            with gr.TabItem("About"):
                gr.Markdown(ABOUT_MD)

    return demo


if __name__ == "__main__":
    app = build_app()
    app.launch()