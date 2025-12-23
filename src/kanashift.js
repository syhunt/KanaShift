/* kana-rain.js — red kana rain background (canvas)
   Requires: none. (Optionally uses window.KANA64 if you expose it.)
*/
(() => {
  const prefersReduced =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReduced) return;

  // Create canvas
  let canvas = document.getElementById("kanaRain");
  if (!canvas) {
    canvas = document.createElement("canvas");
    canvas.id = "kanaRain";
    document.body.prepend(canvas);
  }
  const ctx = canvas.getContext("2d", { alpha: true });

  // Optional: reuse your exact alphabet if you do window.KANA64 = KANA64;
  const fallbackKANA64 =
    "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん" +
    "アイウエオカキクケコサシスセソタチツ";
  const KANA64_SRC =
    (typeof window.KANA64 === "string" && window.KANA64.length >= 64)
      ? window.KANA64
      : fallbackKANA64;

  const RAIN_CHARS =
    KANA64_SRC + "ゃゅょャュョぁぃぅぇぉァィゥェォー・「」『』。、】【！？";
  const randChar = () => RAIN_CHARS.charAt((Math.random() * RAIN_CHARS.length) | 0);

  let w = 0, h = 0, dpr = 1;
  let cols = 0;
  let drops = [];
  let speeds = [];
  let sizes = [];
  let colW = 14;

  // Breathing state
  let breathePhase = 0;

  function resize() {
    dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    w = window.innerWidth;
    h = window.innerHeight;

    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const baseSize = Math.max(13, Math.min(22, Math.round(w / 70)));
    colW = Math.round(baseSize * 0.9);

    cols = Math.floor(w / colW) + 1;

    drops = new Array(cols);
    speeds = new Array(cols);
    sizes = new Array(cols);

    for (let i = 0; i < cols; i++) {
      drops[i] = Math.random() * h;
      speeds[i] = 0.8 + Math.random() * 2.5;
      sizes[i] = baseSize + ((Math.random() * 6) | 0);
    }

    ctx.textBaseline = "top";
  }

  // Helper: 0..1 -> 0..1 but spends more time near 0 and 1
  function smoothstep01(x) {
    x = Math.max(0, Math.min(1, x));
    return x * x * (3 - 2 * x);
  }

  function paintFrame() {
    // Slow breath: set speed here
    breathePhase += 0.0012; // lower = longer period
    const raw = (Math.sin(breathePhase) + 1) * 0.5; // 0..1

    // Shape it so it actually gets *very* close to 0 for longer
    // then back up (full invisibility happens below)
    const shaped = smoothstep01(raw);
    const rainAlpha = Math.pow(shaped, 3.2); // key: drives to near-zero hard

    // When rainAlpha is low, aggressively fade to black to clear trails.
    // When rainAlpha is high, keep a gentle trail.
    const clear = 0.10 + (1 - rainAlpha) * 0.80; // goes up to ~0.90 near invis
    ctx.fillStyle = `rgba(7, 6, 10, ${clear})`;
    ctx.fillRect(0, 0, w, h);

    // If we are effectively invisible, skip drawing entirely (true blackout moment)
    if (rainAlpha < 0.015) {
      requestAnimationFrame(paintFrame);
      return;
    }

    for (let i = 0; i < cols; i++) {
      const x = i * colW;
      if (x > w) continue;

      const y = drops[i];
      const head = Math.random() < 0.09;

      // Base alphas multiplied by rainAlpha so it fades to 0
      const aHead = (0.55 + rainAlpha * 0.45) * rainAlpha;     // strong at peak, 0 at low
      const aBody = (0.12 + rainAlpha * 0.28) * rainAlpha;     // subtle body

      ctx.fillStyle = head
        ? `rgba(255, 80, 120, ${aHead})`
        : `rgba(255, 46, 85, ${aBody})`;

      ctx.font = `${sizes[i]}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
      ctx.fillText(randChar(), x, y);

      // FALL SPEED (lower = slower)
      drops[i] += speeds[i] * sizes[i] * 0.50;

      if (drops[i] > h + 40 && Math.random() < 0.03) {
        drops[i] = -Math.random() * 200;
        speeds[i] = 0.8 + Math.random() * 2.2;
        sizes[i] = Math.max(12, Math.min(24, sizes[i] + ((Math.random() * 5 - 2) | 0)));
      }
    }

    requestAnimationFrame(paintFrame);
  }

  resize();
  window.addEventListener("resize", resize, { passive: true });
  requestAnimationFrame(paintFrame);
})();