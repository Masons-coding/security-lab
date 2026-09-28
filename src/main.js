import { HASHES, bitDiff, digest } from "./hashing.js";
import { decrypt, encrypt } from "./aes.js";
import { ENGLISH, caesar, crackCaesar, crackVigenere, frequencies, vigenere } from "./ciphers.js";
import { analyzePassword } from "./password.js";
import { auditJwt, decodeJwt, signHS256, verifyHS256 } from "./jwt.js";
import { fromBase64Url, toBase64Url } from "./encoding.js";
import { initTabs } from "./ui/tabs.js";

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
};
const debounce = (fn, ms = 120) => {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
};

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "copied ✓";
    setTimeout(() => (button.textContent = "copy"), 1200);
  } catch {
    button.textContent = "copy failed";
  }
}

/* ================= Hashing ================= */
async function renderHashes() {
  const text = $("hash-input").value;
  const rows = await Promise.all(
    HASHES.map(async (algo) => {
      const hex = await digest(algo, text);
      const button = el("button", { className: "copy", type: "button", textContent: "copy" });
      button.addEventListener("click", () => copy(hex, button));
      const name = el("span", { className: "hash-row__name", textContent: `${algo} · ${hex.length * 4} bits` });
      if (algo === "SHA-1") name.append(el("span", { className: "broken", textContent: "⚠ collision-broken" }));
      return el("div", { className: "hash-row" }, el("div", { className: "hash-row__head" }, name, button), el("div", { className: "hash-row__value", textContent: hex }));
    })
  );
  $("hash-list").replaceChildren(...rows);
}

async function renderAvalanche() {
  const [a, b] = await Promise.all([digest("SHA-256", $("av-a").value), digest("SHA-256", $("av-b").value)]);
  const { flipped, count, total, ratio } = bitDiff(a, b);
  $("av-summary").replaceChildren("Bits changed: ", el("b", { textContent: `${count} / ${total}` }), ` (${(ratio * 100).toFixed(1)}%)`);
  $("bitgrid").replaceChildren(...flipped.map((f) => el("span", { className: `bit${f ? " bit--flip" : ""}` })));
}

$("hash-input").addEventListener("input", debounce(renderHashes));
$("av-a").addEventListener("input", debounce(renderAvalanche));
$("av-b").addEventListener("input", debounce(renderAvalanche));

/* ================= Encryption ================= */
$("enc-btn").addEventListener("click", async () => {
  const btn = $("enc-btn");
  btn.disabled = true;
  $("enc-meta").textContent = "Deriving key (600,000 PBKDF2 iterations)…";
  try {
    const t0 = performance.now();
    const bundle = await encrypt($("enc-text").value, $("enc-pw").value);
    const ms = performance.now() - t0;
    $("enc-out").value = bundle;
    $("dec-in").value = bundle;
    const [, salt, iv, ct] = bundle.split(".");
    $("enc-meta").textContent = `${ms.toFixed(0)} ms · salt ${fromBase64Url(salt).length} B · IV ${fromBase64Url(iv).length} B · ciphertext + 16 B tag = ${fromBase64Url(ct).length} B. Encrypt again: the output changes every time.`;
  } catch (err) {
    $("enc-meta").textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

$("dec-btn").addEventListener("click", async () => {
  const out = $("dec-out");
  out.className = "output";
  out.textContent = "Decrypting…";
  try {
    const plain = await decrypt($("dec-in").value, $("dec-pw").value);
    out.className = "output ok";
    out.textContent = `✅ Authentic and decrypted:\n\n${plain}`;
  } catch (err) {
    out.className = "output bad";
    out.textContent = `❌ ${err.message}`;
  }
});

$("tamper-btn").addEventListener("click", () => {
  const parts = $("dec-in").value.trim().split(".");
  if (parts.length !== 4) {
    $("dec-out").textContent = "Encrypt something first, then tamper with it.";
    return;
  }
  const ct = fromBase64Url(parts[3]);
  ct[Math.floor(Math.random() * ct.length)] ^= 1 << Math.floor(Math.random() * 8);
  parts[3] = toBase64Url(ct);
  $("dec-in").value = parts.join(".");
  $("dec-out").className = "output";
  $("dec-out").textContent = "One random bit of the ciphertext was flipped. Now try to decrypt with the correct password…";
});

/* ================= Passwords ================= */
const METER_COLORS = ["#ff5f57", "#e34f26", "#febc2e", "#84cc16", "#22c55e"];

function renderPassword() {
  const pw = $("pw").value;
  if (!pw) {
    $("pw-meter").style.width = "0";
    $("pw-label").textContent = "Start typing…";
    $("pw-stats").replaceChildren();
    $("pw-findings").replaceChildren();
    $("pw-times").replaceChildren();
    $("pw-tips").replaceChildren();
    return;
  }
  const r = analyzePassword(pw);
  $("pw-meter").style.width = `${Math.max(6, (r.score + 1) * 20)}%`;
  $("pw-meter").style.background = METER_COLORS[r.score];
  $("pw-label").textContent = r.label;
  $("pw-label").style.color = METER_COLORS[r.score];
  const stat = (label, value) => el("div", { className: "stat" }, el("span", { className: "stat__label", textContent: label }), el("span", { className: "stat__value", textContent: value }));
  $("pw-stats").replaceChildren(stat("Length", String(r.length)), stat("Character pool", String(r.pool)), stat("Entropy", `${r.bits.toFixed(0)} bits`));
  $("pw-findings").replaceChildren(
    ...(r.patterns.length ? r.patterns.map((p) => el("li", { className: "warn", textContent: `⚠ ${p.text}` })) : [el("li", { className: "ok", textContent: "✓ No common patterns detected" })]),
    ...r.notes.map((n) => el("li", { textContent: `ℹ ${n}` }))
  );
  $("pw-times").replaceChildren(...r.crackTimes.map((t) => el("tr", {}, el("td", { textContent: t.label }), el("td", { textContent: t.display }))));
  $("pw-tips").replaceChildren(...r.suggestions.map((s) => el("li", { textContent: s })));
}

$("pw").addEventListener("input", renderPassword);
$("pw-toggle").addEventListener("click", () => {
  const show = $("pw").type === "password";
  $("pw").type = show ? "text" : "password";
  $("pw-toggle").textContent = show ? "Hide" : "Show";
});
document.querySelectorAll("[data-pw]").forEach((b) =>
  b.addEventListener("click", () => {
    $("pw").value = b.dataset.pw;
    renderPassword();
  })
);

/* ================= Classical ciphers ================= */
function renderCaesar() {
  $("shift-out").textContent = $("shift").value;
  $("caesar-out").value = caesar($("caesar-in").value, +$("shift").value);
  $("caesar-result").hidden = true;
}

function drawFrequencyChart(ciphertext, shift) {
  const canvas = $("freq-chart");
  const ctx = canvas.getContext("2d");
  const { width: W, height: H } = canvas;
  ctx.clearRect(0, 0, W, H);
  const observed = frequencies(ciphertext).relative;
  // English frequencies rotated by the cracked shift should line up with the ciphertext's
  const expected = ENGLISH.map((_, i) => ENGLISH[(i - shift + 26) % 26]);
  const max = Math.max(...observed, ...expected);
  const col = W / 26;
  ctx.font = "10px ui-monospace, Consolas, monospace";
  ctx.textAlign = "center";
  for (let i = 0; i < 26; i++) {
    const x = i * col;
    const h1 = (observed[i] / max) * (H - 22);
    const h2 = (expected[i] / max) * (H - 22);
    ctx.fillStyle = "#e34f26";
    ctx.fillRect(x + col * 0.12, H - 16 - h1, col * 0.36, h1);
    ctx.fillStyle = "#00adff";
    ctx.fillRect(x + col * 0.52, H - 16 - h2, col * 0.36, h2);
    ctx.fillStyle = "#a9b4d0";
    ctx.fillText(String.fromCharCode(65 + i), x + col / 2, H - 4);
  }
}

$("caesar-in").addEventListener("input", renderCaesar);
$("shift").addEventListener("input", renderCaesar);
$("crack-caesar").addEventListener("click", () => {
  const cipher = $("caesar-out").value;
  const result = crackCaesar(cipher);
  $("caesar-result").hidden = false;
  $("caesar-verdict").replaceChildren("Most English-like shift: ", el("b", { textContent: String(result.shift) }), ` → "${result.plaintext.slice(0, 60)}…"`);
  drawFrequencyChart(cipher, result.shift);
});

function renderVigenere() {
  try {
    $("vig-out").value = vigenere($("vig-in").value, $("vig-key").value);
  } catch (err) {
    $("vig-out").value = err.message;
  }
  $("vig-result").hidden = true;
}

$("vig-in").addEventListener("input", renderVigenere);
$("vig-key").addEventListener("input", renderVigenere);
$("crack-vig").addEventListener("click", () => {
  $("vig-result").hidden = false;
  try {
    const r = crackVigenere($("vig-out").value);
    $("vig-verdict").replaceChildren("Key length ", el("b", { textContent: String(r.keyLength) }), " · recovered key ", el("b", { textContent: r.key }), ` → "${r.plaintext.slice(0, 50)}…"`);
    const iocs = r.lengthScores.map((s) => s.ioc);
    const [lo, hi] = [Math.min(...iocs), Math.max(...iocs)];
    $("ioc-bars").replaceChildren(
      ...r.lengthScores.map((s) => {
        const bar = el("div", { className: "ioc__bar" });
        bar.style.height = `${8 + (hi > lo ? (s.ioc - lo) / (hi - lo) : 1) * 72}%`;
        bar.title = s.ioc.toFixed(4);
        return el("div", { className: `ioc__col${s.length === r.keyLength ? " ioc__col--pick" : ""}` }, bar, el("span", { textContent: String(s.length) }));
      })
    );
  } catch (err) {
    $("vig-verdict").textContent = err.message;
    $("ioc-bars").replaceChildren();
  }
});

/* ================= JWT ================= */
function renderJwt() {
  const token = $("jwt-in").value.trim();
  $("jwt-verdict").textContent = "";
  try {
    const decoded = decodeJwt(token);
    const [h, p, s] = decoded.parts;
    $("jwt-colored").replaceChildren(el("span", { className: "jwt-h", textContent: h }), el("span", { className: "jwt-dot", textContent: "." }), el("span", { className: "jwt-p", textContent: p }), el("span", { className: "jwt-dot", textContent: "." }), el("span", { className: "jwt-s", textContent: s }));
    $("jwt-header").textContent = JSON.stringify(decoded.header, null, 2);
    $("jwt-payload").textContent = JSON.stringify(decoded.payload, null, 2);
    const { findings, times } = auditJwt(decoded);
    $("jwt-findings").replaceChildren(
      ...times.map((t) => el("li", { textContent: `${t.label} (${t.claim}): ${t.iso}` })),
      ...findings.map((f) => el("li", { className: f.level === "danger" ? "danger" : f.level === "warn" ? "warn" : "", textContent: f.text }))
    );
  } catch (err) {
    $("jwt-colored").textContent = "";
    $("jwt-header").textContent = "";
    $("jwt-payload").textContent = "";
    $("jwt-findings").replaceChildren(el("li", { className: "danger", textContent: err.message }));
  }
}

async function newSampleToken() {
  const now = Math.floor(Date.now() / 1000);
  $("jwt-in").value = await signHS256({ sub: "1024", name: "Recruiter", role: "user", iat: now, exp: now + 3600 }, $("jwt-secret").value || "portfolio-demo-secret");
  renderJwt();
}

$("jwt-in").addEventListener("input", renderJwt);
$("jwt-sample").addEventListener("click", newSampleToken);
$("jwt-verify").addEventListener("click", async () => {
  try {
    const ok = await verifyHS256($("jwt-in").value, $("jwt-secret").value);
    $("jwt-verdict").textContent = ok ? "✅ Signature valid — token was issued by someone holding this secret." : "❌ Invalid signature — wrong secret, or the token was modified.";
    $("jwt-verdict").style.color = ok ? "#4ade80" : "#ff8a65";
  } catch (err) {
    $("jwt-verdict").textContent = err.message;
    $("jwt-verdict").style.color = "#febc2e";
  }
});
$("jwt-forge").addEventListener("click", () => {
  try {
    const { parts, payload } = decodeJwt($("jwt-in").value);
    const forged = toBase64Url(new TextEncoder().encode(JSON.stringify({ ...payload, role: "admin" })));
    $("jwt-in").value = `${parts[0]}.${forged}.${parts[2]}`;
    renderJwt();
    $("jwt-verdict").textContent = "Payload changed to role=admin but the old signature was kept. Now press Verify…";
    $("jwt-verdict").style.color = "#febc2e";
  } catch (err) {
    $("jwt-verdict").textContent = err.message;
  }
});

/* ================= Boot ================= */
initTabs();
renderHashes();
renderAvalanche();
renderCaesar();
renderVigenere();
newSampleToken();
