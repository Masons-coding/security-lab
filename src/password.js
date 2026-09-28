// Password strength estimation: character-pool entropy, penalised for the patterns that
// real cracking tools try first (common passwords, dictionary words, keyboard walks,
// repeats, sequences and dates).

const COMMON = new Set(
  `password 123456 123456789 12345678 12345 qwerty abc123 password1 111111 123123 1234567 iloveyou admin welcome
  monkey dragon letmein football baseball sunshine princess master shadow superman trustno1 hello freedom whatever
  qazwsx michael charlie donald password123 starwars login batman access mustang 654321 666666 121212 696969 000000
  passw0rd p@ssword p@ssw0rd qwerty123 1q2w3e4r zaq12wsx summer winter hockey canada toronto ottawa maple`
    .split(/\s+/)
    .filter(Boolean)
);

const WORDS = ["password", "admin", "welcome", "love", "hello", "dragon", "monkey", "secret", "summer", "winter", "spring", "hockey", "soccer", "canada", "master", "login", "letmein", "sunshine", "qwerty", "shadow", "football", "flower", "computer", "mason", "clarke"];

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
const LEET = { 0: "o", 1: "i", 3: "e", 4: "a", 5: "s", 7: "t", "@": "a", $: "s", "!": "i" };

export function poolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return pool;
}

function findPatterns(pw) {
  const lower = pw.toLowerCase();
  const unleet = [...lower].map((c) => LEET[c] ?? c).join("");
  const found = [];

  if (COMMON.has(lower) || COMMON.has(unleet)) found.push({ type: "common", text: "Appears on lists of the most common passwords", penalty: 1 });

  const word = WORDS.find((w) => unleet.includes(w));
  if (word && !found.length) {
    const viaLeet = !lower.includes(word);
    found.push({ type: "dictionary", text: `Contains the dictionary word "${word}"${viaLeet ? " (l33t-speak doesn't fool crackers)" : ""}`, penalty: 0.45 });
  }

  for (const row of KEYBOARD_ROWS) {
    for (let len = Math.min(row.length, lower.length); len >= 4; len--) {
      const hit = [...Array(row.length - len + 1).keys()].map((i) => row.slice(i, i + len)).find((s) => lower.includes(s) || lower.includes([...s].reverse().join("")));
      if (hit) {
        found.push({ type: "keyboard", text: `Keyboard pattern "${hit}"`, penalty: 0.35 });
        break;
      }
    }
    if (found.some((f) => f.type === "keyboard")) break;
  }

  if (/(.)\1{2,}/.test(pw)) found.push({ type: "repeat", text: "Repeated characters (e.g. \"aaa\")", penalty: 0.25 });

  // Ascending/descending runs like "abcd" or "6543"
  for (let i = 0; i + 3 < lower.length; i++) {
    const d = [1, 2, 3].map((k) => lower.charCodeAt(i + k) - lower.charCodeAt(i + k - 1));
    if (d.every((x) => x === 1) || d.every((x) => x === -1)) {
      found.push({ type: "sequence", text: `Sequential characters "${pw.slice(i, i + 4)}"`, penalty: 0.3 });
      break;
    }
  }

  if (/(19[5-9]\d|20[0-3]\d)/.test(pw)) found.push({ type: "date", text: "Contains a year — birthdays and anniversaries are guessed early", penalty: 0.2 });
  if (/^[A-Z][a-z]+\d{1,4}[!.?]?$/.test(pw)) found.push({ type: "shape", text: "Predictable shape: Capitalised word + digits (+ symbol)", penalty: 0.3 });

  return found;
}

// Seconds → human readable
export function humanTime(seconds) {
  if (seconds < 1) return "instantly";
  const units = [
    ["year", 31557600],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1],
  ];
  if (seconds > 31557600 * 1e9) return "billions of years";
  for (const [name, size] of units) {
    if (seconds >= size) {
      const n = seconds / size;
      const rounded = n >= 1e6 ? n.toExponential(1) : Math.round(n).toLocaleString("en-US");
      return `${rounded} ${name}${Math.round(n) === 1 ? "" : "s"}`;
    }
  }
  return "instantly";
}

// Guesses per second for common attack scenarios
export const ATTACKS = [
  { id: "online-throttled", label: "Online, rate-limited (100/hour)", rate: 100 / 3600 },
  { id: "online", label: "Online, no rate limit (10/second)", rate: 10 },
  { id: "offline-slow", label: "Offline vs bcrypt/PBKDF2 hash (10k/second)", rate: 1e4 },
  { id: "offline-fast", label: "Offline vs fast unsalted hash (10B/second)", rate: 1e10 },
];

export function analyzePassword(pw) {
  const pool = poolSize(pw);
  const rawBits = pw.length ? pw.length * Math.log2(pool || 1) : 0;
  const patterns = findPatterns(pw);
  let bits = rawBits;
  for (const p of patterns) bits *= 1 - p.penalty;
  if (patterns.some((p) => p.type === "common")) bits = Math.min(bits, 10);

  // Passphrases: attackers guess whole words, not characters. Model each word as a pick
  // from a 7,776-word Diceware list (≈12.9 bits) instead of per-character entropy.
  const notes = [];
  const chunks = pw.split(/[\s\-_.,+]+/).filter(Boolean);
  if (chunks.length >= 3 && chunks.every((c) => /^[a-z]+$/i.test(c) || /^\d{1,4}$/.test(c))) {
    const words = chunks.filter((c) => /^[a-z]+$/i.test(c)).length;
    const digitBits = chunks.filter((c) => /^\d+$/.test(c)).reduce((s, c) => s + c.length * Math.log2(10), 0);
    const passphraseBits = words * Math.log2(7776) + digitBits + (/[A-Z]/.test(pw) ? words : 0);
    if (words >= 3 && passphraseBits < bits) {
      bits = passphraseBits;
      notes.push(`Looks like a ${words}-word passphrase, so it's estimated the way attackers guess it: as words from a 7,776-word list (Diceware), not individual characters.`);
    }
  }
  bits = Math.max(0, bits);

  const score = bits < 28 ? 0 : bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  const guesses = 2 ** bits / 2; // on average an attacker searches half the space
  const suggestions = [];
  if (pw.length < 12) suggestions.push("Use at least 12 characters — length beats complexity.");
  if (pool < 60) suggestions.push("Mix in upper-case letters, digits and symbols.");
  if (patterns.length) suggestions.push("Avoid words, names, dates and keyboard patterns.");
  if (score >= 3) suggestions.push("Great — store it in a password manager and don't reuse it.");
  else suggestions.push("Try a passphrase of 5+ random words, e.g. \"ribbon-cactus-velvet-harbor-lantern\".");

  return {
    length: pw.length,
    pool,
    rawBits,
    bits,
    score,
    label: ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score],
    patterns,
    notes,
    crackTimes: ATTACKS.map((a) => ({ ...a, seconds: guesses / a.rate, display: humanTime(guesses / a.rate) })),
    suggestions,
  };
}
