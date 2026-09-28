// Classical ciphers and the statistics that break them.

// Relative letter frequencies of English text (A–Z)
export const ENGLISH = [
  0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406,
  0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.0236, 0.0015, 0.01974, 0.00074,
];

const A = 65;
const isLetter = (c) => /[a-z]/i.test(c);

function shiftChar(ch, k) {
  const base = ch >= "a" && ch <= "z" ? 97 : A;
  return String.fromCharCode(((((ch.charCodeAt(0) - base + k) % 26) + 26) % 26) + base);
}

export function caesar(text, shift) {
  return [...text].map((c) => (isLetter(c) ? shiftChar(c, shift) : c)).join("");
}

export function vigenere(text, key, decrypt = false) {
  const shifts = [...key.toUpperCase()].filter((c) => c >= "A" && c <= "Z").map((c) => c.charCodeAt(0) - A);
  if (!shifts.length) throw new Error("Key must contain at least one letter");
  let i = 0;
  return [...text]
    .map((c) => {
      if (!isLetter(c)) return c;
      const k = shifts[i++ % shifts.length];
      return shiftChar(c, decrypt ? -k : k);
    })
    .join("");
}

export const lettersOnly = (text) => text.toUpperCase().replace(/[^A-Z]/g, "");

export function frequencies(text) {
  const letters = lettersOnly(text);
  const counts = new Array(26).fill(0);
  for (const c of letters) counts[c.charCodeAt(0) - A]++;
  return { counts, total: letters.length, relative: counts.map((n) => (letters.length ? n / letters.length : 0)) };
}

// Chi-squared distance between observed letter counts and English expectations (lower = more English-like)
export function chiSquared(text) {
  const { counts, total } = frequencies(text);
  if (!total) return Infinity;
  return counts.reduce((sum, observed, i) => {
    const expected = ENGLISH[i] * total;
    return sum + (observed - expected) ** 2 / expected;
  }, 0);
}

// Try all 26 shifts and keep the one whose output looks most like English
export function crackCaesar(ciphertext) {
  const scores = Array.from({ length: 26 }, (_, shift) => ({ shift, score: chiSquared(caesar(ciphertext, -shift)) }));
  const best = scores.reduce((a, b) => (b.score < a.score ? b : a));
  return { shift: best.shift, plaintext: caesar(ciphertext, -best.shift), scores };
}

// Index of coincidence: probability two random letters match. English ≈ 0.066, random ≈ 0.038.
export function indexOfCoincidence(letters) {
  const n = letters.length;
  if (n < 2) return 0;
  const { counts } = frequencies(letters);
  return counts.reduce((s, c) => s + c * (c - 1), 0) / (n * (n - 1));
}

// Break Vigenère: guess the key length from the IoC of every k-th letter, then solve each
// column as an independent Caesar cipher.
export function crackVigenere(ciphertext, maxKeyLength = 12) {
  const letters = lettersOnly(ciphertext);
  if (letters.length < 40) throw new Error("Need at least 40 letters of ciphertext to crack");

  const lengthScores = [];
  for (let k = 1; k <= Math.min(maxKeyLength, Math.floor(letters.length / 4)); k++) {
    let total = 0;
    for (let c = 0; c < k; c++) {
      let column = "";
      for (let i = c; i < letters.length; i += k) column += letters[i];
      total += indexOfCoincidence(column);
    }
    lengthScores.push({ length: k, ioc: total / k });
  }
  // Multiples of the true length score just as well, so prefer the shortest length that is
  // close to the best score.
  const bestIoc = Math.max(...lengthScores.map((s) => s.ioc));
  const keyLength = lengthScores.find((s) => s.ioc >= bestIoc * 0.9).length;

  let key = "";
  for (let c = 0; c < keyLength; c++) {
    let column = "";
    for (let i = c; i < letters.length; i += keyLength) column += letters[i];
    key += String.fromCharCode(A + crackCaesar(column).shift);
  }
  return { key, keyLength, lengthScores, plaintext: vigenere(ciphertext, key, true) };
}
