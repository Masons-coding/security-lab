// Cryptographic hashing with the Web Crypto API, plus an avalanche-effect analyser.
import { toHex, utf8 } from "./encoding.js";

export const HASHES = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

export async function digest(algorithm, text) {
  return toHex(await crypto.subtle.digest(algorithm, utf8.encode(text)));
}

const bitsOf = (hex) =>
  [...hex].flatMap((h) => {
    const n = parseInt(h, 16);
    return [8, 4, 2, 1].map((m) => (n & m ? 1 : 0));
  });

// Compare two equal-length hex digests bit by bit.
// A good hash flips ~50% of output bits when a single input bit changes (the avalanche effect).
export function bitDiff(hexA, hexB) {
  if (hexA.length !== hexB.length) throw new Error("Digests must be the same length");
  const a = bitsOf(hexA);
  const b = bitsOf(hexB);
  const flipped = a.map((bit, i) => bit !== b[i]);
  const count = flipped.filter(Boolean).length;
  return { flipped, count, total: a.length, ratio: count / a.length };
}
