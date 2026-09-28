// Password-based authenticated encryption:
//   key = PBKDF2-HMAC-SHA256(password, random 16-byte salt, 600,000 iterations)  (OWASP 2023 guidance)
//   ciphertext = AES-256-GCM(key, random 12-byte IV, plaintext)                  (includes a 128-bit auth tag)
// Output format: "v1.<salt>.<iv>.<ciphertext+tag>" in base64url.
import { fromBase64Url, toBase64Url, utf8, utf8Decode } from "./encoding.js";

export const DEFAULT_ITERATIONS = 600_000;

async function deriveKey(password, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", utf8.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encrypt(plaintext, password, { iterations = DEFAULT_ITERATIONS } = {}) {
  if (!password) throw new Error("A password is required");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // never reuse an IV with the same key
  const key = await deriveKey(password, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, utf8.encode(plaintext));
  const prefix = iterations === DEFAULT_ITERATIONS ? "v1" : `v1i${iterations}`;
  return [prefix, toBase64Url(salt), toBase64Url(iv), toBase64Url(ciphertext)].join(".");
}

export async function decrypt(bundle, password) {
  const parts = bundle.trim().split(".");
  if (parts.length !== 4 || !parts[0].startsWith("v1")) throw new Error("Not a valid encrypted message");
  const iterations = parts[0] === "v1" ? DEFAULT_ITERATIONS : Number(parts[0].slice(3));
  const [salt, iv, ciphertext] = parts.slice(1).map(fromBase64Url);
  const key = await deriveKey(password, salt, iterations);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return utf8Decode.decode(plain);
  } catch {
    // GCM verifies the auth tag before releasing any plaintext
    throw new Error("Decryption failed: wrong password, or the message was tampered with");
  }
}
