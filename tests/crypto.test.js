import { test } from "node:test";
import assert from "node:assert/strict";

import { bitDiff, digest } from "../src/hashing.js";
import { decrypt, encrypt } from "../src/aes.js";
import { fromBase64Url, fromHex, toBase64Url, toHex } from "../src/encoding.js";
import { auditJwt, decodeJwt, signHS256, verifyHS256 } from "../src/jwt.js";

test("SHA hashes match the official FIPS 180 test vectors", async () => {
  assert.equal(await digest("SHA-1", "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
  assert.equal(await digest("SHA-256", "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(await digest("SHA-256", ""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("avalanche effect: one changed character flips roughly half the bits", async () => {
  const { count, total, ratio } = bitDiff(await digest("SHA-256", "Mason"), await digest("SHA-256", "mason"));
  assert.equal(total, 256);
  assert.ok(ratio > 0.35 && ratio < 0.65, `ratio ${ratio}`);
  assert.equal(bitDiff("ff", "00").count, 8);
  assert.equal(bitDiff("a5", "a5").count, 0);
  assert.ok(count > 0);
});

test("hex and base64url helpers round-trip", () => {
  const bytes = Uint8Array.from([0, 1, 250, 255, 62, 63]);
  assert.deepEqual(fromHex(toHex(bytes)), bytes);
  assert.deepEqual(fromBase64Url(toBase64Url(bytes)), bytes);
  assert.ok(!/[+/=]/.test(toBase64Url(bytes)), "base64url must be URL-safe");
});

test("AES-GCM encrypts and decrypts with the right password", async () => {
  const secret = "Meet at the café at 5 ☕";
  const bundle = await encrypt(secret, "correct horse", { iterations: 1000 });
  assert.equal(await decrypt(bundle, "correct horse"), secret);
});

test("AES-GCM rejects the wrong password and tampered ciphertext", async () => {
  const bundle = await encrypt("top secret", "pw1", { iterations: 1000 });
  await assert.rejects(decrypt(bundle, "pw2"), /wrong password|tampered/);
  const parts = bundle.split(".");
  const ct = fromBase64Url(parts[3]);
  ct[0] ^= 1; // flip a single bit
  parts[3] = toBase64Url(ct);
  await assert.rejects(decrypt(parts.join("."), "pw1"), /tampered/);
});

test("the same message encrypts differently every time (random salt + IV)", async () => {
  const a = await encrypt("same", "pw", { iterations: 1000 });
  const b = await encrypt("same", "pw", { iterations: 1000 });
  assert.notEqual(a, b);
});

test("default key derivation uses 600k PBKDF2 iterations", async () => {
  const bundle = await encrypt("x", "pw");
  assert.ok(bundle.startsWith("v1."));
  assert.equal(await decrypt(bundle, "pw"), "x");
});

test("JWT: sign, decode and verify HS256", async () => {
  const token = await signHS256({ sub: "42", name: "Mason", iat: 1700000000, exp: 1700003600 }, "s3cret");
  const { header, payload } = decodeJwt(token);
  assert.deepEqual(header, { alg: "HS256", typ: "JWT" });
  assert.equal(payload.name, "Mason");
  assert.equal(await verifyHS256(token, "s3cret"), true);
  assert.equal(await verifyHS256(token, "wrong"), false);
});

test("JWT: a tampered payload fails verification", async () => {
  const token = await signHS256({ role: "user" }, "k");
  const [h, , s] = token.split(".");
  const forged = `${h}.${toBase64Url(new TextEncoder().encode(JSON.stringify({ role: "admin" })))}.${s}`;
  assert.equal(await verifyHS256(forged, "k"), false);
});

test("JWT audit flags alg none, expiry, missing exp and secrets in the payload", () => {
  const none = auditJwt({ header: { alg: "none" }, payload: { password: "x" }, signature: "" }, 100);
  const texts = none.findings.map((f) => f.text).join(" ");
  assert.match(texts, /alg "none"/);
  assert.match(texts, /never expires/);
  assert.match(texts, /sensitive/);

  const expired = auditJwt({ header: { alg: "HS256" }, payload: { exp: 50, iat: 10 }, signature: "x" }, 100);
  assert.ok(expired.findings.some((f) => /expired/.test(f.text)));
  assert.equal(expired.times.length, 2);
});

test("decodeJwt rejects malformed tokens", () => {
  assert.throws(() => decodeJwt("abc"), /three/);
  assert.throws(() => decodeJwt("a.b.c"), /base64url/);
});
