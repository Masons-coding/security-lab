import { test } from "node:test";
import assert from "node:assert/strict";

import { caesar, chiSquared, crackCaesar, crackVigenere, indexOfCoincidence, lettersOnly, vigenere } from "../src/ciphers.js";
import { analyzePassword, humanTime, poolSize } from "../src/password.js";

const ENGLISH_TEXT = `Security is not a product but a process. Every system that stores data must assume that someday
someone will try to break in, so good engineers design defences in depth: strong authentication, least privilege,
encryption of data at rest and in transit, careful logging and monitoring, and a plan for responding when something
goes wrong. Classical ciphers like the Caesar and Vigenere ciphers were once considered unbreakable, yet simple
frequency analysis reveals their secrets because the statistics of the language leak straight through the encryption.`;

test("Caesar cipher round-trips and preserves case and punctuation", () => {
  const enc = caesar("Hello, World!", 3);
  assert.equal(enc, "Khoor, Zruog!");
  assert.equal(caesar(enc, -3), "Hello, World!");
  assert.equal(caesar("xyz", 29), "abc");
});

test("frequency analysis cracks a Caesar cipher", () => {
  for (const shift of [1, 7, 13, 25]) {
    const result = crackCaesar(caesar(ENGLISH_TEXT, shift));
    assert.equal(result.shift, shift);
    assert.equal(result.plaintext, ENGLISH_TEXT);
  }
});

test("English text scores far lower chi-squared than gibberish", () => {
  assert.ok(chiSquared(ENGLISH_TEXT) * 5 < chiSquared(caesar(ENGLISH_TEXT, 11)));
});

test("Vigenère round-trips", () => {
  const enc = vigenere("Attack at dawn!", "LEMON");
  assert.equal(enc, "Lxfopv ef rnhr!");
  assert.equal(vigenere(enc, "LEMON", true), "Attack at dawn!");
  assert.throws(() => vigenere("x", "123"));
});

test("index of coincidence separates English from polyalphabetic ciphertext", () => {
  const plain = indexOfCoincidence(lettersOnly(ENGLISH_TEXT));
  const cipher = indexOfCoincidence(lettersOnly(vigenere(ENGLISH_TEXT, "CRYPTOGRAPHY")));
  assert.ok(plain > 0.058, `plain IoC ${plain}`);
  assert.ok(cipher < 0.05, `cipher IoC ${cipher}`);
});

test("Kasiski/IoC + frequency analysis recovers a Vigenère key", () => {
  for (const key of ["KEY", "SECURITY", "MASON"]) {
    const result = crackVigenere(vigenere(ENGLISH_TEXT, key));
    assert.equal(result.key, key);
    assert.equal(result.plaintext, ENGLISH_TEXT);
  }
  assert.throws(() => crackVigenere("too short"));
});

test("password pool size counts character classes", () => {
  assert.equal(poolSize("abc"), 26);
  assert.equal(poolSize("aB3"), 62);
  assert.equal(poolSize("aB3!"), 95);
});

test("common and patterned passwords score as weak", () => {
  for (const pw of ["password", "P@ssw0rd", "qwerty123", "Summer2024!", "aaaaaaaa"]) {
    const r = analyzePassword(pw);
    assert.ok(r.score <= 1, `${pw} scored ${r.score}`);
    assert.ok(r.patterns.length > 0, `${pw} should have patterns`);
  }
});

test("passphrases are scored as words (Diceware), not characters", () => {
  const four = analyzePassword("ribbon-cactus-velvet-harbor");
  const five = analyzePassword("ribbon-cactus-velvet-harbor-lantern");
  assert.equal(five.patterns.length, 0);
  assert.equal(four.notes.length, 1);
  assert.ok(Math.abs(four.bits - 4 * Math.log2(7776)) < 1e-9, `4 words = ${four.bits} bits`);
  assert.ok(four.bits < four.rawBits, "word model must be more conservative than character model");
  assert.equal(four.score, 2);
  assert.ok(five.score >= 3, `5 words scored ${five.score}`);
});

test("long random character passwords score as very strong", () => {
  const r = analyzePassword("xK9#vQ2!mZ7$pL4&");
  assert.equal(r.score, 4);
  assert.equal(r.notes.length, 0);
});

test("the l33t-speak hint only appears when substitutions were needed", () => {
  assert.doesNotMatch(analyzePassword("Summer2024!").patterns.map((p) => p.text).join(), /l33t/);
  assert.match(analyzePassword("dr4g0nfly").patterns.map((p) => p.text).join(), /l33t/);
});

test("crack times are ordered by attacker speed and human-readable", () => {
  const r = analyzePassword("Tr0ub4dor&3xyz");
  const secs = r.crackTimes.map((t) => t.seconds);
  assert.ok(secs.every((s, i) => i === 0 || s < secs[i - 1]));
  assert.equal(humanTime(0.5), "instantly");
  assert.equal(humanTime(90), "2 minutes");
  assert.equal(humanTime(86400 * 3), "3 days");
});
