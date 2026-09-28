// JSON Web Token inspection: decode, audit claims, and sign/verify HS256 with Web Crypto.
import { b64urlDecodeText, b64urlEncodeText, fromBase64Url, toBase64Url, utf8 } from "./encoding.js";

export function decodeJwt(token) {
  const parts = token.trim().split(".");
  if (parts.length !== 3) throw new Error("A JWT has three dot-separated parts: header.payload.signature");
  let header;
  let payload;
  try {
    header = JSON.parse(b64urlDecodeText(parts[0]));
    payload = JSON.parse(b64urlDecodeText(parts[1]));
  } catch {
    throw new Error("Header or payload is not valid base64url-encoded JSON");
  }
  return { header, payload, signature: parts[2], parts };
}

const TIME_CLAIMS = { exp: "Expires", iat: "Issued at", nbf: "Not before" };

// Security review of a decoded token. `now` is seconds since the epoch.
export function auditJwt({ header, payload, signature }, now = Math.floor(Date.now() / 1000)) {
  const findings = [];
  const alg = String(header.alg ?? "");
  if (alg.toLowerCase() === "none" || !signature) findings.push({ level: "danger", text: 'alg "none" / unsigned token — anyone can forge it. Servers must reject these.' });
  if (!("exp" in payload)) findings.push({ level: "warn", text: "No exp claim — this token never expires." });
  if (typeof payload.exp === "number" && payload.exp < now) findings.push({ level: "warn", text: "Token is expired." });
  if (typeof payload.nbf === "number" && payload.nbf > now) findings.push({ level: "warn", text: "Token is not valid yet (nbf is in the future)." });
  if (typeof payload.exp === "number" && typeof payload.iat === "number" && payload.exp - payload.iat > 60 * 60 * 24 * 30) {
    findings.push({ level: "warn", text: "Lifetime is over 30 days — long-lived tokens are risky if leaked." });
  }
  const sensitive = Object.keys(payload).filter((k) => /pass|secret|ssn|card|token/i.test(k));
  if (sensitive.length) findings.push({ level: "danger", text: `Payload contains sensitive-looking fields (${sensitive.join(", ")}). JWT payloads are only encoded, not encrypted.` });
  if (/^HS/.test(alg)) findings.push({ level: "info", text: `${alg} uses a shared secret — anyone who can verify can also mint tokens.` });
  if (/^(RS|ES|PS)/.test(alg)) findings.push({ level: "info", text: `${alg} is asymmetric — verifiers only need the public key.` });

  const times = Object.entries(TIME_CLAIMS)
    .filter(([k]) => typeof payload[k] === "number")
    .map(([k, label]) => ({ claim: k, label, iso: new Date(payload[k] * 1000).toISOString() }));
  return { findings, times };
}

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", utf8.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signHS256(payload, secret) {
  const header = b64urlEncodeText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64urlEncodeText(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), utf8.encode(`${header}.${body}`));
  return `${header}.${body}.${toBase64Url(sig)}`;
}

// Constant-time verification is handled by crypto.subtle.verify
export async function verifyHS256(token, secret) {
  const { header, parts } = decodeJwt(token);
  if (header.alg !== "HS256") throw new Error(`This demo verifies HS256 only (token uses ${header.alg})`);
  return crypto.subtle.verify("HMAC", await hmacKey(secret), fromBase64Url(parts[2]), utf8.encode(`${parts[0]}.${parts[1]}`));
}
