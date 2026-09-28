// Byte/string encoding helpers shared by the crypto modules.

export const utf8 = new TextEncoder();
export const utf8Decode = new TextDecoder();

export const toHex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

export function fromHex(hex) {
  if (hex.length % 2) throw new Error("Hex string must have an even length");
  return Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
}

export function toBase64Url(bytes) {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const b64urlEncodeText = (text) => toBase64Url(utf8.encode(text));
export const b64urlDecodeText = (text) => utf8Decode.decode(fromBase64Url(text));
