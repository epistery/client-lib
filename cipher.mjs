// Per-session content and key wraps — the client-lib entry over epistery core's
// one construction (epistery/client/peer-cipher.mjs). Nothing is implemented
// here: a wrap is ECDH → SHA-256 → AES-256-GCM and sealed content is AES-256-GCM
// under K, defined once in core, and this module names them for the session
// layer in both environments (the browser page and a Node participant).
//
// Shape:
//   - One symmetric 32-byte session key K per session (the TreeKEM group key).
//   - K, or a per-message / per-document key, is wrapped to a peer's published
//     public key: { ciphertext, iv, tag } as 0x-hex, unwrapped with the
//     WRAPPER's public key by whoever holds the peer key (a rivet through its
//     own capability, a derived server wallet through its key).
//   - Content is { iv, ciphertext } as 0x-hex; bytes as an opaque Blob + iv.
//   - Server and relay only ever see ciphertext.
//
// Resolved as `epistery/client/peer-cipher.mjs` in Node and, on the console's
// pages, through the import map that points `epistery/client/` at `/lib/`.

import {
  randomKey, wrapKey, unwrapKey, encryptText as encryptTextK, decryptText as decryptTextK,
  encryptBytes, decryptBytes, fromHex,
} from 'epistery/client/peer-cipher.mjs';

// Random 32-byte key as 0x-hex.
export function randomSessionKey() { return randomKey(); }

// Wrap K to a peer's published public key. Returns { ciphertext, iv, tag } as 0x-hex.
export function wrapSessionKey(K, peerPubKey, wallet) { return wrapKey(K, peerPubKey, wallet); }

// Unwrap K. wrapperPubKey is the public key of the device that produced the wrap.
export function unwrapSessionKey(wrap, wrapperPubKey, wallet) { return unwrapKey(wrap, wrapperPubKey, wallet); }

// Encrypt UTF-8 text with K → { iv, ciphertext } as 0x-hex (ct‖tag).
export function encryptText(K, text) { return encryptTextK(K, text); }
export function decryptText(K, blob) { return decryptTextK(K, blob); }

// Binary-payload helpers — for the files plugin where hex-encoding the
// ciphertext would double an arbitrarily large upload. The encrypted Blob
// is always typed 'application/octet-stream' so the relay's /upload (which
// accepts that mime as opaque .bin) takes it without inspection.
export async function encryptBlob(K, source) {
  const inputBuf = source instanceof ArrayBuffer ? source : await source.arrayBuffer();
  const { iv, ciphertext } = await encryptBytes(K, new Uint8Array(inputBuf));
  return { blob: new Blob([ciphertext], { type: 'application/octet-stream' }), iv };
}

export async function decryptBlob(K, iv, source, mime = 'application/octet-stream') {
  const inputBuf = source instanceof ArrayBuffer ? source : await source.arrayBuffer();
  const pt = await decryptBytes(K, fromHex(iv), new Uint8Array(inputBuf));
  return new Blob([pt], { type: mime });
}
