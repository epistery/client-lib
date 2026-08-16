// Per-session content encryption (browser-side).
//
// The browser twin of @epistery/sessions `bot-identity` (the server side):
// both mirror the epistery RivetWallet peer-encryption primitive (ECDH
// secp256k1 → SHA-256 → AES-256-GCM) for wraps, and AES-256-GCM with the
// ciphertext‖tag concatenated into one `ciphertext` field for content. Keep the
// two in lockstep — a wrap or a post written by a browser must unwrap/decrypt on
// the server (MCP boundary, steward handout) and vice versa.
//
// Shape:
//   - One symmetric 32-byte session key K per session.
//   - K is wrapped per member via wallet.encryptForPeer(memberPub, K_bytes).
//   - Wraps live in _keys.json under the session folder.
//   - Each post body is AES-256-GCM encrypted with K (Web Crypto), fresh IV.
//   - Server (and relay) only ever see ciphertext.

const E = () => window.ethers;

// Random 32-byte key as 0x-hex.
export function randomSessionKey() {
  return E().utils.hexlify(crypto.getRandomValues(new Uint8Array(32)));
}

// Wrap K to peer's chat.publicKey. Returns { ciphertext, iv, tag } as 0x-hex.
export async function wrapSessionKey(K, peerPubKey, wallet) {
  const ethers = E();
  const keyBytes = ethers.utils.arrayify(K);
  const { ciphertext, iv, tag } = await wallet.encryptForPeer(peerPubKey, keyBytes, ethers);
  return {
    ciphertext: ethers.utils.hexlify(ciphertext),
    iv: ethers.utils.hexlify(iv),
    tag: ethers.utils.hexlify(tag),
  };
}

// Unwrap K. wrapperPubKey is the public key of the address that produced the
// wrap — for the owner-creates-session flow, that's the owner's pubkey,
// surfaced in _keys.json's `wrapperPubKey` field.
export async function unwrapSessionKey(wrap, wrapperPubKey, wallet) {
  const ethers = E();
  const ct = ethers.utils.arrayify(wrap.ciphertext);
  const iv = ethers.utils.arrayify(wrap.iv);
  const tag = ethers.utils.arrayify(wrap.tag);
  const bytes = await wallet.decryptFromPeer(wrapperPubKey, ct, iv, tag, ethers);
  return ethers.utils.hexlify(new Uint8Array(bytes));
}

async function importAesKey(K) {
  const keyBytes = E().utils.arrayify(K);
  return crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

// Encrypt UTF-8 text with K. Returns { iv, ciphertext } as 0x-hex. Web
// Crypto's AES-GCM emits ciphertext+auth-tag concatenated — we keep them
// together in the `ciphertext` field rather than splitting.
export async function encryptText(K, text) {
  const ethers = E();
  const aesKey = await importAesKey(K);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(text)
  );
  return {
    iv: ethers.utils.hexlify(iv),
    ciphertext: ethers.utils.hexlify(new Uint8Array(ctBuf)),
  };
}

export async function decryptText(K, blob) {
  const ethers = E();
  const aesKey = await importAesKey(K);
  const iv = ethers.utils.arrayify(blob.iv);
  const ct = ethers.utils.arrayify(blob.ciphertext);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return new TextDecoder().decode(new Uint8Array(ptBuf));
}

// Binary-payload helpers — for the files plugin where hex-encoding the
// ciphertext would double an arbitrarily large upload. The encrypted Blob
// is always typed 'application/octet-stream' so the relay's /upload (which
// accepts that mime as opaque .bin) takes it without inspection.
export async function encryptBlob(K, source) {
  const aesKey = await importAesKey(K);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const inputBuf = source instanceof ArrayBuffer
    ? source
    : await source.arrayBuffer();
  const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, inputBuf);
  return {
    blob: new Blob([ctBuf], { type: 'application/octet-stream' }),
    iv: E().utils.hexlify(iv),
  };
}

export async function decryptBlob(K, iv, source, mime = 'application/octet-stream') {
  const aesKey = await importAesKey(K);
  const inputBuf = source instanceof ArrayBuffer
    ? source
    : await source.arrayBuffer();
  const ivBytes = E().utils.arrayify(iv);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, aesKey, inputBuf);
  return new Blob([ptBuf], { type: mime });
}
