// treekem-kdf — secp256k1 DHKEM + HKDF-SHA256 key schedule for the Epistery
// frontier's ratchet tree (EpisteryDataFrontier decision #1). Production port of
// the proven P0(b) spike (app/spike/treekem-kdf), which established that this
// schedule computes BIT-IDENTICALLY across the browser (WebCrypto) and the
// server (Node crypto).
//
// The port collapses the spike's two twin stacks into ONE universal WebCrypto
// stack: Node ≥20 exposes the same `globalThis.crypto` (subtle + getRandomValues)
// the browser has, so a single implementation runs both places — parity by
// construction, and no `node:crypto` import to break the browser bundle. ECDH is
// ethers `SigningKey.computeSharedSecret` on both (WebCrypto has no secp256k1).
//
// "Borrow the math, not the wire format": the label encoding is ours, required
// only to be internally consistent (LABEL_PREFIX below).

// ethers is the page global (window.ethers) in the browser — the same convention
// cipher.mjs / witness.js use — and set on globalThis in Node. Never a bare
// `import 'ethers'` (unresolvable in the served browser module).
const eth = () => globalThis.ethers;

// ---- byte helpers (browser-safe: no Buffer) ---------------------------------
const utf8 = (s) => new TextEncoder().encode(s);
const u16 = (n) => Uint8Array.of((n >> 8) & 0xff, n & 0xff);
function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
const vec16 = (a) => concat(u16(a.length), a); // 2-byte length-prefixed vector
export const toHex = (u8) => { let s = ''; for (const b of u8) s += b.toString(16).padStart(2, '0'); return s; };
export const fromHex = (hex) => {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};

// ---- the universal crypto stack (browser + Node 20+) ------------------------
// digest / hmac / aead over raw bytes + CSPRNG. ECDH is ethers (below).
export function cryptoStack() {
  const c = globalThis.crypto;
  const subtle = c.subtle;
  return {
    name: 'webcrypto',
    random(n) { const b = new Uint8Array(n); c.getRandomValues(b); return b; },
    async digest(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); },
    async hmac(key, data) {
      const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return new Uint8Array(await subtle.sign('HMAC', k, data));
    },
    async aeadEncrypt(key, iv, pt) {
      const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
      return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, pt)); // ct‖tag
    },
    async aeadDecrypt(key, iv, ctTag) {
      const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
      return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, ctTag));
    },
  };
}

// ---- HKDF (RFC 5869) built on the stack's HMAC ------------------------------
async function hkdfExtract(stack, salt, ikm) {
  const s = salt && salt.length ? salt : new Uint8Array(32); // empty salt -> HashLen zeros
  return stack.hmac(s, ikm);
}
async function hkdfExpand(stack, prk, info, length) {
  const chunks = [];
  let t = new Uint8Array(0);
  let counter = 1;
  let have = 0;
  while (have < length) {
    t = await stack.hmac(prk, concat(t, info, Uint8Array.of(counter)));
    chunks.push(t); have += t.length; counter++;
  }
  return concat(...chunks).slice(0, length);
}

// MLS-style labeled derivation. KDFLabel = struct{ uint16 length; label<V>; context<V> }.
const LABEL_PREFIX = 'epistery-treekem-v1 ';
function kdfLabel(length, label, context) {
  return concat(u16(length), vec16(utf8(LABEL_PREFIX + label)), vec16(context));
}
async function expandWithLabel(stack, secret, label, context, length) {
  return hkdfExpand(stack, secret, kdfLabel(length, label, context), length);
}
export async function deriveSecret(stack, secret, label) {
  return expandWithLabel(stack, secret, label, new Uint8Array(0), 32);
}

// ---- secp256k1 (ethers, common to every environment) ------------------------
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
// Deterministically turn 32 secret bytes into a valid secp256k1 private key.
export function privFromSecret(secretBytes) {
  let x = BigInt('0x' + toHex(secretBytes)) % SECP256K1_N;
  if (x === 0n) x = 1n;
  return '0x' + x.toString(16).padStart(64, '0');
}
export function pubFromPriv(privHex) {
  return eth().utils.computePublicKey(privHex); // uncompressed 0x04… (65 bytes), matches peer pubkeys
}
export function ecdh(privHex, peerPubHex) {
  const shared = new (eth().utils.SigningKey)(privHex).computeSharedSecret(peerPubHex);
  return eth().utils.arrayify(shared); // 32-byte shared X-coordinate
}

// ---- DHKEM(secp256k1, HKDF-SHA256) — HPKE-flavored --------------------------
// Deterministic variant (caller injects the ephemeral private key) is kept for
// the parity test; production encap generates the ephemeral key from the stack.
export async function dhkemEncapDeterministic(stack, recipientPubHex, ephemeralPrivHex) {
  const enc = pubFromPriv(ephemeralPrivHex);
  const dh = ecdh(ephemeralPrivHex, recipientPubHex);
  const prk = await hkdfExtract(stack, utf8('eae_prk'), dh);
  const shared = await expandWithLabel(stack, prk, 'shared_secret', utf8(enc), 32);
  return { enc, shared };
}
export async function dhkemEncap(stack, recipientPubHex) {
  return dhkemEncapDeterministic(stack, recipientPubHex, privFromSecret(stack.random(32)));
}
export async function dhkemDecap(stack, recipientPrivHex, encHex) {
  return dhkemDecapFromDH(stack, ecdh(recipientPrivHex, encHex), encHex);
}
// Decap from an already-computed ECDH shared secret. This is the seam for a
// NON-EXTRACTABLE leaf key (the browser rivet): the wallet computes the raw
// shared secret (ECDH(rivetPriv, ephemeralEnc)) internally and hands us `dhBytes`
// — we never see the private key. Intermediate nodes (derived, extractable) and
// server participants keep using dhkemDecap with a raw priv.
export async function dhkemDecapFromDH(stack, dhBytes, encHex) {
  const prk = await hkdfExtract(stack, utf8('eae_prk'), dhBytes);
  return expandWithLabel(stack, prk, 'shared_secret', utf8(encHex), 32);
}

// ---- TreeKEM path ratchet + node keypair ------------------------------------
export async function pathNext(stack, pathSecret) { return deriveSecret(stack, pathSecret, 'path'); }
export async function nodeKeyPair(stack, pathSecret) {
  const nodeSecret = await deriveSecret(stack, pathSecret, 'node');
  const priv = privFromSecret(nodeSecret);
  return { priv, pub: pubFromPriv(priv), nodeSecret };
}

// ---- group key schedule -----------------------------------------------------
export async function nextEpoch(stack, initSecret, commitSecret) {
  const epochSecret = await deriveSecret(stack, await hkdfExtract(stack, initSecret, commitSecret), 'epoch');
  const groupKey = await expandWithLabel(stack, epochSecret, 'exporter', new Uint8Array(0), 32);
  const nextInit = await deriveSecret(stack, epochSecret, 'init');
  return { epochSecret, groupKey, nextInit };
}
