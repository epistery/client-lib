// Sealed session content — THE one mechanism for writing and reading content
// under a session's group key. Every plugin gets it as `ctx.keys` (browser) or
// from its key provider (server); no plugin handles K or an epoch itself.
//
// Why one mechanism: each plugin used to hand-roll "seal with K, stamp the
// epoch" and "pick the key by the record's epoch". They drifted — a writer that
// forgot the tag, a writer that read K and the epoch on either side of an await,
// readers that fell back to the current key. An untagged record reads with the
// CURRENT key, so it stops opening at the session's first key rotation: mjs
// recipes and SunriseWalks went dark that way (2026-09-22/23). Here the tag
// cannot be forgotten and a record is never opened with a guessed key.
//
// The cipher is injected, so the browser and the server run this same code:
//   browser: sealedKeys(group, cipher)        — /lib/cipher.mjs (Web Crypto)
//   server:  sealedKeys(group, botIdentity)   — @epistery/sessions/bot-identity
// Both expose encryptText/decryptText; the browser cipher also blobs.
//
// `group` is a DsGroup (groupKey(), epoch(), keyForEpoch(e)), or null for a
// device that holds no key yet — then seal throws and open reports 'no-key'.
//
// The record contract: a sealed value is { epoch, iv, ciphertext }, the epoch
// being the group epoch whose key sealed it. A sealed value nested inside a
// record may leave its epoch to the enclosing object (a chatbot `{ epoch, enc }`,
// a board attachment `{ epoch, url, iv, name: {iv, ciphertext} }`); readers pass
// that enclosing epoch as `parentEpoch`. A blob reference is { epoch, url, iv }.
// The relay refuses a session-content write in which any seal or blob reference
// has no epoch at any level.

export const isEpoch = (e) => Number.isInteger(e) && e >= 1;
export const isSealed = (v) => !!v && typeof v === 'object' && typeof v.iv === 'string' && typeof v.ciphertext === 'string';

// What went wrong, as a sentence a person can act on. `cause` is the stable code.
const MESSAGES = {
  'no-key': 'this device does not hold the key to this session yet',
  'untagged': 'this record was sealed without its key epoch — the owner must re-tag it',
  'no-key-for-epoch': 'this device holds no key for the epoch this record was sealed under',
  'not-opened': 'this record did not open under the key for its epoch (a divergent key, or damaged data)',
  'not-sealed': 'this record is not sealed content',
};
const failure = (cause, detail) => ({ ok: false, cause, message: MESSAGES[cause] + (detail ? ` (${detail})` : '') });

export function sealedKeys(group, crypto) {
  if (!crypto?.encryptText || !crypto?.decryptText) throw new Error('sealedKeys: a cipher with encryptText/decryptText is required');
  const currentKey = () => (group ? group.groupKey() || null : null);
  const currentEpoch = () => (group ? group.epoch() : null);
  const keyAt = (epoch) => (group && isEpoch(epoch) ? group.keyForEpoch(epoch) || null : null);

  // A group that cannot follow its own log (a commit it cannot apply) still reads
  // up to the epoch before it, but seals nothing: its "current" key is no longer
  // the group's, and anything sealed under it would be unreadable to the rest.
  const stuck = () => group?.stuck || null;

  // The key and its epoch, read TOGETHER — never on either side of an await.
  function writeKey() {
    if (stuck()) throw new Error(`this session cannot be written: its key history stops at epoch ${stuck().epoch} (${stuck().reason}); it reads up to there until an owner restores it`);
    const K = currentKey();
    const epoch = currentEpoch();
    if (!K) throw new Error(MESSAGES['no-key']);
    if (!isEpoch(epoch)) throw new Error(`no key epoch for this session (got ${epoch}) — refusing to seal untagged content`);
    return { K, epoch };
  }

  // The key a sealed value opens under, or a failure. The value's own epoch wins;
  // an enclosing record's epoch applies to a nested value that carries none.
  function readKey(value, parentEpoch) {
    if (!group || !currentKey()) return { fail: failure('no-key') };
    const epoch = value?.epoch ?? parentEpoch;
    // A tag that is not a key epoch (absent, 0, a string) is no tag — the same rule
    // the relay applies on write.
    if (!isEpoch(epoch)) return { fail: failure('untagged', epoch == null ? '' : `tag ${JSON.stringify(epoch)}`) };
    const K = keyAt(epoch);
    if (!K) return { fail: failure('no-key-for-epoch', `epoch ${epoch}`) };
    return { K, epoch };
  }

  return {
    // True when this device can seal (holds the current key).
    get ready() { return !!currentKey() && isEpoch(currentEpoch()) && !stuck(); },
    // Why this device can read but not write, or null: { epoch, code, reason, signer }.
    get stuck() { return stuck(); },
    // The current epoch — for display and diagnostics only; seal() stamps it.
    get epoch() { return currentEpoch(); },

    // Seal text → { epoch, iv, ciphertext }.
    async seal(text) {
      const { K, epoch } = writeKey();
      return { epoch, ...(await crypto.encryptText(K, String(text))) };
    },

    // Seal bytes (Blob/ArrayBuffer) → { epoch, iv, blob }. Browser cipher only.
    async sealBlob(source) {
      if (!crypto.encryptBlob) throw new Error('sealBlob: this cipher does not seal bytes');
      const { K, epoch } = writeKey();
      const { blob, iv } = await crypto.encryptBlob(K, source);
      return { epoch, iv, blob };
    },

    // Open a sealed value → { ok:true, text, epoch } | { ok:false, cause, message }.
    // Never throws: a reader decides what to show, and must treat !ok as
    // READ-ONLY — the failure text is a message, never the content.
    async open(value, { parentEpoch } = {}) {
      if (!isSealed(value)) return failure('not-sealed');
      const r = readKey(value, parentEpoch);
      if (r.fail) return r.fail;
      try { return { ok: true, text: await crypto.decryptText(r.K, value), epoch: r.epoch }; }
      catch { return failure('not-opened', `epoch ${r.epoch}`); }
    },

    // Open sealed bytes for a blob reference { epoch, iv } → { ok:true, blob } |
    // failure. `bytes` is the fetched ciphertext (Blob/ArrayBuffer). Browser only.
    async openBlob(ref, bytes, { parentEpoch, mime } = {}) {
      if (!crypto.decryptBlob) throw new Error('openBlob: this cipher does not open bytes');
      if (!ref || typeof ref.iv !== 'string') return failure('not-sealed');
      const r = readKey(ref, parentEpoch);
      if (r.fail) return r.fail;
      try { return { ok: true, blob: await crypto.decryptBlob(r.K, ref.iv, bytes, mime || ref.mime), epoch: r.epoch }; }
      catch { return failure('not-opened', `epoch ${r.epoch}`); }
    },
  };
}
