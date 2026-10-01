// The relay client — one module for the browser and for Node, beside ds-group,
// which already proved the shape: the signer and fetch are injected, the wire
// is core's, and the module itself knows nothing about where it runs.
//
// The relay's substrate has no notion of a domain: storage is addressed by
// contract, the data store and inbox by address, content by hash. This client
// speaks that: /storage, /upload, /inbox, /identity, /ds, /cas, and a bounded
// `json()` for the rest of the relay's read surface.
//
// WRITES ARE SIGNED BY A MEMBER. The signer IS the authority — a browser rivet,
// a session member whose derived key the server holds (a bot, an MCP agent).
// The message and the `Bot` envelope are core's (signStorageWrite): the same
// bytes every signer signs and the relay verifies, with signature recovery plus
// the signer's on-chain folder/section authorization. There is no host-operator
// path: nothing signs on anyone's behalf.
//
// A RELAY ANSWER THAT FAILED IS NOT AN ANSWER. Reads that reach the chain
// (roleOf, identityRead, sectionAcl, memberships, identityRivets) throw when the
// relay could not read it (its 503 CHAIN_UNREACHABLE / CHAIN_DISAGREES), so a
// caller can tell "no" from "could not ask"; only a 404 is a "none". Every
// thrown error carries `status` and the relay's `code` when it sent one; a
// caller that must speak to a person wraps it (`errors` hook below).
//
//   relayClient({ baseUrl, signer, fetchImpl, checksum, errors, timeoutMs })
//     baseUrl   '' for the same origin (the relay is mounted in the console), or
//               the relay's origin for a server-side caller.
//     signer    { address, sign(message) → signature, identity? } or a function
//               returning one at call time (a browser whose active rivet changes).
//               `identity` is the IdentityContract the signer acts for (its own
//               address when it has none); a derived participant is its own origin.
//     checksum  address → checksummed address (ethers getAddress); the relay keys
//               storage by the exact folder string, so a path is never built from
//               a lowercased address.
//     errors    { fromResponse(path, status, body), fromTransport(path, cause) } —
//               how a failure is typed for the caller (a browser gives a sentence).
//     .as(signer) → the same client bound to another signer.

import { signStorageWrite, sha256hex } from 'epistery/client/storage-message.mjs';

const DEFAULT_TIMEOUT_MS = 120_000;

// A thrown fetch for a reason that a fresh connection fixes: the relay is being
// restarted under a deploy. HTTP error RESPONSES are answers and never retried.
const TRANSIENT_CODES = new Set(['UND_ERR_SOCKET', 'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN']);
function isTransient(err) {
  if (!(err instanceof TypeError)) return false;
  const code = err.cause?.code;
  if (code && TRANSIENT_CODES.has(code)) return true;
  const msg = ((err.cause && err.cause.message) || err.message || '').toLowerCase();
  return msg.includes('other side closed') || msg.includes('socket') || err.message === 'fetch failed';
}

const randomHex = (bytes) => {
  const b = new Uint8Array(bytes); globalThis.crypto.getRandomValues(b);
  let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s;
};
const utf8 = new TextEncoder();
const toBytes = (payload) => payload instanceof Uint8Array ? payload
  : utf8.encode(typeof payload === 'string' ? payload : JSON.stringify(payload));

function defaultErrors() {
  return {
    fromResponse: (path, status, body) => Object.assign(
      new Error(body?.error || body?.message || `relay ${path} failed (${status})`),
      { status, code: body?.code || null, path }),
    fromTransport: (path, cause) => Object.assign(new Error(`relay ${path} unreachable: ${cause?.message || cause}`), { status: 0, code: 'RELAY_UNREACHABLE', path, cause }),
  };
}

export function relayClient(opts = {}) {
  const baseUrl = String(opts.baseUrl || '').replace(/\/+$/, '');
  const fetchImpl = opts.fetchImpl || globalThis.fetch.bind(globalThis);
  const checksum = opts.checksum || ((a) => globalThis.ethers.utils.getAddress(a));
  const errors = opts.errors || defaultErrors();
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const headers = opts.headers || (() => ({}));
  const signerOf = async () => {
    const s = typeof opts.signer === 'function' ? await opts.signer() : opts.signer;
    if (!s?.sign || !s?.address) throw new Error('relay: a signer {address, sign} is required for a signed call');
    return s;
  };

  // One bounded fetch with transient retry; a response is returned as is. `init`
  // may be a FUNCTION producing the request per attempt: a signed write is
  // re-signed on every retry, because the relay honours a credential once and a
  // retry that reused the first attempt's signature would be refused as a replay
  // whenever the first attempt had in fact been processed.
  async function send(path, init = {}, { tries = 5, baseDelayMs = 250, maxDelayMs = 2000 } = {}) {
    const url = `${baseUrl}${path}`;
    let lastErr;
    for (let attempt = 0; attempt < tries; attempt++) {
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), timeoutMs);
      try {
        const i = typeof init === 'function' ? await init() : init;
        return await fetchImpl(url, { ...i, headers: { ...(await headers()), ...(i.headers || {}) }, signal: abort.signal });
      } catch (err) {
        lastErr = err;
        if (!isTransient(err) || attempt === tries - 1) throw errors.fromTransport(path, err);
        await new Promise((r) => setTimeout(r, Math.min(baseDelayMs * (2 ** attempt), maxDelayMs)));
      } finally {
        clearTimeout(timer);
      }
    }
    throw errors.fromTransport(path, lastErr);
  }
  async function failed(path, r) {
    const body = await r.json().catch(() => ({}));
    return errors.fromResponse(path, r.status, body);
  }

  // The signed `Bot` credential for a write: core's envelope, this signer.
  async function credential(method, contract, subpath, bodyBytes) {
    const s = await signerOf();
    const bodyHashHex = bodyBytes && bodyBytes.length ? await sha256hex(bodyBytes) : '';
    return signStorageWrite({
      sign: (m) => s.sign(m), address: s.address, identity: s.identity || null,
      method, contract: checksum(contract), subpath, bodyHashHex,
    });
  }

  const client = {
    baseUrl,
    as: (signer) => relayClient({ ...opts, signer }),

    /** A bounded JSON call to any relay path; throws the typed error on !ok. */
    async json(path, init) {
      const r = await send(path, init);
      if (!r.ok) throw await failed(path, r);
      return r.json();
    },

    // ── storage: contract-rooted records ─────────────────────────────────
    async storagePut(contract, path, value) {
      const body = toBytes(JSON.stringify(value));
      const folder = checksum(contract);
      const p = `/storage/${folder}/${path}`;
      const r = await send(p, async () => ({ method: 'PUT', headers: { 'content-type': 'application/json', authorization: (await credential('PUT', folder, path, body)).authorization }, body }));
      if (!r.ok) throw await failed(p, r);
      return r.json();
    },
    async storageDelete(contract, path) {
      const folder = checksum(contract);
      const p = `/storage/${folder}/${path}`;
      const r = await send(p, async () => ({ method: 'DELETE', headers: { authorization: (await credential('DELETE', folder, path, null)).authorization } }));
      if (r.status === 404) return { ok: true, deleted: false };
      if (!r.ok) throw await failed(p, r);
      return r.json();
    },
    async storageGet(contract, path) {
      const p = `/storage/${checksum(contract)}/${path}`;
      const r = await send(p);
      if (r.status === 404) return null;
      if (!r.ok) throw await failed(p, r);
      return r.json();
    },
    // Listing is STRUCTURE, not content (structure is clear, content is
    // ciphertext at rest), so it is a plain read like storageGet.
    async storageList(contract, prefix = '') {
      const p = `/storage/${checksum(contract)}${prefix ? `?prefix=${encodeURIComponent(prefix)}` : ''}`;
      const r = await send(p);
      if (!r.ok) throw await failed(p, r);
      return (await r.json()).items || [];
    },
    // Upload ALREADY-sealed bytes, rooted at `contract` and signed as a member of
    // `session`: the same credential a storage write carries, over the bytes
    // themselves (subpath `<session>/_upload`), so only a member seated to write
    // in that session may fill its owner's store. The relay keeps opaque bytes;
    // what makes the upload count is the signed record that references it, and
    // the relay reclaims an upload no record references. → { url, id }
    async uploadBlob(contract, bytesOrBlob, { session } = {}) {
      if (!session) throw new Error('uploadBlob: the session the bytes belong to is required');
      const folder = checksum(contract);
      const isBlob = typeof Blob !== 'undefined' && bytesOrBlob instanceof Blob;
      const bytes = new Uint8Array(isBlob ? await bytesOrBlob.arrayBuffer() : bytesOrBlob);
      const blob = isBlob ? bytesOrBlob : new Blob([bytes], { type: 'application/octet-stream' });
      const r = await send('/upload', async () => {
        const fd = new FormData();
        fd.append('file', blob, 'blob.bin');
        fd.append('contract', folder);
        fd.append('session', session);
        const { authorization } = await credential('POST', folder, `${session}/_upload`, bytes);
        return { method: 'POST', headers: { authorization }, body: fd };
      });
      if (!r.ok) throw await failed('/upload', r);
      return r.json();
    },

    // ── courier: address-to-address envelopes ───────────────────────────
    // The courier is blind: `payload` is opaque bytes the recipient unseals.
    // send() proves ORIGIN with the same envelope storage writes use — the relay
    // gates on that alone, never on a role at `to`, so anyone may address anyone.
    async inboxSend(to, payload) {
      const body = toBytes(payload);
      const id = randomHex(16);   // sender-minted envelope id (32 hex)
      const dest = checksum(to);
      const p = `/inbox/${dest}`;
      const r = await send(p, async () => ({ method: 'POST', headers: { 'content-type': 'application/octet-stream', authorization: `Inbox ${(await credential('POST', dest, `_inbox/${id}`, body)).credential}`, 'x-inbox-id': id }, body }));
      if (!r.ok) throw await failed(p, r);
      return r.json();   // { id }
    },
    // The caller's own spool since a cursor (ms). A public read; rows carry
    // opaque base64 `sealed`. The cursor is floored and clamped: a millisecond
    // timestamp does not fit in 32 bits, and `since|0` once pulled whole spools.
    async inboxList(address, sinceMs = 0) {
      const since = Math.max(0, Math.floor(Number(sinceMs) || 0));
      return client.json(`/inbox/${checksum(address)}?since=${since}`);
    },

    // ── DS: the commit signer a DsGroup needs ───────────────────────────
    dsSign: (contract) => async (method, subpath, bodyBytes) => (await credential(method, contract, subpath, bodyBytes)).authorization,

    // ── identity reads (the chain, through the relay) ───────────────────
    // null when the address holds no code (404) or is not address-shaped (400);
    // throws when the relay could not read the chain.
    async identityRead(contract) {
      const p = `/identity/${contract}`;
      const r = await send(p);
      if (r.status === 400 || r.status === 404) return null;
      if (!r.ok) throw await failed(p, r);
      return r.json();
    },
    // 0 none · 1 read · 2 write · 3 admin · 4 owner, carrying the MULTISIG two-hop:
    // `signer` is the proven rivet, `identity` the identity it claims. 0 is the
    // chain's answer; a read the relay could not make THROWS.
    async roleOf(contract, section, signer, identity = signer) {
      const body = await client.json(`/identity/${contract}/role?${new URLSearchParams({ section, signer, identity })}`);
      return Number(body?.role) || 0;
    },
    // Whether `address` holds a leaf in a session's group (the relay's seat
    // index). null = the relay could not answer — unknown, never "not seated".
    async seatOf(contract, session, address) {
      try {
        const r = await send(`/ds/${contract}/${session}/seat/${address}`);
        return r.ok ? await r.json() : null;
      } catch { return null; }
    },
    async sectionAcl(contract, section) {
      const body = await client.json(`/identity/${contract}/acl?${new URLSearchParams({ section })}`);
      return Array.isArray(body?.members) ? body.members : [];
    },
    // Sessions an identity was granted into on OTHER contracts. 404 = none;
    // anything else throws, so "none" and "could not ask" never look alike.
    async memberships(contract) {
      const p = `/identity/${contract}/memberships`;
      const r = await send(p);
      if (r.status === 404) return [];
      if (!r.ok) throw await failed(p, r);
      const body = await r.json().catch(() => null);
      if (!Array.isArray(body?.sessions)) throw new Error('relay memberships: malformed response');
      return body.sessions;
    },
    // Lowercased rivet addresses; null when not an IdentityContract (404).
    async identityRivets(contract) {
      const p = `/identity/${contract}/rivets`;
      const r = await send(p);
      if (r.status === 404) return null;
      if (!r.ok) throw await failed(p, r);
      return ((await r.json())?.rivets || []).map((x) => (x.address || x).toString().toLowerCase());
    },
    async resolveName(name, domain) {
      const qs = new URLSearchParams({ name });
      if (domain) qs.set('domain', domain);
      const p = `/identity/resolve?${qs}`;
      const r = await send(p);
      if (r.status === 404) return null;
      if (!r.ok) throw await failed(p, r);
      return r.json();
    },

    // ── seals ───────────────────────────────────────────────────────────
    storageSeal: (contract, session) => client.json(`/cas/${contract}/seal`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ session }) }),
    storageCasStatus: (contract, session) => client.json(`/cas/${contract}/root?session=${encodeURIComponent(session)}`),
  };
  return client;
}

/** An ethers Wallet (or anything with signMessage + address) as a relay signer. */
export function walletSigner(wallet, identity = null) {
  return { address: wallet.address, sign: (m) => wallet.signMessage(m), identity: identity || wallet.address };
}
