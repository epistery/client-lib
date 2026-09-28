// Chain reads a client makes ITSELF — straight to the chain's RPC endpoints, never
// through the relay or the host. Trust lives in identity and data: a server may
// carry a signed transaction or a signed commit, but no client ever takes a
// server's word for what the chain says.
//
// Used where a device has nothing of its own to check against: a device joining a
// group from scratch confirms, on chain, that the member who seated it may commit
// to the session (a rivet of the owner contract, or a section member with write),
// and that the founder of any restore it follows is a rivet of the owner contract.
// A relay cannot produce either: it holds no such key.
//
// Endpoints are tried in order (the operator's own node first). A contract
// REVERT is an answer — "no". An endpoint that does not answer (network, HTTP
// error, rate limit, a JSON-RPC error that is not a revert) is not an answer: the
// next endpoint is tried, and when none answers the read fails with
// CHAIN_UNREACHABLE — the caller refuses rather than guesses (ethers v5 codes a
// dead endpoint like an empty return; this does not).
//
// The rules mirror the relay's storage-auth, so a client and the relay reach the
// same verdict from the same chain:
//   rivet  : isAuthorized(addr) on the contract, or — an identity admitted as a
//            signer vouching for its own rivet — any contract in getRivets() whose
//            isAuthorized(addr) is true
//   role   : roleOf(section, addr); an identity that vouches for addr lends its
//            own role (the credential's `identity`)

const ABI = [
  'function isAuthorized(address) view returns (bool)',
  'function getRivets() view returns (address[])',
  'function roleOf(string section, address account) view returns (uint8)',
];
const ROLE_WRITE = 2;

export function chainReader({ rpcs, fetchImpl = globalThis.fetch?.bind(globalThis), ttlMs = 10 * 60 * 1000 } = {}) {
  const endpoints = [...new Set((rpcs || []).filter(Boolean))];
  if (!endpoints.length) throw new Error('chainReader: at least one RPC endpoint is required');
  const iface = () => new globalThis.ethers.utils.Interface(ABI);
  const cache = new Map();   // key → { at, value }

  // One eth_call. Returns the result hex, null for a revert, or throws
  // CHAIN_UNREACHABLE when no endpoint answered.
  async function call(to, data) {
    const failures = [];
    for (const url of endpoints) {
      try {
        const r = await fetchImpl(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] }),
        });
        if (!r.ok) { failures.push(`${host(url)} HTTP ${r.status}`); continue; }
        const j = await r.json();
        if (j.error) {
          const msg = String(j.error.message || '');
          if (j.error.code === 3 || /revert/i.test(msg)) return null;   // the contract answered: no
          failures.push(`${host(url)} ${msg || j.error.code}`);
          continue;
        }
        return typeof j.result === 'string' ? j.result : null;
      } catch (e) { failures.push(`${host(url)} ${e.message}`); }
    }
    const e = new Error(`no chain endpoint answered (${failures.join('; ')})`);
    e.code = 'CHAIN_UNREACHABLE';
    throw e;
  }
  async function read(to, fn, args) {
    const i = iface();
    const out = await call(to, i.encodeFunctionData(fn, args));
    if (out == null || out === '0x') return null;   // revert, or no contract there
    return i.decodeFunctionResult(fn, out)[0];
  }
  const cached = async (key, compute) => {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < ttlMs) return hit.value;
    const value = await compute();
    cache.set(key, { at: Date.now(), value });
    return value;
  };

  async function isRivet(contract, addr) {
    return cached(`rivet|${lc(contract)}|${lc(addr)}`, async () => {
      if (await read(contract, 'isAuthorized', [addr])) return true;
      const admitted = (await read(contract, 'getRivets', [])) || [];
      for (const entry of admitted) {
        if (lc(entry) === lc(contract)) continue;
        if (await read(entry, 'isAuthorized', [addr])) return true;   // an identity signer vouching for its rivet
      }
      return false;
    });
  }

  async function roleOf(contract, section, addr) {
    return cached(`role|${lc(contract)}|${section}|${lc(addr)}`, async () => Number((await read(contract, 'roleOf', [section, addr])) || 0));
  }

  // May `signer` commit to this session's group? (What the relay requires of a
  // commit, read by the client itself.)
  async function mayCommit(contract, section, signer, identity = null) {
    if (await isRivet(contract, signer)) return true;
    if ((await roleOf(contract, section, signer)) >= ROLE_WRITE) return true;
    if (identity && lc(identity) !== lc(signer) && await read(identity, 'isAuthorized', [signer])) {
      return (await roleOf(contract, section, identity)) >= ROLE_WRITE;
    }
    return false;
  }

  return { isRivet, roleOf, mayCommit, endpoints };
}

const lc = (a) => String(a || '').toLowerCase();
const host = (url) => { try { return new URL(url).host; } catch { return String(url); } };
