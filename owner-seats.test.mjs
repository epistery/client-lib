// Every key the owner holds is a member of every session the owner creates — and
// nothing else is. Real TreeKEM groups (@epistery/client-lib ds-group) over an
// in-memory delivery service; owner-seats.mjs over a stubbed runtime.
//
//   cd client-lib && node owner-seats.test.mjs
//
// The requirement it proves: the creating device is lost, and the paper backup —
// from its phrase key alone — reads the whole session. A removed device reads
// nothing written after, and the removal converges from another device. The boost
// verifier is never seated even when handed a key that derives to its address.
import { ethers } from 'ethers';
globalThis.ethers = ethers; globalThis.window ??= globalThis;
const { ownerSeats } = await import('./owner-seats.mjs');
// The runtime the policy is injected with, stubbed: the chain's signer list,
// contract-root storage, the boost verifier, the acting device, openGroup, and
// the session list — all set by the test.
const state = { signers: [], storage: new Map(), verifier: null, me: null, openGroup: null, sessions: [] };
const seats = ownerSeats({
  me: () => ({ signer: state.me }),
  contractSigners: async () => state.signers.map((s) => ({ ...s })),
  boostVerifierAddress: async () => state.verifier,
  storageGet: async (c, p) => { const v = state.storage.get(`${c}/${p}`); return v === undefined ? null : JSON.parse(JSON.stringify(v)); },
  storagePut: async (c, p, v) => { state.storage.set(`${c}/${p}`, JSON.parse(JSON.stringify(v))); return { ok: true }; },
  openGroup: (s) => state.openGroup(s),
  listSessions: async () => state.sessions,
});
const { DsGroup, DS_FORMAT } = await import('./ds-group.mjs');
const { cryptoStack, privFromSecret, pubFromPriv } = await import('./treekem-kdf.mjs');
const { sealedKeys } = await import('./sealed.mjs');
const cipher = await import('./cipher.mjs');
// Everyone may commit on this test's chain: what a joining device asks the chain is
// client-lib's ds-group.chain.test.mjs.
const anyoneMayCommit = { isRivet: async () => true, roleOf: async () => 3, mayCommit: async () => true, mayRotate: async () => true, endpoints: [] };

let failures = 0; const check = (c, m) => c ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const stack = cryptoStack();
const kp = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); const priv = privFromSecret(b); const pub = pubFromPriv(priv); return { priv, pub, addr: ethers.utils.computeAddress(pub).toLowerCase() }; };

// ── an in-memory delivery service ────────────────────────────────────────────
// A real commit credential, as every signer produces it (members verify these).
const botSigner = (priv, contract) => async (method, subpath, body) => {
  const w = new ethers.Wallet(priv);
  const message = ['epistery-storage-write', method, contract, subpath, ethers.utils.sha256(body).slice(2), String(Date.now())].join('\n');
  const json = JSON.stringify({ address: w.address, signature: await w.signMessage(message), message });
  return 'Bot ' + btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const credOf = (a) => (typeof a === 'string' && a.startsWith('Bot ') ? a.slice(4) : null);
const ds = []; const raws = []; const creds = [];
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    if (Number(opts.headers['x-ds-format']) !== DS_FORMAT) return { ok: false, status: 426, json: async () => ({}) };
    if (Number(opts.headers['x-ds-epoch']) !== ds.length) return { ok: false, status: 409, json: async () => ({ current: ds.length }) };
    ds.push(dec(opts.body)); raws.push(opts.body); creds.push(credOf(opts.headers.authorization)); return { ok: true, json: async () => ({ ok: true, epoch: ds.length }) };
  }
  if (/\/log\?/.test(url)) {
    const since = Number(new URL(url).searchParams.get('since') || 0);
    return { ok: true, json: async () => ds.map((e, i) => ({ epoch: i + 1, cred: creds[i] })).filter((e) => e.epoch > since) };
  }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => raws[Number(m[1]) - 1] } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const OWNER = '0xowner', SESSION = { owner: OWNER, id: '0xsess', name: 'notes' };
// One tree store per KEY, as localStorage is one per browser rivet.
const stores = new Map();
const storeFor = (k) => { if (!stores.has(k.addr)) { let saved = null; stores.set(k.addr, { load: async () => saved, save: async (s) => { saved = JSON.parse(JSON.stringify(s)); } }); } return stores.get(k.addr); };
const groupFor = (k) => { return new DsGroup({ chain: anyoneMayCommit,
  relayUrl: 'https://x', contract: OWNER, session: SESSION.id, address: k.addr, rivetPriv: k.priv, rivetPub: k.pub,
  sign: botSigner(k.priv, OWNER), stack, fetchImpl: fakeFetch, capacity: 8,
  store: storeFor(k),
}); };

// ── the owner: two devices, a paper backup; plus things that must NOT be seated ─
const A = kp(), B = kp(), P = kp(), V = kp(), I = kp(), D = kp(), C = kp(), C2 = kp();
state.verifier = V.addr;
state.sessions = [SESSION];
state.signers = [
  { address: A.addr, name: 'browser', publicKey: A.pub },
  { address: B.addr, name: 'device', publicKey: B.pub },
  { address: P.addr, name: 'backup', publicKey: '' },                // a backup publishes nothing
  { address: V.addr, name: 'boost', publicKey: V.pub },              // WORST CASE: a verifier with a real, matching key
  { address: I.addr, name: 'rootz', publicKey: '', kind: 'identity' },
  { address: D.addr, name: 'device', publicKey: D.pub, pending: true },
  { address: C.addr, name: 'device', publicKey: C2.pub },            // a lying list: C's row carries someone else's key
];
let threw = false; try { await seats.recordRivetKey(OWNER, P.addr, C.pub); } catch { threw = true; }
check(threw, 'a recorded key that does not derive to its address is refused');
await seats.recordRivetKey(OWNER, P.addr, P.pub);   // the adding device held the phrase: record the backup's key

const keys = await seats.ownerSeatKeys(OWNER);
const addrs = new Set(keys.map((k) => k.address));
check(addrs.has(A.addr) && addrs.has(B.addr) && addrs.has(P.addr), 'the owner’s devices and the paper backup are seat keys');
check(!addrs.has(V.addr), 'the boost verifier is never a seat key — even with a key that derives to its address');
check(!addrs.has(I.addr) && !addrs.has(D.addr), 'an identity-signer (no device key) and a pending device are not');
check(!addrs.has(C.addr), 'a row whose key does not derive to its address is not');

// ── A creates the session and seats every key the owner holds ──────────────────
const gA = groupFor(A); await gA.create();
const newly = await seats.seatKeys(gA, keys);
check(newly.length === 2 && gA.isSeated(B.addr) && gA.isSeated(P.addr), 'create seats B and the backup beside the founder');
const kA = sealedKeys(gA, cipher);
const early = await kA.seal('written on the day the session was made');

// ── A is lost. The backup — its phrase key and the log, nothing else — reads it all ─
const gP = groupFor(P); await gP.load();
const kP = sealedKeys(gP, cipher);
check((await kP.open(early)).text === 'written on the day the session was made', 'device lost: the PAPER BACKUP alone opens the session');
const gB = groupFor(B); await gB.load();
check((await sealedKeys(gB, cipher).open(early)).ok, 'the other device opens it too');

// ── B is removed from the identity while offline; the removal converges from P ──
state.signers = state.signers.filter((s) => s.address !== B.addr);   // the chain no longer lists B
await seats.recordRemoved(OWNER, B.addr);
state.me = P.addr;
state.openGroup = async () => { const g = groupFor(P); await g.load(); return g; };
const rep = await seats.seatInOwnedSessions(OWNER, { keys: [] });
check(rep.unreachable.length === 0, 'the backup device can act on the session');
const gP2 = groupFor(P); await gP2.load();
check(!gP2.isSeated(B.addr), 'the removed device is taken out of the session from ANOTHER device');
const later = await sealedKeys(gP2, cipher).seal('written after B was removed');
const gB2 = groupFor(B); let bOpen;
try { await gB2.load(); bOpen = await sealedKeys(gB2, cipher).open(later); } catch (e) { bOpen = { ok: false, cause: e.code || e.message }; }
check(!bOpen.ok, `the removed device reads nothing written after (${bOpen.cause})`);
check((await sealedKeys(gP2, cipher).open(early)).ok, 'the backup still reads what came before');

// ── a re-added device is a signer again; its old removal record no longer applies ─
state.signers.push({ address: B.addr, name: 'device', publicKey: B.pub });
const rep2 = await seats.seatInOwnedSessions(OWNER);
const gP3 = groupFor(P); await gP3.load();
check(gP3.isSeated(B.addr) && rep2.done[0].result.includes(B.addr), 're-added, the device is seated again (its removal record is ignored)');

console.log(failures ? `OWNER-SEATS FAIL — ${failures}` : 'OWNER-SEATS PASS'); process.exit(failures ? 1 : 0);
