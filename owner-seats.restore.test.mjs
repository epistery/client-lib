// Restoring a wedged group (owner-seats restoreGroup): the owner
// device reinits past the change nobody can apply, re-seats the owner's keys and
// the old tree's members — all but the signer of that change — and everyone
// re-seated reads the whole history and what comes after.
//
//   cd client-lib && node owner-seats.restore.test.mjs
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
// A real commit credential, as every signer produces it (members verify these).
const botSigner = (priv, contract) => async (method, subpath, body) => {
  const w = new ethers.Wallet(priv);
  const message = ['epistery-storage-write', method, contract, subpath, ethers.utils.sha256(body).slice(2), String(Date.now())].join('\n');
  const json = JSON.stringify({ address: w.address, signature: await w.signMessage(message), message });
  return 'Bot ' + btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const credOf = (a) => (typeof a === 'string' && a.startsWith('Bot ') ? a.slice(4) : null);
const ds = []; const signers = []; const raws = []; const creds = []; let postingAs = null;
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    if (Number(opts.headers['x-ds-format']) !== DS_FORMAT) return { ok: false, status: 426, json: async () => ({}) };
    if (Number(opts.headers['x-ds-epoch']) !== ds.length) return { ok: false, status: 409, json: async () => ({ current: ds.length }) };
    ds.push(dec(opts.body)); raws.push(opts.body); creds.push(credOf(opts.headers.authorization)); signers.push(postingAs); return { ok: true, json: async () => ({ ok: true, epoch: ds.length }) };
  }
  if (/\/head$/.test(url)) return { ok: true, json: async () => ({ epoch: ds.length }) };
  if (/\/log\?/.test(url)) { const since = Number(new URL(url).searchParams.get('since') || 0); return { ok: true, json: async () => ds.map((e, i) => ({ epoch: i + 1, signer: signers[i], cred: creds[i] })).filter((e) => e.epoch > since) }; }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => raws[Number(m[1]) - 1] } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const OWNER = '0xowner', SESSION = { owner: OWNER, id: '0xsess', name: 'board' };
const stores = new Map();
const storeFor = (k) => { if (!stores.has(k.addr)) { let saved = null; stores.set(k.addr, { load: async () => saved, save: async (s) => { saved = JSON.parse(JSON.stringify(s)); } }); } return stores.get(k.addr); };
const groupFor = (k) => new DsGroup({ chain: anyoneMayCommit, relayUrl: 'https://x', contract: OWNER, session: SESSION.id, address: k.addr, rivetPriv: k.priv, rivetPub: k.pub,
  sign: async (...a) => { postingAs = k.addr; return botSigner(k.priv, OWNER)(...a); }, stack, fetchImpl: fakeFetch, capacity: 8, store: storeFor(k) });

// Owner devices A, P(backup); collaborator X; bot Z; bad writer W.
const A = kp(), P = kp(), X = kp(), Z = kp(), W = kp();
state.me = A.addr;
state.signers = [{ address: A.addr, name: 'browser', publicKey: A.pub }];
await seats.recordRivetKey(OWNER, P.addr, P.pub);
state.signers.push({ address: P.addr, name: 'backup', publicKey: '' });

const gA = groupFor(A); postingAs = A.addr; await gA.create();
for (const k of [P, X, Z, W]) await gA.addMember(k.addr, k.pub);
const before = await sealedKeys(gA, cipher).seal('the history');
// W posts a change nobody can apply — one that passes every PUBLIC check (built on
// the log's tree, from W's own leaf) and fails only privately: path secrets sealed
// to no one. A change with a public fault is skipped by everyone instead
// (client-lib ds-group.diligence.test.mjs); this is the case that still wedges.
const wLeaf = Number(gA.leafDir[W.addr]);
{
  const env = { commit: { type: 'update', format: DS_FORMAT, committerLeafIndex: wLeaf, capacity: 8, parentHash: ds[ds.length - 1].commit.treeHash, treeHash: '0x00',
    path: [{ dNodeId: 0, newPub: kp().pub, encs: [] }] }, dir: {} };
  const raw = enc(env);
  ds.push(env); raws.push(raw); creds.push(credOf(await botSigner(W.priv, OWNER)('POST', `${SESSION.id}/_ds/commit`, raw))); signers.push(W.addr);
}

const stuck = groupFor(A); await stuck.load();
check(!!stuck.stuck && stuck.stuck.signer === W.addr, 'the owner device loads the group stuck, naming the bad writer');
const badEpoch = stuck.stuck.epoch;
const out = await seats.restoreGroup(SESSION, stuck);
check(out.epoch === badEpoch + 1 && out.leftOut[0] === W.addr, `restored at epoch ${out.epoch}, just past the bad change (${badEpoch}); the bad writer is left out and named`);
check(new Set(out.seated).size === 3 && [P, X, Z].every((k) => out.seated.includes(k.addr)), 'the backup, the collaborator and the bot are re-seated');
const after = await sealedKeys(stuck, cipher).seal('after the restore');
for (const [name, k] of [['backup P', P], ['collaborator X', X], ['bot Z', Z]]) {
  const g = groupFor(k); await g.load();
  const kk = sealedKeys(g, cipher);
  check((await kk.open(before)).ok && (await kk.open(after)).ok && kk.ready, `${name}: reads the history and what follows, and can write`);
}
let wr; try { const g = groupFor(W); await g.load(); wr = await sealedKeys(g, cipher).open(after); } catch (e) { wr = { ok: false, cause: e.code }; }
check(!wr.ok, `the bad writer reads nothing written after the restore (${wr.cause})`);

console.log(failures ? `RESTORE FAIL — ${failures}` : 'RESTORE PASS'); process.exit(failures ? 1 : 0);
