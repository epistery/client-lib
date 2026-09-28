// One commit that members cannot apply — a buggy, stale or hostile writer — must
// not cost anyone the history they already hold. The relay accepts any commit from
// a section writer (it cannot read them), so this is reachable by any collaborator.
//
//   STUCK, NOT LOST  a member that cannot apply commit N stops at N-1 with every key
//                    up to there: it reads all of it, and seals / commits nothing
//   NAMED            the stuck state names the epoch, the cause and the signer
//   FRESH DEVICE     a device bootstrapping from the log ends up the same way
//   RESTORE          an owner device reinits past the bad commit, carrying its keyring;
//                    re-seated members join the new tree with all their history, and
//                    the bad committer, not re-seated, reads nothing written after
//
//   node client-lib/ds-group.wedge.test.mjs
import { ethers } from 'ethers';
globalThis.ethers = ethers; globalThis.window ??= globalThis;
import { DsGroup, DS_FORMAT } from './ds-group.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';
import { sealedKeys } from './sealed.mjs';
import * as cipher from './cipher.mjs';

let failures = 0; const check = (c, m) => c ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const stack = cryptoStack();
const kp = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); const priv = privFromSecret(b); const pub = pubFromPriv(priv); return { priv, pub, addr: ethers.utils.computeAddress(pub).toLowerCase() }; };

const ds = []; const signers = [];
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));
let postingAs = null;
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    if (Number(opts.headers['x-ds-format']) !== DS_FORMAT) return { ok: false, status: 426, json: async () => ({}) };
    if (Number(opts.headers['x-ds-epoch']) !== ds.length) return { ok: false, status: 409, json: async () => ({ current: ds.length }) };
    ds.push(dec(opts.body)); signers.push(postingAs); return { ok: true, json: async () => ({ ok: true, epoch: ds.length }) };
  }
  if (/\/head$/.test(url)) return { ok: true, json: async () => ({ epoch: ds.length, head: null }) };
  if (/\/log\?/.test(url)) {
    const since = Number(new URL(url).searchParams.get('since') || 0);
    return { ok: true, json: async () => ds.map((e, i) => ({ epoch: i + 1, signer: signers[i] })).filter((e) => e.epoch > since) };
  }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => enc(e) } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const stores = new Map();
const storeFor = (k) => { if (!stores.has(k.addr)) { let saved = null; stores.set(k.addr, { load: async () => saved, save: async (s) => { saved = JSON.parse(JSON.stringify(s)); } }); } return stores.get(k.addr); };
const groupFor = (k) => new DsGroup({ relayUrl: 'https://x', contract: '0xowner', session: '0xs', address: k.addr, rivetPriv: k.priv, rivetPub: k.pub,
  sign: async () => { postingAs = k.addr; return 'Bot test'; }, stack, fetchImpl: fakeFetch, capacity: 8, store: storeFor(k) });

console.log('\n[wedge] one unappliable commit');
const A = kp(), B = kp(), C = kp(), W = kp();
const gA = groupFor(A); postingAs = A.addr; await gA.create();
await gA.addMember(B.addr, B.pub); await gA.addMember(C.addr, C.pub); await gA.addMember(W.addr, W.pub);
await gA.update();   // a rotation, so history spans two keys
const kA = sealedKeys(gA, cipher);
const before = await kA.seal('written before the bad commit');
const beforeEpoch = gA.epoch();

// W posts a commit nobody can apply: a rotation whose path secrets are sealed to no one.
const good = ds.length;
ds.push({ commit: { type: 'update', committerLeafIndex: 3, capacity: 8, path: [{ dNodeId: 12, newPub: kp().pub, encs: [] }, { dNodeId: 8, newPub: kp().pub, encs: [] }, { dNodeId: 0, newPub: kp().pub, encs: [] }] }, dir: {} });
signers.push(W.addr);
const bad = ds.length;

for (const [name, k] of [['owner A', A], ['member B', B]]) {
  const g = groupFor(k); await g.load();
  const keys = sealedKeys(g, cipher);
  check(g.stuck?.epoch === bad, `${name}: loads STUCK at epoch ${bad} instead of failing`);
  check(g.stuck?.signer === W.addr && /no sealed path secret|cannot apply/.test(g.stuck?.reason || ''), `${name}: the stuck state names the signer and the cause`);
  check(g.epoch() === good, `${name}: stays at the last good epoch (${good})`);
  check((await keys.open(before)).text === 'written before the bad commit', `${name}: reads everything sealed before it`);
  check(!keys.ready, `${name}: not ready to write`);
  let sealErr = null; try { await keys.seal('x'); } catch (e) { sealErr = e.message; }
  check(/cannot be written/.test(sealErr || ''), `${name}: seal refuses, saying why`);
  let commitErr = null; try { await g.addMember(kp().addr, kp().pub); } catch (e) { commitErr = e.code; }
  check(commitErr === 'STUCK', `${name}: commits refuse (STUCK)`);
}

// A device with NO saved state, seated before the bad commit, bootstraps from the log.
stores.delete(C.addr);
const gC = groupFor(C); await gC.load();
check(gC.stuck?.epoch === bad, 'fresh device: bootstraps STUCK at the bad epoch, not failing');
check((await sealedKeys(gC, cipher).open(before)).ok, 'fresh device: reads the history it was given');
check(Object.keys(gC.leafDir).length === 4, 'fresh device: its directory describes the tree before the bad commit');

// ── RESTORE: the owner device starts a new tree past the bad commit ─────────────
console.log('\n[wedge] restore (reinit)');
const gR = groupFor(A); await gR.load();
const prior = Object.entries(gR.leafDir).filter(([a]) => a !== A.addr && a !== W.addr)
  .map(([a, leaf]) => ({ address: a, publicKey: gR.member.leaves[Number(leaf)].pub }));
const { epoch: restored } = await gR.reinit();
check(restored === bad + 1 && !gR.stuck, `the owner device restores the group at epoch ${restored}, past the bad commit`);
for (const p of prior) await gR.addMember(p.address, p.publicKey);   // re-seat the previous members, not the bad committer
const kR = sealedKeys(gR, cipher);
check(kR.ready, 'the restored group is writable');
check((await kR.open(before)).text === 'written before the bad commit', 'the founder of the new tree still reads the old history');
const after = await kR.seal('written after the restore');

for (const [name, k] of [['member B', B], ['fresh device C', C]]) {
  const g = groupFor(k); await g.load();
  const keys = sealedKeys(g, cipher);
  check(!g.stuck && keys.ready, `${name}: joins the restored group, writable`);
  check((await keys.open(before)).ok, `${name}: still reads the history from before the wedge`);
  check((await keys.open(after)).text === 'written after the restore', `${name}: reads what is written after the restore`);
}
let wOut; try { const g = groupFor(W); await g.load(); wOut = await sealedKeys(g, cipher).open(after); } catch (e) { wOut = { ok: false, cause: e.code }; }
check(!wOut.ok, `the bad committer, not re-seated, reads nothing written after the restore (${wOut.cause})`);

void beforeEpoch;

console.log('\n' + (failures ? `WEDGE FAIL — ${failures}` : 'WEDGE PASS — one bad commit costs no member the history it holds.'));
process.exit(failures ? 1 : 0);
