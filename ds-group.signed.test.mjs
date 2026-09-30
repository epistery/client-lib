// Every commit is signed, and members check it themselves (DS_FORMAT 4). The relay
// serves each commit's credential; a member verifies the signature, that it covers
// these exact bytes and this session, and that the signer holds the committer's
// leaf in its own tree. A relay — which can post anything but holds no member key —
// can then add nothing to a group.
//
//   FORGED        a commit claiming a member's leaf, signed by another key → skipped
//   STRIPPED      a signed-format commit served without its credential → skipped
//   ALTERED       bytes changed after signing (a directory entry slipped in) → skipped
//   DOWNGRADE     an unsigned commit after the group went signed → skipped
//   FAKE RESTORE  a reinit by a key that never sat in the group → ignored
//   REAL RESTORE  a reinit by a seated owner device → followed
//   and through all of it: nobody is stuck, keys do not move, honest commits apply.
//
//   node client-lib/ds-group.signed.test.mjs
import { ethers } from 'ethers';
globalThis.ethers = ethers; globalThis.window ??= globalThis;
import { DsGroup, DS_FORMAT, treeHashOf } from './ds-group.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';
import { sealedKeys } from './sealed.mjs';
import * as cipher from './cipher.mjs';
import { botSigner, credOf, anyoneMayCommit } from './ds-test-kit.mjs';

let failures = 0; const check = (c, m) => c ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const stack = cryptoStack();
const kp = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); const priv = privFromSecret(b); const pub = pubFromPriv(priv); return { priv, pub, addr: ethers.utils.computeAddress(pub).toLowerCase() }; };
const CONTRACT = '0xo', SESSION = '0xs', PATH = `${SESSION}/_ds/commit`;
const log = [];   // { env, raw, cred }
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    if (Number(opts.headers['x-ds-epoch']) !== log.length) return { ok: false, status: 409, json: async () => ({ current: log.length }) };
    log.push({ env: dec(opts.body), raw: opts.body, cred: credOf(opts.headers.authorization) });
    return { ok: true, json: async () => ({ ok: true, epoch: log.length }) };
  }
  if (/\/head$/.test(url)) return { ok: true, json: async () => ({ epoch: log.length }) };
  if (/\/log\?/.test(url)) { const since = Number(new URL(url).searchParams.get('since') || 0); return { ok: true, json: async () => log.map((e, i) => ({ epoch: i + 1, cred: e.cred })).filter((e) => e.epoch > since) }; }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = log[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => e.raw } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const stores = new Map();
const storeFor = (k) => { if (!stores.has(k.addr)) { let saved = null; stores.set(k.addr, { load: async () => saved, save: async (s) => { saved = JSON.parse(JSON.stringify(s)); } }); } return stores.get(k.addr); };
const groupFor = (k) => new DsGroup({ chain: anyoneMayCommit, relayUrl: 'https://x', contract: CONTRACT, session: SESSION, address: k.addr, rivetPriv: k.priv, rivetPub: k.pub,
  sign: botSigner(k.priv, CONTRACT), stack, fetchImpl: fakeFetch, capacity: 8, store: storeFor(k) });
// What the RELAY can do: put any bytes in the log, with any credential — but it can
// only SIGN with keys it holds (R), never a member's.
const relayPosts = async (env, { signWith = null, cred, mutate } = {}) => {
  const raw = enc(env);
  const c = cred !== undefined ? cred : (signWith ? credOf(await botSigner(signWith.priv, CONTRACT)('POST', PATH, raw)) : null);
  const served = mutate ? enc(mutate(JSON.parse(JSON.stringify(env)))) : raw;
  log.push({ env, raw: served, cred: c });
};

console.log('\n[signed] members check who signed each commit');
check(DS_FORMAT === 5, 'commit format 5');
const A = kp(), B = kp(), R = kp();   // A owner device, B member, R the relay's own key
const gA = groupFor(A); await gA.create();
await gA.addMember(B.addr, B.pub);
const history = await sealedKeys(gA, cipher).seal('history');
const gB = groupFor(B); await gB.load();
check(!gB.stuck && gB.signedFrom != null && gB.inStep, 'a member follows the signed log and is confirmed in step');
const tip = () => ({ hash: gA.inStep, epoch: log.length });

// FORGED: an add claiming A's leaf 0 — the relay seating its own key — signed by R.
await gA.load();
await relayPosts({ commit: { type: 'add', format: DS_FORMAT, committerLeafIndex: 0, capacity: 8, addLeafIndex: 2, addPub: R.pub, parentHash: tip().hash, treeHash: '0x00', path: [], welcome: null }, dir: { set: { [R.addr]: 2 } } }, { signWith: R });
// STRIPPED: a signed-format commit with no credential served.
await relayPosts({ commit: { type: 'add', format: DS_FORMAT, committerLeafIndex: 0, capacity: 8, addLeafIndex: 3, addPub: R.pub, parentHash: tip().hash, treeHash: '0x00', path: [], welcome: null }, dir: { set: { [R.addr]: 3 } } }, { cred: null });
// ALTERED: a genuine commit by A, its directory changed after A signed it.
const bLeaf = Number(gA.leafDir[B.addr]);
const genuine = { commit: { type: 'update', format: DS_FORMAT, committerLeafIndex: 0, capacity: 8, parentHash: tip().hash, treeHash: '0x00', path: [] }, dir: {} };
await relayPosts(genuine, { signWith: A, mutate: (e) => { e.dir = { set: { [R.addr]: 4 } }; return e; } });
// DOWNGRADE: hashes but no format / credential — how the relay would dress a commit it cannot sign.
await relayPosts({ commit: { type: 'add', committerLeafIndex: bLeaf, capacity: 8, addLeafIndex: 5, addPub: R.pub, parentHash: tip().hash, treeHash: '0x00', path: [], welcome: null }, dir: { set: { [R.addr]: 5 } } });
// FAKE RESTORE: a reinit founded by R, signed by R.
await relayPosts({ commit: { type: 'reinit', format: DS_FORMAT, capacity: 8, committerLeafIndex: 0, founderPub: R.pub, path: [], treeHash: '0x00' }, dir: { reset: true, set: { [R.addr]: 0 } } }, { signWith: R });

for (const [name, k] of [['owner A', A], ['member B', B]]) {
  const g = groupFor(k); await g.load();
  const reasons = g.skipped.map((x) => x.reason);
  check(!g.stuck, `${name}: not stuck by any of it`);
  check(/not the member at leaf 0/.test(reasons[0] || ''), `${name}: FORGED skipped — ${reasons[0]}`);
  check(/no signature/.test(reasons[1] || ''), `${name}: STRIPPED skipped — ${reasons[1]}`);
  check(/does not cover these bytes/.test(reasons[2] || ''), `${name}: ALTERED skipped — ${reasons[2]}`);
  check(/unsigned, after/.test(reasons[3] || ''), `${name}: DOWNGRADE skipped — ${reasons[3]}`);
  check(/restore not signed by a member/.test(reasons[4] || ''), `${name}: FAKE RESTORE ignored — ${reasons[4]}`);
  check(!g.isSeated(R.addr) && !Object.keys(g.leafDir).includes(R.addr), `${name}: the relay's key holds no seat and no directory entry`);
  check((await sealedKeys(g, cipher).open(history)).ok && sealedKeys(g, cipher).ready, `${name}: keys unchanged — reads, and can write`);
}

// Honest work continues on top of all that.
const gA2 = groupFor(A); await gA2.load();
const C = kp(); await gA2.addMember(C.addr, C.pub);
const after = await sealedKeys(gA2, cipher).seal('after');
const gB2 = groupFor(B); await gB2.load();
check(gB2.isSeated(C.addr) && (await sealedKeys(gB2, cipher).open(after)).ok, 'an honest commit after the forgeries applies for every member');

// REAL RESTORE: a seated owner device restarts the tree; members follow it.
const gA3 = groupFor(A); await gA3.load(); await gA3.reinit(); await gA3.addMember(B.addr, B.pub);
const post = await sealedKeys(gA3, cipher).seal('after the restore');
const gB3 = groupFor(B); await gB3.load();
check(!gB3.stuck && (await sealedKeys(gB3, cipher).open(post)).ok && (await sealedKeys(gB3, cipher).open(history)).ok, 'REAL RESTORE: a reinit by a seated owner device is followed, history kept');
void treeHashOf;

console.log('\n' + (failures ? `SIGNED FAIL — ${failures}` : 'SIGNED PASS — the relay can put nothing into a group: every commit is checked against its committer by the members themselves.'));
process.exit(failures ? 1 : 0);
