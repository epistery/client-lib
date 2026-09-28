// Diligence before a commit counts (DS_FORMAT 3): every commit states the public
// tree it was built on and the one it produces.
//
//   STALE STOPS      a device whose tree is not the log's refuses to post at all
//   SKIP, IN STEP    a commit built on another tree, or with an invalid public part
//                    (an add over an occupied leaf, a remove of an empty leaf), is
//                    skipped by every in-step member the same way — no one is stuck,
//                    keys do not move, and the next valid commit applies normally
//   CONFIRMED        members confirm each tree they reach against the commit's hash
//   JOINER           a device joining from its Welcome confirms the tree it received
//   LEGACY           history from before these rules replays exactly as it was applied
//
//   node client-lib/ds-group.diligence.test.mjs
import { ethers } from 'ethers';
globalThis.ethers = ethers; globalThis.window ??= globalThis;
import { DsGroup, DS_FORMAT } from './ds-group.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';
import { sealedKeys } from './sealed.mjs';
import * as cipher from './cipher.mjs';
import { botSigner, credOf } from './ds-test-kit.mjs';

let failures = 0; const check = (c, m) => c ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const stack = cryptoStack();
const kp = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); const priv = privFromSecret(b); const pub = pubFromPriv(priv); return { priv, pub, addr: ethers.utils.computeAddress(pub).toLowerCase() }; };
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
  if (/\/log\?/.test(url)) { const since = Number(new URL(url).searchParams.get('since') || 0); return { ok: true, json: async () => ds.map((e, i) => ({ epoch: i + 1, signer: signers[i], cred: creds[i] || null })).filter((e) => e.epoch > since) }; }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => raws[Number(m[1]) - 1] || enc(e) } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const stores = new Map();
const storeFor = (k) => { if (!stores.has(k.addr)) { let saved = null; stores.set(k.addr, { load: async () => saved, save: async (s) => { saved = JSON.parse(JSON.stringify(s)); } }); } return stores.get(k.addr); };
// Put a commit in the log as `k` would post it: exact bytes, signed by k.
const inject = async (env, k) => {
  const raw = enc(env);
  const auth = await botSigner(k.priv, '0xo')('POST', '0xs/_ds/commit', raw);
  ds.push(env); raws.push(raw); creds.push(credOf(auth)); signers.push(k.addr);
};
const groupFor = (k) => new DsGroup({ relayUrl: 'https://x', contract: '0xo', session: '0xs', address: k.addr, rivetPriv: k.priv, rivetPub: k.pub,
  sign: async (...a) => { postingAs = k.addr; return botSigner(k.priv, '0xo')(...a); }, stack, fetchImpl: fakeFetch, capacity: 8, store: storeFor(k) });

console.log('\n[diligence] every commit states its tree');
check(DS_FORMAT === 4, 'commit format 4');
const A = kp(), B = kp(), C = kp(), X = kp();
const gA = groupFor(A); await gA.create();
await gA.addMember(B.addr, B.pub); await gA.addMember(C.addr, C.pub);
check(ds.every((e) => e.commit.treeHash) && ds.slice(1).every((e) => e.commit.parentHash), 'every commit carries its tree hash, and its parent hash after genesis');
const gB = groupFor(B); await gB.load();
check(gB.inStep && gB.inStep === ds[ds.length - 1].commit.treeHash, 'a joiner confirms the tree it holds against the log');
await gB.update();                                  // a normal rotation, from a member
const gC = groupFor(C); await gC.load();
check(!gC.stuck && gC.inStep === ds[ds.length - 1].commit.treeHash, 'members apply and confirm a normal rotation');
const before = await sealedKeys(gC, cipher).seal('history');

// STALE STOPS: B's saved copy goes stale (it misses A's next change), then B tries to commit.
const staleSave = JSON.parse(JSON.stringify(await storeFor(B).load()));
await gA.load(); await gA.update();                 // the log moves on
const gBstale = groupFor(B); gBstale.member = null;
await storeFor(B).save(staleSave);
await gBstale.load();                               // catches up normally…
check(gBstale.inStep === ds[ds.length - 1].commit.treeHash, 'a device that was behind catches up and confirms');
// …but a device whose copy is DIFFERENT (not merely behind) must not post:
const tampered = groupFor(B); await tampered.load();
tampered.member.leaves[7].blank = false; tampered.member.leaves[7].pub = kp().pub;   // a diverged local tree
let refused = null; try { await tampered.addMember(X.addr, X.pub); } catch (e) { refused = e.code; }
check(refused === 'OUT_OF_STEP', 'a device whose tree is not the log\'s refuses to post (diligence at the source)');
const head = ds.length;

// SKIP: commits no in-step member will accept, posted by a writer running other code.
const lastHash = ds[head - 1].commit.treeHash;
// Each is genuinely signed by the member at its committer leaf, so it reaches the
// check it is here to exercise.
const leafB = Number(gA.leafDir[B.addr]);
await inject({ commit: { type: 'update', format: DS_FORMAT, committerLeafIndex: leafB, capacity: 8, parentHash: '0xdeadbeef', treeHash: '0x00', path: [] }, dir: { set: { ['0x' + 'ee'.repeat(20)]: 5 } } }, B);
await inject({ commit: { type: 'add', format: DS_FORMAT, committerLeafIndex: 0, capacity: 8, addLeafIndex: leafB, addPub: kp().pub, parentHash: lastHash, treeHash: '0x00', path: [] }, dir: { set: { ['0x' + 'dd'.repeat(20)]: 1 } } }, A);
await inject({ commit: { type: 'remove', format: DS_FORMAT, committerLeafIndex: 0, capacity: 8, removeLeafIndex: 6, parentHash: lastHash, treeHash: '0x00', path: [] }, dir: {} }, A);
for (const [name, k] of [['owner A', A], ['member C', C]]) {
  const g = groupFor(k); await g.load();
  check(!g.stuck && g.skipped.length === 3, `${name}: skips all three invalid commits, and is not stuck`);
  check(g.skipped[0].reason.includes('tree other than') && /occupied|already holds/.test(g.skipped[1].reason) && /holds no member/.test(g.skipped[2].reason), `${name}: says why each was skipped`);
  check(g.epoch() === ds.length && !Object.keys(g.leafDir).some((a) => a.startsWith('0xee') || a.startsWith('0xdd')), `${name}: follows the log's epochs, and no skipped commit touched the directory`);
  check((await sealedKeys(g, cipher).open(before)).ok && sealedKeys(g, cipher).ready, `${name}: keys unchanged — reads history, can write`);
}
// …and the group moves on: a valid commit after the skipped ones applies for everyone.
const gA2 = groupFor(A); await gA2.load(); await gA2.addMember(X.addr, X.pub);
const after = await sealedKeys(gA2, cipher).seal('after the skipped commits');
const gC2 = groupFor(C); await gC2.load();
check(!gC2.stuck && gC2.isSeated(X.addr) && (await sealedKeys(gC2, cipher).open(after)).ok, 'the next valid commit applies for every member');
stores.delete(X.addr);
const gX = groupFor(X); await gX.load();
check(!gX.stuck && gX.inStep && (await sealedKeys(gX, cipher).open(before)).ok, 'a newcomer after the skipped commits bootstraps confirmed, with the history');

// LEGACY: history from before format 3 carries no hashes and is replayed as it was
// applied — even a commit the new rules would reject (an add over an occupied leaf,
// which the library's log really contains at epoch 21). Judging it now would strand
// every device that replays that history.
{
  ds.length = 0; signers.length = 0; raws.length = 0; creds.length = 0; stores.clear();
  const L = kp(), M = kp(), N = kp();
  const gL = groupFor(L); await gL.create();
  await gL.addMember(M.addr, M.pub);
  // Strip to the old format — no format, no hashes, no credential — as history
  // written before these rules really is.
  ds.forEach((e, i) => { delete e.commit.format; delete e.commit.parentHash; delete e.commit.treeHash; raws[i] = null; creds[i] = null; });
  // An old-format add over M's occupied leaf, as the old code could post (non-rotating).
  const mLeaf = Number(gL.leafDir[M.addr]);
  ds.push({ commit: { type: 'add', committerLeafIndex: 0, capacity: 8, addLeafIndex: mLeaf, addPub: N.pub, path: [], welcome: null }, dir: { set: { [N.addr]: mLeaf } } }); signers.push(L.addr); raws.push(null); creds.push(null);
  stores.clear();   // M replays the whole log from its Welcome, as a device with no saved state does
  const gM = groupFor(M); await gM.load();
  check(!gM.stuck && gM.epoch() === ds.length, 'LEGACY: a device replaying old-format history applies a commit the new rules would reject, as it always did — not stuck');
}

console.log('\n' + (failures ? `DILIGENCE FAIL — ${failures}` : 'DILIGENCE PASS — invalid commits are refused at the source or skipped by everyone alike.'));
process.exit(failures ? 1 : 0);
