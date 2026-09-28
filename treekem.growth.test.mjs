// The tree GROWS: a full group doubles instead of refusing a member.
//
// "A session is that group small. A board is the same group at a thousand
// members" (EncryptedGroup). The v1 spike fixed the tree at 8 leaves and threw
// 'group at capacity', which is the one thing the tree was adopted to avoid.
//
//   node client-lib/treekem.growth.test.mjs

globalThis.ethers = (await import('ethers')).ethers;
import { Member } from './treekem.mjs';
import { DsGroup } from './ds-group.mjs';
import { anyoneMayCommit } from './ds-test-kit.mjs';
import { cryptoStack, privFromSecret, pubFromPriv, ecdh } from './treekem-kdf.mjs';

const E = globalThis.ethers;
const stack = cryptoStack();
const CAP = 8;
let fails = 0;
const ok = (m) => console.log('  ok  : ' + m);
const bad = (m) => { console.log('  FAIL: ' + m); fails++; };
const check = (c, m, extra) => (c ? ok(m) : bad(m + (extra ? ` — ${extra}` : '')));
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const kp = () => { const priv = privFromSecret(rand(32)); const pub = pubFromPriv(priv); return { priv, pub, addr: E.utils.computeAddress(pub) }; };
const lc = (a) => String(a).toLowerCase();

// ── a group that fills up, then grows ────────────────────────────────────────
const founderKp = kp();
const founder = new Member('founder', CAP, stack);
founder.seat(0, founderKp.priv, founderKp.pub);
const ds = [];
const push = (commit, dir) => ds.push({ epoch: ds.length + 1, commit, dir });
push(await founder.commit({ type: 'update' }), { set: { [lc(founderKp.addr)]: 0 } });

const members = [];   // { kp, m } seated members other than the founder
async function seat(leafIndex) {
  const k = kp();
  const commit = await founder.commit({ type: 'add', addLeafIndex: leafIndex, addPub: k.pub });
  for (const x of members) await x.m.apply(commit);           // everyone already seated
  const m = new Member(`m${leafIndex}`, CAP, stack);
  await m.applyWelcome(commit.welcome, leafIndex, k.priv);
  members.push({ kp: k, m, leafIndex });
  push(commit, { set: { [lc(k.addr)]: leafIndex } });
  return commit;
}

for (let i = 1; i <= 7; i++) await seat(i);
check(founder.capacity === 8, 'the tree holds 8 members without growing');
check(members.every((x) => x.m.groupKey === founder.groupKey), 'all 8 members share one key');

// Content sealed BEFORE the growth, to prove the past stays readable after it.
const preEpoch = founder.epoch;
const preKey = founder.groupKey;

// The 9th member: no free leaf, so this add must double the tree.
const ninth = await seat(8);
check(ninth.grow === true && ninth.capacity === 16, 'the 9th member grew the tree to 16', `grow=${ninth.grow} capacity=${ninth.capacity}`);
check(founder.capacity === 16, 'the committer is on the taller tree');
check(ninth.path.length > 0, 'the grown add rotated (the new root needed a secret)');
check(founder.groupKey !== preKey, 'growth minted a new epoch key');

const everyone = [{ m: founder }, ...members];
check(everyone.every((x) => x.m.groupKey === founder.groupKey), 'every member converged on the key after growth',
  everyone.map((x) => String(x.m.groupKey).slice(0, 10)).join(' '));
check(everyone.every((x) => x.m.capacity === 16), 'every member grew its own copy');
check(everyone.every((x) => x.m.keyForEpoch(preEpoch) === preKey), 'content sealed before the growth is still readable');

// ── the taller tree keeps working: seat the rest, then double again ──────────
for (let i = 9; i <= 15; i++) await seat(i);
check(founder.capacity === 16, 'leaves 9-15 filled without another growth');
const seventeenth = await seat(16);
check(seventeenth.grow === true && founder.capacity === 32, 'the 17th member grew the tree again, to 32');
check([{ m: founder }, ...members].every((x) => x.m.groupKey === founder.groupKey), 'all 17 members converged after the second growth');

// ── removal still cuts a member off, on the grown tree ───────────────────────
const victim = members.find((x) => x.leafIndex === 3);
const keyBefore = founder.groupKey;
const rm = await founder.commit({ type: 'remove', removeLeafIndex: 3 });
for (const x of members) if (x !== victim) await x.m.apply(rm);
await victim.m.apply(rm);
push(rm, { del: [lc(victim.kp.addr)] });
check(founder.groupKey !== keyBefore, 'removal rotated the key');
check(members.filter((x) => x !== victim).every((x) => x.m.groupKey === founder.groupKey), 'remaining members converged after a removal on the grown tree');
check(victim.m.groupKey !== founder.groupKey, 'the removed member cannot derive the new key');

// ── persistence across a growth ──────────────────────────────────────────────
const survivor = members.find((x) => x.leafIndex === 5);
const state = survivor.m.exportState();
const restored = new Member('restored', CAP, stack);      // a FRESH small tree
restored.importState(state, survivor.kp.priv);
check(restored.capacity === 32, 'restored state rebuilt the grown tree');
check(restored.groupKey === survivor.m.groupKey, 'restored member holds the same key');
const upd = await founder.commit({ type: 'update' });
await restored.apply(upd);
check(restored.groupKey === founder.groupKey, 'restored member keeps converging after restore');
for (const x of members) if (x !== victim && x !== survivor) await x.m.apply(upd);
push(upd, {});

// ── a fresh device bootstraps from a log that CONTAINS the growths ───────────
const newcomer = kp();
const addCommit = await founder.commit({ type: 'add', addLeafIndex: 17, addPub: newcomer.pub });
push(addCommit, { set: { [lc(newcomer.addr)]: 17 } });
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const fakeFetch = async (url) => {
  if (/\/log\?/.test(url)) return { ok: true, json: async () => ds.map((e) => ({ epoch: e.epoch, hash: '', signer: lc(founderKp.addr), prev: null, ts: 0 })) };
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return { ok: true, status: 200, arrayBuffer: async () => enc({ commit: e.commit, dir: e.dir }) }; }
  return { ok: false, status: 404 };
};
const group = new DsGroup({ chain: anyoneMayCommit,
  relayUrl: 'https://x', contract: '0xc', session: '0xs',
  address: newcomer.addr, rivetPriv: null, rivetPub: newcomer.pub,
  sign: async () => 'unused', leafDecap: async (encHex) => ecdh(newcomer.priv, encHex),
  stack, store: null, fetchImpl: fakeFetch, capacity: CAP,
});
try {
  const K = await group.load();
  check(K === founder.groupKey, 'a fresh device bootstrapped through two growths and converged', `${String(K).slice(0, 12)} vs ${String(founder.groupKey).slice(0, 12)}`);
} catch (e) {
  bad(`bootstrap through growth THREW: ${e.message} [${e.epLabel || '-'}]`);
}

console.log('\n' + (fails === 0 ? 'GROWTH PASS — a full group doubles and every member follows.' : `GROWTH FAIL — ${fails} failing`));
process.exit(fails ? 1 : 0);
