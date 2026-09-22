// The library bug, through the real DsGroup load()/addMember() path: a founder
// resumes from a tree snapshot saved by a client that predates growth.
//
// Epoch 19 grew the tree (8 → 16) seating X at leaf 8; epoch 20 seated Y at 9.
// A tab still running pre-growth code applied 19 as a plain add — tree left at
// 8 leaves, no `capacity` in its export — and persisted "epoch 20". Current code
// then resumed from that snapshot, `_nextLeaf` returned `capacity` (8) without
// looking at the directory, and epoch 21 seated Z over X, growing 8 → 16 again.
//
//   STALE      that snapshot now refuses to load (OUT_OF_STEP) — it never commits
//   ALLOCATE   an in-step founder seats Z at the first FREE leaf (10), not 8
//   REUSE      a blank left by a removal is still reused first
//   REBASE     a lost race re-picks the leaf and rolls a grown tree back cleanly
//   DOUBLE     removing a stale directory claim leaves the leaf's occupant seated
//   IDEMPOTENT re-adding a seated member commits nothing
//   SHAPE      a snapshot with a taller tree's nodes but no capacity is refused
//   CLAIM      a directory entry at an empty leaf neither blocks loading nor counts
//              as a seat, and the claimant can be seated again
//
//   node client-lib/ds-group.leafgrow.test.mjs

globalThis.ethers = (await import('ethers')).ethers;
import { DsGroup, DS_FORMAT } from './ds-group.mjs';
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';

const E = globalThis.ethers;
let fails = 0;
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const kp = () => { const priv = privFromSecret(rand(32)); const pub = pubFromPriv(priv); return { priv, pub, addr: E.utils.computeAddress(pub).toLowerCase() }; };
const ok = (m) => console.log('  ok  : ' + m);
const bad = (m) => { console.log('  FAIL: ' + m); fails++; };
const stack = cryptoStack();
const clone = (o) => JSON.parse(JSON.stringify(o));

// ── the log: founder seats 1..7, then X@8 (the growth), then Y@9 ──────────────
const founder = kp();
const fm = new Member('founder', 8, stack);
fm.seat(0, founder.priv, founder.pub);
const ds = [];
const dir = {};
const push = (commit, d) => { ds.push({ epoch: ds.length + 1, commit, dir: d }); Object.assign(dir, d.set || {}); };
// The OBSERVER (leaf 1) joins by Welcome and applies every later commit: the
// independent check that a committer's K is the group's K.
let obs = null;
const observe = async (commit) => { if (obs) await obs.apply(commit); };
push(await fm.commit({ type: 'update' }), { set: { [founder.addr]: 0 } });
for (let i = 1; i <= 7; i++) {
  const m = kp();
  const c = await fm.commit({ type: 'add', addLeafIndex: i, addPub: m.pub });
  push(c, { set: { [m.addr]: i } });
  if (i === 1) { obs = new Member('observer', 8, stack); await obs.applyWelcome(c.welcome, 1, m.priv); }
  else await observe(c);
}
const preGrowth = { member: fm.exportState(), leafDir: clone(dir) };          // 8 leaves, epoch 8
const X = kp(), Y = kp();
for (const [who, at] of [[X, 8], [Y, 9]]) {
  const c = await fm.commit({ type: 'add', addLeafIndex: at, addPub: who.pub });
  push(c, { set: { [who.addr]: at } }); await observe(c);
}
const current = { member: fm.exportState(), leafDir: clone(dir) };           // 16 leaves, epoch 10

// ── a fake blind DS: /log, /commit/{n}, POST /commit (optionally losing races) ─
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));
let loseRaces = 0;
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    const base = Number(opts.headers['x-ds-epoch']);
    // The relay refuses a commit that does not declare its format (426).
    if (Number(opts.headers['x-ds-format']) !== DS_FORMAT) { bad(`commit sent without x-ds-format ${DS_FORMAT}`); return { ok: false, status: 426, json: async () => ({}) }; }
    if (loseRaces > 0) {
      // The observer commits first: a plain add of W at the next free leaf.
      loseRaces--;
      const W = kp(); const at = Math.max(...Object.values(dir)) + 1;
      push(await obs.commit({ type: 'add', addLeafIndex: at, addPub: W.pub }), { set: { [W.addr]: at } });
      return { ok: false, status: 409, json: async () => ({ current: ds.length }) };
    }
    if (base !== ds.length) return { ok: false, status: 409, json: async () => ({ current: ds.length }) };
    const env = dec(opts.body);
    push(env.commit, env.dir);
    await observe(env.commit);
    return { ok: true, json: async () => ({ ok: true, epoch: ds.length }) };
  }
  if (/\/log\?/.test(url)) {
    const since = Number(new URL(url).searchParams.get('since') || 0);
    return { ok: true, json: async () => ds.filter(e => e.epoch > since).map(e => ({ epoch: e.epoch })) };
  }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => enc({ commit: e.commit, dir: e.dir }) } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const groupFrom = (saved) => new DsGroup({
  relayUrl: 'https://x', contract: '0xc', session: '0xs',
  address: founder.addr, rivetPriv: founder.priv, rivetPub: founder.pub,
  sign: async () => 'Bot test', stack, fetchImpl: fakeFetch, capacity: 8,
  store: { load: async () => clone(saved), save: async () => {} },
});

// STALE — what pre-growth code left behind: 8 leaves, no capacity, epoch 10,
// and a directory that names X@8 and Y@9.
const stale = clone(preGrowth);
delete stale.member.capacity;
stale.member.epoch = current.member.epoch;
stale.leafDir = clone(current.leafDir);
try {
  await groupFrom(stale).load();
  bad('a pre-growth snapshot loaded — it would go on to commit over leaf 8');
} catch (e) {
  e.code === 'OUT_OF_STEP' ? ok('pre-growth snapshot refused: OUT_OF_STEP') : bad(`wrong failure: ${e.message}`);
}

// ALLOCATE — an in-step founder seats Z at the first free leaf.
const g = groupFrom(current);
await g.load();
const Z = kp();
await g.addMember(Z.addr, Z.pub);
g.leafDir[Z.addr] === 10 ? ok('Z seated at leaf 10 — X@8 and Y@9 untouched') : bad(`Z seated at ${g.leafDir[Z.addr]}`);
g.groupKey() === obs.groupKey ? ok('committer and observer agree on K') : bad('K diverged after the add');

// REUSE — a removed member's leaf is taken first.
await g.removeMember(X.addr);
const V = kp();
await g.addMember(V.addr, V.pub);
g.leafDir[V.addr] === 8 ? ok('freed leaf 8 reused') : bad(`V seated at ${g.leafDir[V.addr]}, expected 8`);

// REBASE — lose a race: the concurrent add takes the leaf this add first picked.
loseRaces = 1;
const U = kp();
await g.addMember(U.addr, U.pub);
const taken = Object.entries(g.leafDir).filter(([, l]) => l === g.leafDir[U.addr]);
taken.length === 1 ? ok(`after a lost race U took its own leaf (${g.leafDir[U.addr]})`) : bad(`U shares leaf ${g.leafDir[U.addr]} with ${taken.length - 1} other(s)`);
g.groupKey() === obs.groupKey ? ok('committer and observer agree on K after the rebase') : bad('K diverged after the rebase');

// DOUBLE CLAIM — what epoch 21 left: two directory entries on one leaf, only
// one of them seated. Removing the stale one must not evict the occupant.
const T = kp(), S = kp();
const at = Math.max(...Object.values(dir)) + 1;
const cT = await obs.commit({ type: 'add', addLeafIndex: at, addPub: T.pub });
push(cT, { set: { [S.addr]: at, [T.addr]: at } });   // S's claim is stale; T sits at `at`
await g.removeMember(S.addr);
const last = ds[ds.length - 1];
last.commit.type === 'update' ? ok('stale claim removed by a directory-only update') : bad(`stale claim removed with a ${last.commit.type} commit`);
g.leafDir[S.addr] === undefined && g.leafDir[T.addr] === at && !g.member.leaves[at].blank
  ? ok(`occupant T still seated at leaf ${at}`) : bad('the occupant lost its seat');
g.groupKey() === obs.groupKey ? ok('committer and observer agree on K after the correction') : bad('K diverged after the correction');
await g.removeMember(T.addr);
ds[ds.length - 1].commit.type === 'remove' && g.member.leaves[at].blank
  ? ok('the real occupant is removed with a rotating remove') : bad('occupant removal did not blank its leaf');

// IDEMPOTENT — re-adding an address that already holds its leaf commits nothing
// (concurrent responders used to seat one address over and over).
const before = ds.length;
await g.addMember(Z.addr, Z.pub);
ds.length === before ? ok('re-adding a seated member is a no-op') : bad(`re-add committed ${ds.length - before} time(s)`);

// SHAPE — a snapshot carrying a taller tree's nodes but no capacity is refused,
// not loaded as the short tree with half its nodes dropped.
const shapeless = clone(current);
delete shapeless.member.capacity;
try { await groupFrom(shapeless).load(); bad('a shapeless snapshot loaded'); }
catch (e) { e.code === 'OUT_OF_STEP' ? ok('shapeless snapshot refused: OUT_OF_STEP') : bad(`wrong failure: ${e.message}`); }

// STALE CLAIM — what epoch 22 left: the directory names a leaf a remove blanked.
// Shared by every device, so it must not block loading, and is not a seat.
const latest = { member: g.member.exportState(), leafDir: clone(g.leafDir) };   // the founder's last save
const R = kp();
const atR = Math.max(...Object.values(dir)) + 1;
const cR = await obs.commit({ type: 'add', addLeafIndex: atR, addPub: R.pub });
push(cR, { set: { [R.addr]: atR } });
const cRm = await obs.commit({ type: 'remove', removeLeafIndex: atR });
push(cRm, {});                                   // the directory keeps R's claim
const g2 = groupFrom(latest);   // the same founder, resuming: catches up on the observer's commits
try {
  await g2.load();
  ok('a stale claim at an empty leaf does not block loading');
  !g2.isSeated(R.addr) ? ok('the stale claimant is not counted as seated') : bad('stale claim counted as a seat');
  await g2.addMember(R.addr, R.pub);
  g2.isSeated(R.addr) && g2.groupKey() === obs.groupKey ? ok(`the claimant is re-seated for real (leaf ${g2.leafDir[R.addr]})`) : bad('re-seat failed');
} catch (e) { bad(`load with a stale claim threw: ${e.message}`); }

console.log('\n' + (fails === 0 ? 'PASS' : `FAILED ${fails}`));
process.exit(fails === 0 ? 0 : 1);
