// Two instances of ONE rivet — two tabs, or two group objects in one tab — share a
// tree store. One commits a rotation (here the growth); the other, stale, catches
// up and meets its own commit in the log. It cannot open path secrets it did not
// generate, and used to apply it as a silent divergence: a placeholder key, the
// growth epoch missing from its keyring, then a plausible wrong key from the next
// rotation on. The library's 0x159a did exactly this at epoch 19.
//
//   REFUSE   Member.apply refuses a rotating commit from its own leaf, untouched
//   ADOPT    a stale DsGroup takes the committing twin's saved state and converges
//   NO COVER with no saved state that reaches the commit, catch-up fails loudly
//   REMOVED  a removed device's stale save reports NO_SEAT; added back, it bootstraps
//
//   node client-lib/ds-group.twin.test.mjs

globalThis.ethers = (await import('ethers')).ethers;
import { DsGroup, DS_FORMAT } from './ds-group.mjs';
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv, ecdh } from './treekem-kdf.mjs';
import { botSigner, credOf, anyoneMayCommit } from './ds-test-kit.mjs';

const E = globalThis.ethers;
let fails = 0;
const ok = (m) => console.log('  ok  : ' + m);
const bad = (m) => { console.log('  FAIL: ' + m); fails++; };
const stack = cryptoStack();
const rand = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); return b; };
const kp = () => { const priv = privFromSecret(rand()); const pub = pubFromPriv(priv); return { priv, pub, addr: E.utils.computeAddress(pub).toLowerCase() }; };
const clone = (o) => JSON.parse(JSON.stringify(o));

// ── the log: founder F seats 1..7; the TWIN rivet T is leaf 1 ─────────────────
const f = kp(), T = kp();
const F = new Member('F', 8, stack); F.seat(0, f.priv, f.pub);
const ds = []; const dir = {};
const push = (commit, d) => { ds.push({ epoch: ds.length + 1, commit, dir: d }); Object.assign(dir, d.set || {}); for (const a of d.del || []) delete dir[a]; };
push(await F.commit({ type: 'update' }), { set: { [f.addr]: 0 } });
let twinSeed = null;
for (let i = 1; i <= 7; i++) {
  const m = i === 1 ? T : kp();
  const c = await F.commit({ type: 'add', addLeafIndex: i, addPub: m.pub });
  push(c, { set: { [m.addr]: i } });
  if (i === 1) twinSeed = new Member('T', 8, stack), await twinSeed.applyWelcome(c.welcome, 1, T.priv);
  else await twinSeed.apply(c);
}

const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    if (Number(opts.headers['x-ds-format']) !== DS_FORMAT) return { ok: false, status: 426, json: async () => ({}) };
    if (Number(opts.headers['x-ds-epoch']) !== ds.length) return { ok: false, status: 409, json: async () => ({ current: ds.length }) };
    const env = dec(opts.body); push(env.commit, env.dir); Object.assign(ds[ds.length - 1], { raw: opts.body, cred: credOf(opts.headers.authorization) }); await F.apply(env.commit);
    return { ok: true, json: async () => ({ ok: true, epoch: ds.length }) };
  }
  if (/\/log\?/.test(url)) {
    const since = Number(new URL(url).searchParams.get('since') || 0);
    return { ok: true, json: async () => ds.filter(e => e.epoch > since).map(e => ({ epoch: e.epoch, cred: e.cred || null })) };
  }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => e.raw || enc({ commit: e.commit, dir: e.dir }) } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};

// ONE store for the rivet, as localStorage is one per browser.
let stored = { member: twinSeed.exportState(), leafDir: clone(dir) };
const sharedStore = { load: async () => clone(stored), save: async (s) => { stored = clone(s); } };
const twin = (store) => new DsGroup({ chain: anyoneMayCommit,
  relayUrl: 'https://x', contract: '0xc', session: '0xs',
  address: T.addr, rivetPriv: null, rivetPub: T.pub,
  sign: botSigner(T.priv, '0xc'), leafDecap: async (e) => ecdh(T.priv, e),
  stack, fetchImpl: fakeFetch, capacity: 8, store,
});

const A = twin(sharedStore), B = twin(sharedStore);
await A.load(); await B.load();                           // both at the same epoch
const stale = B.member.exportState();

// A commits the GROWTH (leaf 8 needs the tree doubled).
const X = kp();
await A.addMember(X.addr, X.pub);
const growth = ds[ds.length - 1];
growth.commit.grow ? ok(`A committed the growth at epoch ${growth.epoch}`) : bad('expected a growing add');

// REFUSE — a bare Member copy of the twin must refuse its own rotating commit.
const M = new Member('M', 8, stack); M.importState(stale, T.priv);
const before = M.epoch;
try { await M.apply(growth.commit); bad('twin applied its own rotating commit'); }
catch (e) { e.code === 'OWN_COMMIT' && M.epoch === before ? ok('Member refuses its own rotating commit, untouched') : bad(`wrong refusal: ${e.code} ${e.message}`); }

// ADOPT — the stale DsGroup B catches up (through its next commit) and converges.
const Y = kp();
await B.addMember(Y.addr, Y.pub);
B.groupKey() === F.groupKey ? ok('stale twin adopted the saved state and agrees with the founder') : bad('stale twin diverged');
B.keyForEpoch(growth.epoch) === F.keyForEpoch(growth.epoch) ? ok('its keyring carries the growth epoch') : bad('growth epoch missing from the twin keyring');
!String(B.groupKey()).startsWith('DIVERGED') ? ok('no placeholder key') : bad('placeholder key');

// NO COVER — a twin whose store never saw the commit does not guess. It loads
// STUCK at that commit (ds-group.wedge.test.mjs): readable up to the epoch before
// it, named OWN_COMMIT, and it neither seals nor commits.
const lonely = { member: stale, leafDir: clone(stored.leafDir) };
const C = twin({ load: async () => clone(lonely), save: async () => {} });
try {
  await C.load();
  C.stuck?.code === 'OWN_COMMIT' && C.stuck.epoch === growth.epoch && C.epoch() === growth.epoch - 1 && !String(C.groupKey()).startsWith('DIVERGED')
    ? ok('with no saved state reaching the commit, the twin is STUCK before it (OWN_COMMIT), not guessing')
    : bad(`expected STUCK at ${growth.epoch} with OWN_COMMIT, got ${JSON.stringify(C.stuck)} epoch ${C.epoch()}`);
} catch (e) { bad(`a twin without the committing state threw instead of loading stuck: ${e.code} ${e.message}`); }

// REMOVED — a device removed since its last save reloads that save. The catch-up
// applies its own removal (a quiet divergence, by design); load must not hand back
// that placeholder key as a readable group. It reports NO_SEAT, so the key-request
// starts; once added back, the same stale save bootstraps from the new Welcome.
const R = kp();
const cR = await F.commit({ type: 'add', addLeafIndex: 12, addPub: R.pub });
push(cR, { set: { [R.addr]: 12 } });
const rSave = (() => { const m = new Member('R', 8, stack); return m; })();
await rSave.applyWelcome(cR.welcome, 12, R.priv);
const rStored = { member: rSave.exportState(), leafDir: clone(dir) };
push(await F.commit({ type: 'remove', removeLeafIndex: 12 }), { del: [R.addr] });
const rGroup = () => new DsGroup({ chain: anyoneMayCommit,
  relayUrl: 'https://x', contract: '0xc', session: '0xs',
  address: R.addr, rivetPriv: null, rivetPub: R.pub,
  sign: botSigner(R.priv, '0xc'), leafDecap: async (e) => ecdh(R.priv, e),
  stack, fetchImpl: fakeFetch, capacity: 8, store: { load: async () => clone(rStored), save: async () => {} },
});
try { await rGroup().load(); bad('a removed device loaded its stale save as a readable group'); }
catch (e) { e.code === 'NO_SEAT' ? ok('removed device reports NO_SEAT, not a placeholder key') : bad(`wrong failure: ${e.code} ${e.message}`); }
const cR2 = await F.commit({ type: 'add', addLeafIndex: 13, addPub: R.pub });
push(cR2, { set: { [R.addr]: 13 } });
try {
  const g = rGroup(); const K = await g.load();
  K === F.groupKey ? ok('added back, the same stale save bootstraps from the new Welcome') : bad('re-added device got the wrong key');
} catch (e) { bad(`re-added device failed to load: ${e.code} ${e.message}`); }

console.log('\n' + (fails === 0 ? 'PASS' : `FAILED ${fails}`));
process.exit(fails === 0 ? 0 : 1);
