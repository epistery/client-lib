// The us-wiki bug, through the real DsGroup.load() path: leaf REUSE.
//
// bot1 added@leaf1 → removed → the PHONE added@leaf1 (reusing it) → bot2 added@2
// → removed. The phone (non-extractable) bootstraps. `_bootstrapFromWelcome` used
// to pick the FIRST add at leaf 1 (bot1's Welcome, sealed to bot1's key) → the
// phone's aeadDecrypt failed on Welcome.initBox. The fix selects the add at my
// leaf sealed to MY pubkey. This drives the whole load() through a fake DS.
//
//   node client-lib/ds-group.leafreuse.test.mjs

globalThis.ethers = (await import('ethers')).ethers;
import { DsGroup } from './ds-group.mjs';
import { anyoneMayCommit } from './ds-test-kit.mjs';
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv, ecdh } from './treekem-kdf.mjs';

const E = globalThis.ethers;
const CAP = 8;
let fails = 0;
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const kp = () => { const priv = privFromSecret(rand(32)); const pub = pubFromPriv(priv); return { priv, pub, addr: E.utils.computeAddress(pub) }; };
const lc = (a) => String(a).toLowerCase();
const ok = (m) => console.log('  ok  : ' + m);
const bad = (m) => { console.log('  FAIL: ' + m); fails++; };
const stack = cryptoStack();

// ── build the real commit log with a founder Member, capturing {commit, dir} ──
const founder = kp();
const fm = new Member('founder', CAP, stack);
fm.seat(0, founder.priv, founder.pub);
const ds = [];   // [{epoch, commit, dir}]
const push = (commit, dir) => ds.push({ epoch: ds.length + 1, commit, dir });

push(await fm.commit({ type: 'update' }), { set: { [lc(founder.addr)]: 0 } });          // 1
const bot1 = kp();
push(await fm.commit({ type: 'add', addLeafIndex: 1, addPub: bot1.pub }), { set: { [lc(bot1.addr)]: 1 } }); // 2
push(await fm.commit({ type: 'remove', removeLeafIndex: 1 }), { del: [lc(bot1.addr)] });  // 3
const phone = kp();
push(await fm.commit({ type: 'add', addLeafIndex: 1, addPub: phone.pub }), { set: { [lc(phone.addr)]: 1 } }); // 4  ← REUSE
const bot2 = kp();
push(await fm.commit({ type: 'add', addLeafIndex: 2, addPub: bot2.pub }), { set: { [lc(bot2.addr)]: 2 } }); // 5
push(await fm.commit({ type: 'remove', removeLeafIndex: 2 }), { del: [lc(bot2.addr)] });  // 6
const founderK = fm.groupKey;
console.log('founder final K:', founderK.slice(0, 14), '… ; bot1 addPub≠phone:', lc(bot1.pub) !== lc(phone.pub));

// ── a fake blind DS: serves /log and /commit/{n} from the captured commits ──────
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const fakeFetch = async (url) => {
  if (/\/log\?/.test(url)) return { ok: true, json: async () => ds.map(e => ({ epoch: e.epoch, hash: '', signer: lc(founder.addr), prev: null, ts: 0 })) };
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = ds[Number(m[1]) - 1]; return { ok: true, status: 200, arrayBuffer: async () => enc({ commit: e.commit, dir: e.dir }) }; }
  return { ok: false, status: 404 };
};

// ── the PHONE loads as a non-extractable rivet, leaf reused before it ──────────
const group = new DsGroup({ chain: anyoneMayCommit,
  relayUrl: 'https://x', contract: '0xcontract', session: '0xsession',
  address: phone.addr, rivetPriv: null, rivetPub: phone.pub,
  sign: async () => 'unused-in-load', leafDecap: async (encHex) => ecdh(phone.priv, encHex),
  stack, store: null, fetchImpl: fakeFetch, capacity: CAP,
});

try {
  const K = await group.load();
  if (K === founderK) ok('phone bootstrapped through a REUSED leaf and converged to the founder key');
  else bad(`bootstrapped but wrong key: ${K?.slice(0, 18)} vs founder ${founderK.slice(0, 18)}`);
} catch (e) {
  bad(`load() THREW: ${e.message}  [epLabel=${e.epLabel || '-'}]  ← the leaf-reuse bug`);
}

console.log('\n' + (fails === 0
  ? 'PASS — leaf-reuse bootstrap selects the RIGHT Welcome (fixed).'
  : `FAIL — leaf-reuse bug present (${fails}).`));
process.exit(fails === 0 ? 0 : 1);
