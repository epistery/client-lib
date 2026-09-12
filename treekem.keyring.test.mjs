// Isolation proof for the Epoch Keyring (step 1 of the rotation-orphaning fix).
//
// Exercises client-lib/treekem.mjs ALONE — no ds-group, no plugins, no relay.
// It proves the one new claim and guards the properties that must NOT regress:
//
//   CONVERGE   after every commit, all CURRENT members share one current key
//   CARRY      after a rotation, a member who STAYED still decrypts content
//              sealed under the pre-rotation key (THE FIX — this failed before)
//   WHOLE-PAST a member added AFTER a rotation reads content from before it
//              joined, via the ring sealed into its Welcome
//   FORWARD    a removed member cannot decrypt content written after its removal
//   PERSIST    exportState/importState round-trips the ring
//   ROLLBACK   importState REPLACES the ring, dropping a speculative epoch entry
//
//   node client-lib/treekem.keyring.test.mjs

globalThis.ethers = (await import('ethers')).ethers;   // treekem-kdf reads globalThis.ethers
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';

const CAP = 8;
let failures = 0;
const ok   = (m) => console.log('  ok  : ' + m);
const fail = (m) => { console.log('  FAIL: ' + m); failures++; };
const check = (cond, m) => cond ? ok(m) : fail(m);

const rand = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; };
const newRivet = () => { const priv = privFromSecret(rand(32)); return { priv, pub: pubFromPriv(priv) }; };
const hexToBytes = (h) => { h = String(h).replace(/^0x/, ''); const u = new Uint8Array(h.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; };
const toHex = (u) => '0x' + [...new Uint8Array(u)].map((b) => b.toString(16).padStart(2, '0')).join('');

// A "record": ciphertext + the epoch tag the writer stamped (mechanism #2).
async function seal(member, text) {
  const keyHex = member.keyForEpoch(member.epoch);   // == current key at write time
  const key = await crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { epoch: member.epoch, iv: toHex(iv), ct: toHex(ct) };
}
// Read = tag lookup (mechanism #2 + #1). Returns null if this member can't open it.
async function open(member, rec) {
  const keyHex = member.keyForEpoch(rec.epoch);
  if (!keyHex || keyHex.startsWith('DIVERGED')) return null;
  try {
    const key = await crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(rec.iv) }, key, hexToBytes(rec.ct));
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

// --- a minimal group harness over Member, mirroring the ds-group usage ---------
class Sim {
  constructor(stack) { this.stack = stack; this.members = []; this.free = []; for (let i = CAP - 1; i >= 1; i--) this.free.push(i); this.removed = []; }
  async create() {
    const m = new Member('founder', CAP, this.stack);
    const r = newRivet(); m.seat(0, r.priv, r.pub);
    await m.commit({ type: 'update' });              // establish epoch 1
    const e = { member: m, rivet: r, leaf: 0 }; this.members.push(e); return e;
  }
  async add(committer, name) {
    const leaf = this.free.pop();
    const r = newRivet();
    const commit = await committer.member.commit({ type: 'add', addLeafIndex: leaf, addPub: r.pub });
    const joiner = new Member(name, CAP, this.stack);
    await joiner.applyWelcome(commit.welcome, leaf, r.priv);   // lands live; ring loaded from Welcome
    for (const e of this.members) if (e !== committer) await e.member.apply(commit);
    const e = { member: joiner, rivet: r, leaf }; this.members.push(e); return e;
  }
  async remove(committer, victim) {
    const commit = await committer.member.commit({ type: 'remove', removeLeafIndex: victim.member.leafIndex });
    for (const e of this.members) if (e !== committer && e !== victim) await e.member.apply(commit);
    await victim.member.apply(commit);               // victim diverges (cannot open)
    this.members = this.members.filter((e) => e !== victim);
    this.free.push(victim.leaf); this.removed.push(victim);
  }
  converged() {
    if (!this.members.length) return true;
    const k = this.members[0].member.groupKey, ep = this.members[0].member.epoch;
    return this.members.every((e) => e.member.groupKey === k && e.member.epoch === ep);
  }
}

// ============================ scenario ========================================
console.log('\n[keyring] scripted scenario');
const s = new Sim(cryptoStack());
const founder = await s.create();
const doc1 = await seal(founder.member, 'DOC-1 written at epoch 1 (K1)');

const alice = await s.add(founder, 'alice');
check(s.converged(), 'create + add converge (one current key)');
const doc2 = await seal(alice.member, 'DOC-2 written after a non-rotating add (still K1)');

// A non-rotating add must NOT have grown the ring (adds reuse the current key).
check(founder.member.keyring.size === 1, 'add did not grow the keyring (only rotations do)');

// ---- the rotation: founder removes alice ----
const bob = await s.add(founder, 'bob');            // add bob so a member remains besides founder
await s.remove(founder, alice);
check(s.converged(), 'remaining members converge after remove');
check(founder.member.keyring.size === 2, 'remove grew the keyring to 2 (K1 + K2)');
check(founder.member.groupKey !== founder.member.keyForEpoch(1), 'rotation produced a new current key');

// THE FIX: a member who stayed still reads content sealed under the pre-rotation key.
check((await open(founder.member, doc1)) === 'DOC-1 written at epoch 1 (K1)', 'CARRY: founder still reads DOC-1 after rotation');
check((await open(bob.member, doc2)) === 'DOC-2 written after a non-rotating add (still K1)', 'CARRY: bob still reads DOC-2 after rotation');

// A doc written AFTER the rotation, under the new key.
const doc3 = await seal(founder.member, 'DOC-3 written at the post-removal epoch (K2)');
check((await open(bob.member, doc3)) === 'DOC-3 written at the post-removal epoch (K2)', 'members read post-rotation content');

// WHOLE-PAST: a newcomer added after the rotation reads everything, pre-join included.
const zoe = await s.add(founder, 'zoe');
check((await open(zoe.member, doc1)) === 'DOC-1 written at epoch 1 (K1)', 'WHOLE-PAST: zoe reads pre-join DOC-1 (K1)');
check((await open(zoe.member, doc3)) === 'DOC-3 written at the post-removal epoch (K2)', 'WHOLE-PAST: zoe reads DOC-3 (K2)');
check(zoe.member.keyring.size === 2, 'zoe received the full ring in her Welcome');

// FORWARD SECRECY: the removed member cannot read content written after removal.
check((await open(alice.member, doc3)) === null, 'FORWARD: removed alice cannot read post-removal DOC-3');
check(alice.member.groupKey !== founder.member.groupKey, 'FORWARD: removed alice does not hold the live key');
// (What she already had, she keeps — that was never recoverable and is not the claim.)
check((await open(alice.member, doc1)) === 'DOC-1 written at epoch 1 (K1)', 'removed alice still reads what she saw before removal (expected)');

// ============================ persistence =====================================
console.log('\n[keyring] persistence + rollback');
{
  const state = founder.member.exportState();
  const restored = new Member('founder-restored', CAP, cryptoStack());
  restored.importState(state, founder.rivet.priv);
  check(restored.keyring.size === founder.member.keyring.size, 'PERSIST: ring survives export/import');
  check((await open(restored, doc1)) === 'DOC-1 written at epoch 1 (K1)', 'PERSIST: restored member reads DOC-1 (K1)');
  check((await open(restored, doc3)) === 'DOC-3 written at the post-removal epoch (K2)', 'PERSIST: restored member reads DOC-3 (K2)');

  // ROLLBACK: a speculative rotation grows the ring; importState must drop it.
  const snapshot = restored.exportState();
  const sizeBefore = restored.keyring.size;
  await restored.commit({ type: 'update' });         // speculative — as _commitWithRebase does before a DS post
  check(restored.keyring.size === sizeBefore + 1, 'speculative rotation grew the ring by one');
  restored.importState(snapshot, founder.rivet.priv);
  check(restored.keyring.size === sizeBefore, 'ROLLBACK: importState dropped the speculative epoch entry');
}

console.log('\n' + (failures === 0
  ? 'KEYRING PASS — rotation carries the past: continuing members and newcomers read across epochs, removed members do not read the future.'
  : `KEYRING FAIL — ${failures} check(s) failed.`));
process.exit(failures === 0 ? 0 : 1);
