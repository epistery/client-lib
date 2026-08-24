// Contract proof for step 2 — the ctx.keys shape + the record epoch-tag.
//
// Step 1 proved the ring inside Member. This proves the INTERFACE the plugins
// depend on: the exact `ctx.keys` object SessionView builds over the session
// group, and the write/read pattern every plugin now uses —
//     write: { epoch: ctx.keys.epoch, ...encrypt(ctx.keys.K) }
//     read : decrypt(ctx.keys.keyFor(rec.epoch), rec)
// — decrypts correctly across a rotation, for stayers, newcomers, and untagged
// legacy records.
//
//   node client-lib/treekem.ctx-contract.test.mjs

globalThis.ethers = (await import('ethers')).ethers;
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';

const CAP = 8;
let failures = 0;
const check = (cond, m) => cond ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const newRivet = () => { const priv = privFromSecret(rand(32)); return { priv, pub: pubFromPriv(priv) }; };
const hexToBytes = (h) => { h = String(h).replace(/^0x/, ''); const u = new Uint8Array(h.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; };
const toHex = (u) => '0x' + [...new Uint8Array(u)].map((b) => b.toString(16).padStart(2, '0')).join('');

// The DsGroup facade the ctx is built over: three accessors (groupKey/epoch are
// methods on DsGroup; on a bare Member they are properties — wrap them).
const facade = (m) => ({ groupKey: () => m.groupKey, epoch: () => m.epoch, keyForEpoch: (e) => m.keyForEpoch(e) });

// EXACTLY the ctx.keys object SessionView._ctx builds.
const ctxKeys = (group) => ({
  get K() { return group.groupKey(); },
  get epoch() { return group.epoch(); },
  keyFor: (epoch) => group.keyForEpoch(epoch),
});

// The plugin write/read pattern, verbatim in shape.
async function writeDoc(keys, text) {
  const key = await crypto.subtle.importKey('raw', hexToBytes(keys.K), { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { epoch: keys.epoch, iv: toHex(iv), ciphertext: toHex(ct) };   // ← the record shape now stored
}
async function readDoc(keys, rec) {
  const keyHex = keys.keyFor(rec.epoch);   // ← the read path: key selected by the record's tag
  if (!keyHex || keyHex.startsWith('DIVERGED')) return null;
  try {
    const key = await crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(rec.iv) }, key, hexToBytes(rec.ciphertext));
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

const stack = cryptoStack();
const members = [];                       // { m, rivet, leaf }
const free = []; for (let i = CAP - 1; i >= 1; i--) free.push(i);
const add = async (committer, name) => {
  const leaf = free.pop(); const r = newRivet();
  const commit = await committer.m.commit({ type: 'add', addLeafIndex: leaf, addPub: r.pub });
  const j = new Member(name, CAP, stack); await j.applyWelcome(commit.welcome, leaf, r.priv);
  for (const e of members) if (e !== committer) await e.m.apply(commit);
  const e = { m: j, rivet: r, leaf }; members.push(e); return e;
};
const remove = async (committer, victim) => {
  const commit = await committer.m.commit({ type: 'remove', removeLeafIndex: victim.m.leafIndex });
  for (const e of members) if (e !== committer && e !== victim) await e.m.apply(commit);
  await victim.m.apply(commit);
  members.splice(members.indexOf(victim), 1); free.push(victim.leaf);
};

console.log('\n[ctx-contract] plugin write/read across a rotation');

// founder + epoch 1
const fr = newRivet(); const fm = new Member('founder', CAP, stack); fm.seat(0, fr.priv, fr.pub);
await fm.commit({ type: 'update' });
const founder = { m: fm, rivet: fr, leaf: 0 }; members.push(founder);

const fKeys = ctxKeys(facade(founder.m));
const doc1 = await writeDoc(fKeys, 'ctx doc-1 at epoch 1');

const alice = await add(founder, 'alice');
const doc2 = await writeDoc(fKeys, 'ctx doc-2 after a non-rotating add');

// A legacy record written now under the current key, but with NO epoch tag.
const legacy = await writeDoc(fKeys, 'untagged legacy record'); delete legacy.epoch;
check(legacy.epoch === undefined, 'legacy record carries no epoch tag');
check((await readDoc(fKeys, legacy)) === 'untagged legacy record', 'MIGRATION: untagged record reads via the current key');

// rotate: founder removes alice (bob stays so a member remains)
const bob = await add(founder, 'bob');
await remove(founder, alice);

// The plugin ctx reads across the rotation.
check((await readDoc(fKeys, doc1)) === 'ctx doc-1 at epoch 1', 'stayer ctx reads doc-1 (K1) after rotation');
check((await readDoc(ctxKeys(facade(bob.m)), doc2)) === 'ctx doc-2 after a non-rotating add', 'stayer ctx reads doc-2 (K1) after rotation');

const doc3 = await writeDoc(fKeys, 'ctx doc-3 at the post-removal epoch');
check((await readDoc(ctxKeys(facade(bob.m)), doc3)) === 'ctx doc-3 at the post-removal epoch', 'ctx reads post-rotation doc-3 (K2)');

// newcomer after the rotation: her ctx reads the whole past.
const zoe = await add(founder, 'zoe');
const zKeys = ctxKeys(facade(zoe.m));
check((await readDoc(zKeys, doc1)) === 'ctx doc-1 at epoch 1', 'newcomer ctx reads pre-join doc-1 (K1)');
check((await readDoc(zKeys, doc3)) === 'ctx doc-3 at the post-removal epoch', 'newcomer ctx reads doc-3 (K2)');

// removed member's ctx cannot read post-removal content.
check((await readDoc(ctxKeys(facade(alice.m)), doc3)) === null, 'removed member ctx cannot read post-removal doc-3');

console.log('\n' + (failures === 0
  ? 'CTX-CONTRACT PASS — the ctx.keys shape + record epoch-tag decrypt correctly across rotation for every role.'
  : `CTX-CONTRACT FAIL — ${failures} check(s) failed.`));
process.exit(failures === 0 ? 0 : 1);
