// The one seal/open mechanism (sealed.mjs) over a real TreeKEM group, across a
// key rotation, with the browser cipher.
//
//   node client-lib/sealed.test.mjs
//
// What it proves: seal() always stamps the epoch of the key it used; open() reads
// by that epoch across a rotation; an untagged record is never opened with a
// guessed key; a nested value inherits its record's epoch but its own wins; and
// every failure comes back as a named cause, never a throw and never a string
// that looks like content.

import { ethers } from 'ethers';
globalThis.ethers = ethers;
globalThis.window ??= globalThis;          // cipher.mjs reads window.ethers
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';
import { sealedKeys } from './sealed.mjs';
import * as cipher from './cipher.mjs';

const CAP = 8;
let failures = 0;
const check = (cond, m) => cond ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const newRivet = () => { const priv = privFromSecret(rand(32)); return { priv, pub: pubFromPriv(priv) }; };
const facade = (m) => ({ groupKey: () => m.groupKey, epoch: () => m.epoch, keyForEpoch: (e) => m.keyForEpoch(e) });

const stack = cryptoStack();
const members = [];
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

console.log('\n[sealed] seal/open across a rotation');

const fr = newRivet(); const fm = new Member('founder', CAP, stack); fm.seat(0, fr.priv, fr.pub);
await fm.commit({ type: 'update' });
const founder = { m: fm, rivet: fr, leaf: 0 }; members.push(founder);
const keys = sealedKeys(facade(founder.m), cipher);

// seal stamps the epoch of the key it used
const doc1 = await keys.seal('doc-1');
check(doc1.epoch === founder.m.epoch && typeof doc1.iv === 'string' && typeof doc1.ciphertext === 'string', `seal() stamps the current epoch (${doc1.epoch})`);
check((await keys.open(doc1)).text === 'doc-1', 'open() reads what seal() wrote');

// nested: inherits the record tag; its own tag wins
const nested = { epoch: doc1.epoch, enc: await keys.seal('nested') };
const bare = { iv: nested.enc.iv, ciphertext: nested.enc.ciphertext };
check((await keys.open(bare, { parentEpoch: nested.epoch })).text === 'nested', 'a nested value without a tag opens under its record epoch');
check((await keys.open(bare)).cause === 'untagged', 'the same value with no tag at any level is "untagged", not opened');

// untagged is never opened with a guessed key
const legacy = { ...(await keys.seal('legacy')) }; delete legacy.epoch;
const r0 = await keys.open(legacy);
check(!r0.ok && r0.cause === 'untagged', 'STRICT: an untagged record is refused before any rotation');

const alice = await add(founder, 'alice');
const bob = await add(founder, 'bob');
const doc2 = await keys.seal('doc-2 after non-rotating adds');
await remove(founder, alice);   // ROTATION

const doc3 = await keys.seal('doc-3 after the rotation');
check(doc3.epoch > doc2.epoch, `the rotation moves seal() to a new epoch (${doc2.epoch} → ${doc3.epoch})`);
const bobKeys = sealedKeys(facade(bob.m), cipher);
check((await bobKeys.open(doc1)).text === 'doc-1', 'a stayer opens pre-rotation doc-1 by its epoch');
check((await bobKeys.open(doc2)).text === 'doc-2 after non-rotating adds', 'a stayer opens doc-2 by its epoch');
check((await bobKeys.open(doc3)).text === 'doc-3 after the rotation', 'a stayer opens post-rotation doc-3');
const r1 = await bobKeys.open(legacy);
check(!r1.ok && r1.cause === 'untagged', 'STRICT after rotation: untagged is still refused, never opened with the new key');

// own tag wins over a parent's older tag (a re-sealed nested value inside an old record)
const resealedInside = { epoch: doc1.epoch, name: await keys.seal('renamed after rotation') };
check((await bobKeys.open(resealedInside.name, { parentEpoch: resealedInside.epoch })).text === 'renamed after rotation', "a nested value's own epoch wins over its parent's");

// the removed member cannot read what was sealed after it left
const aliceKeys = sealedKeys(facade(alice.m), cipher);
const r2 = await aliceKeys.open(doc3);
check(!r2.ok, `a removed member cannot open post-removal content (${r2.cause})`);

// failures are named causes, never throws
const noGroup = sealedKeys(null, cipher);
check(!noGroup.ready && (await noGroup.open(doc1)).cause === 'no-key', 'no group: ready=false, open() → "no-key"');
let threw = false; try { await noGroup.seal('x'); } catch { threw = true; }
check(threw, 'no group: seal() throws rather than write anything');
check((await keys.open({ ...doc1, epoch: 0 })).cause === 'untagged', 'epoch 0 is not a key epoch');
check((await keys.open({ plain: 'text' })).cause === 'not-sealed', 'plain data is "not-sealed"');
const tampered = { ...doc3, ciphertext: doc3.ciphertext.slice(0, -2) + (doc3.ciphertext.endsWith('00') ? '11' : '00') };
const r3 = await keys.open(tampered);
check(!r3.ok && r3.cause === 'not-opened', 'damaged ciphertext is "not-opened" (GCM refuses it)');
check(typeof r3.message === 'string' && !('text' in r3), 'a failure carries a message and no text — nothing to mistake for content');

// blobs
const bytes = new TextEncoder().encode('image bytes');
const sb = await keys.sealBlob(new Blob([bytes]));
check(sb.epoch === doc3.epoch && sb.blob instanceof Blob, 'sealBlob() returns the bytes and the epoch together');
const ob = await bobKeys.openBlob({ iv: sb.iv, epoch: sb.epoch, mime: 'text/plain' }, sb.blob);
check(ob.ok && (await ob.blob.text()) === 'image bytes', 'openBlob() opens by the reference epoch');
const obParent = await bobKeys.openBlob({ iv: sb.iv }, sb.blob, { parentEpoch: sb.epoch });
check(obParent.ok, 'a blob reference without a tag opens under its parent record epoch');
check((await bobKeys.openBlob({ iv: sb.iv }, sb.blob)).cause === 'untagged', 'a blob reference with no tag at any level is refused');

console.log('\n' + (failures === 0
  ? 'SEALED PASS — one mechanism: every seal is tagged, every open reads by its tag, untagged is never guessed.'
  : `SEALED FAIL — ${failures} check(s) failed.`));
process.exit(failures === 0 ? 0 : 1);
