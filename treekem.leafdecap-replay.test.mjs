// Reproduce the phone's us-wiki failure OFF-PHONE, faithfully.
//
// The real sequence (from the DS log): founder@0 creates; bot1 added@leaf1;
// bot1 REMOVED; the PHONE added@leaf1 (REUSING the just-freed leaf); bot2
// added@leaf2; bot2 removed. The phone — a NON-EXTRACTABLE rivet (leaf-decap,
// rivetPriv=null) — bootstraps FRESH from its Welcome and replays the later
// commits (add bot2, remove bot2). In production, replaying the remove throws
// OperationError at aeadDecrypt. This test exercises that exact path, which the
// keyring/ctx tests missed (they used extractable keys and never reused a leaf).
//
//   node client-lib/treekem.leafdecap-replay.test.mjs

globalThis.ethers = (await import('ethers')).ethers;
import { Member } from './treekem.mjs';
import { cryptoStack, privFromSecret, pubFromPriv, ecdh } from './treekem-kdf.mjs';

const CAP = 8;
let fails = 0;
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const kp = () => { const priv = privFromSecret(rand(32)); return { priv, pub: pubFromPriv(priv) }; };
const ok = (m) => console.log('  ok  : ' + m);
const bad = (m) => { console.log('  FAIL: ' + m); fails++; };
const stack = cryptoStack();

// founder@0
const fk = kp();
const founder = new Member('founder', CAP, stack);
founder.seat(0, fk.priv, fk.pub);
await founder.commit({ type: 'update' });                                   // epoch 1

// bot1 added@1, then REMOVED — freeing leaf 1 (all before the phone)
const bot1 = kp();
await founder.commit({ type: 'add', addLeafIndex: 1, addPub: bot1.pub });   // epoch 2
await founder.commit({ type: 'remove', removeLeafIndex: 1 });               // epoch 3

// the PHONE added@1 — REUSING the leaf bot1 vacated
const phone = kp();
const addPhone = await founder.commit({ type: 'add', addLeafIndex: 1, addPub: phone.pub }); // epoch 4

// bot2 added@2, then removed (the rotation the phone must replay)
const bot2 = kp();
const addBot2 = await founder.commit({ type: 'add', addLeafIndex: 2, addPub: bot2.pub });   // epoch 5
const rmBot2  = await founder.commit({ type: 'remove', removeLeafIndex: 2 });                // epoch 6
console.log('founder final K@6:', founder.groupKey.slice(0, 14), '…');

// The phone bootstraps FRESH (no prior state) via the wallet leaf-decap seam,
// then replays epoch 5 and epoch 6 — exactly _bootstrapFromWelcome + catch-up.
const phoneM = new Member('phone', CAP, stack);
phoneM.setLeafDecap(async (enc) => ecdh(phone.priv, enc));   // == wallet.computeSharedSecret
await phoneM.applyWelcome(addPhone.welcome, 1, null);        // rivetPriv=null (non-extractable)
ok(`phone bootstrapped @leaf1; K=${phoneM.groupKey?.slice(0, 14)}… ${phoneM.groupKey === (founder.keyForEpoch ? founder.keyForEpoch(4) : '') ? '' : ''}`);

try {
  await phoneM.apply(addBot2);
  ok('phone replayed epoch-5 add');
} catch (e) { bad(`phone.apply(add bot2) THREW: ${e.message} [${e.epLabel || '-'}]`); }

try {
  await phoneM.apply(rmBot2);
  if (phoneM.groupKey === founder.groupKey) ok('phone replayed epoch-6 remove — CONVERGED (bug not reproduced)');
  else bad(`phone diverged on the remove: phone=${phoneM.groupKey?.slice(0,18)} founder=${founder.groupKey.slice(0,18)}`);
} catch (e) { bad(`phone.apply(remove bot2) THREW: ${e.message} [epLabel=${e.epLabel || '-'}]  ← REPRODUCES THE PHONE`); }

console.log('\n' + (fails === 0
  ? 'PASS — faithful us-wiki replay converges; bug NOT reproduced (a further difference remains).'
  : `REPRODUCED — the failure is in leaf-decap replay after a REUSED leaf (${fails} failed).`));
process.exit(fails === 0 ? 0 : 1);
