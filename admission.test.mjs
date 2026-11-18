// Proof for admission.mjs — the M-of-N welcome threshold's ONE definition.
// Uses real ethers signatures so forgery/binding/recovery are genuinely exercised.
//
//   node client-lib/admission.test.mjs

globalThis.ethers = (await import('ethers')).ethers;   // admission resolves verifyMessage off this
import { endorsementMessage, makeEndorsement, validEndorsers, meetsThreshold } from './admission.mjs';

let failures = 0;
const ok   = (m) => console.log('  ok  : ' + m);
const fail = (m) => { console.log('  FAIL: ' + m); failures++; };
const check = (cond, m) => cond ? ok(m) : fail(m);

const E = globalThis.ethers;
const Wallet = E.Wallet;
// Deterministic wallets.
const w = (n) => new Wallet('0x' + String(n).padStart(64, '1'));
const alice = w(1), bob = w(2), carol = w(3), mallory = w(9), asker = w(7);
const signWith = (wallet) => (msg) => wallet.signMessage(msg);

const OWNER = '0xOWNER0000000000000000000000000000000001';
const ID    = '0xSESSION00000000000000000000000000000001';

// Everyone except mallory is a member; isMember is the chain's word (injected).
const members = new Set([alice, bob, carol, asker].map((x) => x.address.toLowerCase()));
const isMember = async (a) => members.has(String(a).toLowerCase());

console.log('admission:');

// A genuine endorsement by a member counts.
{
  const e = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address }, signWith(alice));
  const valid = await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [e], isMember });
  check(valid.length === 1 && valid[0] === alice.address.toLowerCase(), 'a member\'s genuine endorsement counts');
}

// A forged signature (alice's address, bob's pen) does not recover → rejected.
{
  const ts = Date.now();
  const forged = { owner: OWNER.toLowerCase(), id: ID.toLowerCase(), asker: asker.address.toLowerCase(), endorser: alice.address.toLowerCase(), ts,
    signature: await bob.signMessage(endorsementMessage({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address, ts })) };
  const valid = await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [forged], isMember });
  check(valid.length === 0, 'a forged endorsement (signer ≠ stated endorser) is rejected');
}

// Cross-binding: an endorsement for a DIFFERENT asker cannot be replayed here.
{
  const other = w(8);
  const e = await makeEndorsement({ owner: OWNER, id: ID, asker: other.address, endorser: alice.address }, signWith(alice));
  const valid = await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [e], isMember });
  check(valid.length === 0, 'an endorsement bound to another asker does not count here');
}

// A non-member's endorsement does not count (isMember says no).
{
  const e = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: mallory.address }, signWith(mallory));
  const valid = await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [e], isMember });
  check(valid.length === 0, 'a non-member endorsement is rejected');
}

// Staleness: an endorsement older than maxAge is not standing assent.
{
  const ts = Date.now() - 48 * 60 * 60 * 1000;
  const e = { owner: OWNER.toLowerCase(), id: ID.toLowerCase(), asker: asker.address.toLowerCase(), endorser: alice.address.toLowerCase(), ts,
    signature: await alice.signMessage(endorsementMessage({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address, ts })) };
  const valid = await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [e], isMember });
  check(valid.length === 0, 'a stale endorsement does not count');
}

// Dedup: the same endorser twice is one voice.
{
  const e1 = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address }, signWith(alice));
  const e2 = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address }, signWith(alice));
  const valid = await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [e1, e2], isMember });
  check(valid.length === 1, 'duplicate endorsers dedup to one');
}

// fail-closed: an isMember read that THROWS propagates (caller defers).
{
  const e = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address }, signWith(alice));
  let threw = false;
  try { await validEndorsers({ owner: OWNER, id: ID, asker: asker.address, endorsements: [e], isMember: async () => { throw new Error('CALL_EXCEPTION'); } }); }
  catch { threw = true; }
  check(threw, 'a membership read that throws propagates (fail-closed)');
}

// meetsThreshold: the sealer's commit signature is the first assent, so M needs
// M-1 OTHER endorsers; neither the sealer nor the newcomer counts among them.
{
  const eBob   = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: bob.address }, signWith(bob));
  const eAlice = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: alice.address }, signWith(alice));
  const eSelf  = await makeEndorsement({ owner: OWNER, id: ID, asker: asker.address, endorser: asker.address }, signWith(asker));
  // sealer = alice (signs the commit). M=2 wants 1 OTHER endorser → bob satisfies it.
  const two = await meetsThreshold({ owner: OWNER, id: ID, asker: asker.address, sealer: alice.address, endorsements: [eBob], threshold: 2, isMember });
  check(two.ok && two.have === 1 && two.needOthers === 1, 'M=2 met by sealer + one other endorser');
  const none = await meetsThreshold({ owner: OWNER, id: ID, asker: asker.address, sealer: alice.address, endorsements: [], threshold: 2, isMember });
  check(!none.ok && none.have === 0 && none.needOthers === 1, 'M=2 not met by the sealer alone');
  const selfOnly = await meetsThreshold({ owner: OWNER, id: ID, asker: asker.address, sealer: alice.address, endorsements: [eSelf], threshold: 2, isMember });
  check(!selfOnly.ok && selfOnly.have === 0, 'a newcomer cannot self-endorse toward its own admission');
  const sealerSelf = await meetsThreshold({ owner: OWNER, id: ID, asker: asker.address, sealer: alice.address, endorsements: [eAlice], threshold: 2, isMember });
  check(!sealerSelf.ok && sealerSelf.have === 0, 'the sealer\'s own endorsement does not double-count past its commit signature');
  const m1 = await meetsThreshold({ owner: OWNER, id: ID, asker: asker.address, sealer: alice.address, endorsements: [], threshold: 1, isMember });
  check(m1.ok && m1.needOthers === 0, 'M=1 needs zero other endorsers (the miner default)');
}

console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
