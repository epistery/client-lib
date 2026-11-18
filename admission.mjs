// admission.mjs — the ONE definition of multi-party admission (the M-of-N welcome
// threshold). A session may require M distinct members to ENDORSE a newcomer
// before its seat is valid. This module defines what an endorsement IS, how it is
// signed, and when a set of them satisfies a threshold — nothing else.
//
// Two callers share it so they can never drift (NoSecondCopy):
//   - the responder (session-keys) COUNTS valid endorsements to decide when to seal;
//   - the group's commit apply (ds-group) RE-CHECKS the same set carried on the add
//     commit, so a seat is accepted only with real assent — a rogue member cannot
//     seal past the threshold, because every applier re-verifies.
//
// It composes only an injected `verifyMessage` (ethers, either major) and an
// injected membership read `isMember` — it holds no policy, no transport, no key.
// Threshold M lives in session policy (the session record); default 1 = any present
// key-holder welcomes (the miner model), and then endorsements are not consulted.

const lc = (a) => String(a || '').toLowerCase();

// ethers moved verifyMessage from `.utils` (v5) to the top level (v6). Accept both,
// or an explicitly injected verifier (tests, a different stack).
function resolveVerify(verify) {
  if (typeof verify === 'function') return verify;
  const E = (typeof globalThis !== 'undefined' && globalThis.ethers) || null;
  const fn = E && (E.utils?.verifyMessage || E.verifyMessage);
  if (typeof fn !== 'function') throw new Error('admission: no verifyMessage (pass one, or set globalThis.ethers)');
  return fn;
}

// The canonical message an endorser signs: "I, a member, endorse <asker> for a seat
// in <owner>/<id>, at <ts>." Every field is bound in, so a signature cannot be
// replayed onto another asker, another session, or a stale moment. Addresses are
// lowercased so the string is independent of checksum casing.
export function endorsementMessage({ owner, id, asker, endorser, ts }) {
  return [
    'epistery admission v1',
    `session ${lc(owner)}/${lc(id)}`,
    `endorse ${lc(asker)}`,
    `by ${lc(endorser)}`,
    `ts ${Number(ts)}`,
  ].join('\n');
}

// Build a signed endorsement record for `asker`. `endorser` is the signing rivet's
// address; `sign(message) -> signature` is that rivet's signMessage. Returns the
// record shape that rides the courier and later the add commit.
export async function makeEndorsement({ owner, id, asker, endorser }, sign) {
  const ts = Date.now();
  const message = endorsementMessage({ owner, id, asker, endorser, ts });
  const signature = await sign(message);
  return { owner: lc(owner), id: lc(id), asker: lc(asker), endorser: lc(endorser), ts, signature };
}

// Reduce a bag of endorsement records to the set of DISTINCT, VALID, AUTHORIZED
// endorsers of `asker` for this session. An endorsement counts only when:
//   - it is for THIS session and asker (no cross-binding),
//   - its signature recovers to its stated endorser (not forged),
//   - that endorser is a member the chain recognizes (isMember), and
//   - it is within maxAgeMs of now (a stale endorsement is not standing assent).
// A read that THROWS from isMember propagates (fail-closed: the caller defers, it
// does not count the endorser). Returns lowercased endorser addresses, deduped.
export async function validEndorsers({ owner, id, asker, endorsements, isMember, verify, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000 }) {
  const verifyMessage = resolveVerify(verify);
  const out = new Map();   // endorser -> true, deduped
  for (const e of endorsements || []) {
    if (!e || lc(e.owner) !== lc(owner) || lc(e.id) !== lc(id) || lc(e.asker) !== lc(asker)) continue;
    const endorser = lc(e.endorser);
    if (!endorser || out.has(endorser)) continue;
    if (!Number.isFinite(e.ts) || Math.abs(now - e.ts) > maxAgeMs) continue;
    let recovered;
    try { recovered = lc(verifyMessage(endorsementMessage({ owner, id, asker, endorser, ts: e.ts }), e.signature)); }
    catch { continue; }                      // a signature that won't recover is noise
    if (recovered !== endorser) continue;    // signed by someone other than it claims
    if (!(await isMember(endorser))) continue;   // throws → caller defers (fail-closed)
    out.set(endorser, true);
  }
  return [...out.keys()];
}

// Does this endorsement set meet the threshold for a seat SEALED by `sealer`?
// The sealer's own commit signature is the FIRST assent, so a threshold of M needs
// only M-1 OTHER distinct endorsers. Neither the newcomer (it cannot vote itself
// in) nor the sealer (already counted by the commit signature) counts among them.
// At M=1 this needs zero others — the miner default, no endorsements consulted.
export async function meetsThreshold({ owner, id, asker, sealer, endorsements, threshold, isMember, verify, now, maxAgeMs }) {
  const m = Math.max(1, Number(threshold) || 1);
  const skip = new Set([lc(asker), lc(sealer)].filter(Boolean));
  const others = (await validEndorsers({ owner, id, asker, endorsements, isMember, verify, now, maxAgeMs }))
    .filter((e) => !skip.has(e));
  const needOthers = m - 1;
  return { ok: others.length >= needOthers, have: others.length, needOthers, threshold: m, endorsers: others };
}
