// Session-key delivery over the courier — the policy, beside the group it keys.
//
// The security model, stated as a feature: only a member who HOLDS K can hand it
// over. There is no custodian. So a device that lacks K for a session it belongs
// to ASKS — a cheap notification to the session's owner — and any of that owner's
// devices that is online AND holds K ANSWERS by sealing K to the asker.
//
// This is NOT a background heal or a sweep: nothing happens until someone asks. A
// request comes in, a seal goes out — an ordinary message exchange. "Online"
// means the app is open anywhere: the responder runs at boot, not per session
// page. If no key-holder is online, the ask simply waits — that is the system
// working (keys live only on the member's devices), and the waiting screen says so.
//
// THE REQUEST is one shape, defined here and nowhere else: the browser sends it
// for its own rivet, the MCP layer sends it for an agent whose wallet the server
// holds, and the relay's seat route describes it to a member who asks how to
// claim. `keyRequest()` is that shape.
//
// Everything that touches a page or a wallet is injected, so this runs in a
// browser over the console's runtime and in a test over stubs:
//   me()                         → { signer, publicKey, contract }
//   openGroup(session)           → a DsGroup (pendingSeat when this device holds no leaf)
//   sectionRole(owner, id, addr) → the chain's role number; THROWS when it could not be read
//   rivetAuthorized(contract, r) → whether `r` is a device of `contract`; THROWS when unread
//   send(to, payload)            → a courier send to an address
//   listSessions()               → the sessions this identity reaches (for requestAllKeys)
//   log(entry)                   → optional: a structured record of every request
//                                  outcome, so a stuck welcome is diagnosable. It
//                                  carries only public postmark coordinates (owner,
//                                  id, rivet, from, a role number, an error message)
//                                  — never K, a private key or plaintext — and must
//                                  never throw delivery off course.

export const KEY_REQUEST_KIND = 'key-request';

/**
 * The courier key-request: the SESSION's group coordinates the responder opens
 * (owner/id — not the announcement address), and the requesting RIVET with its
 * self-supplied public key, so a responder can seal directly to a key the chain
 * may not yet publish. Only the device waiting for the key can install it.
 */
export function keyRequest({ owner, id, rivet, pubkey }) {
  return { kind: KEY_REQUEST_KIND, owner, id, rivet, pubkey };
}

const lc = (a) => String(a || '').toLowerCase();

export function keyDelivery({ me, openGroup, sectionRole, rivetAuthorized, send, listSessions, log = () => {} }) {
  // Report every request outcome in ONE shape. The "deferred forever" question had
  // no evidence because nothing said WHICH branch deferred, and a chain that could
  // not be READ looked identical to a genuine non-member. `report` fixes both: one
  // reason per branch, and read-failures named apart from real negatives. It only
  // records; it never changes the disposition it returns, and a throwing `log`
  // cannot derail delivery.
  const report = (disp, reason, ctx = {}) => {
    try { log({ ev: 'key-request', disp, reason, ...ctx }); } catch { /* logging is never load-bearing */ }
    return disp;
  };
  // Ask the session's owner for K. Announced to the requester's OWN contract
  // first — a sister rivet is most likely to hold K and can trivially verify its
  // own device — with the session owner as the fallback servicer. Deduped: for a
  // self-owned session the two are identical.
  async function requestKey(session) {
    const m = me();
    if (!m?.signer || !m?.publicKey || !session?.owner || !session?.id) return;
    const payload = keyRequest({ owner: session.owner, id: session.id, rivet: m.signer, pubkey: m.publicKey });
    const targets = [...new Set([m.contract, session.owner].filter(Boolean).map(lc))];
    for (const to of targets) {
      try { await send(to, payload); } catch { /* best-effort per target */ }
    }
  }

  // "Set me up." A freshly-joined device asks for every session's key at once.
  async function requestAllKeys() {
    let sessions = [];
    try { sessions = await listSessions(); } catch { return; }
    for (const s of sessions) { try { await requestKey(s); } catch { /* best-effort per session */ } }
  }

  // The responder, as a durable messenger `request`: answer key-requests for
  // sessions THIS device holds K for. A request this device can't honor right now
  // (it isn't a key-holder, or a chain read did not answer) is DEFERRED and
  // retried, never silently dropped. Only a definitive outcome is terminal:
  // sealed → completed, malformed → rejected.
  const keyRequestHandler = {
    visible: false,
    alert: false,
    retry: true,
    async onMessage(rec) {
      const { owner, id, rivet, pubkey } = rec.data || {};
      const from = rec.from;
      if (!owner || !id || !rivet || !pubkey) return report('rejected', 'malformed', { from });   // the only terminal drop
      // Only a key-HOLDER can answer. If this device doesn't hold K, another of
      // the identity's devices might — leave the request open.
      let g;
      try { g = await openGroup({ owner, id }); }
      catch (e) { return report('defer', 'group-open-failed', { owner, id, from, err: e?.message }); }
      if (g.pendingSeat || !g.groupKey?.()) return report('defer', 'no-key-here', { owner, id, from, pendingSeat: !!g.pendingSeat });
      // Authorize the asker on the chain's word. A read that did not answer must
      // NOT reject — that is exactly how a real member used to be dropped. So a
      // chain that could not be READ (a throw) is reported DISTINCTLY from a genuine
      // role<1: a transient provider failure is never mistaken for a non-member,
      // and the retry closes the gap when the chain answers.
      let role;
      try { role = await sectionRole(owner, id, from); }
      catch (e) { return report('defer', 'role-read-failed', { owner, id, from, err: e?.message }); }
      if (role < 1) return report('defer', 'asker-role-lt-1', { owner, id, from, role });
      if (lc(from) !== lc(rivet)) {
        let ok;
        try { ok = await rivetAuthorized(from, rivet); }
        catch (e) { return report('defer', 'rivet-read-failed', { owner, id, from, rivet, err: e?.message }); }
        if (!ok) return report('defer', 'rivet-unauthorized', { owner, id, from, rivet });
      }
      // Idempotent: a rivet that already HOLDS its leaf is done (a retry after a
      // successful seal, or a re-ask) — never a duplicate seat. Holds, not "is
      // named in the directory": a stale directory entry is a claim, not a seat.
      if (g.isSeated(rivet)) return report('completed', 'already-seated', { owner, id, rivet });
      try { await g.addMember(rivet, pubkey); return report('completed', 'sealed', { owner, id, rivet }); }   // seal K to the asking device
      catch (e) { return report('defer', 'seal-failed', { owner, id, rivet, err: e?.message }); }
    },
  };

  return { requestKey, requestAllKeys, keyRequestHandler };
}
