// Reporting proof for the key-delivery responder (session-keys.mjs).
//
// Exercises keyDelivery().keyRequestHandler ALONE over stubs — no relay, no group,
// no chain. It proves the one new claim and guards the dispositions that must NOT
// regress:
//
//   REASON     every outcome reports ONE named reason, and the disposition it
//              returns is unchanged by reporting
//   READ-APART a chain read that THREW is reported distinctly (role-read-failed /
//              rivet-read-failed) from a genuine negative (asker-role-lt-1 /
//              rivet-unauthorized) — the split that tells a transient provider
//              failure apart from a real non-member (the "deferred forever" gap)
//   SAFE-LOG   a `log` that throws never derails delivery
//
//   node client-lib/session-keys.test.mjs

import { keyDelivery } from './session-keys.mjs';

let failures = 0;
const ok   = (m) => console.log('  ok  : ' + m);
const fail = (m) => { console.log('  FAIL: ' + m); failures++; };
const check = (cond, m) => cond ? ok(m) : fail(m);

// A stub DsGroup. Defaults to a healthy key-holder that has not yet seated the asker.
function group({ pendingSeat = false, key = 'K', seated = false, addThrows = null } = {}) {
  return {
    pendingSeat,
    groupKey: () => key,
    isSeated: () => seated,
    addMember: async () => { if (addThrows) throw new Error(addThrows); },
  };
}

// Build a responder whose injected deps are set per case. `openGroup` may be a value
// (returned) or an Error (thrown). sectionRole / rivetAuthorized likewise.
function responder({ openGroup = group(), sectionRole = 3, rivetAuthorized = true, log } = {}) {
  const asValue = (v) => async () => { if (v instanceof Error) throw v; return v; };
  const seen = [];
  const h = keyDelivery({
    me: () => ({ signer: '0xme', publicKey: '0xmepub', contract: '0xme' }),
    openGroup: asValue(openGroup),
    sectionRole: asValue(sectionRole),
    rivetAuthorized: asValue(rivetAuthorized),
    send: async () => {},
    listSessions: async () => [],
    log: log || ((e) => seen.push(e)),
  }).keyRequestHandler;
  return { h, seen };
}

const REC = (over = {}) => ({
  from: over.from || '0xasker',
  data: { owner: '0xowner', id: '0xsession', rivet: over.rivet || '0xasker', pubkey: '0xpub', ...(over.data || {}) },
});

async function expect(label, { rec = REC(), deps = {} }, disp, reason) {
  const { h, seen } = responder(deps);
  const got = await h.onMessage(rec);
  const last = seen[seen.length - 1] || {};
  check(got === disp && last.reason === reason && last.disp === disp,
    `${label}: ${got}/${last.reason} (want ${disp}/${reason})`);
  return { got, last, seen };
}

console.log('session-keys reporting:');

// Every branch → its named reason + unchanged disposition.
await expect('malformed (no pubkey)', { rec: { from: '0xasker', data: { owner: '0xo', id: '0xi', rivet: '0xasker' } } }, 'rejected', 'malformed');
await expect('group open throws',     { deps: { openGroup: new Error('DS head → 503') } }, 'defer', 'group-open-failed');
await expect('no key on this device', { deps: { openGroup: group({ pendingSeat: true }) } }, 'defer', 'no-key-here');
await expect('no key (groupKey null)',{ deps: { openGroup: group({ key: null }) } }, 'defer', 'no-key-here');

// READ-APART: a thrown read is NOT a negative.
await expect('role read throws',      { deps: { sectionRole: new Error('CALL_EXCEPTION') } }, 'defer', 'role-read-failed');
await expect('asker role 0',          { deps: { sectionRole: 0 } }, 'defer', 'asker-role-lt-1');
await expect('rivet read throws', { rec: REC({ rivet: '0xdevice' }), deps: { rivetAuthorized: new Error('CALL_EXCEPTION') } }, 'defer', 'rivet-read-failed');
await expect('rivet unauthorized',{ rec: REC({ rivet: '0xdevice' }), deps: { rivetAuthorized: false } }, 'defer', 'rivet-unauthorized');

// The from===rivet case must SKIP the rivet read entirely (no rivet-* reason).
{
  const { got, last } = await expect('self-rivet skips rivet read', { deps: { rivetAuthorized: new Error('should not be called') } }, 'completed', 'sealed');
  check(last.reason !== 'rivet-read-failed', 'READ-APART: from===rivet never hits the rivet read');
  void got;
}

// Terminal happy paths.
await expect('already seated',        { deps: { openGroup: group({ seated: true }) } }, 'completed', 'already-seated');
await expect('sealed ok',             {}, 'completed', 'sealed');
await expect('seal throws',           { deps: { openGroup: group({ addThrows: 'nonce too low' }) } }, 'defer', 'seal-failed');

// SAFE-LOG: a throwing log must not change the disposition.
{
  const { h } = responder({ log: () => { throw new Error('log boom'); } });
  const got = await h.onMessage(REC());
  check(got === 'completed', 'SAFE-LOG: a throwing log leaves delivery intact');
}

console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
