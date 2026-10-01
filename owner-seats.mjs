// Every key the owner holds is a member of every session the owner creates.
//
// The expectation this meets: all my devices have my stuff; if I lose one, another
// — or my paper backup — gets it back; nobody else can. A session is lost only when
// every key the owner holds is gone. Before this, a session seated only the device
// that created it; the owner's other devices were seated when they happened to ask
// while a key-holder was online, and the paper backup never was — so losing the
// creating device could lose the session with the owner contract intact.
//
// WHO IS SEATED — the keys the owner has PROVEN they hold, and nothing else:
//   · a rivet on the identity whose public key it published itself (setPublicKey
//     records only msg.sender's key), or
//   · a rivet whose key an owner device recorded in _rivet-keys.json (a paper
//     backup never signs a transaction, so it cannot publish its own).
// Either way the key must DERIVE to the rivet's address — a key is its own proof,
// so the record needs no trust. Never seated: the boost carrier's verifier (a
// shared rivet of every identity that adopted it, not a device of this owner), an
// identity admitted as a signer (no device key), and bots / MCP agents (section
// members derived from the host wallet, never contract rivets). No key the host,
// relay or console can derive ever receives a session key from here.
//
// WHEN — at the moments the owner acts, never as a background sweep (see
// session-keys.mjs): a session is created; a backup is added; a signer is removed;
// the owner asks to seat their keys in the sessions they already have.
//
// REMOVAL converges from any device. A removed signer is recorded in
// _rivet-keys.json `removed`; seating from any owner device also takes recorded
// removals out. That covers a device removing ITSELF (it cannot commit its own
// leaf's removal) and sessions the removing device could not reach. Only addresses
// the owner explicitly removed are ever taken out — never a collaborator or bot —
// and a record applies only while the chain agrees: an address that is a signer
// again (re-added) is simply a signer, and its old record is ignored.
//
// Injected (a browser hands the console's runtime; a test hands stubs):
//   me()                      → { signer }                 the acting device
//   contractSigners(contract) → [{ address, publicKey, name, pending, kind }]; THROWS when unread
//   boostVerifierAddress()    → the boost carrier's verifier rivet, never seated
//   storageGet / storagePut   → the contract-root record (rivet-signed writes)
//   openGroup(session)        → a DsGroup for this device
//   listSessions()            → the sessions this identity reaches

const lc = (a) => String(a || '').toLowerCase();
// Contract root: { keys: { [address]: publicKey }, removed: { [address]: epochMs } }.
export const RIVET_KEYS = '_rivet-keys.json';

// The address a public key belongs to, or null for anything that is not one.
export function addressOf(publicKey) {
  try { return lc(globalThis.ethers.utils.computeAddress(publicKey)); } catch { return null; }
}

export function ownerSeats({ me, contractSigners, boostVerifierAddress, storageGet, storagePut, openGroup, listSessions }) {
  const readRecord = async (contract) => {
    const r = await storageGet(contract, RIVET_KEYS).catch(() => null);
    return { keys: { ...(r?.keys || {}) }, removed: { ...(r?.removed || {}) } };
  };

  // The owner's provable keys: [{ address, publicKey, name }].
  async function ownerSeatKeys(contract) {
    const [signers, record, verifier] = await Promise.all([contractSigners(contract), readRecord(contract), boostVerifierAddress()]);
    const keys = [];
    for (const s of signers) {
      const address = lc(s.address);
      if (!address || address === lc(verifier) || s.kind === 'identity' || s.pending) continue;
      const key = [s.publicKey, record.keys?.[address]].find((k) => k && addressOf(k) === address);
      if (key) keys.push({ address, publicKey: key, name: s.name || '' });
    }
    return keys;
  }

  // Record a key for a rivet that cannot publish its own (a paper backup). Refused
  // unless the key derives to the address — the file only ever holds proofs.
  async function recordRivetKey(contract, address, publicKey) {
    if (addressOf(publicKey) !== lc(address)) throw new Error('that public key does not belong to that address');
    const rec = await readRecord(contract);
    if (rec.keys[lc(address)] === publicKey && !rec.removed[lc(address)]) return;
    rec.keys[lc(address)] = publicKey;
    delete rec.removed[lc(address)];   // re-adding a removed backup restores it
    await storagePut(contract, RIVET_KEYS, rec);
  }

  // Record that the owner removed a signer, so every owner device takes it out of
  // the sessions it can reach — including the device itself, which cannot.
  async function recordRemoved(contract, address) {
    const rec = await readRecord(contract);
    rec.removed[lc(address)] = Date.now();
    delete rec.keys[lc(address)];
    await storagePut(contract, RIVET_KEYS, rec);
  }

  // Seat `keys` in one open group. Returns the addresses newly seated.
  async function seatKeys(group, keys) {
    const seated = [];
    for (const k of keys) {
      if (group.isSeated(k.address)) continue;
      await group.addMember(k.address, k.publicKey);
      seated.push(k.address);
    }
    return seated;
  }

  // The sessions this identity owns (the ones its keys are responsible for).
  async function ownedSessions(contract) {
    const all = await listSessions();
    return all.filter((s) => lc(s.owner) === lc(contract) && !s._deleted);
  }

  // Why something failed, whatever was thrown — a failure in one session must be
  // recorded against it, never abort the pass over the rest.
  const reasonOf = (e) => (e && (e.epLabel || e.message)) || String(e);

  // Apply `fn(group, session)` to every owned session this device holds the key for.
  // Sessions it cannot act on are reported, never skipped silently.
  async function eachOwnedGroup(contract, fn, onProgress = () => {}) {
    const report = { done: [], unreachable: [] };
    const sessions = await ownedSessions(contract);
    for (const [i, s] of sessions.entries()) {
      onProgress(`${i + 1} of ${sessions.length}: ${s.name || s.id}`);
      let group;
      try { group = await openGroup(s); }
      catch (e) { report.unreachable.push({ session: s, reason: reasonOf(e) }); continue; }
      if (group.pendingSeat || !group.groupKey()) { report.unreachable.push({ session: s, reason: 'this device does not hold its key' }); continue; }
      try { report.done.push({ session: s, result: await fn(group, s) }); }
      catch (e) { console.warn(`[ownerSeats] ${s.name || s.id}:`, e); report.unreachable.push({ session: s, reason: reasonOf(e) }); }
    }
    return report;
  }

  // Seat the owner's provable keys (or the given ones) in every owned session, and
  // take out any signer the owner recorded as removed. Never this device itself.
  async function seatInOwnedSessions(contract, { keys = null, onProgress } = {}) {
    const k = keys || await ownerSeatKeys(contract);
    const self = lc(me().signer);
    const signers = new Set((await contractSigners(contract)).map((s) => lc(s.address)));
    const removed = Object.keys((await readRecord(contract)).removed).filter((a) => a !== self && !signers.has(a));
    return eachOwnedGroup(contract, async (group) => {
      const seated = await seatKeys(group, k);
      for (const a of removed) if (group.isSeated(a)) await group.removeMember(a);
      return seated;
    }, onProgress);
  }

  // A signer removed from the identity leaves every owned session: its leaf is
  // removed, which rotates the key, so it reads nothing written after.
  async function unseatFromOwnedSessions(contract, address, { onProgress } = {}) {
    return eachOwnedGroup(contract, async (group) => {
      if (!group.isSeated(address)) return false;
      await group.removeMember(address);
      return true;
    }, onProgress);
  }

  // Restore a STUCK group — one change its members cannot apply — by starting a new
  // tree past it (DsGroup.reinit): this owner device becomes founder, carrying its
  // whole keyring, so the history stays readable to everyone re-seated. Then seat
  // the owner's keys and every member of the old tree EXCEPT the signer of the
  // change that could not be applied: it is named in the result, so the owner can
  // revoke its access (a member the chain still admits is re-seated when it asks).
  // The relay accepts a reinit only from a rivet of the owner contract.
  async function restoreGroup(session, group) {
    const self = lc(me().signer);
    const culprit = lc(group.stuck?.signer);
    // The old tree's seated members, read BEFORE the reinit replaces it — the
    // group's own roster, a seat being a leaf whose key derives to its address.
    const prior = group.seatedMembers().filter((m) => m.address !== self && m.address !== culprit);
    const { epoch } = await group.reinit();
    const byAddress = new Map();
    for (const k of [...await ownerSeatKeys(session.owner), ...prior]) if (k.address !== self) byAddress.set(k.address, k);
    const seated = await seatKeys(group, [...byAddress.values()]);
    return { epoch, seated, leftOut: culprit && culprit !== self ? [culprit] : [] };
  }

  return { ownerSeatKeys, recordRivetKey, recordRemoved, seatKeys, ownedSessions, seatInOwnedSessions, unseatFromOwnedSessions, restoreGroup };
}
