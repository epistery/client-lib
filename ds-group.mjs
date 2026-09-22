// ds-group — the client-side TreeKEM commit-emission layer over the relay's
// blind Delivery Service (EpisteryDataFrontier P2). Turns the proven ratchet
// tree (./treekem.mjs Member) into a live group: it produces commits, posts them
// to the DS for total ordering, applies others' commits to converge, and derives
// the epoch group key K that feeds cipher.mjs.
//
// Roles honored (EpisteryData): the CLIENT does all crypto; the relay orders
// ciphertext blindly (epoch-CAS, never sees K); the chain authorizes (the DS
// reuses on-chain roleOf, so a commit is authorized exactly like a section write).
//
// Key-delivery vs authorization: this module is key-delivery. Whether a rivet MAY
// commit is the chain's answer (the DS enforces it); this module only moves the
// keys to owners the chain already recognizes.
//
// Persistence: a committer CANNOT re-derive its own contributed path secret from
// the log (it was random, sealed only to others), so it persists its tree state
// via the injected `store` (rivet-guarded at rest). A fresh device with no local
// state bootstraps from its Welcome (the add commit that seated it) and replays.
//
// Dual environment: one module for the browser rivet and the server twin
// (bot/steward). Signing + the CSPRNG stack + persistence are injected, so this
// file has no environment assumptions.

import { Member } from './treekem.mjs';
import { cryptoStack } from './treekem-kdf.mjs';

// The commit format this client writes, sent with every commit. 2 = growth-aware:
// commits and saved state carry the tree's capacity, and an add never seats an
// occupied leaf. The relay refuses commits below its floor — the one lever that
// reaches a tab still running older code, which would otherwise commit from a tree
// shape it cannot represent (the library's epoch 21, from a tab open since before
// growth shipped).
export const DS_FORMAT = 2;

// The size a NEW group's tree starts at. Not a ceiling: a full tree doubles when
// the next member is seated (treekem growTree), so a group grows with its
// membership — one primitive at any size, which is what the tree was adopted for.
const DEFAULT_CAPACITY = 8;
const encBytes = (obj) => new TextEncoder().encode(JSON.stringify(obj));
const decBytes = (buf) => JSON.parse(new TextDecoder().decode(new Uint8Array(buf)));
const fromB64 = (b64) => { const s = atob(b64); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };

export class DsGroup {
  // opts:
  //   relayUrl, contract, session      — the DS coordinates
  //   address, rivetPriv, rivetPub     — this member's rivet (its leaf)
  //   sign(method, subpath, bodyBytes) -> Promise<'Bot <cred>'>  (rivet/wallet-signed)
  //   stack   — crypto stack (default cryptoStack())
  //   store   — { load(): state|null, save(state) }  committer persistence (optional)
  //   fetchImpl — default globalThis.fetch
  //   capacity — tree leaf capacity (default 8)
  constructor(opts) {
    this.relayUrl = String(opts.relayUrl).replace(/\/+$/, '');
    this.contract = opts.contract;
    this.session = opts.session;
    this.address = String(opts.address).toLowerCase();
    this.rivetPriv = opts.rivetPriv;
    this.rivetPub = opts.rivetPub;
    this.sign = opts.sign;
    this.stack = opts.stack || cryptoStack();
    this.store = opts.store || null;
    this.fetch = opts.fetchImpl || globalThis.fetch.bind(globalThis);
    this.capacity = opts.capacity || DEFAULT_CAPACITY;
    // leafDecap: for a NON-EXTRACTABLE leaf (the browser rivet), the wallet's
    // computeSharedSecret — (ephemeralEncHex) => Promise<Uint8Array shared>.
    // Null for server participants (extractable derived keys use rivetPriv).
    this.leafDecap = opts.leafDecap || null;
    this.member = null;
    this.leafDir = {};   // addressLower -> leafIndex (public directory)
  }

  // Every Member this group creates inherits the leaf-decap seam so a
  // non-extractable rivet leaf can open commits sealed to it.
  _newMember() {
    const m = new Member('self', this.capacity, this.stack);
    if (this.leafDecap) m.setLeafDecap(this.leafDecap);
    return m;
  }

  _u(p) { return `${this.relayUrl}/ds/${this.contract}/${this.session}${p}`; }
  groupKey() { return this.member?.groupKey || null; }
  epoch() { return this.member?.epoch || 0; }
  // The key that sealed a record tagged with `epoch` — the read path for content
  // written under an earlier epoch (floor lookup over the retained keyring). A
  // null/absent tag resolves to the current key (untagged legacy record).
  keyForEpoch(epoch) { return this.member ? this.member.keyForEpoch(epoch) : null; }

  // ---- DS reads (public) -----------------------------------------------------
  async _log(since = 0) {
    const r = await this.fetch(this._u(`/log?since=${since}`));
    if (!r.ok) return [];
    return r.json();
  }
  async _payload(epoch) {
    const r = await this.fetch(this._u(`/commit/${epoch}`));
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`DS commit/${epoch} → ${r.status}`);
    return decBytes(await r.arrayBuffer());
  }

  // ---- DS write (authorized: on-chain section role, blind) -------------------
  async _post(envelope, baseEpoch) {
    const body = encBytes(envelope);
    const auth = await this.sign('POST', `${this.session}/_ds/commit`, body);
    // Opaque octet-stream, NOT application/json: the relay's global express.json
    // would consume a json body before the DS route's raw parser, and the DS is
    // blind — the bytes are opaque ciphertext to it regardless.
    const r = await this.fetch(this._u('/commit'), {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', authorization: auth, 'x-ds-epoch': String(baseEpoch), 'x-ds-format': String(DS_FORMAT) },
      body,
    });
    if (r.status === 409) { const j = await r.json().catch(() => ({})); return { conflict: true, current: j.current }; }
    if (r.status === 426) {
      const j = await r.json().catch(() => ({}));
      const e = new Error(j.error || 'the relay no longer accepts commits from this client — reload the page');
      e.code = 'STALE_CLIENT';
      throw e;
    }
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `DS commit → ${r.status}`); }
    return r.json();   // { ok, epoch, hash }
  }

  // Awaited: the store may self-encrypt (async), and a committer's own path
  // secret cannot be re-derived from the log — losing the last save would strand
  // the founder on reload. Every mutating path awaits this.
  async _persist() { if (this.store?.save) await this.store.save({ member: this.member.exportState(), leafDir: this.leafDir }); }
  _applyDir(dir) { if (!dir) return; if (dir.set) Object.assign(this.leafDir, dir.set); if (dir.del) for (const a of dir.del) delete this.leafDir[String(a).toLowerCase()]; }

  // ---- create a brand-new group (founder at leaf 0, epoch 1) -----------------
  async create() {
    this.member = this._newMember();
    this.member.seat(0, this.rivetPriv, this.rivetPub);
    const commit = await this.member.commit({ type: 'update' });   // establishes epoch 1
    this.leafDir = { [this.address]: 0 };
    const res = await this._post({ commit, dir: { set: { [this.address]: 0 } } }, 0);
    if (res.conflict) throw new Error('a group already exists at this session');
    await this._persist();
    return this.groupKey();
  }

  // ---- catch up a LIVE member by applying commits after its epoch ------------
  async _catchUp() {
    const log = await this._log(this.member.epoch);
    for (const e of log) {
      if (e.epoch <= this.member.epoch) continue;
      const env = await this._payload(e.epoch);
      if (!env) continue;
      try { await this.member.apply(env.commit); }
      catch (err) {
        // My own rotating commit, made by another instance of this rivet: take the
        // state that instance saved (the store is shared) instead of applying it.
        if (err.code === 'OWN_COMMIT' && await this._adoptSaved(e.epoch)) continue;
        err.epLabel = `catchup@${e.epoch}(${env.commit?.type || '?'}) › ${err.epLabel || err.message}`;
        throw err;
      }
      this._applyDir(env.dir);
    }
  }

  // Replace this in-memory member with the saved state, when that state has
  // reached `epoch` — i.e. it is the committing instance's record of it. Anything
  // older cannot carry the commit, so the caller fails instead.
  async _adoptSaved(epoch) {
    const saved = this.store?.load ? await this.store.load() : null;
    if (!saved?.member || !(saved.member.epoch >= epoch)) return false;
    this.member = this._newMember();
    this.member.importState(saved.member, this.rivetPriv);
    this.leafDir = saved.leafDir || {};
    return true;
  }

  // ---- load existing state: restore-then-catch-up, else Welcome bootstrap ----
  async load() {
    const saved = this.store?.load ? await this.store.load() : null;
    if (saved?.member) {
      this.member = this._newMember();
      this.member.importState(saved.member, this.rivetPriv);
      this.leafDir = saved.leafDir || {};
      await this._catchUp();
      this._assertInStep();
      await this._persist();
      return this.groupKey();
    }
    return this._bootstrapFromWelcome();
  }

  async _bootstrapFromWelcome() {
    const log = await this._log(0);
    if (!log.length) throw new Error('no group commits to load');
    const envs = [];
    for (const e of log) {
      const env = await this._payload(e.epoch);
      envs.push({ epoch: e.epoch, env });
      this._applyDir(env?.dir);
    }
    const myLeaf = this.leafDir[this.address];
    if (myLeaf == null) {
      // Not seated yet. If the chain recognizes this rivet as a member (e.g. a
      // public-read follower), it is entitled to a seat — the caller turns this
      // into a seat request (requestSeat) and waits for a present key-holder to
      // admit it. Typed so openGroup can branch instead of dead-ending.
      const e = new Error('this rivet holds no leaf in the group yet — request a seat');
      e.code = 'NO_SEAT';
      throw e;
    }
    if (myLeaf === 0) throw new Error('founder tree state is held by the creating device (no Welcome for leaf 0)');
    // A leaf can be REUSED: a prior rivet seated here, removed, then THIS rivet
    // added at the same index. Matching on leaf index alone (.find) returns the
    // FIRST add — the prior rivet's Welcome, sealed to a DIFFERENT key — which
    // this device cannot decrypt (its aeadDecrypt fails on Welcome.initBox). Select
    // the add for MY leaf sealed to MY OWN pubkey, and the LATEST if I was re-seated
    // more than once. This is MY Welcome, regardless of who held the leaf before.
    const lc = (a) => String(a || '').toLowerCase();
    const mine = envs.filter(x => x.env?.commit?.type === 'add'
      && x.env.commit.addLeafIndex === myLeaf
      && lc(x.env.commit.addPub) === lc(this.rivetPub));
    const addEntry = mine.length ? mine[mine.length - 1] : null;
    if (!addEntry) throw new Error('no Welcome for this rivet — ask a present key-holder to re-add this device');
    this.member = this._newMember();
    // applyWelcome adopts the live tree (incl. my seated leaf) and the current
    // key — the non-rotating add means there is nothing to replay for my own add.
    try { await this.member.applyWelcome(addEntry.env.commit.welcome, myLeaf, this.rivetPriv); }
    catch (err) { err.epLabel = `bootstrap Welcome@${addEntry.epoch} › ${err.epLabel || err.message}`; throw err; }
    for (const x of envs) {
      if (x.epoch > addEntry.epoch && x.env) {
        this._applyDir(x.env.dir);
        try { await this.member.apply(x.env.commit); }
        catch (err) { err.epLabel = `replay@${x.epoch}(${x.env.commit?.type || '?'}) › ${err.epLabel || err.message}`; throw err; }
      }
    }
    this._assertInStep();
    await this._persist();
    return this.groupKey();
  }

  // ---- commit a membership change, rebasing on a DS conflict -----------------
  // `plan` is { spec, dir }, or a function returning one (or null: nothing left to
  // do) — evaluated AFTER each catch-up, so a choice that depends on the live tree
  // (which leaf an add takes, whether it is still needed) is made against the state
  // the commit actually lands on, not the one it had before a lost race.
  async _commitWithRebase(plan, tries = 5) {
    if (!this.member) throw new Error('group not loaded');
    for (let i = 0; i < tries; i++) {
      await this._catchUp();
      this._assertInStep();
      const planned = typeof plan === 'function' ? plan() : plan;
      if (!planned) return { epoch: this.member.epoch, groupKey: this.groupKey() };   // nothing to commit
      const { spec, dir } = planned;
      const snapshot = this.member.exportState();
      const base = this.member.epoch;
      const commit = await this.member.commit(spec);   // mutates member → base+1
      const res = await this._post({ commit, dir: dir || {} }, base);
      if (!res.conflict) {
        this._applyDir(dir);
        await this._persist();
        return { epoch: res.epoch, groupKey: this.groupKey() };
      }
      // Lost the epoch race — roll back the speculative commit, catch up, retry.
      // Restore into a FRESH member: a speculative add that grew the tree cannot be
      // undone in place (growth only goes up), and would leave its leaf seated.
      this.member = this._newMember();
      this.member.importState(snapshot, this.rivetPriv);
    }
    throw new Error('DS commit failed after retries (persistent epoch conflict)');
  }

  // The leaf the next member takes: the lowest one that is FREE — held by no
  // address in the public directory and not seated in the tree (a blank left by a
  // removal is reused first). Past the last leaf, the add grows the tree.
  //
  // The directory decides, never the shape alone. "Every leaf below capacity is
  // taken, so take capacity" handed a sitting member's leaf to a newcomer when the
  // shape was stale (the library, epoch 21: leaf 8 re-seated over its holder).
  _nextLeaf() {
    const taken = new Set(Object.values(this.leafDir).map(Number));
    const leaves = this.member?.leaves || [];
    let i = 1;
    while (taken.has(i) || (leaves[i] && !leaves[i].blank)) i++;
    return i;
  }

  // Every leaf the public directory names must EXIST in this member's tree. A copy
  // whose tree is shorter than the directory it carries has lost its shape — its
  // K is not the group's, and a commit from it seals path secrets to a tree nobody
  // else holds (the library's epoch 21 grew 8 → 16 a second time over a sitting
  // member). It fails here, before it reads or commits, rather than guessing.
  //
  // A directory entry at an EMPTY leaf is different: that is a stale claim in the
  // group's own record, the same for every device (a remove that blanked a leaf the
  // directory still names). It does not make this copy wrong, so it is not refused;
  // removeMember corrects it, and isSeated() never counts it as a seat.
  _assertInStep() {
    const leaves = this.member?.leaves || [];
    for (const [address, idx] of Object.entries(this.leafDir)) {
      if (!leaves[Number(idx)]) {
        const e = new Error(
          `this device's copy of the group is out of step with the log: ${address} sits at leaf ${idx}, ` +
          `which does not exist in this device's tree (capacity ${this.member?.capacity}). ` +
          'It must not commit — a current key-holder should remove this device from the group and add it again.');
        e.code = 'OUT_OF_STEP';
        throw e;
      }
    }
  }

  // Whether `address` holds a seat: named by the directory AND the occupant of
  // that leaf. A directory entry alone is only a claim.
  isSeated(address) {
    const a = String(address).toLowerCase();
    const leaf = this.leafDir[a];
    return leaf != null && this._holds(a, leaf);
  }

  // Add a member (its rivet pubkey at a free leaf). Authorization (may they be a
  // member) is a separate on-chain setMember by the owner — this is key-delivery.
  //
  // A full group GROWS rather than refusing. Seating past the last leaf doubles
  // the tree, which rotates the committer's path and so advances the epoch; an
  // ordinary add still does not rotate.
  async addMember(address, pub) {
    const a = String(address).toLowerCase();
    // Decided after each catch-up: a concurrent key-holder may already have seated
    // this address (the library's epochs 6–12: one address seated seven times in
    // seven seconds by responders that each chose before catching up).
    return this._commitWithRebase(() => {
      if (this.isSeated(a)) return null;
      const leaf = this._nextLeaf();
      return { spec: { type: 'add', addLeafIndex: leaf, addPub: pub }, dir: { set: { [a]: leaf } } };
    });
  }

  // Remove a member: rotates the committer's path so the removed rivet cannot
  // derive the next epoch key (forward secrecy).
  //
  // A directory entry whose leaf seats someone else (or no one) is a stale claim,
  // not a seat: the commit corrects the directory and leaves the leaf's occupant
  // alone. Removing by leaf index alone evicted the occupant — after the library's
  // epoch 21, leaf 8 carried two directory entries and seated only one of them.
  async removeMember(address) {
    const a = String(address).toLowerCase();
    return this._commitWithRebase(() => {
      const leaf = this.leafDir[a];
      if (leaf == null) throw new Error('not a member of this group');
      return this._holds(a, leaf)
        ? { spec: { type: 'remove', removeLeafIndex: leaf }, dir: { del: [a] } }
        : { spec: { type: 'update' }, dir: { del: [a] } };
    });
  }

  // Whether `address` is the member actually seated at `leaf`: the tree records
  // each seated leaf's rivet public key, and an address is a function of it.
  _holds(address, leaf) {
    const lf = this.member?.leaves?.[Number(leaf)];
    if (!lf || lf.blank || !lf.pub) return false;
    const pub = String(lf.pub).startsWith('0x') ? lf.pub : '0x' + lf.pub;
    return globalThis.ethers.utils.computeAddress(pub).toLowerCase() === address;
  }

  // Self-update (post-compromise healing): rotate this member's own path.
  async update() { return this._commitWithRebase({ spec: { type: 'update' }, dir: {} }); }

  // ---- seat requests: public-read admission via the proposals mailbox --------
  // Membership is the chain's (roleOf); key-delivery is ours. A member with no
  // leaf ASKS for a seat by posting a proposal carrying its rivet pubkey. The
  // relay authorizes the ask at roleOf>=read (a read member is entitled to its
  // key). `by` (the recovered signer) is the authoritative asker; the blob
  // carries the pubkey a committer needs to seat a leaf. No special "reader"
  // path — the asker becomes a normal leaf; roleOf still gates its writes.
  async requestSeat() {
    const body = encBytes({ address: this.address, pub: this.rivetPub });
    const auth = await this.sign('POST', `${this.session}/_ds/proposal`, body);
    const r = await this.fetch(this._u('/proposals'), {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream', authorization: auth },
      body,
    });
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || `seat request → ${r.status}`); }
    return r.json();   // { id }
  }

  async listSeatRequests() {
    const r = await this.fetch(this._u('/proposals'));
    if (!r.ok) return [];
    const rows = await r.json();
    return (rows || []).map((row) => {
      let p = {};
      try { p = decBytes(fromB64(row.blob)); } catch { /* opaque / not a seat request */ }
      return { id: row.id, address: (row.by || p.address || '').toLowerCase(), pub: p.pub, ts: row.ts };
    }).filter((q) => q.address && q.pub);
  }

  // A present key-holder drains seat requests: for each asker the chain still
  // recognizes as a member (isMember(address), the caller's on-chain roleOf
  // check), seat it (Add commit + Welcome) and consume the request. Returns the
  // count newly seated. Best-effort per request — an epoch conflict leaves it
  // pending for the next drain.
  async drainSeatRequests(isMember) {
    if (!this.member) throw new Error('group not loaded');
    const reqs = await this.listSeatRequests();
    const done = [];
    for (const q of reqs) {
      if (this.isSeated(q.address)) { done.push(q.id); continue; }   // already holds its leaf
      if (isMember && !(await isMember(q.address))) continue;               // not a member per the chain
      try { await this.addMember(q.address, q.pub); done.push(q.id); }
      catch { /* epoch conflict — retry next drain */ }
    }
    if (done.length) { try { await this._consumeSeatRequests(done); } catch { /* best-effort */ } }
    return done.length;
  }

  async _consumeSeatRequests(ids) {
    const epoch = this.member.epoch;
    const str = JSON.stringify({ ids, epoch });   // must match the relay's re-stringify order {ids, epoch}
    const auth = await this.sign('POST', `${this.session}/_ds/consume`, new TextEncoder().encode(str));
    const r = await this.fetch(this._u('/proposals/consume'), {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body: str,
    });
    if (!r.ok) throw new Error(`consume → ${r.status}`);
    return r.json();
  }
}
