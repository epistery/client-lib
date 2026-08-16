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

const DEFAULT_CAPACITY = 8;   // v1 fixed capacity (spike scope; tree-doubling is later work)
const encBytes = (obj) => new TextEncoder().encode(JSON.stringify(obj));
const decBytes = (buf) => JSON.parse(new TextDecoder().decode(new Uint8Array(buf)));

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
    const r = await this.fetch(this._u('/commit'), {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth, 'x-ds-epoch': String(baseEpoch) },
      body,
    });
    if (r.status === 409) { const j = await r.json().catch(() => ({})); return { conflict: true, current: j.current }; }
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
      this._applyDir(env.dir);
      await this.member.apply(env.commit);
    }
  }

  // ---- load existing state: restore-then-catch-up, else Welcome bootstrap ----
  async load() {
    const saved = this.store?.load ? await this.store.load() : null;
    if (saved?.member) {
      this.member = this._newMember();
      this.member.importState(saved.member, this.rivetPriv);
      this.leafDir = saved.leafDir || {};
      await this._catchUp();
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
    if (myLeaf == null) throw new Error('this rivet holds no leaf in the group — a present key-holder must add it');
    if (myLeaf === 0) throw new Error('founder tree state is held by the creating device (no Welcome for leaf 0)');
    const addEntry = envs.find(x => x.env?.commit?.type === 'add' && x.env.commit.addLeafIndex === myLeaf);
    if (!addEntry) throw new Error('no Welcome for this rivet — ask a present key-holder to re-add this device');
    this.member = this._newMember();
    await this.member.applyWelcome(addEntry.env.commit.welcome, myLeaf, this.rivetPriv);
    await this.member.apply(addEntry.env.commit);
    for (const x of envs) {
      if (x.epoch > addEntry.epoch && x.env) { this._applyDir(x.env.dir); await this.member.apply(x.env.commit); }
    }
    await this._persist();
    return this.groupKey();
  }

  // ---- commit a membership change, rebasing on a DS conflict -----------------
  async _commitWithRebase(spec, dir, tries = 5) {
    if (!this.member) throw new Error('group not loaded');
    for (let i = 0; i < tries; i++) {
      await this._catchUp();
      const snapshot = this.member.exportState();
      const base = this.member.epoch;
      const commit = await this.member.commit(spec);   // mutates member → base+1
      const res = await this._post({ commit, dir: dir || {} }, base);
      if (!res.conflict) {
        this._applyDir(dir);
        await this._persist();
        return { epoch: res.epoch, groupKey: this.groupKey() };
      }
      // lost the epoch race — roll back the speculative commit, catch up, retry
      this.member.importState(snapshot, this.rivetPriv);
    }
    throw new Error('DS commit failed after retries (persistent epoch conflict)');
  }

  _freeLeaf() {
    const taken = new Set(Object.values(this.leafDir));
    for (let i = 1; i < this.capacity; i++) if (!taken.has(i)) return i;
    return -1;
  }

  // Add a member (its rivet pubkey at a free leaf). Authorization (may they be a
  // member) is a separate on-chain setMember by the owner — this is key-delivery.
  async addMember(address, pub) {
    const leaf = this._freeLeaf();
    if (leaf < 0) throw new Error('group at capacity');
    return this._commitWithRebase({ type: 'add', addLeafIndex: leaf, addPub: pub }, { set: { [String(address).toLowerCase()]: leaf } });
  }

  // Remove a member: rotates the committer's path so the removed rivet cannot
  // derive the next epoch key (forward secrecy).
  async removeMember(address) {
    const a = String(address).toLowerCase();
    const leaf = this.leafDir[a];
    if (leaf == null) throw new Error('not a member of this group');
    return this._commitWithRebase({ type: 'remove', removeLeafIndex: leaf }, { del: [a] });
  }

  // Self-update (post-compromise healing): rotate this member's own path.
  async update() { return this._commitWithRebase({ type: 'update' }, {}); }
}
