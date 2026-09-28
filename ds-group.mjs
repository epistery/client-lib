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
//
// 3 = every commit states the tree it was built on (`parentHash`) and the tree it
// produces (`treeHash`) — hashes of the PUBLIC tree. A committer may post only when
// its tree matches the one the log last recorded, so a stale or diverged device
// stops before it commits. A member skips, deterministically, a commit built on a
// tree other than the log's, or one whose public part is invalid (an add over an
// occupied leaf, ...): every in-step member reaches the same verdict, so the group
// moves on without it. Faults only visible privately (a path secret that will not
// open) still leave a member STUCK, never skipping — members could disagree there.
//
// 4 = every commit is SIGNED, and members check it themselves. The relay serves
// each commit's credential (the committer's own signed message, binding its
// address to the SHA-256 of these exact bytes); a member verifies the signature and
// that the signer holds the committer's leaf in its own tree — a restore, that it
// is signed by its founder, who sat in the tree it replaces. The relay can then add
// nothing to a group: it cannot sign as a member. The format is stated inside the
// commit, and after a member has seen a format-4 commit an older one is a
// downgrade: invalid, so credentials cannot be stripped to slip a commit past.
export const DS_FORMAT = 4;

// The size a NEW group's tree starts at. Not a ceiling: a full tree doubles when
// the next member is seated (treekem growTree), so a group grows with its
// membership — one primitive at any size, which is what the tree was adopted for.
const DEFAULT_CAPACITY = 8;
const encBytes = (obj) => new TextEncoder().encode(JSON.stringify(obj));

// Hash of a member's PUBLIC tree: shape plus each node's public key. A blank node
// hashes as blank whatever stale key it holds, so every member hashes the same tree
// the same way.
export function treeHashOf(member) {
  const nodes = member._snapshotPublic()
    .map((n) => [n.id, n.blank ? 0 : 1, n.blank ? null : String(n.pub || '').toLowerCase()])
    .sort((a, b) => a[0] - b[0]);
  return globalThis.ethers.utils.sha256(encBytes({ c: member.capacity, n: nodes }));
}
const shortHash = (h) => String(h || '').slice(0, 10);
const lc = (a) => String(a || '').toLowerCase();
const addressOfPub = (pub) => { try { return lc(globalThis.ethers.utils.computeAddress(String(pub).startsWith('0x') ? pub : '0x' + pub)); } catch { return null; } };
const sha256hexOf = (bytes) => globalThis.ethers.utils.sha256(bytes).slice(2).toLowerCase();
function decodeCred(b64url) {
  let b = String(b64url || '').replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  const bin = atob(b);
  const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(u));
}
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
    // chain: an attestation chain reader (epistery core's chainReader — owned nodes
    // only) the CLIENT uses itself, never through the relay. With it, a device joining from
    // scratch confirms on chain that whoever seated it may commit to this session,
    // and that the founder of any restore it follows is an owner rivet.
    if (!opts.chain?.mayCommit) throw new Error('DsGroup: a chain reader is required (epistery chainReader) — a group is joined on the chain\'s word, never a server\'s');
    this.chain = opts.chain;
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
  // Set when a commit in the log cannot be applied: { epoch, code, reason, signer }.
  // The member stays at the epoch before it, holding every key up to there — the
  // session reads, and nothing is committed or sealed until the group is restored.
  // One commit that members cannot apply (a buggy, stale or hostile writer) used to
  // leave every member with NO key at all, history included.
  stuck = null;
  // The public-tree hash the log last recorded AND this member was confirmed to
  // hold (null before any hash-bearing commit). Commits built on another tree are
  // skipped only while this holds.
  inStep = null;
  // Commits this member skipped as invalid: [{ epoch, reason, signer }].
  skipped = [];
  // The first epoch at which this member saw a SIGNED (format 4) commit; from then
  // on an unsigned or older-format commit is a downgrade. Persisted.
  signedFrom = null;
  // Raw commit bytes by epoch, as fetched — a credential signs these exact bytes.
  _raw = new Map();
  // The key that sealed a record tagged with `epoch` — the read path for content
  // written under an earlier epoch (floor lookup over the retained keyring). A
  // null/absent tag resolves to NO key: an untagged record is a fault, not a guess.
  keyForEpoch(epoch) { return this.member ? this.member.keyForEpoch(epoch) : null; }

  // ---- DS reads (public) -----------------------------------------------------
  async _log(since = 0) {
    const r = await this.fetch(this._u(`/log?since=${since}`));
    if (!r.ok) return [];
    return r.json();
  }
  async _head() {
    const r = await this.fetch(this._u('/head'));
    if (!r.ok) throw new Error(`DS head → ${r.status}`);
    return r.json();   // { epoch, head }
  }
  async _payload(epoch) {
    const r = await this.fetch(this._u(`/commit/${epoch}`));
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`DS commit/${epoch} → ${r.status}`);
    const raw = new Uint8Array(await r.arrayBuffer());
    this._raw.set(epoch, raw);
    return decBytes(raw);
  }

  // Who signed the commit at `epoch`, verified HERE from the credential the relay
  // serves: { address } or { fault }. Never the relay's own `signer` field.
  _verifiedSigner(epoch, cred) {
    if (!cred) return { fault: 'carries no signature' };
    let c;
    try { c = decodeCred(cred); } catch { return { fault: 'has an unreadable signature' }; }
    const lines = String(c?.message || '').split('\n');
    if (lines.length !== 6 || lines[0] !== 'epistery-storage-write' || lines[1] !== 'POST') return { fault: 'is signed for something other than a commit' };
    if (lc(lines[2]) !== lc(this.contract) || lc(lines[3]) !== lc(`${this.session}/_ds/commit`)) return { fault: 'is signed for another session' };
    const raw = this._raw.get(epoch);
    if (!raw || lc(lines[4]) !== sha256hexOf(raw)) return { fault: 'has a signature that does not cover these bytes' };
    let address;
    try { address = lc(globalThis.ethers.utils.verifyMessage(c.message, c.signature)); } catch { return { fault: 'has a signature that does not verify' }; }
    if (address !== lc(c.address)) return { fault: 'has a signature from a key other than the one it names' };
    return { address, identity: c.identity ? lc(c.identity) : null };
  }

  // THE anchor of a device that joins from scratch. Every later commit is checked
  // against the tree this Welcome hands over (_applyChecked), so this is the one
  // thing such a device takes on trust — and it takes it from the chain, never from
  // a server: the Welcome must be signed by the member at its committer leaf, and
  // that member must be one the chain lets commit to this session (an owner rivet,
  // or a section writer). A relay could build a whole group around a device; it
  // can be neither. A forged restore reaches a new device only through such a
  // Welcome, so this covers it too.
  async _welcomeIsTheGroups(tree, commit, epoch, cred) {
    const refuse = (why) => { const e = new Error(`the Welcome that seats this device ${why} — refusing it`); e.code = 'FORGED_WELCOME'; throw e; };
    const s = this._verifiedSigner(epoch, cred);
    if (s.fault) refuse(s.fault);
    const lf = tree.leaves[commit.committerLeafIndex];
    if (!lf || lf.blank || addressOfPub(lf.pub) !== s.address) refuse('is not signed by the member who seated it');
    if (!(await this._onChain(() => this.chain.mayCommit(this.contract, this.session, s.address, s.identity)))) {
      refuse(`was signed by ${s.address}, who may not commit to this session on chain`);
    }
  }

  // A chain read that must answer. No answer is not "no": the device refuses to
  // join and says why, rather than joining a group it could not check.
  async _onChain(read) {
    try { return await read(); }
    catch (err) {
      if (err.code !== 'CHAIN_UNREACHABLE' && err.code !== 'CHAIN_DISAGREES') throw err;
      const e = new Error(`could not confirm this group against the chain (${err.message}) — try again`);
      e.code = err.code;
      throw e;
    }
  }

  // Whether a reinit at `epoch` is genuine for THIS member: signed by its founder,
  // who sat in the tree it replaces (this member's current one). A relay cannot
  // restart a group — it holds no seat.
  _reinitAccepted(commit, epoch, cred) {
    if ((commit.format || 0) < 4) return !this.signedFrom;   // pre-signature restore: accepted only before signing began
    const s = this._verifiedSigner(epoch, cred);
    if (s.fault || s.address !== addressOfPub(commit.founderPub)) return false;
    if (!this.member) return true;   // a fresh device has no prior tree: its Welcome is its anchor (_welcomeIsTheGroups)
    return this.member.leaves.some((lf) => lf && !lf.blank && lf.pub && addressOfPub(lf.pub) === s.address);
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
  async _persist() { if (this.store?.save) await this.store.save({ member: this.member.exportState(), leafDir: this.leafDir, inStep: this.inStep, signedFrom: this.signedFrom }); }
  _applyDir(dir) { if (!dir) return; if (dir.reset) this.leafDir = {}; if (dir.set) Object.assign(this.leafDir, dir.set); if (dir.del) for (const a of dir.del) delete this.leafDir[String(a).toLowerCase()]; }

  // ---- create a brand-new group (founder at leaf 0, epoch 1) -----------------
  async create() {
    this.member = this._newMember();
    this.member.seat(0, this.rivetPriv, this.rivetPub);
    const commit = await this.member.commit({ type: 'update' });   // establishes epoch 1
    commit.format = DS_FORMAT;
    commit.treeHash = treeHashOf(this.member);
    this.signedFrom = 1;
    this.inStep = commit.treeHash;
    this.leafDir = { [this.address]: 0 };
    const res = await this._post({ commit, dir: { set: { [this.address]: 0 } } }, 0);
    if (res.conflict) throw new Error('a group already exists at this session');
    await this._persist();
    return this.groupKey();
  }

  // The epoch of a reinit by ANOTHER device after `epoch` in `log`, or null.
  async _laterReinit(log, epoch) {
    for (const e of log) {
      if (e.epoch <= epoch) continue;
      const env = await this._payload(e.epoch);
      const c = env?.commit;
      if (c?.type === 'reinit' && String(c.founderPub || '').toLowerCase() !== String(this.rivetPub || '').toLowerCase()
        && this._reinitAccepted(c, e.epoch, e.cred)) return e.epoch;
    }
    return null;
  }

  // Apply a commit with the diligence checks (DS_FORMAT 3), all or nothing:
  // Member.apply can change the tree before it fails, so a failure puts back the
  // member it started from — never a half-applied tree.
  // Returns 'skipped' for
  // a commit every in-step member rejects the same way; throws (→ STUCK) when this
  // member cannot tell; otherwise applies it all or nothing and confirms the tree
  // it produces against the hash the commit records.
  async _applyChecked(commit, meta = {}) {
    const mine = treeHashOf(this.member);
    const confirmed = !!this.inStep && this.inStep === mine;
    const skip = (reason) => {
      this.member.epoch += 1;   // the log's epoch passes; keys, tree and directory do not change
      this.skipped.push({ epoch: meta.epoch ?? this.member.epoch, reason, signer: meta.signer || null });
      return 'skipped';
    };
    const outOfStep = (why) => { const e = new Error(why); e.code = 'OUT_OF_STEP'; return e; };
    if (commit.parentHash && commit.parentHash !== mine) {
      if (confirmed) return skip(`built on a tree other than the log's (${shortHash(commit.parentHash)} ≠ ${shortHash(mine)})`);
      throw outOfStep(`this device's tree (${shortHash(mine)}) is not the one this commit was built on (${shortHash(commit.parentHash)}), and it cannot confirm which is the log's`);
    }
    // Only commits written under these rules (format 3: they carry tree hashes) are
    // judged by them. History from before is replayed exactly as it always was —
    // it contains commits every member already applied (the library's epoch 21
    // added over an occupied leaf), and members' keys depend on applying them.
    const judged = !!(commit.parentHash || commit.treeHash);
    const signed = (commit.format || 0) >= 4;
    // Downgrades: once a group carries hashes, a commit without them is not one of
    // its commits; once it carries signatures, an unsigned one is not either.
    const downgrade = (!judged && this.inStep) ? 'carries no tree hashes, after this group adopted them'
      : (!signed && this.signedFrom) ? 'is unsigned, after this group adopted signed commits' : null;
    if (downgrade) {
      if (confirmed) return skip(downgrade);
      throw outOfStep(`${downgrade} — and this device cannot confirm its tree against the log`);
    }
    if (signed) {
      const s = this._verifiedSigner(meta.epoch, meta.cred);
      const lf = this.member.leaves[commit.committerLeafIndex];
      const bad = s.fault ? s.fault
        : (!lf || lf.blank || addressOfPub(lf.pub) !== s.address) ? `is signed by ${s.address.slice(0, 10)}…, not the member at leaf ${commit.committerLeafIndex}` : null;
      if (bad) {
        if (confirmed || !judged) return skip(bad);
        throw outOfStep(`${bad} — and this device cannot confirm its tree against the log`);
      }
    }
    const fault = judged ? this._publicFault(commit) : null;
    if (fault) {
      if (confirmed) return skip(fault);
      throw outOfStep(`${fault} — and this device cannot confirm its tree against the log`);
    }
    const before = this.member.exportState();
    try {
      await this.member.apply(commit);
      if (commit.treeHash) {
        const after = treeHashOf(this.member);
        if (after !== commit.treeHash) throw outOfStep(`after applying, this device's tree (${shortHash(after)}) is not the one the commit records (${shortHash(commit.treeHash)})`);
        this.inStep = after;
        if (signed && this.signedFrom == null) this.signedFrom = meta.epoch ?? this.member.epoch;
      } else {
        this.inStep = null;   // a commit without a hash (older format): the tree is no longer confirmed
      }
    } catch (err) {
      this.member = this._newMember();
      this.member.importState(before, this.rivetPriv);
      throw err;
    }
    return 'applied';
  }

  // A fault in a commit's PUBLIC part, judged on this member's public tree — the
  // same verdict for every member that holds the log's tree. null when none.
  _publicFault(commit) {
    const m = this.member;
    const cap = Math.max(m.capacity, Number(commit.capacity) || 0);
    const leafAt = (i) => (Number.isInteger(i) && i >= 0 && i < m.leaves.length ? m.leaves[i] : null);
    if (commit.type === 'reinit') return null;
    const committer = leafAt(commit.committerLeafIndex);
    if (!committer || committer.blank) return `committed from leaf ${commit.committerLeafIndex}, which holds no member`;
    if (commit.type === 'add') {
      const i = commit.addLeafIndex;
      if (!Number.isInteger(i) || i < 0 || i >= cap) return `adds at leaf ${i}, outside the tree`;
      const lf = leafAt(i);
      if (lf && !lf.blank) return `adds over leaf ${i}, which already holds a member`;
      if (!commit.addPub) return 'adds a member with no public key';
    }
    if (commit.type === 'remove') {
      const lf = leafAt(commit.removeLeafIndex);
      if (!lf || lf.blank) return `removes leaf ${commit.removeLeafIndex}, which holds no member`;
    }
    return null;
  }

  // Record that the log cannot be followed past `epoch`. The member is left at the
  // epoch before it (see _applyChecked), keys intact.
  _stick(epoch, err, signer = null) {
    this.stuck = { epoch, code: err.code || 'APPLY_FAILED', reason: err.epLabel || err.message, signer };
  }
  _stuckError() {
    const s = this.stuck;
    const e = new Error(`this group cannot move past epoch ${s.epoch} (${s.reason}) — it reads up to epoch ${s.epoch - 1}; nothing can be written until an owner restores the group`);
    e.code = 'STUCK';
    e.stuck = s;
    return e;
  }

  // ---- catch up a LIVE member by applying commits after its epoch ------------
  // `tolerate`: a commit that cannot be applied leaves the group STUCK (readable up
  // to the epoch before it) instead of throwing — used on load, so one bad commit
  // never costs a member the history it already holds. NO_SEAT still throws.
  async _catchUp({ tolerate = false } = {}) {
    const log = await this._log(this.member.epoch);
    for (const e of log) {
      if (e.epoch <= this.member.epoch) continue;
      const env = await this._payload(e.epoch);
      if (!env) continue;
      // A REINIT ends the tree this member is in (reinit()). Its own reinit, made by
      // another instance of this rivet, is adopted from the shared store; anyone
      // else's means this member must join the new tree — load() bootstraps it from
      // its Welcome there, carrying the keys it already holds.
      if (env.commit?.type === 'reinit') {
        const mine = String(env.commit.founderPub || '').toLowerCase() === String(this.rivetPub || '').toLowerCase();
        if (mine && await this._adoptSaved(e.epoch)) continue;
        if (!mine && !this._reinitAccepted(env.commit, e.epoch, e.cred)) {
          // Not a restore this member can accept (unsigned after signing began, not
          // signed by its founder, or a founder who never sat in this tree): it is
          // not the group's, and this member stays in the tree it has.
          this.member.epoch += 1;
          this.skipped.push({ epoch: e.epoch, reason: 'a restore not signed by a member of this group', signer: e.signer || null });
          continue;
        }
        if (mine) { const err = new Error('this device restored the group from another instance whose saved state is not here'); err.code = 'OWN_COMMIT'; err.epLabel = `catchup@${e.epoch}(reinit) › ${err.message}`; if (tolerate) { this._stick(e.epoch, err, e.signer || null); return; } throw err; }
        this.restoredAt = e.epoch;
        return;
      }
      let outcome;
      try { outcome = await this._applyChecked(env.commit, { epoch: e.epoch, signer: e.signer, cred: e.cred }); }
      catch (err) {
        // My own rotating commit, made by another instance of this rivet: take the
        // state that instance saved (the store is shared) instead of applying it.
        if (err.code === 'OWN_COMMIT' && await this._adoptSaved(e.epoch)) continue;
        err.epLabel = `catchup@${e.epoch}(${env.commit?.type || '?'}) › ${err.epLabel || err.message}`;
        if (tolerate && err.code !== 'NO_SEAT') {
          // A commit that will not apply may already have been answered: an owner
          // restored the group past it. Then this member joins the new tree rather
          // than stopping at the wedge.
          const later = await this._laterReinit(log, e.epoch);
          if (later) { this.restoredAt = later; return; }
          this._stick(e.epoch, err, e.signer || null);
          return;
        }
        throw err;
      }
      if (outcome === 'skipped') continue;   // an invalid commit: its directory is not applied either
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
    this.inStep = saved.inStep || null;
    this.signedFrom = saved.signedFrom ?? null;
    return true;
  }

  // ---- load existing state: restore-then-catch-up, else Welcome bootstrap ----
  async load() {
    const saved = this.store?.load ? await this.store.load() : null;
    if (saved?.member) {
      this.member = this._newMember();
      this.member.importState(saved.member, this.rivetPriv);
      this.leafDir = saved.leafDir || {};
      this.inStep = saved.inStep || null;
      this.signedFrom = saved.signedFrom ?? null;
      this.skipped = [];
      this.stuck = null;
      this.restoredAt = null;
      await this._catchUp({ tolerate: true });
      // The group was restored (another owner device's reinit): join the new tree,
      // keeping every key this device already held.
      if (this.restoredAt) return this._bootstrapFromWelcome({ carry: this.member.keyring });
      if (this.stuck) { await this._persist(); return this.groupKey(); }
      // Removed since that save — the catch-up applied this device's own removal,
      // which leaves it on a placeholder key by design (forward secrecy). That is
      // not a readable group: start again from the log, which seats this device
      // from a newer Welcome if it was added back, or reports NO_SEAT so the
      // key-request starts — "waiting for your key", never an undecryptable page.
      if (!this._seatedAsMember()) return this._bootstrapFromWelcome();
      this._assertInStep();
      await this._persist();
      return this.groupKey();
    }
    return this._bootstrapFromWelcome();
  }

  // `carry`: keys this device already holds from an earlier tree (a restored group),
  // kept beside whatever its new Welcome delivers.
  async _bootstrapFromWelcome({ carry = null } = {}) {
    this.stuck = null;
    this.restoredAt = null;
    this.inStep = null;
    this.signedFrom = null;
    this.skipped = [];
    this.leafDir = {};   // rebuilt from the whole log below, never layered over a copy
    const full = await this._log(0);
    if (!full.length) throw new Error('no group commits to load');
    const all = [];
    for (const e of full) all.push({ epoch: e.epoch, env: await this._payload(e.epoch) });
    // Only the current tree counts: everything from the latest reinit on.
    const credOf = (ep) => full.find((l) => l.epoch === ep)?.cred || null;
    const lastReinit = [...all].reverse().find((x) => x.env?.commit?.type === 'reinit' && this._reinitAccepted(x.env.commit, x.epoch, credOf(x.epoch)));
    const envs = lastReinit ? all.filter((x) => x.epoch >= lastReinit.epoch) : all;
    const log = full.filter((e) => envs.some((x) => x.epoch === e.epoch));
    for (const x of envs) this._applyDir(x.env?.dir);
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
    // applyWelcome adopts the live tree (incl. my seated leaf) and the current
    // key — the non-rotating add means there is nothing to replay for my own add.
    // The Welcome is judged before this device takes anything from it.
    const m = this._newMember();
    try { await m.applyWelcome(addEntry.env.commit.welcome, myLeaf, this.rivetPriv); }
    catch (err) { err.epLabel = `bootstrap Welcome@${addEntry.epoch} › ${err.epLabel || err.message}`; throw err; }
    if ((addEntry.env.commit.format || 0) >= 4) {
      await this._welcomeIsTheGroups(m, addEntry.env.commit, addEntry.epoch, credOf(addEntry.epoch));
      this.signedFrom = addEntry.epoch;
    }
    this.member = m;
    if (carry) for (const [e, k] of carry) if (!this.member.keyring.has(Number(e))) this.member.keyring.set(Number(e), k);
    // The Welcome's tree is the one the add produced: confirm it against the hash
    // the add records, so this device can judge the commits that follow.
    if (addEntry.env.commit.treeHash && addEntry.env.commit.treeHash === treeHashOf(this.member)) this.inStep = addEntry.env.commit.treeHash;
    for (const x of envs) {
      if (x.epoch > addEntry.epoch && x.env) {
        let outcome;
        try { outcome = await this._applyChecked(x.env.commit, { epoch: x.epoch, signer: log.find((l) => l.epoch === x.epoch)?.signer || null, cred: credOf(x.epoch) }); }
        catch (err) {
          err.epLabel = `replay@${x.epoch}(${x.env.commit?.type || '?'}) › ${err.epLabel || err.message}`;
          // Stuck, not lost: keep everything up to the commit that will not apply,
          // and a directory that describes that tree, not the one after it.
          this._stick(x.epoch, err, log.find((l) => l.epoch === x.epoch)?.signer || null);
          this.leafDir = {};
          for (const y of envs) if (y.epoch < x.epoch) this._applyDir(y.env?.dir);
          await this._persist();
          return this.groupKey();
        }
      }
    }
    // A skipped commit's directory entry is not the group's: rebuild without them.
    if (this.skipped.length) {
      const skippedAt = new Set(this.skipped.map((x) => x.epoch));
      this.leafDir = {};
      for (const x of envs) if (!skippedAt.has(x.epoch)) this._applyDir(x.env?.dir);
    }
    this._assertInStep();
    await this._persist();
    return this.groupKey();
  }

  // ---- restore a wedged group: start a new tree past the commit nobody can apply
  //
  // This device becomes the founder (leaf 0) of a fresh tree at the next DS epoch,
  // carrying its WHOLE keyring forward — every Welcome it gives out later hands a
  // newcomer the history up to the wedge. The relay accepts a reinit only from a
  // rivet of the owner contract. The caller then seats the owner's keys and the
  // previous members (ownerSeats.restoreGroup). Works from a stuck group, which is
  // the point, and from a healthy one.
  async reinit() {
    const carried = new Map(this.member?.keyring || []);
    for (let i = 0; i < 5; i++) {
      const { epoch: base } = await this._head();
      const m = this._newMember();
      m.seat(0, this.rivetPriv, this.rivetPub);
      m.epoch = base;
      m.keyring = new Map(carried);
      const upd = await m.commit({ type: 'update' });   // base+1: a fresh key, retained beside the carried ones
      const commit = { type: 'reinit', format: DS_FORMAT, capacity: m.capacity, committerLeafIndex: 0, founderPub: this.rivetPub, path: upd.path, treeHash: treeHashOf(m) };
      const res = await this._post({ commit, dir: { reset: true, set: { [this.address]: 0 } } }, base);
      if (res.conflict) continue;
      this.member = m;
      this.leafDir = { [this.address]: 0 };
      this.stuck = null;
      this.restoredAt = null;
      this.inStep = commit.treeHash;
      this.signedFrom = m.epoch;
      this.skipped = [];
      await this._persist();
      return { epoch: m.epoch, groupKey: this.groupKey() };
    }
    throw new Error('restore failed after retries (persistent epoch conflict)');
  }

  // ---- commit a membership change, rebasing on a DS conflict -----------------
  // `plan` is { spec, dir }, or a function returning one (or null: nothing left to
  // do) — evaluated AFTER each catch-up, so a choice that depends on the live tree
  // (which leaf an add takes, whether it is still needed) is made against the state
  // the commit actually lands on, not the one it had before a lost race.
  async _commitWithRebase(plan, tries = 5) {
    if (!this.member) throw new Error('group not loaded');
    if (this.stuck) throw this._stuckError();
    for (let i = 0; i < tries; i++) {
      await this._catchUp();
      if (this.restoredAt) {
        const e = new Error(`this group was restored at epoch ${this.restoredAt} — reload to join the new tree`);
        e.code = 'RESTORED';
        throw e;
      }
      this._assertInStep();
      // Diligence before committing: this device's tree must be the one the log
      // last recorded. A stale tab or a diverged copy stops HERE, before it posts a
      // commit the rest of the group would have to reject.
      const parentHash = treeHashOf(this.member);
      if (this.inStep && this.inStep !== parentHash) {
        const e = new Error(`this device's copy of the group (${shortHash(parentHash)}) is not the tree the log records (${shortHash(this.inStep)}) — reload before changing the group`);
        e.code = 'OUT_OF_STEP';
        throw e;
      }
      const planned = typeof plan === 'function' ? plan() : plan;
      if (!planned) return { epoch: this.member.epoch, groupKey: this.groupKey() };   // nothing to commit
      const { spec, dir } = planned;
      const snapshot = this.member.exportState();
      const base = this.member.epoch;
      const commit = await this.member.commit(spec);   // mutates member → base+1
      commit.format = DS_FORMAT;
      commit.parentHash = parentHash;
      commit.treeHash = treeHashOf(this.member);
      const res = await this._post({ commit, dir: dir || {} }, base);
      if (!res.conflict) {
        this.inStep = commit.treeHash;
        if (this.signedFrom == null) this.signedFrom = res.epoch;
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

  // Whether THIS device's member state is seated where the directory places it.
  // Different from isSeated(this.address): a device removed and later added back
  // at a new leaf is seated by the log, but a member restored from its old save
  // still stands on the old, blanked leaf with the placeholder its removal left.
  _seatedAsMember() {
    const leaf = this.leafDir[this.address];
    return leaf != null && this.member?.leafIndex === Number(leaf)
      && !!this.member.leaves[Number(leaf)] && !this.member.leaves[Number(leaf)].blank;
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
