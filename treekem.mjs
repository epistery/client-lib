// P2 core — the client-side ratchet tree (TreeKEM) for the Epistery frontier.
//
// Built directly on P0(b)'s verified key schedule (../treekem-kdf/kdf.mjs): the
// leaf KEM key IS the rivet's secp256k1 key (frontier decision #1 — one key per
// device, no second key), intermediate node keys are derived from path secrets,
// and the group key falls out of the key schedule at the root. Membership
// changes (Add/Remove/Update) produce a COMMIT — the opaque payload the P1
// Delivery Service orders and every member applies to converge on one group key.
//
// What this module proves (see test.mjs): a shifting set of rivets keeps one
// shared group secret without a custodian — all current members derive the SAME
// key, a removed rivet can NOT derive the next one, and a self-Update rotates a
// member's path (post-compromise healing). Bytes never leave the client.
//
// Deliberate v1 scope: fixed leaf capacity (blank leaves reused on add), no
// tree-doubling; resolution handles blanks (removed leaves); the crypto is real.
// The wire/label encoding is ours ("borrow the math, not the format").

import {
  deriveSecret, dhkemEncapDeterministic, dhkemDecap, dhkemDecapFromDH, nodeKeyPair,
  privFromSecret, nextEpoch, toHex, fromHex,
} from './treekem-kdf.mjs';
// Randomness comes from the crypto stack (stack.random) so the SAME tree code
// runs in the browser (crypto.getRandomValues) and Node — no node:crypto import.

const GENESIS_INIT = new Uint8Array(32); // shared group genesis; real groups seed from the group id
const utf8Enc = (s) => new TextEncoder().encode(s);
const utf8Dec = (u8) => new TextDecoder().decode(u8);

// ---- tree topology (identical across every member's copy) -------------------
let _idc = 0;
class TNode {
  constructor() { this.id = _idc++; this.parent = null; this.l = null; this.r = null; this.isLeaf = false; this.leafIndex = -1; this.blank = true; this.pub = null; }
}
export function buildTree(capacity) {
  _idc = 0; // deterministic ids per build so member copies share them
  const leaves = [];
  const build = (depth) => {
    const n = new TNode();
    if (depth === 0) { n.isLeaf = true; n.leafIndex = leaves.length; leaves.push(n); }
    else { n.l = build(depth - 1); n.r = build(depth - 1); n.l.parent = n; n.r.parent = n; }
    return n;
  };
  const root = build(Math.log2(capacity));
  return { root, leaves };
}
const sibling = (n) => (n.parent.l === n ? n.parent.r : n.parent.l);
function directPath(leaf) { const p = []; let n = leaf.parent; while (n) { p.push(n); n = n.parent; } return p; }
function copath(leaf) { const c = []; let below = leaf, n = leaf.parent; while (n) { c.push(sibling(below)); below = n; n = n.parent; } return c; }
function resolution(node) {
  if (!node.blank) return [node];
  if (node.isLeaf) return [];
  return [...resolution(node.l), ...resolution(node.r)];
}

// ---- seal/open a path secret to one node's KEM key (DHKEM + AEAD) -----------
async function sealTo(stack, recipientPub, secret) {
  const ephPriv = privFromSecret(stack.random(32));
  const { enc, shared } = await dhkemEncapDeterministic(stack, recipientPub, ephPriv);
  const iv = stack.random(12);
  const ct = await stack.aeadEncrypt(shared, iv, secret);
  return { enc, iv: toHex(iv), ct: toHex(ct) };
}
async function openFrom(stack, recipientPriv, box) {
  const shared = await dhkemDecap(stack, recipientPriv, box.enc);
  return stack.aeadDecrypt(shared, fromHex(box.iv), fromHex(box.ct));
}

// ---- a member's local view: its own tree copy + secrets + epoch chain -------
export class Member {
  constructor(name, capacity, stack) {
    this.name = name;
    this.stack = stack;
    const t = buildTree(capacity);
    this.root = t.root;
    this.leaves = t.leaves;
    this.leafIndex = -1;        // set on create/add
    this.rivetPriv = null;
    this.secrets = new Map();   // nodeId -> privHex for intermediate nodes this member knows
    this.initSecret = GENESIS_INIT;
    this.epoch = 0;
    this.groupKey = null;           // current epoch's key — the write frontier
    // The epoch keyring: effectiveEpoch -> groupKey hex, RETAINED so a member can
    // still read content sealed under an earlier epoch after a rotation. Only a
    // rotation adds an entry (a non-rotating add reuses the current key); reads
    // resolve a record's epoch tag by floor lookup (keyForEpoch).
    this.keyring = new Map();
    // For a NON-EXTRACTABLE leaf key (the browser rivet), the wallet computes the
    // raw ECDH shared secret; set via setLeafDecap. Server participants (derived,
    // extractable keys) leave this null and use rivetPriv directly.
    this.leafDecap = null;      // (ephemeralEncHex) => Promise<Uint8Array sharedSecret>
  }
  setLeafDecap(fn) { this.leafDecap = fn; return this; }
  _leaf() { return this.leaves[this.leafIndex]; }
  _privFor(node) { return node.isLeaf && node.leafIndex === this.leafIndex ? this.rivetPriv : this.secrets.get(node.id); }

  // Decap a box sealed to MY leaf pub via the non-extractable wallet: the wallet
  // gives the raw ECDH shared secret (leafDecap), we finish HPKE decap + AEAD.
  async _openLeaf(box) {
    const dh = await this.leafDecap(box.enc);
    const shared = await dhkemDecapFromDH(this.stack, dh, box.enc);
    return this.stack.aeadDecrypt(shared, fromHex(box.iv), fromHex(box.ct));
  }
  // Open a sealed box at a resolution node: own non-extractable leaf → the wallet
  // seam; otherwise the raw priv.
  async _open(res, box) {
    if (res.isLeaf && res.leafIndex === this.leafIndex && this.leafDecap) return this._openLeaf(box);
    return openFrom(this.stack, this._privFor(res), box);
  }

  // Seat this member at leafIndex with a rivet key (its own device on create,
  // or a joiner adopting the shared public tree).
  seat(leafIndex, rivetPriv, rivetPub) {
    this.leafIndex = leafIndex;
    this.rivetPriv = rivetPriv;
    const lf = this.leaves[leafIndex];
    lf.blank = false; lf.pub = rivetPub;
  }

  async _epochAdvance(rootSecret) {
    const { groupKey, nextInit } = await nextEpoch(this.stack, this.initSecret, rootSecret);
    // K is handed out as a canonical 0x-hex string — that is cipher.mjs's key
    // contract (importAesKey → ethers.arrayify, which rejects bare hex). Every
    // consumer (SessionView ctx.keys.K, the server/MCP group, exportState) reads
    // it through `this.groupKey`, so 0x-prefix it once here at the source.
    this.initSecret = nextInit;
    this.groupKey = '0x' + toHex(groupKey);
    this.epoch += 1;
    // Retain the new key at the epoch it becomes effective. THIS is the fix: the
    // prior keys stay in the ring instead of being overwritten, so a rotation no
    // longer orphans content that continuing members are still entitled to read.
    this.keyring.set(this.epoch, this.groupKey);
  }

  // The key that sealed a record tagged with `epoch`: the retained key from the
  // most recent rotation at or before it. A non-rotating add advances the epoch
  // WITHOUT changing the key, so a record's epoch can land between rotations —
  // floor to the rotation in force when it was written. A null/absent tag is an
  // untagged legacy record → the current key (the migration rule: anything
  // readable today was written under the current key).
  keyForEpoch(epoch) {
    if (epoch == null) return this.groupKey;
    let bestEpoch = -1, key = null;
    for (const [e, k] of this.keyring) if (e <= epoch && e > bestEpoch) { bestEpoch = e; key = k; }
    return key;
  }

  // Committer path update from THIS member's leaf. Mutates this member's tree +
  // secrets, advances its epoch, and returns the commit message for others.
  async commit({ type = 'update', addLeafIndex, addPub, removeLeafIndex } = {}) {
    // NON-ROTATING ADD. Forward secrecy is a property of the write frontier and
    // is enforced on REMOVAL — an add needs no rotation, because the newcomer is
    // allowed to read. So: seat the new leaf, hand the newcomer the CURRENT group
    // key (it reads the whole past) plus the current init secret (so it rotates
    // in lockstep with everyone on future removes), and leave every existing
    // member's key untouched. The DS sequence still advances so the commit log
    // stays totally ordered. The Welcome's tree snapshot is taken AFTER seating,
    // so the joiner adopts the live tree and never replays its own add.
    if (type === 'add') {
      this._applyStructuralAdd(addLeafIndex, addPub);
      // Seal the WHOLE keyring to the joiner, not just the current key. A
      // non-rotating add lets the newcomer read the whole past (EpisteryData
      // architecture) — which now means every retained epoch key, so it can open
      // records sealed before it joined, exactly as a member who was always here.
      const ringBox = await sealTo(this.stack, addPub, utf8Enc(JSON.stringify([...this.keyring])));
      const welcome = {
        treeSnapshot: this._snapshotPublic(),
        initBox: await sealTo(this.stack, addPub, this.initSecret),
        keyringBox: ringBox,
        epoch: this.epoch + 1,
      };
      this.epoch += 1;   // DS sequence advances; groupKey + keyring + initSecret unchanged
      return { type: 'add', committerLeafIndex: this.leafIndex, addLeafIndex, addPub, path: [], welcome };
    }

    // REMOVE / UPDATE: rotate the committer's path so a removed leaf cannot derive
    // the next key (forward secrecy), advancing the group key for everyone.
    if (type === 'remove') this._applyStructuralRemove(removeLeafIndex);

    const path = directPath(this._leaf());
    const cop = copath(this._leaf());
    const leafPS = new Uint8Array(this.stack.random(32));

    let ps = leafPS;
    const pathEntries = [];
    for (let m = 0; m < path.length; m++) {
      ps = await deriveSecret(this.stack, ps, 'path');
      const kp = await nodeKeyPair(this.stack, ps);
      const node = path[m];
      node.pub = kp.pub; node.blank = false;
      this.secrets.set(node.id, kp.priv);
      // Seal this path secret to everyone under the copath sibling.
      const encs = [];
      for (const res of resolution(cop[m])) encs.push({ toNodeId: res.id, box: await sealTo(this.stack, res.pub, ps) });
      pathEntries.push({ dNodeId: node.id, newPub: node.pub, encs });
    }
    const rootSecret = ps;
    await this._epochAdvance(rootSecret);

    return {
      type, committerLeafIndex: this.leafIndex,
      addLeafIndex, addPub, removeLeafIndex,
      path: pathEntries, welcome: null,
    };
  }

  _snapshotPublic() { const out = []; const walk = (n) => { if (!n) return; out.push({ id: n.id, blank: n.blank, pub: n.pub }); walk(n.l); walk(n.r); }; walk(this.root); return out; }
  _loadPublic(snap) { for (const s of snap) { const n = this._node(s.id); if (n) { n.blank = s.blank; n.pub = s.pub; } } }

  // Serialize this member's FULL state — including the private path secrets and
  // init secret — for local persistence (the committer cannot re-derive its own
  // contributed secrets from the log) and for commit rollback on a DS conflict.
  // The caller guards confidentiality at rest (rivet-encrypted client store).
  exportState() {
    return {
      leafIndex: this.leafIndex,
      epoch: this.epoch,
      groupKey: this.groupKey,
      keyring: [...this.keyring],             // [effectiveEpoch, groupKeyHex][]
      initSecret: toHex(this.initSecret),
      secrets: [...this.secrets.entries()],   // [nodeId, privHex]
      pubs: this._snapshotPublic(),           // blinded public tree
    };
  }
  // Restore from exportState(). rivetPriv is supplied separately — the leaf key
  // is never serialized (it belongs to the rivet, re-supplied on load).
  importState(state, rivetPriv) {
    this.leafIndex = state.leafIndex;
    this.rivetPriv = rivetPriv;
    this.epoch = state.epoch;
    // Canonical 0x-hex K (cipher.mjs contract), upgrading any state persisted
    // before the source was normalized.
    this.groupKey = state.groupKey && !state.groupKey.startsWith('0x') ? '0x' + state.groupKey : state.groupKey;
    this.initSecret = fromHex(state.initSecret);
    this.secrets = new Map(state.secrets);
    this._loadPublic(state.pubs);
    // Restore the keyring — REPLACE, never merge: a commit rollback relies on
    // importState dropping the speculative epoch's entry. Legacy state persisted
    // before the keyring seeds a one-entry ring at its current epoch.
    if (Array.isArray(state.keyring)) this.keyring = new Map(state.keyring.map(([e, k]) => [Number(e), k]));
    else if (this.groupKey) this.keyring = new Map([[Number(state.epoch), this.groupKey]]);
    else this.keyring = new Map();
  }

  // A joiner adopts the pre-commit public tree + the sealed current init secret,
  // then applies the Add commit like any other member -> lands in the live epoch.
  async applyWelcome(welcome, leafIndex, rivetPriv) {
    this.leafIndex = leafIndex;
    this.rivetPriv = rivetPriv;
    this._loadPublic(welcome.treeSnapshot);   // the live tree, INCLUDING my seated leaf
    // The Welcome (non-rotating add) delivers, sealed to MY leaf pub: the current
    // init secret (to rotate in lockstep on future removes) and the current group
    // key (to read now — the whole past). A non-extractable rivet opens through
    // the wallet seam; an extractable participant with the raw priv.
    const open = (box) => this.leafDecap ? this._openLeaf(box) : openFrom(this.stack, rivetPriv, box);
    this.initSecret = await open(welcome.initBox);
    this.epoch = welcome.epoch;
    if (welcome.keyringBox) {
      const entries = JSON.parse(utf8Dec(await open(welcome.keyringBox)));
      this.keyring = new Map(entries.map(([e, k]) => [Number(e), k]));
    } else {
      // Legacy single-key Welcome (pre-keyring): seed a one-entry ring at the join
      // epoch so this member reads from its join forward, exactly as before.
      this.keyring = new Map([[Number(welcome.epoch), '0x' + toHex(await open(welcome.groupBox))]]);
    }
    this.groupKey = this.keyForEpoch(this.epoch);
  }

  _applyStructuralAdd(leafIndex, pub) {
    const lf = this.leaves[leafIndex];
    lf.blank = false; lf.pub = pub;
    for (const n of directPath(lf)) { n.blank = true; n.pub = null; this.secrets.delete(n.id); } // blank the new path
  }
  _applyStructuralRemove(leafIndex) {
    const lf = this.leaves[leafIndex];
    for (const n of directPath(lf)) { n.blank = true; n.pub = null; this.secrets.delete(n.id); }
    lf.blank = true; lf.pub = null;
  }

  // Apply a commit produced by someone else. Decrypts the one path secret meant
  // for this member, derives to the root, advances the epoch. Converges to the
  // committer's group key.
  async apply(commit) {
    // A non-rotating add: seat the new leaf and advance the DS sequence only —
    // the key is unchanged, so there is no path to open. (Matches commit('add').)
    if (commit.type === 'add') {
      this._applyStructuralAdd(commit.addLeafIndex, commit.addPub);
      this.epoch += 1;
      return;
    }
    if (commit.type === 'remove') this._applyStructuralRemove(commit.removeLeafIndex);

    const committerLeaf = this.leaves[commit.committerLeafIndex];
    const cPath = directPath(committerLeaf);
    const cCop = copath(committerLeaf);

    // A removed member (or one with no overlap) can't apply — that's the point.
    if (this.leafIndex < 0 || this.leaves[this.leafIndex].blank) { this._diverge(); return; }

    // LCA = lowest node on my direct path that is also on the committer's path.
    const cSet = new Set(cPath.map((n) => n.id));
    const myPath = directPath(this._leaf());
    let j = -1, lca = null;
    for (const n of myPath) { const k = cPath.findIndex((c) => c.id === n.id); if (k >= 0) { j = k; lca = n; break; } }
    if (j < 0) { this._diverge(); return; }

    // Adopt the committer's new public path keys.
    for (const e of commit.path) { const node = this._node(e.dNodeId); if (node) { node.pub = e.newPub; node.blank = false; } }

    // Find the resolution node under cCop[j] that I can open, and open it. A node
    // is openable if I hold its priv (intermediates I derived, or an extractable
    // leaf key) OR it is my own leaf and I have a leafDecap (the browser rivet's
    // non-extractable key, delegated to the wallet).
    const resNodes = resolution(cCop[j]);
    let box = null, chosen = null;
    for (const res of resNodes) {
      const hit = commit.path[j].encs.find((x) => x.toNodeId === res.id);
      if (!hit) continue;
      const openable = this._privFor(res) || (res.isLeaf && res.leafIndex === this.leafIndex && this.leafDecap);
      if (openable) { box = hit.box; chosen = res; break; }
    }
    if (!box) { this._diverge(); return; }
    let ps = await this._open(chosen, box);

    // Derive up from the LCA to the root, recording node privs on my path.
    for (let m = j; m < cPath.length; m++) {
      if (m > j) ps = await deriveSecret(this.stack, ps, 'path');
      const kp = await nodeKeyPair(this.stack, ps);
      const node = cPath[m];
      node.pub = kp.pub; node.blank = false;
      this.secrets.set(node.id, kp.priv);
    }
    await this._epochAdvance(ps);
  }

  _node(id) { const walk = (n) => { if (!n) return null; if (n.id === id) return n; return walk(n.l) || walk(n.r); }; return walk(this.root); }
  _diverge() { this.groupKey = 'DIVERGED-' + this.name + '-' + this.epoch; this.epoch += 1; }
}
