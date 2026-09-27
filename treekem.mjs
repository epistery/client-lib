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
// The tree GROWS. A full group doubles rather than refusing a member: the
// existing tree becomes the left half of a taller one, so "a session is that
// group small, a board is the same group at a thousand members" is one mechanism
// at two sizes, not two designs. Blank leaves (removed members) are reused first;
// growth happens only when none is free. Resolution handles blanks; the crypto is
// real. The wire/label encoding is ours ("borrow the math, not the format").
//
// Node identity survives a doubling. Ids are allocated ABOVE every id in use, so
// the nodes a historical commit named still resolve to the same nodes after the
// tree has grown — a member replaying the log from epoch 1 converges whether or
// not a growth happened along the way.

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
class TNode {
  constructor() { this.id = -1; this.parent = null; this.l = null; this.r = null; this.isLeaf = false; this.leafIndex = -1; this.blank = true; this.pub = null; }
}
// Ids are assigned in creation order (a node before its children) from `startId`,
// which is what every member's copy does independently — the numbering is a pure
// function of (capacity, startId, leafOffset), so the copies agree without
// exchanging it. A base tree starts at 0 and numbers exactly as it always has.
export function buildTree(capacity, startId = 0, leafOffset = 0) {
  const leaves = [];
  let next = startId;
  const build = (depth) => {
    const n = new TNode();
    n.id = next++;
    if (depth === 0) { n.isLeaf = true; n.leafIndex = leafOffset + leaves.length; leaves.push(n); }
    else { n.l = build(depth - 1); n.r = build(depth - 1); n.l.parent = n; n.r.parent = n; }
    return n;
  };
  const root = build(Math.log2(capacity));
  return { root, leaves };
}

// Double a tree: the existing root becomes the left child of a new root whose
// right half is blank, so existing leaves keep their indices and new members take
// indices `capacity`..`2*capacity-1`.
//
// Every new id is allocated above the existing ones (a tree of capacity c uses
// ids 0..2c-2), so nothing already committed is renumbered. The new root is blank
// and therefore has no secret: the committer that grows the tree must rotate its
// path in the same commit, which is what `commit({type:'add'})` does when it grows.
export function growTree(root, leaves, capacity) {
  const startId = 2 * capacity - 1;
  const right = buildTree(capacity, startId, capacity);
  const newRoot = new TNode();
  newRoot.id = startId + (2 * capacity - 1);
  newRoot.l = root; newRoot.r = right.root;
  root.parent = newRoot; right.root.parent = newRoot;
  newRoot.blank = true; newRoot.pub = null;
  return { root: newRoot, leaves: [...leaves, ...right.leaves], capacity: capacity * 2 };
}

const nextPow2 = (n) => { let c = 1; while (c < n) c *= 2; return c; };
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
    this.capacity = capacity;
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

  // Double this member's tree. Every member does this independently and
  // deterministically — from a commit that grew, from a Welcome, or from restored
  // state — so their copies stay identical without the shape being transmitted.
  grow() {
    const g = growTree(this.root, this.leaves, this.capacity);
    this.root = g.root; this.leaves = g.leaves; this.capacity = g.capacity;
  }
  growTo(capacity) { while (this.capacity < capacity) this.grow(); }
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
  // floor to the rotation in force when it was written.
  //
  // A null/absent tag gets NO key. It used to get the current key ("anything
  // readable today was written under the current key"), which is true only until
  // the session's first rotation — then every untagged record silently resolved to
  // the wrong key (mjs recipes + SunriseWalks, 2026-09-22/23). Every writer tags;
  // the live data was re-tagged (tmp/retag-untagged.js). An untagged record is a
  // fault to report, never a key to guess.
  keyForEpoch(epoch) {
    if (epoch == null) return null;
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
      // A full tree grows to seat the newcomer. The taller tree's root is blank,
      // so unlike an ordinary add this one MUST rotate to establish a root secret
      // — which advances the epoch and mints a new key for everyone.
      const grew = addLeafIndex >= this.capacity;
      if (grew) this.growTo(nextPow2(addLeafIndex + 1));
      this._applyStructuralAdd(addLeafIndex, addPub);
      if (grew) {
        const path = await this._rotatePath();
        // Sealed AFTER the rotation, so the joiner adopts the live tree and the
        // key the rotation just minted, exactly as it does for an ordinary add.
        const welcome = {
          treeSnapshot: this._snapshotPublic(),
          initBox: await sealTo(this.stack, addPub, this.initSecret),
          keyringBox: await sealTo(this.stack, addPub, utf8Enc(JSON.stringify([...this.keyring]))),
          epoch: this.epoch,
          capacity: this.capacity,
        };
        return { type: 'add', grow: true, capacity: this.capacity, committerLeafIndex: this.leafIndex, addLeafIndex, addPub, path, welcome };
      }
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
        // The SHAPE, always. A member seated into a tree that has already grown
        // must build the taller tree before it adopts the snapshot, or it maps
        // those node ids onto a tree that never had them.
        capacity: this.capacity,
      };
      this.epoch += 1;   // DS sequence advances; groupKey + keyring + initSecret unchanged
      return { type: 'add', capacity: this.capacity, committerLeafIndex: this.leafIndex, addLeafIndex, addPub, path: [], welcome };
    }

    // REMOVE / UPDATE: rotate the committer's path so a removed leaf cannot derive
    // the next key (forward secrecy), advancing the group key for everyone.
    if (type === 'remove') this._applyStructuralRemove(removeLeafIndex);

    const pathEntries = await this._rotatePath();

    return {
      type, capacity: this.capacity, committerLeafIndex: this.leafIndex,
      addLeafIndex, addPub, removeLeafIndex,
      path: pathEntries, welcome: null,
    };
  }

  // Rotate this member's path: fresh secrets from its leaf to the root, each
  // sealed to the copath resolution, advancing the epoch to the key they derive.
  // Shared by remove, update, and the add that grew the tree.
  async _rotatePath() {
    const path = directPath(this._leaf());
    const cop = copath(this._leaf());
    let ps = new Uint8Array(this.stack.random(32));
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
    await this._epochAdvance(ps);
    return pathEntries;
  }

  _snapshotPublic() { const out = []; const walk = (n) => { if (!n) return; out.push({ id: n.id, blank: n.blank, pub: n.pub }); walk(n.l); walk(n.r); }; walk(this.root); return out; }
  _loadPublic(snap) { for (const s of snap) { const n = this._node(s.id); if (n) { n.blank = s.blank; n.pub = s.pub; } } }

  // Serialize this member's FULL state — including the private path secrets and
  // init secret — for local persistence (the committer cannot re-derive its own
  // contributed secrets from the log) and for commit rollback on a DS conflict.
  // The caller guards confidentiality at rest (rivet-encrypted client store).
  exportState() {
    return {
      capacity: this.capacity,
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
    // Restore the SHAPE before the contents: a state saved after a growth carries
    // ids that only exist in the taller tree.
    if (state.capacity) this.growTo(state.capacity);
    this.leafIndex = state.leafIndex;
    this.rivetPriv = rivetPriv;
    this.epoch = state.epoch;
    // Canonical 0x-hex K (cipher.mjs contract), upgrading any state persisted
    // before the source was normalized.
    this.groupKey = state.groupKey && !state.groupKey.startsWith('0x') ? '0x' + state.groupKey : state.groupKey;
    this.initSecret = fromHex(state.initSecret);
    this.secrets = new Map(state.secrets);
    // Every node the snapshot names must exist in the restored shape. A state that
    // carries nodes of a taller tree without saying how tall (no `capacity`) would
    // otherwise load as the short tree with half its nodes silently dropped.
    for (const n of state.pubs || []) {
      if (!this._node(n.id)) {
        const e = new Error(`tree state names node ${n.id}, which a capacity-${this.capacity} tree does not have — its shape was not saved`);
        e.code = 'OUT_OF_STEP';
        throw e;
      }
    }
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
    // The tree the Welcome snapshots may be taller than this fresh member's.
    if (welcome.capacity) this.growTo(welcome.capacity);
    this.leafIndex = leafIndex;
    this.rivetPriv = rivetPriv;
    this._loadPublic(welcome.treeSnapshot);   // the live tree, INCLUDING my seated leaf
    // The Welcome (non-rotating add) delivers, sealed to MY leaf pub: the current
    // init secret (to rotate in lockstep on future removes) and the current group
    // key (to read now — the whole past). A non-extractable rivet opens through
    // the wallet seam; an extractable participant with the raw priv.
    // `label` rides a thrown error (diagnostic breadcrumb) so a decrypt failure
    // names WHICH sealed box could not be opened, not just "OperationError".
    const open = async (box, label) => {
      try { return this.leafDecap ? await this._openLeaf(box) : await openFrom(this.stack, rivetPriv, box); }
      catch (e) { if (!e.epLabel) e.epLabel = label; throw e; }
    };
    this.initSecret = await open(welcome.initBox, 'Welcome.initBox');
    this.epoch = welcome.epoch;
    if (welcome.keyringBox) {
      const entries = JSON.parse(utf8Dec(await open(welcome.keyringBox, 'Welcome.keyringBox')));
      this.keyring = new Map(entries.map(([e, k]) => [Number(e), k]));
    } else {
      // Legacy single-key Welcome (pre-keyring): seed a one-entry ring at the join
      // epoch so this member reads from its join forward, exactly as before.
      this.keyring = new Map([[Number(welcome.epoch), '0x' + toHex(await open(welcome.groupBox, 'Welcome.groupBox'))]]);
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
    // A ROTATING commit from my own leaf was made by another instance of this same
    // rivet (another tab, or another group object in this one). Its path secrets
    // were generated there and sealed to everyone but me, so applying it here can
    // only diverge — silently, with a plausible key from the next rotation on (the
    // library's 0x159a lost its own epoch-19 key this way). Refuse it untouched;
    // the committing instance saved the state that carries it.
    const rotates = commit.type !== 'add' || commit.grow;
    if (rotates && this.leafIndex >= 0 && commit.committerLeafIndex === this.leafIndex) {
      const e = new Error('this commit was made from this device\'s own leaf by another instance — load that instance\'s saved state');
      e.code = 'OWN_COMMIT';
      throw e;
    }
    // The shape first, whatever the commit does: the leaf it seats, and every node
    // id its path names, exist only in a tree at least this tall.
    if (commit.capacity) this.growTo(commit.capacity);
    // A non-rotating add: seat the new leaf and advance the DS sequence only —
    // the key is unchanged, so there is no path to open. (Matches commit('add').)
    if (commit.type === 'add') {
      this._applyStructuralAdd(commit.addLeafIndex, commit.addPub);
      if (!commit.grow) { this.epoch += 1; return; }
      // A grown add rotated the committer's path — open it like any rotation.
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
    if (j < 0) throw this._outOfStep(commit, 'no node of my path is on the committer\'s');

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
    if (!box) throw this._outOfStep(commit, 'no sealed path secret is addressed to a node I can open');
    // The openable check said this node is mine, but the actual decrypt can still
    // fail (a mismatched sealed box) — label it so the failure names the path.
    let ps;
    try { ps = await this._open(chosen, box); }
    catch (e) { if (!e.epLabel) e.epLabel = `apply(${commit.type}) path-secret @node${chosen?.id}`; throw e; }

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
  // A REMOVED member cannot follow the group past its removal — that is forward
  // secrecy, and the only case that diverges quietly.
  _diverge() { this.groupKey = 'DIVERGED-' + this.name + '-' + this.epoch; this.epoch += 1; }
  // A SEATED member that cannot open a commit is out of step with the tree the
  // committer holds. That is a fault, not a removal: fail, never carry on with a
  // placeholder key that the next rotation turns into a plausible wrong one.
  _outOfStep(commit, why) {
    const e = new Error(`cannot apply the ${commit.type} from leaf ${commit.committerLeafIndex} at epoch ${this.epoch + 1}: ${why}`);
    e.code = 'OUT_OF_STEP';
    return e;
  }
}
