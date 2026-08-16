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
  deriveSecret, dhkemEncapDeterministic, dhkemDecap, nodeKeyPair,
  privFromSecret, nextEpoch, toHex, fromHex,
} from './treekem-kdf.mjs';
// Randomness comes from the crypto stack (stack.random) so the SAME tree code
// runs in the browser (crypto.getRandomValues) and Node — no node:crypto import.

const GENESIS_INIT = new Uint8Array(32); // shared group genesis; real groups seed from the group id

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
    this.groupKey = null;
  }
  _leaf() { return this.leaves[this.leafIndex]; }
  _privFor(node) { return node.isLeaf && node.leafIndex === this.leafIndex ? this.rivetPriv : this.secrets.get(node.id); }

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
    this.initSecret = nextInit;
    this.groupKey = toHex(groupKey);
    this.epoch += 1;
  }

  // Committer path update from THIS member's leaf. Mutates this member's tree +
  // secrets, advances its epoch, and returns the commit message for others.
  async commit({ type = 'update', addLeafIndex, addPub, removeLeafIndex } = {}) {
    // A joiner must land in the CURRENT epoch, not replay from genesis: the
    // Welcome carries the pre-commit public tree + the current init secret sealed
    // to the joiner's rivet key. Captured before any mutation.
    let welcome = null;
    if (type === 'add') {
      welcome = { treeSnapshot: this._snapshotPublic(), initBox: await sealTo(this.stack, addPub, this.initSecret), epoch: this.epoch };
    }

    // Structural op first (same order the recipients apply), then rekey.
    if (type === 'add') this._applyStructuralAdd(addLeafIndex, addPub);
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
      path: pathEntries, welcome,
    };
  }

  _snapshotPublic() { const out = []; const walk = (n) => { if (!n) return; out.push({ id: n.id, blank: n.blank, pub: n.pub }); walk(n.l); walk(n.r); }; walk(this.root); return out; }
  _loadPublic(snap) { for (const s of snap) { const n = this._node(s.id); if (n) { n.blank = s.blank; n.pub = s.pub; } } }

  // A joiner adopts the pre-commit public tree + the sealed current init secret,
  // then applies the Add commit like any other member -> lands in the live epoch.
  async applyWelcome(welcome, leafIndex, rivetPriv) {
    this.leafIndex = leafIndex;
    this.rivetPriv = rivetPriv;
    this._loadPublic(welcome.treeSnapshot);
    this.initSecret = await openFrom(this.stack, rivetPriv, welcome.initBox);
    this.epoch = welcome.epoch;
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
    if (commit.type === 'add') this._applyStructuralAdd(commit.addLeafIndex, commit.addPub);
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

    // Find the resolution node under cCop[j] that I hold a key for, and open it.
    const resNodes = resolution(cCop[j]);
    let box = null, myPriv = null;
    for (const res of resNodes) {
      const priv = this._privFor(res);
      if (priv) { const hit = commit.path[j].encs.find((x) => x.toNodeId === res.id); if (hit) { box = hit.box; myPriv = priv; break; } }
    }
    if (!box) { this._diverge(); return; }
    let ps = await openFrom(this.stack, myPriv, box);

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
