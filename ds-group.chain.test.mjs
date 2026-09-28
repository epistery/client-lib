// A device joining from scratch has no tree of its own to check a commit against,
// so it asks the CHAIN — itself, straight to the RPC endpoints, never through the
// relay — whether the member who seated it may commit to the session, and whether
// the founder of any restore it follows is an owner rivet.
//
//   SEATED BY A RIVET        → joins
//   SEATED BY A SECTION WRITER → joins
//   SEATED BY A NON-WRITER   → refused (FORGED_WELCOME), holds nothing
//   AFTER A RESTORE          → the same rule, through the Welcome; members unaffected
//   CHAIN UNREACHABLE        → refused (CHAIN_UNREACHABLE), never guessed; joins once it answers
//   first endpoint dead      → the next endpoint answers
//
// The chain here is a fake JSON-RPC node that decodes real calldata, so chainReader's
// encoding is exercised too.
//
//   node client-lib/ds-group.chain.test.mjs
import { ethers } from 'ethers';
globalThis.ethers = ethers; globalThis.window ??= globalThis;
import { DsGroup } from './ds-group.mjs';
import { cryptoStack, privFromSecret, pubFromPriv } from './treekem-kdf.mjs';
import { chainReader } from './chain-read.mjs';
import { sealedKeys } from './sealed.mjs';
import * as cipher from './cipher.mjs';
import { botSigner, credOf } from './ds-test-kit.mjs';

let failures = 0; const check = (c, m) => c ? console.log('  ok  : ' + m) : (console.log('  FAIL: ' + m), failures++);
const stack = cryptoStack();
const kp = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); const priv = privFromSecret(b); const pub = pubFromPriv(priv); return { priv, pub, addr: ethers.utils.computeAddress(pub).toLowerCase() }; };
const CONTRACT = ethers.Wallet.createRandom().address.toLowerCase();
const SESSION = 'recipes';

// ---- the chain: a fake RPC node answering eth_call from calldata ----
const onChain = { rivets: new Set(), writers: new Set() };
let chainUp = true;
const iface = new ethers.utils.Interface([
  'function isAuthorized(address) view returns (bool)',
  'function getRivets() view returns (address[])',
  'function roleOf(string section, address account) view returns (uint8)',
]);
const rpcFetch = async (url, opts) => {
  if (url.includes('dead') || !chainUp) throw new Error('connect ECONNREFUSED');
  const { params: [{ to, data }] } = JSON.parse(opts.body);
  const tx = iface.parseTransaction({ data });
  let result;
  if (to.toLowerCase() !== CONTRACT) result = iface.encodeFunctionResult(tx.name, tx.name === 'getRivets' ? [[]] : tx.name === 'roleOf' ? [0] : [false]);
  else if (tx.name === 'isAuthorized') result = iface.encodeFunctionResult('isAuthorized', [onChain.rivets.has(tx.args[0].toLowerCase())]);
  else if (tx.name === 'getRivets') result = iface.encodeFunctionResult('getRivets', [[]]);
  else result = iface.encodeFunctionResult('roleOf', [tx.args[0] === SESSION && onChain.writers.has(tx.args[1].toLowerCase()) ? 2 : 0]);
  return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) };
};
// A fresh reader per device (the reader caches answers, as a browser tab would).
const chain = () => chainReader({ rpcs: ['https://dead.example/', 'https://node.example/'], fetchImpl: rpcFetch });

// ---- the relay: a plain log ----
const log = [];
const fakeFetch = async (url, opts = {}) => {
  if (opts.method === 'POST' && /\/commit$/.test(url)) {
    if (Number(opts.headers['x-ds-epoch']) !== log.length) return { ok: false, status: 409, json: async () => ({ current: log.length }) };
    log.push({ raw: opts.body, cred: credOf(opts.headers.authorization) });
    return { ok: true, json: async () => ({ ok: true, epoch: log.length }) };
  }
  if (/\/head$/.test(url)) return { ok: true, json: async () => ({ epoch: log.length }) };
  if (/\/log\?/.test(url)) { const since = Number(new URL(url).searchParams.get('since') || 0); return { ok: true, json: async () => log.map((e, i) => ({ epoch: i + 1, cred: e.cred })).filter((e) => e.epoch > since) }; }
  const m = url.match(/\/commit\/(\d+)/);
  if (m) { const e = log[Number(m[1]) - 1]; return e ? { ok: true, status: 200, arrayBuffer: async () => e.raw } : { ok: false, status: 404 }; }
  return { ok: false, status: 404 };
};
const stores = new Map();
const storeFor = (k) => { if (!stores.has(k.addr)) { let saved = null; stores.set(k.addr, { load: async () => saved, save: async (s) => { saved = JSON.parse(JSON.stringify(s)); } }); } return stores.get(k.addr); };
const groupFor = (k, opts = {}) => new DsGroup({ relayUrl: 'https://x', contract: CONTRACT, session: SESSION, address: k.addr, rivetPriv: k.priv, rivetPub: k.pub,
  sign: botSigner(k.priv, CONTRACT), stack, fetchImpl: fakeFetch, capacity: 16, store: storeFor(k), chain: chain(), ...opts });
const joins = async (k) => { const g = groupFor(k); try { await g.load(); return { g, ok: !!g.groupKey() }; } catch (e) { return { g, ok: false, code: e.code, message: e.message }; } };

console.log('\n[chain] a fresh device checks who seated it, on chain');
const A = kp(), W = kp(), M = kp();   // A owner rivet, W a section writer, M a member with no write
onChain.rivets.add(A.addr); onChain.writers.add(W.addr);
const gA = groupFor(A); await gA.create();
const history = await sealedKeys(gA, cipher).seal('history');

// SEATED BY A RIVET
const C1 = kp(); await gA.addMember(C1.addr, C1.pub);
let r = await joins(C1);
check(r.ok && (await sealedKeys(r.g, cipher).open(history)).ok, 'seated by an owner rivet → joins and reads');

// SEATED BY A SECTION WRITER
await gA.addMember(W.addr, W.pub);
const gW = groupFor(W); await gW.load();
const C2 = kp(); await gW.addMember(C2.addr, C2.pub);
r = await joins(C2);
check(r.ok, 'seated by a section writer → joins');

// SEATED BY A NON-WRITER (a member the chain does not let commit — the relay would
// have refused this commit; a relay that let it through still gets nothing)
await gA.load(); await gA.addMember(M.addr, M.pub);
const gM = groupFor(M); await gM.load();
const C3 = kp(); await gM.addMember(C3.addr, C3.pub);
r = await joins(C3);
check(!r.ok && r.code === 'FORGED_WELCOME' && !r.g.groupKey(), `seated by a non-writer → refused, holds nothing (${r.message})`);

// CHAIN UNREACHABLE: never guessed, and the device joins once the chain answers.
const C4 = kp(); await gA.load(); await gA.addMember(C4.addr, C4.pub);
chainUp = false;
r = await joins(C4);
check(!r.ok && r.code === 'CHAIN_UNREACHABLE' && !r.g.groupKey(), `chain unreachable → refused, not guessed (${r.message})`);
chainUp = true;
r = await joins(C4);
check(r.ok, 'chain back → the same device joins');

// first endpoint dead: every read above went through the second one
check(chain().endpoints.length === 2, 'the dead first endpoint is skipped for the next (every join above)');

// A RESTORE changes nothing about the rule: the fresh device follows it through the
// Welcome that seats it, judged the same way. Members already in the group keep loading.
const gA2 = groupFor(A); await gA2.load(); await gA2.reinit();
const C5 = kp(); await gA2.addMember(C5.addr, C5.pub);
r = await joins(C5);
check(r.ok && (await sealedKeys(r.g, cipher).open(history)).ok, 'after an owner restore, a fresh device seated by the owner joins, history kept');
await gA2.addMember(W.addr, W.pub);
const gW3 = groupFor(W); await gW3.load();
check(!!gW3.groupKey() && !gW3.stuck, 'an existing member follows the restore as before');

// Required, not optional: a group without a chain reader is not built at all.
let refused = false; try { groupFor(kp(), { chain: undefined }); } catch { refused = true; }
check(refused, 'a group without a chain reader refuses to exist');

console.log('\n' + (failures ? `CHAIN FAIL — ${failures}` : 'CHAIN PASS — a fresh device takes its seat only from someone the chain lets commit, and never on a guess.'));
process.exit(failures ? 1 : 0);
