// The signed statements a domain and a session make about themselves — the one
// definition, for the publisher (the console serves /.well-known/ai and a
// session's inner page) and the verifier (scan reads every domain's), so a
// signature taken on one side can never read as forgery on the other because
// the two held separate copies of the construction.
//
// Pure ESM, browser and Node: the hash is core's sha256hex (WebCrypto), and the
// signature is recovered by a function the caller injects (ethers v5
// `utils.verifyMessage`, ethers v6 `verifyMessage`), so no ethers is imported.
//
// THE DOMAIN MANIFEST (/.well-known/ai) is the last rung of the chain of proof.
// The rivet's own signature binds an event to a device. The origin certificate
// binds that device to a domain. This binds the domain to the address it signs
// as, so a stranger can walk the whole way from a piece of content to a key
// without asking anyone to vouch for it.
//
// What is signed is a tagged, newline-joined message, the same house pattern as
// the storage, bot-auth and origin-certificate messages, so a signature taken
// here can never be replayed as some other kind of statement:
//
//   epistery-domain-manifest\n1\n<domain>\n<contentHash>
//
// The manifest states that construction in `signedOver`, literally, so a
// verifier rebuilds the bytes rather than guessing them. The hash covers the
// whole document with `_signature` and `generated` removed and every key sorted,
// sha256, hex — `generated` moves on every request, and excluding it is what
// lets one signature stay valid across fetches.
//
// v1 (the epistery-host block) carried a content hash and a claimed address and
// no signature at all. v2 keeps every v1 field, so an older reader scores it as
// before, and adds the bytes signed by the domain's own wallet.
//
// A SESSION DECLARATION is the same idea one level down: what a session says
// about itself (title, description, concepts, audience, ads), signed by one of
// its admins with a device rivet. A reader recovers the signer and asks the
// owner contract `authorized(<session>, signer, ROLE_ADMIN)` — the contract is
// the voucher, never the host that serves the page.
//
//   epistery-session-declaration\n1\n<owner contract>\n<session id>\n<sha256:contentHash>

import { sha256hex } from 'epistery/client/storage-message.mjs';

export const MANIFEST_TAG = 'epistery-domain-manifest';
export const MANIFEST_VERSION = '1';
export const SIGNATURE_METHOD = 'epistery-domain-v2';
export const SPEC_VERSION = '1.2.0';

export const DECLARATION_TAG = 'epistery-session-declaration';
export const DECLARATION_VERSION = '1';
export const DECLARATION_SIGNED_OVER = `${DECLARATION_TAG}\n${DECLARATION_VERSION}\n<contract>\n<session>\n<contentHash>`;

/** Recursive key sort — the canonical form of a document. */
export function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k]);
    return out;
  }
  return v;
}

/** The one way to hash a document: sorted keys, compact JSON, SHA-256, `sha256:` + hex. */
export async function canonicalHash(value) {
  return 'sha256:' + await sha256hex(JSON.stringify(sortKeys(value ?? null)));
}

/** The manifest's content hash: the document without `_signature` and `generated`. */
export async function contentHash(doc) {
  const clone = JSON.parse(JSON.stringify(doc));
  delete clone._signature;
  delete clone.generated;
  return canonicalHash(clone);
}

/** The exact bytes the domain wallet signs. Stated in the manifest as `signedOver`. */
export function manifestMessage({ domain, hash }) {
  return [MANIFEST_TAG, MANIFEST_VERSION, String(domain).toLowerCase(), hash].join('\n');
}

// The document itself. Deliberately narrow: it claims only what the serving
// origin actually offers. A manifest that overstates its capabilities is the
// same class of error as a signature block with no signature.
function domainDocument({ domain, wallet, chainId, providerName, publicRpc, version, platform, searchUrl }) {
  return {
    specVersion: SPEC_VERSION,
    standard: 'AI Discovery Standard v1.2',
    generated: new Date().toISOString(),
    identity: { name: domain, domain, platform, version: version || null },
    capabilities: {
      search: searchUrl ? { available: true, url: searchUrl } : { available: false },
      // The identity probe: this origin's own wallet, which is what verifies both
      // this manifest and the origin certificates issued at key exchange.
      identity: { available: true, url: '/', accept: 'application/json' },
      // MCP is per SESSION and bearer-gated, not one endpoint for the domain, so
      // no url is advertised. Saying otherwise would send an agent nowhere.
      mcp: { available: false, reason: 'per-session, issued from a session\'s Bot access settings' },
      agents: { available: false },
      blockchain: { available: !!wallet },
    },
    blockchain: wallet ? {
      chain: providerName || null,
      chainId: chainId || null,
      // The address this domain signs as. A domain holds a wallet and no
      // IdentityContract, and says so rather than naming a contract that does not
      // exist — `identityType` keeps v1's contract-shaped `digitalName` honest.
      wallet,
      contract: null,
      rpc: publicRpc || null,
    } : null,
    well_known: { ai_discovery: '/.well-known/ai', epistery_status: '/' },
  };
}

/**
 * Build and sign the domain manifest.
 *
 * @param {object} p
 * @param {string} p.domain
 * @param {{signMessage:(m:string)=>Promise<string>, address:string}} [p.signer]
 *        the DOMAIN's own wallet. Absent → an unsigned document, which is
 *        honest: no `_signature` block at all rather than an empty one.
 * @param {string} [p.platform]   what serves it (default 'epistery-console')
 * @param {string} [p.searchUrl]  the origin's search surface, if it has one
 */
export async function buildManifest({ domain, signer, chainId, providerName, publicRpc, version, platform = 'epistery-console', searchUrl = null }) {
  const doc = domainDocument({ domain, wallet: signer?.address || null, chainId, providerName, publicRpc, version, platform, searchUrl });
  if (!signer?.signMessage) return doc;
  const hash = await contentHash(doc);
  doc._signature = {
    method: SIGNATURE_METHOD,
    // v1 compatibility: readers key on digitalName's presence. Here it is the
    // wallet, and identityType says so instead of letting it be read as a contract.
    digitalName: signer.address,
    identityType: 'wallet',
    contentHash: hash,
    signedAt: new Date().toISOString(),
    signedOver: `${MANIFEST_TAG}\\n${MANIFEST_VERSION}\\n<domain>\\n<contentHash>`,
    signature: await signer.signMessage(manifestMessage({ domain, hash })),
  };
  return doc;
}

/**
 * Verify a domain manifest: recompute the hash, rebuild the message, recover the
 * signer with `recover(message, signature) → address` (ethers v5
 * `utils.verifyMessage`, v6 `verifyMessage`). A typed result: `signed:false` is
 * a v1 manifest that offered no signature — unsigned, not forged — and the two
 * must stay distinguishable or every honest older domain looks like an attacker.
 */
export async function verifyManifest(doc, recover) {
  const sig = doc?._signature;
  if (!sig?.digitalName) return { ok: false, signed: false, reason: 'no _signature block' };
  if (!sig.signature) return { ok: false, signed: false, digitalName: sig.digitalName, method: sig.method || null, reason: `method "${sig.method}" carries a content hash but no signature (v1)` };
  const hash = await contentHash(doc);
  if (hash !== sig.contentHash) return { ok: false, signed: true, digitalName: sig.digitalName, method: sig.method || null, hash, reason: `content hash mismatch (computed ${hash})` };
  const domain = doc?.identity?.domain;
  let signer;
  try { signer = recover(manifestMessage({ domain, hash }), sig.signature); }
  catch (e) { return { ok: false, signed: true, digitalName: sig.digitalName, method: sig.method || null, hash, reason: `signature does not recover: ${e.message}` }; }
  if (String(signer).toLowerCase() !== String(sig.digitalName).toLowerCase()) {
    return { ok: false, signed: true, digitalName: sig.digitalName, method: sig.method || null, hash, signer, reason: `signed by ${signer}, not the declared ${sig.digitalName}` };
  }
  return { ok: true, signed: true, digitalName: sig.digitalName, method: sig.method || null, hash, signer, domain };
}

/** A session declaration's content hash: everything but `_signature`, canonical. */
export async function declarationHash(declaration) {
  const { _signature, ...content } = declaration || {};
  return canonicalHash(content);
}

/** The exact bytes an admin's rivet signs over a session declaration. */
export function declarationMessage(owner, sessionId, hash) {
  return [DECLARATION_TAG, DECLARATION_VERSION, String(owner).toLowerCase(), String(sessionId).toLowerCase(), hash].join('\n');
}

/**
 * Verify a declaration's signature: recomputes the hash and recovers the signer.
 * Whether that signer is an admin of the session is the contract's to say
 * (`authorized(<session>, signer, ROLE_ADMIN)`), asked by the caller.
 */
export async function verifyDeclaration(declaration, { owner, sessionId }, recover) {
  const sig = declaration?._signature;
  if (!sig?.signature) return { ok: false, signed: false, reason: 'no signature' };
  const hash = await declarationHash(declaration);
  if (sig.contentHash && sig.contentHash !== hash) return { ok: false, signed: true, hash, reason: `content hash mismatch (computed ${hash})` };
  let signer;
  try { signer = recover(declarationMessage(owner, sessionId, hash), sig.signature); }
  catch (e) { return { ok: false, signed: true, hash, reason: `signature does not recover: ${e.message}` }; }
  return { ok: true, signed: true, hash, signer };
}

/**
 * A session as an INNER PAGE of its identity, in the ai-discovery shape: what
 * the session declares about itself, with its parent context — the identity
 * that owns it — named for everything it does not declare. The host only serves
 * the page; the voucher is the contract (`digitalName` is the owner contract).
 */
export function sessionDiscoveryDocument({ origin, owner, ownerName = null, session, declaration = null }) {
  const d = declaration;
  const handle = encodeURIComponent(ownerName || owner);
  return {
    specVersion: SPEC_VERSION,
    standard: 'ai-discovery',
    generated: new Date().toISOString(),
    page: { url: `${origin}/@${handle}/${encodeURIComponent(session.name)}`, kind: session.kind, session: session.id },
    parent: { identity: owner, profile: `${origin}/@${handle}`, host: `${origin}/.well-known/ai` },
    organization: {
      name: d?.title || session.title || session.name,
      description: d?.description || session.description || null,
      digitalName: owner,
    },
    audience: d?.audience || null,
    coreConcepts: d?.coreConcepts || [],
    ads: { enabled: d?.ads?.enabled === true, agency: d?.ads?.agency || null },
    // The signed declaration, verbatim — the part a reader verifies.
    declaration: d,
  };
}
