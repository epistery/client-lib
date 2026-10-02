// Fields a member derives from a plaintext argument before sealing it — as the
// kind's manifest declares, with public componentry, on the device.
//
// A record can carry what only the plaintext can yield: a wiki doc's outbound
// `_refs` (its WikiWords) ride the write because the host, which sees only
// ciphertext, cannot extract them. In the bot path the kind's own write
// transform derives them on the host; a member's plaintext never reaches the
// host, so the kind declares the derivation instead:
//
//   "derive": { "_refs": { "from": "body", "fn": "wikiwords" } }
//
// and the device applies it with the named public function below. A device
// needs nothing of the kind installed — the manifest names the function, this
// module holds it. A name this module does not hold is a misdeclaration and
// throws; nothing is derived by guesswork.

import { extractWikiWords } from './wikiwords.mjs';

/**
 * The derivations a manifest may name. Each takes a string, returns a value.
 * A null-prototype map, looked up by own property only: a name a manifest
 * could not have meant — `constructor`, `toString` — is no derivation, not a
 * function fished off Object.prototype that copies the plaintext somewhere the
 * seal list does not cover.
 */
export const DERIVATIONS = Object.freeze(Object.assign(Object.create(null), {
  wikiwords: extractWikiWords,
}));

/**
 * Apply a tool's `derive` declaration to its call arguments, in place.
 * `spec` is `{ [target]: { from, fn } }`. A target the caller already supplied
 * is kept; a source that is not a string (absent, or already sealed) yields
 * nothing. Returns `args`.
 */
export function deriveFields(spec, args) {
  for (const [target, d] of Object.entries(spec || {})) {
    const fn = typeof d?.fn === 'string' && Object.hasOwn(DERIVATIONS, d.fn) ? DERIVATIONS[d.fn] : null;
    if (!fn) throw new Error(`derive ${target}: unknown derivation "${d?.fn}" — this device holds no such function`);
    if (args[target] !== undefined) continue;
    const source = args[d.from];
    if (typeof source !== 'string') continue;
    args[target] = fn(source);
  }
  return args;
}
