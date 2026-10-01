// deriveFields — what a member derives from its plaintext before sealing, as
// the manifest declares.   node client-lib/derive.test.mjs
import assert from 'node:assert/strict';
import { deriveFields, DERIVATIONS } from './derive.mjs';

const spec = { _refs: { from: 'body', fn: 'wikiwords' } };

// the declared target is derived from the plaintext source
let args = deriveFields(spec, { id: 'HomePage', body: 'See EpisteryCore and [Plugins] for more.' });
assert.ok(Array.isArray(args._refs) && args._refs.includes('EpisteryCore'), 'derives _refs from the body');

// a supplied target is kept — the caller's word stands
args = deriveFields(spec, { body: 'See EpisteryCore.', _refs: ['Mine'] });
assert.deepEqual(args._refs, ['Mine'], 'a supplied target is not overwritten');

// an absent or already-sealed source yields nothing
args = deriveFields(spec, { iv: 'x', ciphertext: 'y' });
assert.equal(args._refs, undefined, 'no plaintext, nothing derived');

// an unknown function is a misdeclaration, not a guess
assert.throws(() => deriveFields({ x: { from: 'body', fn: 'nope' } }, { body: 'a' }), /unknown derivation "nope"/);

// no declaration is a no-op
assert.deepEqual(deriveFields(undefined, { a: 1 }), { a: 1 });

assert.ok(typeof DERIVATIONS.wikiwords === 'function');
console.log('derive.test: ok');
