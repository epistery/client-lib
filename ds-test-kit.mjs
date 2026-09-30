// Test support for DsGroup suites (not shipped: not in package.json "files").
//
// A real commit credential, as every signer in the stack produces it: the
// `epistery-storage-write` message over the SHA-256 of the exact commit bytes,
// signed by the member's key, wrapped as `Bot <base64url JSON>`. DsGroup verifies
// these itself (DS_FORMAT 4), so tests must sign for real — a dummy credential is
// exactly the forgery the check exists to refuse.

const E = () => globalThis.ethers;

export function botSigner(privHex, contract) {
  return async (method, subpath, bodyBytes) => {
    const e = E();
    const wallet = new e.Wallet(privHex);
    const hash = e.utils.sha256(bodyBytes).slice(2);
    const message = ['epistery-storage-write', method, contract, subpath, hash, String(Date.now())].join('\n');
    const signature = await wallet.signMessage(message);
    const json = JSON.stringify({ address: wallet.address, signature, message });
    const b64 = btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `Bot ${b64}`;
  };
}

// The credential part of an Authorization header, as the relay stores it.
export const credOf = (authorization) => (typeof authorization === 'string' && authorization.startsWith('Bot ') ? authorization.slice(4) : null);

// A chain on which everyone may commit — for tests about something other than the
// chain. What a fresh device asks the chain is tested in ds-group.chain.test.mjs.
export const anyoneMayCommit = { isRivet: async () => true, roleOf: async () => 3, mayCommit: async () => true, mayRotate: async () => true, endpoints: [] };
