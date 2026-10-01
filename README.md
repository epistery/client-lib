# @epistery/client-lib

The shared **browser** modules that plugin client bundles (`client/mount.mjs`)
need by URL, plus one util the wiki plugin also uses server-side. Extracted from
`epistery/app`'s `client/lib/` (console/README.md §2, §3, §8).

| module | environment | purpose |
|---|---|---|
| `records.mjs` | browser + Node | the record shapes every kind shares: `listRecords` (list, match, read, drop tombstones), `tombstone`, `stamp`, `newId`, `nextNumbered`, `isSealed` |
| `cipher.mjs` | browser + Node | per-session content + key wraps, over epistery core's one construction (`epistery/client/peer-cipher.mjs`); the server's `serverKeys` uses this same module |
| `markup.mjs` | browser only | `MarkUp` — wiki markdown renderer (marked + Mermaid from CDN), WikiWord auto-linking |
| `wikiwords.mjs` | **browser + Node** | pure WikiWord/reference extraction — served to the browser *and* imported by the wiki plugin's server code |
| `componentry.mjs` | browser | the atomic-component base class (cloned+trimmed from @metric-im/componentry) — event hub, own-css injection, notification init |
| `IdForge.mjs` | browser + Node | random / dated id generation |
| `Toast.mjs` | browser | the one canonical toast/prompt (`window.toast`) |
| `Popup.mjs` | browser | the one canonical modal (`window.popup`) |
| `component-acl.mjs` | **Node** | server-side `//ACL` delivery preprocessor + `levelOf(role)` |
| `treekem-kdf.mjs` | browser + Node | secp256k1 DHKEM + HKDF-SHA256 key schedule (EpisteryDataFrontier); one universal WebCrypto stack |
| `treekem.mjs` | browser + Node | the ratchet-tree CGKA core (`Member`: commit/apply/Welcome) — the group key that feeds `cipher.mjs` |

## TreeKEM — the frontier's key layer

`treekem-kdf.mjs` + `treekem.mjs` are the production port of the proven P0(b)/P2
spikes (EpisteryDataFrontier). One dual-environment module: `ethers` is the page
global (`window.ethers`) in the browser and `globalThis.ethers` in Node, and the
crypto stack is `globalThis.crypto` (WebCrypto) both places — so a browser rivet
and a server participant derive the SAME group key by construction. The tree's
per-epoch **exporter secret is K** for `cipher.mjs`. Commits are ordered by the
relay's blind Delivery Service (`/ds/...`); this module is the crypto only.

## componentry — the shared framework

The value is **atomicity**: a concept (a save button, a modal, a toast) has ONE
canonical implementation, so it is never quietly rebuilt a dozen subtly-different
ways. Components extend `componentry.mjs` and OWN their css via `static css`
(authored scoped to the component's class; the base injects it once). No live css
scope/concat serve — a component is self-contained.

The `//ACL` **delivery preprocessor** (`component-acl.mjs`) is the one server
piece: the shell strips `/*ACL>N*/…/*ENDACL*/` blocks the caller's level doesn't
meet before delivering a component's `.mjs`, so privileged logic never reaches a
lower-privilege browser. Level derives from `req.episteryClient` (initial map:
0 anonymous, 1 authenticated).

## How it's consumed

**The shell serves the package directory at `/lib/`** (the same way `@epistery/art`
is served at `/art`), so a plugin bundle does:

```js
import * as cipher from '/lib/cipher.mjs';
import MarkUp from '/lib/markup.mjs';
```

`markup.mjs`'s `import './wikiwords.mjs'` resolves to `/lib/wikiwords.mjs` in the
browser and to the package file in Node — the same source either way.

**Server-side (wiki plugin)**, `wikiwords` is a normal package import:

```js
import { extractWikiWords } from '@epistery/client-lib/wikiwords';
```

## One cipher, in core

`cipher.mjs` implements nothing: a wrap (ECDH secp256k1 → SHA-256 → AES-256-GCM,
`{ciphertext, iv, tag}`) and sealed content (AES-256-GCM under K, `{iv,
ciphertext}` = ciphertext‖tag) are defined once in epistery core
(`epistery/client/peer-cipher.mjs`), with vectors frozen against what is already
stored. The browser page and a Node participant (`@epistery/sessions`
`serverKeys`) run this same module, so nothing can drift. In the browser the
console's import map resolves `epistery/client/` to `/lib/`.

## Dependencies

- `epistery` (peer) — `client/peer-cipher.mjs` for the cipher, and a
  `chainReader` is required to construct a `DsGroup`.
- `ethers` v5 on `globalThis` in Node (the tree crypto and ECDH read it there);
  the page provides `window.ethers`.
