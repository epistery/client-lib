# @epistery/client-lib

The shared **browser** modules that plugin client bundles (`client/mount.mjs`)
need by URL, plus one util the wiki plugin also uses server-side. Extracted from
`epistery/app`'s `client/lib/` (console/README.md §2, §3, §8).

| module | environment | purpose |
|---|---|---|
| `cipher.mjs` | browser only | per-session content + wrap crypto — the **browser twin** of `@epistery/sessions` `bot-identity` |
| `markup.mjs` | browser only | `MarkUp` — wiki markdown renderer (marked + Mermaid from CDN), WikiWord auto-linking |
| `wikiwords.mjs` | **browser + Node** | pure WikiWord/reference extraction — served to the browser *and* imported by the wiki plugin's server code |

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

## Wire-compatibility invariant (do not break)

`cipher.mjs` and `@epistery/sessions/bot-identity` are two halves of one wire
format and MUST stay in lockstep:

- **content:** AES-256-GCM, 12-byte IV, `ciphertext` = ciphertext‖tag (Web
  Crypto's native output). A post encrypted in a browser decrypts on the server
  (MCP boundary) and vice versa.
- **wraps:** the epistery RivetWallet `encryptForPeer` primitive (ECDH secp256k1
  → SHA-256 → AES-256-GCM). A wrap written by either side unwraps on the other.

Changing one side's format without the other silently breaks every session.

## Dependencies

None. `cipher.mjs` uses the page's `window.ethers` and Web Crypto; `markup.mjs`
pulls marked/Mermaid from CDN at runtime; `wikiwords.mjs` is pure JS.
