// pool — the shared component pool (SERVER-side).
//
// componentry's most valuable trait: components from DIFFERENT repos live in one
// namespace, resolvable by name. The core ships `saveButton`; a plugin ships
// `wikiBlock`; any client imports `/components/<Name>.mjs` and the pool resolves
// which repo's file that is — no new API, no deep dependency between repos.
//
// Each repo contributes a `components/` folder. The shell registers those
// folders (core first, then app/plugin folders); later registrations OVERRIDE
// earlier ones by name, so a host can specialize a shared atom. The shell serves
// the resolved file at /components/:name AFTER running the //ACL delivery
// preprocessor (see ./component-acl.mjs) against the caller's level.
//
// Server util (fs) — not a browser module.

import fs from 'fs';
import path from 'path';

// Read a repo's components/ folder into a { filename: absolutePath } map.
// Keyed by full filename (e.g. "saveButton.mjs") so the browser imports
// /components/saveButton.mjs. Missing/!dir folders are simply empty.
export function loadComponentDir(dir) {
  const out = {};
  try {
    for (const file of fs.readdirSync(dir)) {
      if (file.endsWith('.mjs') || file.endsWith('.js')) {
        out[file] = path.join(dir, file);
      }
    }
  } catch { /* no components/ folder — fine */ }
  return out;
}

export class ComponentPool {
  constructor() {
    this.components = {};   // name(filename) → absolute path
  }

  // Register a repo's components/ folder. Later calls override earlier names.
  addDir(dir) {
    Object.assign(this.components, loadComponentDir(dir));
    return this;
  }

  // Absolute path for a pooled component filename, or null.
  resolve(name) {
    return this.components[name] || null;
  }

  // Every pooled component filename (for diagnostics / a manifest).
  names() {
    return Object.keys(this.components);
  }
}
