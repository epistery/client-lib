// Record helpers — the shapes every session kind writes and reads, defined once
// and shared by server and browser the way sealed.mjs is. Ten copies of
// "list the folder, match the name, read each, drop the tombstones" and six of
// the tombstone shape lived in the kinds; this is their one home
// (EpisteryRefactor3Q26Review C4).
//
// Pure ESM, no environment assumptions: `storage` is any facade with
// list() → [{ path, ... }] and readJSON(path, fallback).

import { isSealed } from './sealed.mjs';
export { isSealed };

/** A random hex id (12 bytes by default) for a record name. */
export function newId(bytes = 12) {
  const b = new Uint8Array(bytes); globalThis.crypto.getRandomValues(b);
  let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s;
}

/** A record stamped as modified now, by `by`. Returns a new object. */
export function stamp(record, by) {
  return { ...record, _modified: Date.now(), _modifiedBy: by };
}

/** True for a tombstoned record. */
export const isDeleted = (record) => !!record && record._deleted === true;

/**
 * The tombstone that replaces a deleted record: the identifying fields a reader
 * needs to render "deleted" in place (`keep`), the marker, who and when. Content
 * is never carried over.
 */
export function tombstone(record, by, keep = ['id', 'type', 'from', 'timestamp']) {
  const t = {};
  for (const k of keep) if (record && record[k] !== undefined) t[k] = record[k];
  return { ...t, _deleted: true, _deletedBy: by, _deletedAt: Date.now() };
}

/**
 * The live records in a folder whose names match `re`: list, filter, read each
 * (a record that fails to read is skipped, never a thrown list), drop tombstones.
 * Returns [{ path, match, record }] in listing order; `match` is the regex match
 * so a caller can take an id out of the name without a second parse.
 */
export async function listRecords(storage, re) {
  const items = await storage.list();
  const hits = [];
  for (const it of items) {
    const match = re.exec(it.path);
    if (match) hits.push({ path: it.path, match });
  }
  const records = await Promise.all(hits.map(async (h) => {
    let record = null;
    try { record = await storage.readJSON(h.path, null); } catch { record = null; }
    return record && !isDeleted(record) ? { ...h, record } : null;
  }));
  return records.filter(Boolean);
}

/**
 * The next number in a numbered series of names (`post-<N>.json`): the largest N
 * among the listed items that match `re` (whose first group is N), plus one.
 */
export function nextNumbered(items, re) {
  let max = 0;
  for (const it of items) {
    const m = re.exec(it.path);
    if (m) { const n = parseInt(m[1], 10); if (Number.isInteger(n) && n > max) max = n; }
  }
  return max + 1;
}
