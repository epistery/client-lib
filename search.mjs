// search.mjs — pure keyword projection for the sealed search sidecar.
//
// The sibling of wikiwords.mjs: no DOM, no markdown deps, so it imports cleanly
// in both the browser (served at /lib/search.mjs) and Node (a kind's server
// index.mjs, and the MCP write path). Where wikiwords.mjs extracts the LINK
// graph a body points at, this extracts the TERM set a body is found by.
//
// Deliberately dumb (ClientDoesTheCompute, no intelligence): lowercase, split on
// non-word, drop stopwords and one-char tokens, dedupe. Decades-old inverted
// index, nothing more — a keyword hook, not an answer engine. A member who wants
// depth seats a chatbot on the session; this is only the cheap door.
//
// It runs client-side on purpose: the host never reads a sealed body, so the
// WRITER projects the terms from the plaintext before sealing and the sealed
// result rides the write — the same seam _refs ride. The term set itself is
// content (it reveals the body), so unlike _refs it is sealed, never clear.

// Common words carry no signal and bloat every posting list; a short, boring
// stop set keeps the sidecar lean. English only for v1 — grow it when a
// non-English corpus actually needs it rather than guessing now.
const STOP = new Set((
  'a an and are as at be but by for from had has have he her his i in is it its ' +
  'of on or that the their them they this to was were will with you your not no ' +
  'if then else when which who whom what where how all any can do does did done ' +
  'we us our so up out get got also into over than too very about above after'
).split(' '));

// A token is a run of 2+ word characters, lowercased. Markdown punctuation,
// URLs' separators and code-fence backticks are not word characters, so they
// fall away without a strip pass — splitting on \W is the strip.
const TOKEN_RE = /[a-z0-9][a-z0-9_]+/g;

/**
 * Project a body (and anything else worth finding it by — a wiki passes
 * `${title}\n${body}`) into the unique set of terms it is searchable under.
 * @param {string} text  plaintext source (never ciphertext)
 * @returns {string[]} unique lowercased terms, stopwords and one-char runs removed
 */
export function extractTokens(text) {
  if (!text || typeof text !== 'string') return [];
  const terms = new Set();
  let m;
  TOKEN_RE.lastIndex = 0;
  const lower = text.toLowerCase();
  while ((m = TOKEN_RE.exec(lower)) !== null) {
    const t = m[0];
    if (t.length < 2 || STOP.has(t)) continue;
    terms.add(t);
  }
  return [...terms];
}

/**
 * Build an in-memory inverted index from per-doc term sets. The sidecar stores
 * the forward map { docId: terms[] } (cheap to update one doc); the reader
 * inverts it once at query time. Kept here so every kind's search UI inverts
 * and matches the same way rather than each re-deriving it.
 * @param {Object<string,string[]>} forward  { docId: terms[] }
 * @returns {Map<string,Set<string>>} term → set of docIds
 */
export function buildInverted(forward) {
  const inv = new Map();
  for (const [docId, terms] of Object.entries(forward || {})) {
    for (const t of Array.isArray(terms) ? terms : []) {
      let set = inv.get(t);
      if (!set) inv.set(t, (set = new Set()));
      set.add(docId);
    }
  }
  return inv;
}

/**
 * Rank docs for a free-text query against an inverted index. A doc scores by how
 * many distinct query terms it carries (AND-ish: more terms matched ranks
 * higher); ties keep input order via the forward map's insertion. No TF-IDF, no
 * stemming — the dumb hook. Prefix matching so "past" finds "pasta".
 * @param {Map<string,Set<string>>} inverted  from buildInverted
 * @param {string} query  raw user text
 * @returns {Array<{docId:string, score:number}>} best first
 */
export function rankMatches(inverted, query) {
  const qTerms = extractTokens(query);
  if (!qTerms.length) return [];
  const score = new Map();
  for (const qt of qTerms) {
    // Exact term, plus any index term that starts with it (prefix match).
    const hitDocs = new Set();
    for (const [term, docs] of inverted) {
      if (term === qt || term.startsWith(qt)) for (const d of docs) hitDocs.add(d);
    }
    for (const d of hitDocs) score.set(d, (score.get(d) || 0) + 1);
  }
  return [...score.entries()]
    .map(([docId, s]) => ({ docId, score: s }))
    .sort((a, b) => b.score - a.score);
}
