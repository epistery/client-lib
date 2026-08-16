// wikiwords.mjs — pure WikiWord link extraction.
//
// No DOM, no markdown deps, so it imports cleanly in both the browser (served
// at /lib/wikiwords.mjs) and Node (the wiki plugin's server index.mjs).
//
// "References" are the doc ids a body links to: CamelCase WikiWords and
// [Bracketed] forced links — skipping code fences, external search links
// (W:/G:), and !escaped words. This is the single source of truth for the
// reference graph the wiki tree is built from, so the regexes here MUST stay
// in lockstep with WikiWord.process() in markup.mjs (they are copied from it).

const DOC_ID_RE = /^[A-Za-z0-9_]{3,}$/;
// [Word] forced link — not an image (!), not an existing [text](url).
const BRACKET_RE = /(?<!!)\[([A-Za-z0-9_]+)\](?!\()/g;
// CamelCase WikiWord, with a leading capture (`pre`) so W:/G: prefixes and a
// preceding word char can be distinguished, and a lookahead that skips words
// already inside a [...] span.
const CAMEL_RE = /(^|[^a-zA-Z0-9:_\-=.["'}{\\/[])([!A-Z][A-Z0-9]*[a-z][a-z0-9_]*[A-Z][A-Za-z0-9_]*)(?![^\[]*\])/g;

/**
 * Collect the doc ids a markdown body links to.
 * @param {string} body markdown source
 * @returns {string[]} unique referenced doc ids (validated WikiWords)
 */
export function extractWikiWords(body) {
  if (!body || typeof body !== 'string') return [];
  const ids = new Set();
  let skipping = false, fenceChar = null, fenceLength = 0;

  for (const line of body.split('\n')) {
    // Track ``` / ~~~ code fences; never link inside them.
    const fence = line.match(/^([`~]){3,}/);
    if (fence) {
      if (!skipping) {
        skipping = true; fenceChar = fence[1]; fenceLength = fence[0].length;
      } else if (fence[1] === fenceChar && fence[0].length >= fenceLength) {
        skipping = false; fenceChar = null; fenceLength = 0;
      }
      continue;
    }
    if (skipping) continue;

    let m;
    BRACKET_RE.lastIndex = 0;
    while ((m = BRACKET_RE.exec(line)) !== null) {
      if (DOC_ID_RE.test(m[1])) ids.add(m[1]);
    }
    CAMEL_RE.lastIndex = 0;
    while ((m = CAMEL_RE.exec(line)) !== null) {
      const pre = m[1], word = m[2];
      if (word.charAt(0) === '!') continue;        // !Escaped — not a link
      if (pre === 'W:' || pre === 'G:') continue;   // external search links
      if (DOC_ID_RE.test(word)) ids.add(word);
    }
  }
  return Array.from(ids);
}
