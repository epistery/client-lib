/**
 * MarkUp - Wiki markdown renderer with extensions
 *
 * Adapted from wiki-mixin for the epistery wiki. Browser-side: uses marked for
 * markdown and Mermaid for diagrams (both loaded from CDN at runtime). Served
 * by the shell at /lib/markup.mjs; its `./wikiwords.mjs` import resolves to the
 * sibling served file in the browser and to the package file in Node.
 */

import { extractWikiWords, splitInlineCode } from './wikiwords.mjs';

// WikiWord processor - converts CamelCase words to wiki links
class WikiWord {
  constructor(basePath = '/wiki') {
    this.basePath = basePath;
  }

  process(body, currentDocId = '') {
    let lines = body.split('\n');
    let newLines = [];
    let skipping = false;
    let fenceChar = null;
    let fenceLength = 0;

    for (let line of lines) {
      // Check for code fence start/end: ``` or ~~~, 3 or more chars
      const fenceMatch = line.match(/^([`~]){3,}/);

      if (fenceMatch) {
        if (!skipping) {
          // Starting a code block
          skipping = true;
          fenceChar = fenceMatch[1];
          fenceLength = fenceMatch[0].length;
        } else if (fenceMatch[1] === fenceChar && fenceMatch[0].length >= fenceLength) {
          // Ending a code block - must match the opening fence char and be at least as long
          skipping = false;
          fenceChar = null;
          fenceLength = 0;
        }
        // Always push fence lines without processing
        newLines.push(line);
        continue;
      }

      if (!skipping) {
        // Inline `code` spans stay literal — see splitInlineCode.
        line = splitInlineCode(line).map((seg, i) => {
          if (i % 2) return seg;
          // To force a link not in camel case surround the word in brackets
          // Skip image syntax (![...]) and existing markdown links ([...](...))
          seg = seg.replace(/(?<!!)\[([A-Za-z0-9_]+)\](?!\()/g, (match, word) => {
            return `[${word}](${this.basePath}/${word})`;
          });
          // Match CamelCase WikiWords, but avoid matching words already in markdown links
          // The negative lookbehind (?<![[(]) prevents matching inside [text] or already-created [text](url)
          seg = seg.replace(/(^|[^a-zA-Z0-9:_\-=.["'}{\\/[])([!A-Z][A-Z0-9]*[a-z][a-z0-9_]*[A-Z][A-Za-z0-9_]*)(?![^\[]*\])/g, (match, pre, word) => {
            if (word.charAt(0) === '!') return pre + (word.slice(1));
            else if (pre === "W:") return `[${word}](wikipedia.org?s=${word})`;
            else if (pre === "G:") return `[${word}](google.com?s=${word})`;
            else return `${pre}[${word}](${this.basePath}/${word})`;
          });
          return seg;
        }).join('');
      }
      newLines.push(line);
    }
    return newLines.join('\n');
  }
}

export default class MarkUp {
  constructor(options = {}) {
    // WikiWord auto-linking is wiki-specific. Plugins like message-board
    // pass `noWikiWord: true` so CamelCase in post bodies stays inert.
    this.wikiWordEnabled = !options.noWikiWord;
    if (this.wikiWordEnabled) {
      this.wikiWord = new WikiWord(options.basePath || '/wiki');
    }
    this.marked = null;
    this.mermaidInitialized = false;
  }

  /**
   * Initialize the renderer
   * Must be called before render()
   */
  async init() {
    // Dynamic import marked
    if (!this.marked) {
      const { marked } = await import('https://cdn.jsdelivr.net/npm/marked@12.0.0/lib/marked.esm.js');
      this.marked = marked;

      // Configure marked - allow raw HTML to pass through
      this.marked.setOptions({
        gfm: true,
        breaks: false,
        sanitize: false,  // Don't sanitize HTML
        smartypants: false
      });
    }

    // Initialize Mermaid
    if (!this.mermaidInitialized && typeof window !== 'undefined') {
      await this.initMermaid();
    }
  }

  /**
   * Initialize Mermaid diagram renderer
   */
  async initMermaid() {
    if (typeof window === 'undefined') return;

    // Check if mermaid is already loaded
    if (window.mermaid) {
      this.mermaidInitialized = true;
      return;
    }

    await new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js';
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });

    const config = {
      startOnLoad: false,
      theme: 'default',
      securityLevel: 'loose',
      flowchart: { nodeSpacing: 60, rankSpacing: 100 }
    };

    try {
      const elk = await import('https://cdn.jsdelivr.net/npm/@mermaid-js/layout-elk@0.2.0/dist/mermaid-layout-elk.esm.min.mjs');
      window.mermaid.registerLayoutLoaders(elk.default);
      config.layout = 'elk';
    } catch (err) {
      console.warn('[MarkUp] ELK layout plugin failed to load; falling back to dagre', err);
    }

    window.mermaid.initialize(config);
    this.mermaidInitialized = true;
  }

  /**
   * Render markdown to HTML
   * @param {string} body - Markdown content
   * @param {object} options - Render options
   * @returns {Promise<string>} HTML content
   */
  async render(body, options = {}) {
    await this.init();

    // Process WikiWords first (properly skips code blocks now). Skipped
    // entirely for plugins that opted out (e.g. message-board posts).
    const wordified = this.wikiWordEnabled
      ? this.wikiWord.process(body, options._pid)
      : body;

    // Render markdown (this will convert ```mermaid to <pre><code class="language-mermaid">)
    let result = await this.marked.parse(wordified);

    // Post-process: convert mermaid code blocks to mermaid containers
    result = this.convertMermaidBlocks(result);

    // Add default styles
    result += `
<style>
.doclet-render h1 { margin-top: 0; }
.mermaid-container { margin: 1em 0; }
.frame-set { display: flex; flex-wrap: wrap; gap: 1em; }
.frame-container { flex: 1; min-width: 300px; }
.frame-container.titled { border: 1px solid #ccc; border-radius: 4px; }
.frame-title { background: #f5f5f5; padding: 0.5em 1em; font-weight: bold; }
.frame-container iframe { width: 100%; height: 400px; border: none; }
</style>`;

    return result;
  }

  /**
   * Convert mermaid code blocks to mermaid containers
   * Processes HTML after marked.js rendering
   */
  convertMermaidBlocks(html) {
    let blockId = 0;

    // Find <pre><code class="language-mermaid"> blocks and convert to mermaid containers
    // marked.js converts ```mermaid to <pre><code class="language-mermaid">
    html = html.replace(/<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g, (match, content) => {
      const id = `mermaid-${++blockId}`;
      // Content is already HTML-encoded by marked, we need to decode it for Mermaid
      const decoded = this.decodeHtml(content);
      return `<div class="mermaid-container" id="${id}">${decoded}</div>`;
    });

    return html;
  }

  /**
   * Decode HTML entities
   */
  decodeHtml(html) {
    const txt = document.createElement('textarea');
    txt.innerHTML = html;
    return txt.value;
  }

  /**
   * Post-process rendered HTML to initialize Mermaid diagrams
   * Call this after inserting rendered HTML into the DOM
   */
  async renderMermaidDiagrams(container) {
    if (typeof window === 'undefined' || !window.mermaid) return;

    const mermaidElements = container.querySelectorAll('.mermaid-container');
    for (const el of mermaidElements) {
      try {
        const id = el.id;
        const content = el.textContent;
        const { svg } = await window.mermaid.render(id + '-svg', content);
        el.innerHTML = svg;
      } catch (error) {
        console.error('[MarkUp] Mermaid render error:', error);
        el.innerHTML = `<pre class="mermaid-error">Diagram error: ${error.message}</pre>`;
      }
    }
  }

  /**
   * Escape HTML entities
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * List the doc ids this body links to (CamelCase + [Bracketed] WikiWords).
   * Used to build the wiki's reference-graph hierarchy. Returns [] for plugins
   * that disabled WikiWord linking (e.g. message-board posts).
   * @param {string} body markdown source
   * @returns {string[]} unique referenced doc ids
   */
  extractLinks(body) {
    if (!this.wikiWordEnabled) return [];
    return extractWikiWords(body);
  }
}

// Export for use as ES module or in browser
if (typeof window !== 'undefined') {
  window.MarkUp = MarkUp;
}
