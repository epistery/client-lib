// Popup — the canonical modal element (window.popup). Owns its css.
//
// ONE modal for the whole app: a small centred dialog (display/prompt) AND a
// large scrolling PANEL with an optional tab strip (openTabs) share this single
// frame — shim, window, header+title, close, content, footer. Consumers never
// hand-roll overlay chrome; a settings panel is this component in `panel`
// variant, so session and identity modals look and behave identically.

import Component from './componentry.mjs';

export default class Popup extends Component {
  static css = `
.Popup {
  display: flex;
  position: absolute;
  top: 0; bottom: 0; left: 0; right: 0;
  z-index: -1000;
  align-items: center;
  justify-content: center;
  transition: all 250ms;
  opacity: 0;
}
.Popup .window {
  flex: 0 0;
  border: 1px solid var(--page-border);
  background-color: var(--bg-color);
}
.Popup .header { flex: 30px 0; display: flex; justify-content: space-between; }
.Popup .header-title { font-weight: bold; margin: 3px; }
.Popup .header-close { cursor: pointer; }
.Popup .control {
  display: flex;
  flex-direction: row;
  justify-content: flex-end;
  padding: var(--spacer);
}
.Popup .control:empty { display: none; }
.Popup .control > DIV { margin-left: var(--spacerhalf); }
.Popup .content {
  display: flex;
  flex-direction: column;
  flex: 1 0;
  align-items: center;
  justify-content: center;
  padding: var(--spacer3);
}
/* Tab strip — hidden until openTabs populates it. */
.Popup .tabstrip { display: none; }
.Popup .shim {
  position: absolute;
  top: 0; bottom: 0; left: 0; right: 0;
  background-color: var(--tray-bg);
  opacity: 50%;
  z-index: -1;
}
.Popup .popup-form > div { margin-bottom: var(--spacer); }
.Popup .popup-form { min-width: 300px; max-width: 80vw; }
.Popup .popup-form input {
  width: 100%; padding: 8px 10px; box-sizing: border-box;
  border: 1px solid var(--page-border); border-radius: 8px; font: inherit;
}
.Popup .popup-form .prompt-err { color: var(--status-error, #c0392b); font-size: 12px; min-height: 14px; margin: 4px 0 0; }
.Popup .popup-form .prompt-btns { display: flex; justify-content: flex-end; gap: var(--spacer); margin-top: var(--spacer2); }
.Popup .popup-form button {
  padding: 6px 14px; border-radius: 8px; border: none; font: inherit; cursor: pointer;
  background: var(--primary); color: var(--primary-contrast);
}
.Popup .popup-form button.ghost { background: transparent; color: var(--primary); border: 1px solid var(--page-border); }

/* ── PANEL variant — a large, scrolling, optionally tabbed settings modal ─────
   The same frame as the dialog above, resized and re-flowed: the window takes a
   definite size, the header reads as a title bar, the content becomes a top-
   aligned scroll region, and the tab strip (if any) sits between them. */
.Popup.panel .window {
  width: min(640px, 94vw); max-height: 84vh;
  display: flex; flex-direction: column;
  border-radius: 12px; box-shadow: 0 12px 48px rgba(0,0,0,0.35); overflow: hidden;
}
.Popup.panel .header { flex: none; align-items: center; padding: var(--spacer2); border-bottom: 1px solid var(--page-border); }
.Popup.panel .header-title { margin: 0; }
.Popup.panel .header-close { font-size: 20px; line-height: 1; color: var(--text-muted); }
.Popup.panel .header-close:hover { color: var(--text-color); }
.Popup.panel .tabstrip {
  display: flex; gap: 2px; flex: none; padding: 0 var(--spacer2);
  border-bottom: 1px solid var(--page-border); overflow-x: auto;
}
.Popup.panel .tabstrip .tab {
  background: none; border: none; border-bottom: 2px solid transparent;
  padding: 10px var(--spacer); font: inherit; font-size: 13px; cursor: pointer;
  color: var(--text-muted); white-space: nowrap;
}
.Popup.panel .tabstrip .tab:hover { color: var(--text-color); }
.Popup.panel .tabstrip .tab.active { color: var(--primary); border-bottom-color: var(--primary); }
.Popup.panel .content {
  align-items: stretch; justify-content: flex-start; text-align: left;
  flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: var(--spacer2);
}
`;

  async render(element) {
    await super.render(element);
    this.shim = this.div('shim', this.element);
    this.window = this.div('window', this.element);
    this.header = this.div('header', this.window);
    this.headerTitle = this.div('header-title', this.header);
    this.headerClose = this.div('header-close', this.header);
    this.headerClose.innerHTML = `<span class='icon icon-cross'>`;
    // Tab strip sits between the header and the content; empty (and hidden) for
    // the dialog variant, populated by openTabs for the panel variant.
    this.tabstrip = this.div('tabstrip', this.window);
    this.content = this.div('content', this.window);
    this.control = this.div('control', this.window);
    this.headerClose.addEventListener('click', () => { this.close(); });
    this.shim.addEventListener('click', () => { if (this._dismissable) this.close(); });
    window.popup = this;
  }

  // Common open path for every variant: reset state, set the title, apply the
  // variant, and record the caller's close hook + dismissable flag. `close()`
  // reverses all of it so the next open starts clean.
  _open(title, { variant = 'dialog', onClose = null, dismissable } = {}) {
    this._onClose = onClose;
    // Panels dismiss on ESC / backdrop like the overlay they replace; plain
    // dialogs keep the original behaviour (their own forms own ESC) unless a
    // caller opts in.
    this._dismissable = dismissable ?? (variant === 'panel');
    this.element.classList.toggle('panel', variant === 'panel');
    this.setTitle(title);
    this.tabstrip.innerHTML = '';
    this.tabstrip.style.display = 'none';
    this.content.innerHTML = '';
    this.control.innerHTML = '';
    this.element.style.zIndex = '1000';
    this.element.style.opacity = '100%';
    // ESC closes any dismissable modal — owned here, not re-added per consumer.
    this._removeEsc();
    if (this._dismissable) {
      this._esc = (e) => { if (e.key === 'Escape') { e.preventDefault(); this.close(); } };
      document.addEventListener('keydown', this._esc);
    }
  }
  _removeEsc() { if (this._esc) { document.removeEventListener('keydown', this._esc); this._esc = null; } }

  setTitle(html = '') { this.headerTitle.innerHTML = html; }

  // Small centred content (a form, a message) + optional footer buttons. The
  // original contract (title, element, buttons) is unchanged; `options` adds the
  // close hook so a consumer no longer has to watch the element to learn it closed.
  async display(title = '', element, buttons = [], options = {}) {
    this._open(title, { variant: 'dialog', ...options });
    if (element) this.content.append(element);
    for (const btn of buttons) await btn.render(this.control);
  }

  // Large scrolling panel with a tab strip. `tabs` is [{ id, label, build }],
  // where build(contentEl) fills the tab's pane (called lazily on first select,
  // then cached). `options.initial` selects a starting tab by id. Returns a small
  // handle so the opener can drive it (select a tab, retitle, close).
  async openTabs(title = '', tabs = [], options = {}) {
    this._open(title, { variant: 'panel', ...options });
    this.tabstrip.style.display = tabs.length > 1 ? 'flex' : 'none';
    const panes = new Map();     // id → built pane node (lazy)
    const btns = new Map();      // id → tab button
    const select = (id) => {
      const t = tabs.find(x => x.id === id) || tabs[0];
      if (!t) return;
      for (const [tid, b] of btns) b.classList.toggle('active', tid === t.id);
      for (const [, node] of panes) node.hidden = true;
      let pane = panes.get(t.id);
      if (!pane) {
        pane = document.createElement('div');
        this.content.append(pane);
        panes.set(t.id, pane);
        try { t.build(pane); } catch (e) { pane.textContent = 'Failed to load: ' + (e?.message || e); }
      }
      pane.hidden = false;
    };
    for (const t of tabs) {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'tab'; b.textContent = t.label;
      b.addEventListener('click', () => select(t.id));
      this.tabstrip.append(b);
      btns.set(t.id, b);
    }
    select(options.initial || (tabs[0] && tabs[0].id));
    return { select, setTitle: (t) => this.setTitle(t), close: () => this.close() };
  }

  // The canonical TEXT prompt (window.popup.prompt) — the singular replacement
  // for native prompt(). Non-blocking; resolves to the trimmed string, or null
  // on cancel/escape. `validate(value)` may return an error message to keep the
  // dialog open. Pair with window.toast.prompt(msg) for yes/no confirms.
  async prompt(title = '', options = {}) {
    const { placeholder = '', value = '', ok = 'OK', cancel = 'Cancel', validate = null } = options;
    return new Promise((resolve) => {
      const form = document.createElement('div');
      form.className = 'popup-form';
      const input = document.createElement('input');
      input.type = 'text'; input.value = value; input.placeholder = placeholder;
      input.autocomplete = 'off'; input.spellcheck = false;
      const err = document.createElement('p'); err.className = 'prompt-err';
      const btns = document.createElement('div'); btns.className = 'prompt-btns';
      const cancelBtn = document.createElement('button'); cancelBtn.className = 'ghost'; cancelBtn.textContent = cancel;
      const okBtn = document.createElement('button'); okBtn.textContent = ok;
      btns.append(cancelBtn, okBtn);
      form.append(input, err, btns);
      let settled = false;
      const done = (v) => { if (settled) return; settled = true; this.close(); resolve(v); };
      const submit = () => {
        const v = input.value.trim();
        if (validate) { const msg = validate(v); if (msg) { err.textContent = msg; input.focus(); return; } }
        done(v || null);
      };
      okBtn.addEventListener('click', submit);
      cancelBtn.addEventListener('click', () => done(null));
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); submit(); }
        else if (e.key === 'Escape') { e.preventDefault(); done(null); }
      });
      // The header X / shim / ESC route through onClose → resolve(null), so a
      // dismiss can't leave the awaiting caller hanging.
      this.display(title, form, [], { onClose: () => done(null) });
      setTimeout(() => input.focus(), 50);
    });
  }

  close() {
    this._removeEsc();
    this.element.style.zIndex = '-1000';
    this.element.style.opacity = '0';
    this.element.classList.remove('panel');
    const cb = this._onClose; this._onClose = null;
    if (cb) { try { cb(); } catch { /* consumer teardown is best-effort */ } }
  }
}
