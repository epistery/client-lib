// Popup — the canonical modal element (window.popup). Owns its css.

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
.Popup .control > DIV { margin-left: var(--spacerhalf); }
.Popup .content {
  display: flex;
  flex-direction: column;
  flex: 1 0;
  align-items: center;
  justify-content: center;
  padding: var(--spacer3);
}
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
`;

  async render(element) {
    await super.render(element);
    this.shim = this.div('shim', this.element);
    this.window = this.div('window', this.element);
    this.header = this.div('header', this.window);
    this.headerTitle = this.div('header-title', this.header);
    this.headerClose = this.div('header-close', this.header);
    this.headerClose.innerHTML = `<span class='icon icon-cross'>`;
    this.content = this.div('content', this.window);
    this.control = this.div('control', this.window);
    this.headerClose.addEventListener('click', () => { this.close(); });
    window.popup = this;
  }

  async display(title = '', element, buttons = []) {
    this.content.innerHTML = '';
    this.headerTitle.innerHTML = title;
    this.element.style.zIndex = '1000';
    this.element.style.opacity = '100%';
    this.content.append(element);
    this.control.innerHTML = '';
    for (const btn of buttons) await btn.render(this.control);
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
      const done = (v) => { this.close(); resolve(v); };
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
      this.display(title, form, []);
      setTimeout(() => input.focus(), 50);
    });
  }

  close() {
    this.element.style.zIndex = '-1000';
    this.element.style.opacity = '0';
  }
}
