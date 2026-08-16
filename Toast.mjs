// Toast — the transient notification + prompt element. One canonical
// implementation (window.toast); never rebuilt inline. Owns its css.

import Component from './componentry.mjs';

export default class Toast extends Component {
  static css = `
.Toast .layout {
  position: fixed;
  width: 100%;
  height: 0;
  max-height: 0;
  left: 0;
  top: 0;
  z-index: var(--z-index-toast);
}
.Toast .display {
  display: flex;
  flex-direction: column;
  align-items: center;
  position: relative;
  border: 3px solid var(--bg-color);
  border-radius: var(--spacer2);
  padding: var(--spacer2);
  background-color: var(--bg-color);
  width: fit-content;
  max-width: 380px;
  margin: 0 auto;
  top: -200px;
  transition: all 200ms;
}
.Toast .display.active { top: 30px; }
.Toast .display.warning { border-color: var(--status-warning); }
.Toast .display.error { border-color: var(--status-error); }
.Toast .display.success { border-color: var(--status-success); }
.Toast .display.prompt { border-color: var(--text-color); }
.Toast .display .message { flex: 1 0; text-align: center; color: var(--text-color); }
.Toast .display .controls {
  display: none;
  margin-top: var(--spacer);
  flex-direction: row;
  flex: 1 0;
}
.Toast .display.prompt .controls { display: flex; }
.Toast .display .controls button {
  border: 2px solid var(--page-border);
  background-color: var(--tray-bg);
  border-radius: 8px;
  cursor: pointer;
  color: var(--text-color);
  white-space: nowrap;
  min-width: 80px;
  margin: var(--spacer);
  padding: var(--spacerhalf);
}
.Toast .display .controls button:hover { background-color: var(--page-action); }
`;

  async render(element) {
    await super.render(element);
    this.layout = this.div('layout');
    this.window = this.div('display', this.layout);
    this.message = this.div('message', this.window);
    this.controls = this.div('controls', this.window);
    this.okButton = document.createElement('button');
    this.controls.append(this.okButton);
    this.cancelButton = document.createElement('button');
    this.controls.append(this.cancelButton);
    window.toast = this;
  }

  display(message, flavor = 'status') {
    this.close();
    this.message.innerHTML = message;
    this.window.classList.remove('status', 'warning', 'error', 'success', 'prompt');
    this.window.classList.add('active', flavor);
  }

  notify(message, flavor) {
    this.close();
    this.display(message, flavor);
    this.timer = setTimeout(this.close.bind(this), 2500);
    this.window.addEventListener('click', this.clickHandler.bind(this));
  }

  async prompt(message, options) {
    if (!options) options = {};
    const ok_text = options.ok ? options.ok : 'ok';
    const cancel_text = options.cancel ? options.cancel : 'cancel';
    return new Promise((resolve) => {
      this.display(message, 'prompt');
      this.okButton.innerHTML = ok_text;
      this.okButton.onclick = () => { this.close(); resolve(true); };
      this.cancelButton.innerHTML = cancel_text;
      this.cancelButton.onclick = () => { this.close(); resolve(false); };
    });
  }

  clickHandler() {
    if (this.window.classList.contains('prompt')) return;
    this.close();
  }

  close() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    this.window.classList.remove('active');
  }

  status(message) { this.notify(message, 'status'); }
  warning(message) { this.notify(message, 'warning'); }
  error(message) { this.notify(message, 'error'); }
  success(message) { this.notify(message, 'success'); }
}
