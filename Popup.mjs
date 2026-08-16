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

  close() {
    this.element.style.zIndex = '-1000';
    this.element.style.opacity = '0';
  }
}
