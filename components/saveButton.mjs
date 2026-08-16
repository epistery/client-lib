// saveButton — THE canonical save button. One implementation, pooled and shared,
// so no repo ever rewrites a subtly-different save control again.
//
// Pooled component: served at /components/saveButton.mjs and imported by name.
// It imports the base by its served URL (/lib/componentry.mjs) so it resolves
// the same wherever the pool places it. Browser-only.
//
// Props: { label='Save', onSave } — onSave is an async fn; the button disables
// while it runs, toasts success/failure, and re-enables. Callers get consistent
// save behaviour for free.

import Component from '/lib/componentry.mjs';

export default class SaveButton extends Component {
  static css = `
.SaveButton button {
  border: 2px solid var(--page-border);
  background-color: var(--page-action);
  color: var(--text-color);
  border-radius: 8px;
  padding: var(--spacerhalf) var(--spacer);
  min-width: 80px;
  cursor: pointer;
  font: inherit;
}
.SaveButton button:hover { filter: brightness(1.08); }
.SaveButton button:disabled { opacity: 0.5; cursor: default; }
`;

  async render(element) {
    await super.render(element);
    this.button = document.createElement('button');
    this.button.textContent = this.props.label || 'Save';
    this.button.addEventListener('click', () => this.save());
    this.element.append(this.button);
  }

  async save() {
    if (this.button.disabled) return;
    this.button.disabled = true;
    try {
      if (this.props.onSave) await this.props.onSave();
      window.toast?.success('Saved');
      this.fire('save');
    } catch (e) {
      window.toast?.error('Save failed: ' + (e?.message || e));
    } finally {
      this.button.disabled = false;
    }
  }
}
