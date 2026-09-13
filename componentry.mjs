// componentry — epistery's atomic-component base.
//
// Cloned and TRIMMED from @metric-im/componentry (Michael's homegrown system),
// kept in-ecosystem rather than taken as a heavy external dep so every epistery
// repo shares one set of display elements and one notification system, owned and
// current. The point is ATOMICITY: a concept (a save button, a modal, a toast)
// has exactly ONE canonical implementation, so it is never quietly rebuilt a
// dozen subtly-different ways.
//
// Two deliberate departures from the original:
//   * NO live css scope/concat serve. That existed only because editing css
//     inside an .mjs was cumbersome — a non-problem now. A component OWNS its
//     css via `static css` (authored scoped to its own class name); the base
//     injects it into <head> exactly once per class. Self-contained, no server
//     preprocessor for styling.
//   * The `//ACL` DELIVERY preprocessor is retained, but as a server-side text
//     transform applied when a component's .mjs is delivered (see
//     ./component-acl.mjs) — not here in the client runtime.
//
// Pure browser ESM. Only dependency: ./IdForge.mjs.

import IdForge from './IdForge.mjs';

// Track which component classes have had their `static css` injected, so a
// concept's styles land once no matter how many instances render.
const _injectedStyles = new Set();

export default class Component {
  constructor(props) {
    this.props = props || {};
    this.props.data = this.props.data || {};
    this.element = document.createElement('div');
    this.element.id = IdForge.randomId();
    this.element.classList.add(this.constructor.name);
    this.components = [];
    this.watchers = {};
    this.lock = new Lock(this);
    this.hub = false;
  }

  // A component owns its css: subclasses set `static css = \`...\``, authored
  // scoped to their own class (e.g. `.Toast .display { }`). Injected once.
  _ensureStyles() {
    const name = this.constructor.name;
    const css = this.constructor.css;
    if (!css || _injectedStyles.has(name)) return;
    _injectedStyles.add(name);
    const style = document.createElement('style');
    style.setAttribute('data-epistery-component', name);
    style.textContent = css;
    document.head.appendChild(style);
  }

  /**
   * Create a component and attach it to the given element.
   * This is new() followed by render().
   */
  async draw(Comp, props, element) {
    let component = new Comp(props);
    this.components.push(component);
    component.parent = this;
    await component.render(element);
    return component;
  }

  new(Comp, props) {
    let component = new Comp(props);
    this.components.push(component);
    component.parent = this;
    return component;
  }

  async render(element) {
    this._ensureStyles();
    this.element.innerHTML = '';
    if (element) element.appendChild(this.element);
  }

  async update(props) {
    Object.assign(this.props, props);
    await this.render();
  }

  /**
   * Create a div with classes, attached to a parent (or this.element).
   */
  div(classlist, parent) {
    let div = document.createElement('div');
    div.id = IdForge.randomId();
    if (classlist) div.classList.add(...classlist.split(' '));
    if (parent) parent.append(div);
    else this.element.append(div);
    return div;
  }

  /**
   * Listen for a named event fired anywhere within the hub.
   */
  on(event, action) {
    let args = Array.from(arguments).splice(2);
    let hubComponent = this.getHub();
    hubComponent.watchers[event] = hubComponent.watchers[event] || [];
    // Keep the ORIGINAL alongside the bound copy. bind() returns a new function,
    // so without this the caller can never name what it registered and off() is
    // impossible — which is why watchers here could only ever accumulate. The
    // owner is recorded too, so a component can drop everything it registered in
    // one call when it is torn down.
    const bound = action.bind(hubComponent, ...args);
    bound._source = action;
    bound._owner = this;
    hubComponent.watchers[event].push(bound);
  }

  /**
   * Stop listening. `off(event, action)` removes that registration, `off(event)`
   * removes every watcher for the event, and `off()` removes everything this
   * component registered — the teardown case, so a view that comes and goes does
   * not leave a listener behind on each visit.
   */
  off(event, action) {
    let hubComponent = this.getHub();
    if (!hubComponent?.watchers) return;
    if (!event) {
      for (const name of Object.keys(hubComponent.watchers)) {
        hubComponent.watchers[name] = hubComponent.watchers[name].filter((w) => w._owner !== this);
      }
      return;
    }
    const list = hubComponent.watchers[event];
    if (!list) return;
    hubComponent.watchers[event] = action ? list.filter((w) => w._source !== action) : [];
  }

  /**
   * Fire a named event to hub listeners, passing any arguments.
   */
  fire(event) {
    let args = Array.from(arguments).splice(1);
    let hubComponent = this.getHub();
    if (hubComponent?.watchers[event]) {
      for (let w of hubComponent.watchers[event]) w(...args);
    }
  }

  show() { this.element.style.display = 'block'; }
  hide() { this.element.style.display = 'none'; }

  async announceUpdate(attributeName) {
    let hubComponent = this.getHub();
    if (hubComponent) await hubComponent.handleUpdate(attributeName);
  }
  async handleUpdate(attributeName) {
    for (let comp of this.components) {
      if (comp.handleUpdate) await comp.handleUpdate(attributeName);
    }
  }

  /**
   * Traverse up the parent tree to a hub component, or settle on self.
   */
  getHub() {
    let hubComponent = this;
    while (hubComponent && !hubComponent.hub) {
      let test = (hubComponent.parent && hubComponent.parent !== hubComponent) ? hubComponent.parent : null;
      if (test) hubComponent = test;
      else break;
    }
    return hubComponent;
  }

  /**
   * Data state is held by reference; local-only keys are prefaced with "__".
   * scrub recursively removes any attribute starting with "__".
   */
  scrub(data) {
    return loop(data);
    function loop(data) {
      let o = {};
      for (let key of Object.keys(data)) {
        if (!key.startsWith('__')) {
          if (Array.isArray(data[key])) o[key] = data[key].map(o => loop(o));
          else if (data[key] === null) o[key] = null;
          else if (typeof data[key] === 'object') o[key] = loop(data[key]);
          else o[key] = data[key];
        }
      }
      return o;
    }
  }

  /**
   * Attach the global popup + toast singletons (the notification system).
   * Call once at app boot with the mount element.
   */
  static async init(element) {
    const Popup = await import('./Popup.mjs');
    const Toast = await import('./Toast.mjs');
    window.popup = new Popup.default();
    await window.popup.render(element);
    window.toast = new Toast.default();
    await window.toast.render(element);
  }
}

/**
 * Locks warn against actions (save/exit) while a component is mid-edit.
 */
class Lock {
  constructor(comp) {
    this.comp = comp;
    this.locks = {};
  }
  async test(action) {
    if (!this.find(action)) return true;
    return await ({
      save: async () => {
        window.toast.warning('Please complete editing before saving');
        return false;
      },
      exit: async () => await window.toast.prompt('Continue without saving?'),
    })[action]();
  }
  find(action) {
    let components = [];
    if (this.locks.hasOwnProperty(action)) components.push(this.comp);
    for (let comp of this.comp.components) {
      components = components.concat(comp.lock.find(action) || []);
    }
    return components.length > 0 ? components : null;
  }
  add(action) { this.locks[action] = true; }
  remove(action) { if (this.locks.hasOwnProperty(action)) delete this.locks[action]; }
  clear(action) {
    if (action) this.remove(action);
    else this.locks = {};
    for (let comp of this.comp.components) comp.lock.clear(action);
  }
}
