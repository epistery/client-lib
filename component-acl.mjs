// component-acl — the `//ACL` delivery preprocessor (SERVER-side).
//
// Retained from @metric-im/componentry: before a component's .mjs is delivered
// to the browser, strip code blocks the caller's access level does not meet.
// PHP-like — dynamic code meant only for certain users is extracted BEFORE
// delivery, so a lower-privilege browser never even receives privileged logic.
//
// Syntax (block comments so the source stays valid JS when un-stripped):
//   /*ACL>1*/  ...code only delivered when level > 1 ...  /*ENDACL*/
//   /*ACL<1*/  ...code only delivered when level < 1 ...  /*ENDACL*/
//
// The caller's level comes from their episteryClient (every visitor has one).
// This is a server util — the shell applies it in the route that serves
// component modules; it is not part of the browser runtime.

const ACL_RE = /\/\*ACL([<>])(\d)\*\/(.*?)\/\*ENDACL\*\//gs;

/**
 * Strip ACL-guarded blocks the given level does not satisfy.
 * @param {string} source component module source
 * @param {number} level  the caller's access level
 * @returns {string} source with unmet blocks removed
 */
export function aclPreprocess(source, level) {
  if (typeof source !== 'string') return source;
  const lvl = Number(level) || 0;
  return source.replace(ACL_RE, (_match, op, acl, code) => {
    const bound = parseInt(acl, 10);
    const keep = op === '>' ? lvl > bound : lvl < bound;
    return keep ? code : '';
  });
}

// The ACL scale maps ONE-TO-ONE onto the EpisteryAccess role numbers used
// throughout app and epistery-host: 0 none · 1 read · 2 write · 3 admin.
// (app calls role 2 "edit"; it is the same level as chain "write".) So a
// component annotation reads naturally: `/*ACL>1*/ … /*ENDACL*/` delivers only
// to write-and-above (2,3); `/*ACL>2*/` is admin-only.
export const ROLE_LEVEL = { none: 0, read: 1, edit: 2, write: 2, admin: 3 };

/**
 * Numeric ACL level for a role. Accepts a role name (none/read/edit/write/admin)
 * or a number (returned clamped as-is). Rights in epistery are contextual (a
 * caller's role is per session), so the shell computes the caller's role for the
 * relevant context and passes the result here; absent a role, level is 0 (none).
 * @param {string|number|null} role
 * @returns {number}
 */
export function levelOf(role) {
  if (typeof role === 'number') return role;
  return ROLE_LEVEL[role] ?? 0;
}
