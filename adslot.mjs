// adslot — fill an element with an ad for a session that has chosen to carry ads.
//
// A session declares itself (its params.discovery — title, audience, concepts)
// and, in that declaration, whether it carries ads and which ad network serves
// them. This asks that network for a server-rendered fragment, naming the session
// as the publisher: `?session=<owner contract>:<session id>`. The network does
// not take that on trust — it checks with Scan that the session's own contract
// vouches for the declaration, and pays the contract. The host serving the page
// (epistery.com) is never the publisher.
//
// Agency-neutral: nothing here names an ad network; the session's declaration
// does. The fragment protocol is the one any network following Adnet's rails
// serves: GET {agency}/render/{format}?session=… → HTML (204 = nothing to show).
//
// Every fill records a view at the network, so a caller fills a slot once per
// real display — never re-fills an ad already on screen.

const FORMATS = new Set(['banner', 'square', 'card', 'badge', 'qr']);

// The first-party continuity id Adnet's own client keeps (adnet_vid): evidence
// on an event, never identity. Best-effort — no storage, no id.
function continuityId() {
  try {
    let v = localStorage.getItem('adnet_vid');
    if (!v) { v = crypto.randomUUID(); localStorage.setItem('adnet_vid', v); }
    return v;
  } catch { return null; }
}

/** The ad network a session's declaration names, when it carries ads — else null. */
export function adAgency(session) {
  const d = session?.params?.discovery;
  if (d?.ads?.enabled !== true) return null;
  if ((session.defaultRole || 'none') === 'none') return null;   // a private session declares nothing to strangers
  try {
    const u = new URL(d.ads.agency);
    return u.protocol === 'https:' || u.hostname === 'localhost' ? u.origin : null;
  } catch { return null; }
}

/**
 * Fill `el` with one ad for `session`. Resolves true when an ad landed, false when
 * the session carries no ads or the network had nothing to show.
 */
export async function fillAdSlot(el, session, { format = 'banner' } = {}) {
  const agency = adAgency(session);
  if (!agency || !el || !FORMATS.has(format)) return false;
  // Declare the space before asking for the ad. The class says which shape is
  // coming and the publisher's own css gives it a band, so the fragment arrives
  // into a box that already exists instead of pushing the page down as it loads.
  el.classList.add('adnet-slot', `adnet-slot-${format}`);
  const q = new URLSearchParams({ session: `${session.owner}:${session.id}`, page: location.pathname });
  const cid = continuityId();
  if (cid) q.set('cid', cid);
  try {
    const r = await fetch(`${agency}/render/${format}?${q}`, { credentials: 'omit' });
    if (!r.ok || r.status === 204) return release(el, format);
    const html = await r.text();
    if (!html.trim()) return release(el, format);
    el.innerHTML = html;
    el.dataset.adFilled = '1';
    return true;
  } catch (e) {
    console.warn('[adslot] no ad:', e.message);
    return release(el, format);
  }
}

/** Nothing to show: give the declared space back, so no empty band is left. */
function release(el, format) {
  el.classList.remove('adnet-slot', `adnet-slot-${format}`);
  return false;
}
