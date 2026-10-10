/* In-place data refresh, without reloading the page.
   rolelensRefresh.regions(url, selector) fetches the page at url (default: the current
   URL), and swaps every element matching selector (default: [data-refresh]) for the
   element with the same id in the fresh page; elements missing from the fresh page stay
   as they are. Then it re-renders local times and dispatches "rolelens:data-refreshed"
   on document, so a page can re-fetch data it holds itself (the role graph re-reads its
   graph.json). One request per selector is in flight: a newer call aborts the older one
   (its promise rejects with an AbortError). */
(function () {
  "use strict";

  const pending = new Map();  // selector -> AbortController

  function regions(url, selector) {
    const target = url || window.location.href;
    const sel = selector || "[data-refresh]";
    if (pending.has(sel)) pending.get(sel).abort();
    const ctrl = new AbortController();
    pending.set(sel, ctrl);
    return fetch(target, { credentials: "same-origin", signal: ctrl.signal, headers: { Accept: "text/html" } })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then((text) => {
        const fresh = new DOMParser().parseFromString(text, "text/html");
        document.querySelectorAll(sel).forEach((el) => {
          const next = el.id ? fresh.getElementById(el.id) : null;
          if (next) el.replaceWith(document.adoptNode(next));
        });
        if (window.rolelensLocalTime) window.rolelensLocalTime.render(document);
        document.dispatchEvent(new CustomEvent("rolelens:data-refreshed", { detail: { url: target, selector: sel } }));
      })
      .finally(() => { if (pending.get(sel) === ctrl) pending.delete(sel); });
  }

  window.rolelensRefresh = { regions };
})();
