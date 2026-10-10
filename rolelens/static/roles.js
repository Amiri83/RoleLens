/* Roles page column filters. The filters are a GET form (#role-filters; the inputs sit in
   the table header and join it with form="role-filters"), filtered on the server so the
   page and "Export to Excel" (/roles.xlsx with the same query) always show the same rows.
   With JavaScript every change updates the URL and re-fetches only the row count / export
   link and the table body in place (refresh.js); without it, "Apply filters" submits the
   form. Listeners are delegated: the whole region is replaced after a collection. */
(function () {
  "use strict";

  const DEBOUNCE_MS = 250;
  const FORM_ID = "role-filters";
  let timer = null;

  function filterForm(el) {
    return el && el.form && el.form.id === FORM_ID ? el.form : null;
  }

  function apply(form) {
    clearTimeout(timer);
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => {
      if (String(value).trim()) params.set(key, String(value).trim());
    });
    const qs = params.toString();
    const url = new URL(form.getAttribute("action"), window.location.href);
    url.search = qs;
    window.history.replaceState(null, "", url);
    if (!window.rolelensRefresh) { window.location.assign(url); return; }
    window.rolelensRefresh.regions(url.href, "#roles-summary, #roles-tbody").catch((err) => {
      if (err.name !== "AbortError") window.location.assign(url);
    });
  }

  document.addEventListener("input", (evt) => {
    const form = filterForm(evt.target);
    if (!form || evt.target.tagName === "SELECT") return;
    clearTimeout(timer);
    timer = setTimeout(() => apply(form), DEBOUNCE_MS);
  });
  document.addEventListener("change", (evt) => {
    const form = filterForm(evt.target);
    if (form && evt.target.tagName === "SELECT") apply(form);
  });
  document.addEventListener("submit", (evt) => {
    if (evt.target.id !== FORM_ID) return;
    evt.preventDefault();
    apply(evt.target);
  });
})();
