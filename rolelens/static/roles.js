/* Column filters of the Roles, Users and Policies pages. The filters are a GET form
   (form[data-filters], e.g. #role-filters; the inputs sit in the table header and join it
   with form="..."), filtered on the server so the page and "Export to Excel" (the .xlsx
   URL with the same query) always show the same rows. With JavaScript every change
   updates the URL and re-fetches only the regions named by the form's data-regions (row
   count / export link and the table body) in place (refresh.js); without it, "Apply
   filters" submits the form. Listeners are delegated: the whole region is replaced after
   a collection. */
(function () {
  "use strict";

  const DEBOUNCE_MS = 250;
  let timer = null;

  function filterForm(el) {
    const form = el && el.form;
    return form && form.hasAttribute("data-filters") ? form : null;
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
    const regions = form.dataset.regions || "#roles-summary, #roles-tbody";
    window.rolelensRefresh.regions(url.href, regions).catch((err) => {
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
    if (!evt.target.hasAttribute || !evt.target.hasAttribute("data-filters")) return;
    evt.preventDefault();
    apply(evt.target);
  });
})();
