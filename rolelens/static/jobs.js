/* RoleLens background jobs: IAM collection.
   Forms marked data-job are posted with background=1; the server starts the job (one per
   account) and this script polls its state into the modal: current step, done / total,
   elapsed time, the live log tail, Cancel (while running) and Close. Close on a running
   job only hides the modal (a badge follows the job; when it ends, its result is shown).
   Closing a finished job that changed data (changes_data, e.g. a collection) re-fetches
   the page's data in place (refresh.js) instead of reloading the page. A reload
   re-attaches to the account's running job; a job started from this tab and finished
   while the page was reloading is shown once more with its result. Without JavaScript
   the forms post normally and the job runs to the end before the page is redrawn. */
(function () {
  "use strict";

  const POLL_MS = 1000;
  const WATCH_KEY = "rolelens-job-watch";  // sessionStorage: job started from this tab
  const modal = document.getElementById("job-modal");
  if (!modal) return;
  const $ = (id) => document.getElementById(id);
  const title = $("job-title");
  const stepEl = $("job-step");
  const bar = $("job-progress");
  const counts = $("job-counts");
  const elapsed = $("job-elapsed");
  const stateEl = $("job-state");
  const messages = $("job-messages");
  const logEl = $("job-log");
  const cancelBtn = $("job-cancel");
  const closeBtn = $("job-close");
  const badge = $("job-badge");
  const csrf = modal.dataset.csrf;
  let jobId = null;
  let lastJob = null;
  let refreshedFor = null;  // id of the finished job whose data was re-fetched
  let timer = null;
  let running = false;

  const url = (template, id) => template.replace("__ID__", encodeURIComponent(id));

  function fmtElapsed(s) {
    const m = Math.floor(s / 60);
    return m ? `${m}m ${s % 60}s` : `${s}s`;
  }

  function stateLabel(job) {
    if (job.running) return job.cancel_requested ? "cancelling (after the current step)" : "running";
    return { done: "finished", cancelled: "cancelled", error: "failed" }[job.state] || job.state;
  }

  function renderMessages(list) {
    messages.replaceChildren(...(list || []).map((m) => {
      const li = document.createElement("li");
      li.className = "flash " + (m.category || "");
      li.append(m.text);
      if (m.link_url) {
        const a = document.createElement("a");
        a.href = m.link_url;
        a.textContent = m.link_text || m.link_url;
        li.append(" ", a);
      }
      return li;
    }));
  }

  function render(job) {
    const wasRunning = running;
    running = Boolean(job.running);
    lastJob = job;
    title.textContent = job.label + (running ? "…" : "");
    stepEl.textContent = job.step || "";
    bar.max = Math.max(job.total || 0, 1);
    bar.value = Math.min(job.done || 0, bar.max);
    if (!job.total && running) bar.removeAttribute("value");  // indeterminate
    counts.textContent = job.total ? `${job.done} / ${job.total}` : "–";
    elapsed.textContent = fmtElapsed(job.elapsed || 0);
    stateEl.textContent = stateLabel(job);
    const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
    logEl.textContent = (job.log || []).join("\n");
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
    renderMessages(job.messages);
    cancelBtn.hidden = !running;
    cancelBtn.disabled = Boolean(job.cancel_requested);
    closeBtn.title = running ? "Keep it running in the background" : "";
    badge.textContent = running ? `${job.label}: ${job.step} (${job.done}/${job.total || "?"})` : "";
    if (!running) {
      badge.hidden = true;
      sessionStorage.removeItem(WATCH_KEY);
      if (wasRunning && modal.hidden) open();  // the job ran hidden: show its result
    }
  }

  function open() {
    modal.hidden = false;
    badge.hidden = true;
  }

  function close() {
    modal.hidden = true;
    badge.hidden = !running;
    const job = lastJob;
    if (running || !job || !job.changes_data || refreshedFor === job.id) return;
    refreshedFor = job.id;
    if (!window.rolelensRefresh) { window.location.reload(); return; }
    window.rolelensRefresh.regions().catch((err) => {
      if (err.name !== "AbortError") window.location.reload();  // e.g. the role is gone
    });
  }

  function poll() {
    clearTimeout(timer);
    if (!jobId) return;
    fetch(url(modal.dataset.statusUrl, jobId), { credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((d) => {
        render(d.job);
        if (d.job.running) timer = setTimeout(poll, POLL_MS);
      })
      .catch((err) => {
        stateEl.textContent = `lost contact with RoleLens (${err.message}); retrying…`;
        timer = setTimeout(poll, POLL_MS * 3);
      });
  }

  function attach(job, show) {
    jobId = job.id;
    render(job);
    if (show) open(); else close();
    if (job.running) timer = setTimeout(poll, POLL_MS);
  }

  function post(target, fields) {
    const body = new URLSearchParams({ csrf_token: csrf, ...fields });
    return fetch(target, { method: "POST", body: body, credentials: "same-origin" });
  }

  cancelBtn.addEventListener("click", () => {
    if (!jobId) return;
    cancelBtn.disabled = true;
    post(url(modal.dataset.cancelUrl, jobId), {}).then(poll).catch(poll);
  });
  closeBtn.addEventListener("click", close);
  badge.addEventListener("click", open);
  document.addEventListener("keydown", (evt) => {
    if (evt.key === "Escape" && !modal.hidden) close();
  });

  // Forms that start a job: posted in the background, followed in the modal.
  document.querySelectorAll("form[data-job]").forEach((form) => {
    form.addEventListener("submit", (evt) => {
      evt.preventDefault();
      const fields = Object.fromEntries(new FormData(form).entries());
      fields.background = "1";
      const buttons = form.querySelectorAll("button");
      buttons.forEach((b) => { b.disabled = true; });
      post(form.action, fields)
        .then((r) => r.json().then((d) => ({ status: r.status, d: d })))
        .then(({ status, d }) => {
          if (d.job) {
            if (d.ok) sessionStorage.setItem(WATCH_KEY, d.job.id);
            attach(d.job, true);
            if (!d.ok) {  // another job of this account is running: follow that one
              renderMessages([{ category: "error", text: d.error }]);
            }
            return;
          }
          jobId = null;
          lastJob = null;
          title.textContent = "Not started";
          stepEl.textContent = "";
          logEl.textContent = "";
          renderMessages([{ category: "error", text: d.error || `HTTP ${status}` }]);
          running = false;
          cancelBtn.hidden = true;
          open();
        })
        .catch((err) => {
          renderMessages([{ category: "error", text: `Could not start the job (${err.message}).` }]);
          open();
        })
        .finally(() => buttons.forEach((b) => { b.disabled = false; }));
    });
  });

  // Re-attach after a reload: the account's running job, or the result of the job this
  // tab started if it ended while the page was loading.
  fetch(modal.dataset.currentUrl, { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : { job: null }))
    .then((d) => {
      const job = d.job;
      if (!job) return;
      if (job.running) attach(job, true);
      else if (sessionStorage.getItem(WATCH_KEY) === job.id) attach(job, true);
    })
    .catch(() => {});
})();
