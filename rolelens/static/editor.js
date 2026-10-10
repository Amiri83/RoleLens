/* RoleLens draft editor: role settings, one JSON editor per document (trust policy and
   each permission policy), live validation, live graph and diff against the collected
   role. Every change is sent (debounced) to /drafts/<id>/preview, which parses and
   validates the draft and returns the issues, the graph and the diff; nothing is stored
   until Save. AWS managed policies are read-only (they can be removed, not edited).
   RoleLens never writes drafts to AWS. */
(function () {
  "use strict";

  const DEBOUNCE_MS = 400;
  const KIND_LABELS = { inline: "inline", managed: "customer managed", aws: "AWS managed", trust: "trust" };
  const NEW_POLICY = {
    Version: "2012-10-17",
    Statement: [{ Effect: "Allow", Action: ["s3:ListBucket"], Resource: ["arn:aws:s3:::bucket-a"] }],
  };

  const cfgEl = document.getElementById("editor-config");
  if (!cfgEl) return;
  const cfg = cfgEl.dataset;
  const data = JSON.parse(document.getElementById("draft-data").textContent);
  const $ = (id) => document.getElementById(id);
  const select = $("doc-select");
  const nameInput = $("doc-name");
  const kindLabel = $("doc-kind");
  const saveState = $("save-state");
  const issuesEl = $("issues");
  const diffEl = $("diff");
  const rawModel = $("raw-model");
  const form = $("save-form");

  const pretty = (doc) => JSON.stringify(doc ?? {}, null, 2);
  const model = data.model;
  const meta = {};
  document.querySelectorAll("#role-fields [data-field]").forEach((input) => {
    const field = input.dataset.field;
    input.value = model[field] ?? "";
    meta[field] = input.value;
    input.addEventListener("input", () => { meta[field] = input.value; changed(); });
  });
  const docs = [{ kind: "trust", name: "Trust policy", text: pretty(model.trust) }].concat(
    (model.policies || []).map((p) => ({
      kind: p.kind || "inline", name: p.name || "", arn: p.arn || "", path: p.path || "",
      text: p.document === null || p.document === undefined ? "" : pretty(p.document),
    }))
  );
  let current = 0;
  let dirty = false;
  let timer = null;
  let seq = 0;
  let lastIssues = [];

  const graph = window.RoleGraph.mount($("cy"));
  const editor = window.JsonEdit.attach($("doc-editor"), {
    onChange(text) { docs[current].text = text; changed(); },
  });

  function where(doc, index) {
    return doc.kind === "trust" ? "trust" : `policy:${doc.name || index - 1}`;
  }

  function serialize() {
    const session = Number(meta.max_session_duration);
    return {
      role_name: meta.role_name || "",
      path: meta.path || "",
      description: meta.description || "",
      max_session_duration: Number.isInteger(session) ? session : meta.max_session_duration,
      permissions_boundary: meta.permissions_boundary || "",
      trust: docs[0].text,
      policies: docs.slice(1).map((d) => ({
        name: d.name, kind: d.kind, arn: d.arn, path: d.path,
        document: d.kind === "aws" ? null : d.text,
      })),
    };
  }

  function issueCount(doc, index) {
    const w = where(doc, index);
    return lastIssues.filter((i) => i.where === w && i.level === "error").length;
  }

  function renderSelect() {
    select.replaceChildren(...docs.map((d, i) => {
      const o = document.createElement("option");
      o.value = String(i);
      const errors = issueCount(d, i);
      o.textContent = (i === 0 ? "Trust policy" : `${d.name || "(unnamed)"} · ${KIND_LABELS[d.kind] || d.kind}`) +
        (errors ? ` (${errors} error${errors === 1 ? "" : "s"})` : "");
      return o;
    }));
    select.value = String(current);
  }

  function show(index) {
    current = Math.max(0, Math.min(index, docs.length - 1));
    const doc = docs[current];
    editor.setValue(doc.kind === "aws" && !doc.text ? "// document not readable" : doc.text);
    editor.setReadOnly(doc.kind === "aws");
    $("doc-meta").hidden = current === 0;
    nameInput.value = doc.name;
    nameInput.readOnly = doc.kind !== "inline";
    kindLabel.textContent = current === 0 ? "" :
      KIND_LABELS[doc.kind] + (doc.kind === "aws" ? " (read-only; remove it to detach)" : "") +
      (doc.arn ? ` · ${doc.arn}` : "");
    $("doc-remove").disabled = current === 0;
    renderSelect();
    markErrorLine();
  }

  function markErrorLine() {
    const w = where(docs[current], current);
    const hit = lastIssues.find((i) => i.where === w && /line (\d+)/.test(i.message));
    editor.markError(hit ? Number(hit.message.match(/line (\d+)/)[1]) : 0);
  }

  function changed() {
    dirty = true;
    saveState.textContent = "unsaved changes";
    clearTimeout(timer);
    timer = setTimeout(preview, DEBOUNCE_MS);
  }

  function post(url, fields) {
    const body = new URLSearchParams({ csrf_token: cfg.csrf, ...fields });
    return fetch(url, { method: "POST", body, credentials: "same-origin" });
  }

  function preview() {
    const mine = ++seq;
    post(cfg.previewUrl, { model: JSON.stringify(serialize()) })
      .then((r) => r.json())
      .then((result) => { if (mine === seq) render(result); })
      .catch((err) => { saveState.textContent = `preview failed (${err.message})`; });
  }

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }

  function badge(text, cls) { return el("span", text, "badge " + cls); }

  function renderIssues(issues) {
    const errors = issues.filter((i) => i.level === "error").length;
    const warnings = issues.length - errors;
    const h = el("h2", "Validation ");
    h.append(errors ? badge(`${errors} error${errors === 1 ? "" : "s"}`, "err") : badge("valid", "ok"));
    if (warnings) h.append(" ", badge(`${warnings} warning${warnings === 1 ? "" : "s"}`, "warn"));
    const ul = el("ul", null, "issue-list");
    issues.forEach((i) => {
      const li = el("li", null, `issue ${i.level}`);
      li.dataset.where = i.where;
      li.append(badge(i.level, i.level === "error" ? "err" : "warn"), " ", el("b", i.where));
      if (i.path) li.append(" ", el("span", i.path, "mono"));
      li.append(": " + i.message);
      ul.append(li);
    });
    if (!issues.length) {
      ul.append(el("li", "No problems found (structure, Effect / Action / Resource, principals, " +
        "conditions and known action names).", "muted"));
    }
    issuesEl.replaceChildren(h, ul);
  }

  function renderDiff(diff) {
    if (!diff) {
      diffEl.replaceChildren(el("p", "Fix the JSON syntax errors to see the diff.", "muted"));
      return;
    }
    if (!diff.changed) {
      diffEl.replaceChildren(el("p", "No changes yet.", "muted"));
      return;
    }
    const s = diff.summary;
    const out = [el("p", `${s.changed} changed · ${s.added} added · ${s.removed} removed`, "muted small")];
    diff.sections.filter((x) => x.status !== "unchanged").forEach((sec) => {
      const det = el("details", null, "card diff-section");
      det.open = true;
      const sum = el("summary");
      sum.append(el("b", sec.title), " ",
        badge(sec.status, { added: "ok", removed: "err", changed: "warn" }[sec.status]));
      const pre = el("pre", null, "diff");
      sec.lines.forEach((l) => { pre.append(el("span", l.text, `d-${l.cls}`), "\n"); });
      det.append(sum, pre);
      out.push(det);
    });
    diffEl.replaceChildren(...out);
  }

  function render(result) {
    lastIssues = result.issues || [];
    renderIssues(lastIssues);
    renderSelect();
    markErrorLine();
    if (result.graph) graph.setData(result.graph);
    renderDiff(result.diff);
  }

  select.addEventListener("change", () => show(Number(select.value)));
  nameInput.addEventListener("input", () => {
    if (current === 0 || docs[current].kind !== "inline") return;
    docs[current].name = nameInput.value;
    renderSelect();
    changed();
  });
  $("doc-format").addEventListener("click", () => {
    if (docs[current].kind === "aws") return;
    if (!editor.format()) saveState.textContent = "cannot format: the JSON has a syntax error";
  });
  $("doc-add").addEventListener("click", () => {
    const taken = new Set(docs.map((d) => d.name));
    let name = "inline-policy";
    for (let n = 2; taken.has(name); n += 1) name = `inline-policy-${n}`;
    docs.push({ kind: "inline", name, arn: "", path: "", text: pretty(NEW_POLICY) });
    show(docs.length - 1);
    changed();
    nameInput.focus();
    nameInput.select();
  });
  $("doc-remove").addEventListener("click", () => {
    if (current === 0) return;
    const d = docs[current];
    const verb = d.kind === "inline" ? "Delete the inline policy" : "Detach the policy";
    if (!window.confirm(`${verb} ${d.name} from this draft?`)) return;
    docs.splice(current, 1);
    show(0);
    changed();
  });
  issuesEl.addEventListener("click", (evt) => {
    const li = evt.target.closest("li[data-where]");
    if (!li) return;
    const index = docs.findIndex((d, i) => where(d, i) === li.dataset.where);
    if (index >= 0) show(index);
  });

  form.addEventListener("submit", (evt) => {
    evt.preventDefault();
    const raw = JSON.stringify(serialize(), null, 2);
    rawModel.value = raw;
    saveState.textContent = "saving…";
    post(cfg.saveUrl, { model: raw, ajax: "1" })
      .then((r) => r.json())
      .then((result) => {
        render(result);
        if (result.saved) {
          dirty = false;
          saveState.textContent = result.ok ? "saved" : "saved (with validation errors)";
        } else {
          saveState.textContent = "not saved: fix the JSON syntax errors";
        }
      })
      .catch(() => form.submit());  // fall back to a plain form post
  });
  window.addEventListener("beforeunload", (evt) => {
    if (dirty) { evt.preventDefault(); evt.returnValue = ""; }
  });

  show(0);
  if (data.graph) graph.setData(data.graph);
  // Issues of the saved draft were rendered by the server; fetch them as data too.
  preview();
})();
