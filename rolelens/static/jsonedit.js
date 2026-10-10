/* RoleLens JSON editor: a dependency-free enhancement of a <textarea> for policy JSON.
   Line-number gutter (synced scrolling, the line of a syntax error is marked), Tab /
   Shift+Tab indent and outdent (selected lines too), Enter keeps the indentation and opens
   a block after "{" / "[", and Format (pretty-print). Edits go through
   execCommand("insertText") where available so the browser's undo keeps working.

   window.JsonEdit.attach(textarea, { onChange }) ->
     { getValue, setValue, setReadOnly, markError(line), format(), focus } */
(function () {
  "use strict";

  const INDENT = "  ";

  function attach(textarea, opts) {
    const options = opts || {};
    const wrap = document.createElement("div");
    wrap.className = "jsonedit";
    const gutter = document.createElement("div");
    gutter.className = "jsonedit-gutter";
    gutter.setAttribute("aria-hidden", "true");
    textarea.parentNode.insertBefore(wrap, textarea);
    wrap.append(gutter, textarea);
    textarea.classList.add("jsonedit-text");
    textarea.setAttribute("wrap", "off");
    let errorLine = 0;
    let lines = -1;

    function renderGutter(force) {
      const n = textarea.value.split("\n").length;
      if (n === lines && !force) return;
      lines = n;
      const frag = document.createDocumentFragment();
      for (let i = 1; i <= n; i += 1) {
        const s = document.createElement("span");
        s.textContent = String(i);
        if (i === errorLine) s.className = "err";
        frag.append(s);
      }
      gutter.replaceChildren(frag);
      gutter.scrollTop = textarea.scrollTop;
    }

    function changed() {
      renderGutter(false);
      if (options.onChange) options.onChange(textarea.value);
    }

    function insert(text) {
      textarea.focus();
      let ok = false;
      try { ok = document.execCommand("insertText", false, text); } catch (e) { ok = false; }
      if (!ok) {
        textarea.setRangeText(text, textarea.selectionStart, textarea.selectionEnd, "end");
        textarea.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }

    function lineStart(pos) { return textarea.value.lastIndexOf("\n", pos - 1) + 1; }

    function reindent(outdent) {
      const v = textarea.value;
      const start = lineStart(textarea.selectionStart);
      let end = textarea.selectionEnd;
      if (end > start && v[end - 1] === "\n") end -= 1;
      const endLine = v.indexOf("\n", end);
      const stop = endLine === -1 ? v.length : endLine;
      const block = v.slice(start, stop);
      const next = block.split("\n").map((l) => (
        outdent ? l.replace(/^ {1,2}/, "") : INDENT + l
      )).join("\n");
      textarea.setSelectionRange(start, stop);
      insert(next);
      textarea.setSelectionRange(start, start + next.length);
    }

    textarea.addEventListener("keydown", (evt) => {
      if (textarea.readOnly) return;
      if (evt.key === "Tab" && !evt.ctrlKey && !evt.metaKey && !evt.altKey) {
        evt.preventDefault();
        const multi = textarea.value.slice(textarea.selectionStart, textarea.selectionEnd).includes("\n");
        if (evt.shiftKey || multi) reindent(evt.shiftKey);
        else insert(INDENT);
      } else if (evt.key === "Enter" && !evt.shiftKey && !evt.ctrlKey && !evt.metaKey) {
        evt.preventDefault();
        const v = textarea.value;
        const pos = textarea.selectionStart;
        const current = v.slice(lineStart(pos), pos);
        const indent = (current.match(/^\s*/) || [""])[0];
        const before = v.slice(0, pos).trimEnd().slice(-1);
        const after = v.slice(textarea.selectionEnd).trimStart().charAt(0);
        if (before === "{" || before === "[") {
          if ((before === "{" && after === "}") || (before === "[" && after === "]")) {
            insert("\n" + indent + INDENT + "\n" + indent);
            const caret = pos + 1 + indent.length + INDENT.length;
            textarea.setSelectionRange(caret, caret);
          } else {
            insert("\n" + indent + INDENT);
          }
        } else {
          insert("\n" + indent);
        }
      }
    });
    textarea.addEventListener("input", changed);
    textarea.addEventListener("scroll", () => { gutter.scrollTop = textarea.scrollTop; });

    renderGutter(true);
    return {
      getValue: () => textarea.value,
      setValue(text) {
        textarea.value = text;
        textarea.scrollTop = 0;
        errorLine = 0;
        renderGutter(true);
      },
      setReadOnly(ro) {
        textarea.readOnly = Boolean(ro);
        wrap.classList.toggle("readonly", Boolean(ro));
      },
      markError(line) {
        errorLine = line || 0;
        renderGutter(true);
      },
      format() {
        try {
          const pretty = JSON.stringify(JSON.parse(textarea.value), null, 2);
          textarea.select();
          insert(pretty);
          return true;
        } catch (e) {
          return false;
        }
      },
      focus: () => textarea.focus(),
    };
  }

  window.JsonEdit = { attach };
})();
