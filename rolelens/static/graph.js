/* RoleLens role graph (cytoscape.js + dagre, both vendored).
   principals -> role -> policies -> services -> actions -> resources, as built by
   rolelens/graph.py. Allow edges are green, Deny edges red and thicker, statements with a
   Condition are dashed; nodes reached by both Allow and Deny are "mixed". Grid is the
   default layout; the choice is remembered in localStorage. Clicking a node shows its
   detail (the statements behind it) in the side panel.

   window.RoleGraph.mount(container) -> { setData(graph), cy } */
(function () {
  "use strict";

  const LAYOUT_KEY = "rolelens-layout";
  const RANK = { principal: 0, role: 1, policy: 2, service: 3, action: 4, resource: 5 };
  const COLORS = {
    allow: "#2f8f4e", deny: "#c0392b", mixed: "#c27c0e", neutral: "#8a94a3",
    role: "#2457c5", line: "#5b6573",
  };

  // Node size from its label (approximate text metrics; labels wrap at 150px).
  const textWidth = (n) => String(n.data("label") || "").length * 6.4;
  const nodeWidth = (n) => Math.max(36, Math.min(150, textWidth(n))) + 8;
  const nodeHeight = (n) => 14 * Math.max(1, Math.ceil(textWidth(n) / 150)) + 8;

  const STYLE = [
    { selector: "node", style: {
      "label": "data(label)", "font-size": 11, "color": "#1f2933",
      "text-valign": "center", "text-halign": "center", "text-wrap": "wrap", "text-max-width": 150,
      "width": nodeWidth, "height": nodeHeight, "padding": "8px", "shape": "round-rectangle",
      "background-color": "#fff", "border-width": 2, "border-color": COLORS.line,
    } },
    { selector: "node.principal", style: { "background-color": "#e8edf3", "shape": "round-rectangle" } },
    { selector: "node.role", style: {
      "background-color": COLORS.role, "color": "#fff", "font-weight": 700, "font-size": 13,
      "border-color": "#1b3f8f", "padding": "12px",
    } },
    { selector: "node.policy", style: { "shape": "rectangle", "border-color": "#8c4fff", "background-color": "#f7f3ff" } },
    { selector: "node.service", style: { "shape": "ellipse", "background-color": "#f6f7f9", "border-color": COLORS.role } },
    { selector: "node.action", style: { "shape": "round-tag", "font-size": 10 } },
    { selector: "node.action.allow", style: { "background-color": "#e1f3e6", "border-color": COLORS.allow } },
    { selector: "node.action.deny", style: { "background-color": "#fbe4e1", "border-color": COLORS.deny, "border-width": 3 } },
    { selector: "node.resource", style: { "shape": "cut-rectangle", "border-color": "#7aa116", "font-size": 10 } },
    { selector: "node.deny", style: { "border-color": COLORS.deny, "border-width": 3 } },
    { selector: "node.mixed", style: { "border-color": COLORS.mixed, "border-style": "dashed", "border-width": 3 } },
    { selector: "node:selected", style: { "border-color": "#1f2933", "border-width": 4, "overlay-opacity": 0 } },
    { selector: "edge", style: {
      "width": 1.6, "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.8,
      "line-color": COLORS.neutral, "target-arrow-color": COLORS.neutral,
      "label": "data(label)", "font-size": 9, "text-rotation": "autorotate", "color": "#535e6b",
      "text-background-color": "#fff", "text-background-opacity": 0.8,
    } },
    { selector: "edge.allow", style: { "line-color": COLORS.allow, "target-arrow-color": COLORS.allow } },
    { selector: "edge.deny", style: {
      "line-color": COLORS.deny, "target-arrow-color": COLORS.deny, "width": 3, "target-arrow-shape": "tee",
    } },
    { selector: "edge.conditional", style: { "line-style": "dashed" } },
    { selector: ".faded", style: { "opacity": 0.15 } },
  ];

  function rank(n) { return RANK[n.data("type")] ?? 9; }

  function byRank(a, b) {
    return rank(a) - rank(b) || String(a.data("label")).localeCompare(String(b.data("label")));
  }

  function layoutOptions(cy, name) {
    const common = { fit: true, padding: 30, animate: false };
    switch (name) {
      case "breadthfirst": {
        const roots = cy.nodes(".principal");
        return { ...common, name, directed: true, spacingFactor: 1.1,
                 roots: roots.length ? roots : cy.nodes(".role") };
      }
      case "concentric":
        return { ...common, name, concentric: (n) => 10 - Math.abs(rank(n) - 1) * 2, levelWidth: () => 2,
                 minNodeSpacing: 20 };
      case "circle":
        return { ...common, name, sort: byRank };
      default: {
        const n = cy.nodes().length;
        return { ...common, name: "grid", sort: byRank, avoidOverlap: true, avoidOverlapPadding: 16,
                 cols: Math.max(1, Math.ceil(Math.sqrt(n * 1.6))) };
      }
    }
  }

  // Left-to-right dagre layout, applied through cytoscape's preset layout.
  function dagreLayout(cy) {
    const g = new dagre.graphlib.Graph({ multigraph: true });
    g.setGraph({ rankdir: "LR", nodesep: 14, ranksep: 70, marginx: 10, marginy: 10 });
    g.setDefaultEdgeLabel(() => ({}));
    cy.nodes().forEach((n) => {
      const dim = n.layoutDimensions({ nodeDimensionsIncludeLabels: true });
      g.setNode(n.id(), { width: dim.w, height: dim.h });
    });
    cy.edges().forEach((e) => g.setEdge(e.source().id(), e.target().id(), {}, e.id()));
    dagre.layout(g);
    cy.layout({
      name: "preset", fit: true, padding: 30, animate: false,
      positions: (n) => { const p = g.node(n.id()); return { x: p.x, y: p.y }; },
    }).run();
  }

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }

  function renderDetail(panel, node) {
    panel.replaceChildren();
    if (!node) {
      panel.append(el("h2", "Detail"), el("p", "Click a node to see the statements behind it.", "muted"));
      return;
    }
    const d = node.data();
    const detail = d.detail || {};
    const head = el("h2", d.label);
    head.append(" ", el("span", d.type + (d.effect && d.effect !== "role" ? " · " + d.effect : ""), "badge"));
    panel.append(head);
    const dl = el("dl");
    Object.entries(detail).forEach(([k, v]) => {
      if (k === "kind" || k === "statements" || v === "" || v === null || (Array.isArray(v) && !v.length)) return;
      dl.append(el("dt", k.replace(/_/g, " ")));
      dl.append(el("dd", Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)));
    });
    panel.append(dl);
    if (Array.isArray(detail.statements) && detail.statements.length) {
      panel.append(el("h3", `Statements (${detail.statements.length})`));
      panel.append(el("pre", JSON.stringify(detail.statements, null, 2), "json small"));
    }
  }

  function mount(container) {
    const panel = document.getElementById("node-detail");
    const select = document.getElementById("layout");
    const stats = document.getElementById("graph-stats");
    const fitBtn = document.getElementById("graph-fit");
    if (typeof window.cytoscape !== "function") {
      container.textContent = "The graph library (static/vendor/cytoscape.min.js) is missing.";
      return { setData() {}, cy: null };
    }
    const cy = window.cytoscape({ container, style: STYLE, wheelSensitivity: 0.3, minZoom: 0.1, maxZoom: 3 });
    const saved = localStorage.getItem(LAYOUT_KEY);
    if (select && saved && [...select.options].some((o) => o.value === saved)) select.value = saved;

    function run() {
      const name = select ? select.value : "grid";
      if (name === "dagre" && window.dagre) dagreLayout(cy);
      else cy.layout(layoutOptions(cy, name)).run();
    }

    function highlight(node) {
      cy.elements().removeClass("faded");
      if (!node) return;
      const keep = node.closedNeighborhood().union(node.successors()).union(node.predecessors());
      cy.elements().not(keep).addClass("faded");
    }

    cy.on("tap", "node", (evt) => { renderDetail(panel, evt.target); highlight(evt.target); });
    cy.on("tap", (evt) => { if (evt.target === cy) { renderDetail(panel, null); highlight(null); } });
    if (select) select.addEventListener("change", () => { localStorage.setItem(LAYOUT_KEY, select.value); run(); });
    if (fitBtn) fitBtn.addEventListener("click", () => cy.fit(undefined, 30));

    return {
      cy,
      setData(graph) {
        const selected = cy.$("node:selected").map((n) => n.id());
        cy.batch(() => {
          cy.elements().remove();
          cy.add(graph.elements || []);
        });
        run();
        const again = selected.length ? cy.getElementById(selected[0]) : null;
        if (again && again.nonempty()) { again.select(); renderDetail(panel, again); highlight(again); }
        else { renderDetail(panel, null); }
        if (stats && graph.stats) {
          const s = graph.stats;
          stats.textContent = `${s.principals} principals · ${s.policies} policies · ${s.services} services · ` +
            `${s.actions} actions · ${s.resources} resources · ${s.deny_edges} deny edges` +
            (s.truncated ? ` · ${s.truncated} left out (too large)` : "");
        }
      },
    };
  }

  window.RoleGraph = { mount };
})();
