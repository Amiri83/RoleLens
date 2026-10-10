"""Role graph for cytoscape.js: principals -> role -> policies -> services -> actions -> resources.

Every edge carries the statement's effect (``Allow`` / ``Deny``) and whether it has a
``Condition``; nodes shared by Allow and Deny statements are ``mixed``. Action nodes are
per effect (``s3:GetObject`` allowed by one policy and denied by another shows twice), so
a Deny is never hidden behind an Allow. Each node carries a ``detail`` object (the
statements behind it) that the page shows when the node is clicked.
"""

from __future__ import annotations

from typing import Any

from . import iam_actions
from .policy import as_list, principal_label, split_action, statements, trust_principals

KIND_LABELS = {"inline": "inline", "managed": "customer managed", "aws": "AWS managed"}
# Above these, the rest is left out of the graph (and counted in "truncated").
MAX_ACTION_NODES = 400
MAX_RESOURCE_EDGES = 2000


def _effect_class(effects: set[str]) -> str:
    effects = effects & {"Allow", "Deny"}  # "Attached" (role -> policy) does not count
    if not effects:
        return "neutral"
    if effects == {"Deny"}:
        return "deny"
    if effects == {"Allow"}:
        return "allow"
    return "mixed"


def short_resource(res: str) -> str:
    """``s3:::bucket-a/*`` for ``arn:aws:s3:::bucket-a/*`` (the full ARN stays in the detail)."""
    if res.startswith("arn:"):
        parts = res.split(":", 2)
        return parts[2] if len(parts) == 3 else res
    return res


class _Builder:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.effects: dict[str, set[str]] = {}
        self.truncated = 0

    def node(self, nid: str, label: str, ntype: str, **data: Any) -> dict[str, Any]:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "label": label, "type": ntype, "detail": {}, **data}
        return self.nodes[nid]

    def edge(
        self, source: str, target: str, effect: str, conditional: bool, label: str = ""
    ) -> None:
        eid = f"{source}->{target}#{effect}"
        e = self.edges.get(eid)
        if e is None:
            self.edges[eid] = {
                "id": eid,
                "source": source,
                "target": target,
                "effect": effect,
                "conditional": conditional,
                "label": label,
            }
        else:
            # Unconditional wins: one statement without a Condition is enough.
            e["conditional"] = e["conditional"] and conditional
        for nid in (source, target):
            self.effects.setdefault(nid, set()).add(effect)

    def elements(self) -> list[dict[str, Any]]:
        out = []
        for nid in sorted(self.nodes):
            data = self.nodes[nid]
            if data["type"] not in ("role", "action"):
                data["effect"] = _effect_class(self.effects.get(nid, set()))
            classes = f"{data['type']} {data['effect']}"
            out.append({"group": "nodes", "data": data, "classes": classes})
        for eid in sorted(self.edges):
            e = self.edges[eid]
            cls = e["effect"].lower() + (" conditional" if e["conditional"] else "")
            out.append({"group": "edges", "data": e, "classes": cls})
        return out


def build_graph(model: dict[str, Any]) -> dict[str, Any]:
    """``{"elements": [...], "stats": {...}}`` for a role model (see :mod:`rolelens.queries`)."""
    b = _Builder()
    role = b.node(
        "role",
        model.get("role_name", ""),
        "role",
        effect="role",
        detail={
            "kind": "role",
            "name": model.get("role_name", ""),
            "path": model.get("path", "/"),
            "arn": model.get("arn", ""),
            "description": model.get("description", ""),
            "max_session_duration": model.get("max_session_duration", 3600),
            "permissions_boundary": model.get("permissions_boundary", ""),
            "last_used_at": model.get("last_used_at", ""),
        },
    )

    for p in trust_principals(model.get("trust")):
        pid = f"principal:{p['type']}:{p['id']}"
        label = principal_label(p["type"], p["id"])
        node = b.node(
            pid,
            ("NOT " if p["negated"] else "") + label,
            "principal",
            detail={"kind": "principal", "type": p["type"], "id": p["id"], "statements": []},
        )
        node["detail"]["statements"].append(
            {
                "sid": p["sid"],
                "effect": p["effect"],
                "negated": p["negated"],
                "actions": p["actions"],
                "condition": p["conditions"],
            }
        )
        actions = ", ".join(a.removeprefix("sts:") for a in p["actions"])
        b.edge(pid, role["id"], p["effect"], bool(p["conditions"]), actions)

    action_nodes = 0
    resource_edges = 0
    for pol in model.get("policies") or []:
        kind = pol.get("kind", "inline")
        pid = f"policy:{kind}:{pol.get('name', '')}"
        sts = statements(pol.get("document"))
        b.node(
            pid,
            pol.get("name", ""),
            "policy",
            detail={
                "kind": "policy",
                "policy_kind": KIND_LABELS.get(kind, kind),
                "name": pol.get("name", ""),
                "arn": pol.get("arn", ""),
                "statements": len(sts),
                "document_missing": pol.get("document") is None,
            },
        )
        b.edge(role["id"], pid, "Attached", False)
        for i, st in enumerate(sts):
            effect = st.get("Effect", "Allow")
            effect = effect if effect in ("Allow", "Deny") else "Allow"
            conditional = bool(st.get("Condition"))
            negated_actions = "NotAction" in st
            raw_actions = as_list(st.get("NotAction" if negated_actions else "Action"))
            negated_res = "NotResource" in st
            raw_res = as_list(st.get("NotResource" if negated_res else "Resource"))
            resources = [str(r) for r in raw_res]
            ref = {
                "policy": pol.get("name", ""),
                "sid": st.get("Sid", "") or f"#{i}",
                "effect": effect,
                "condition": st.get("Condition") or {},
            }
            for action in (str(a) for a in raw_actions):
                service, name = split_action(action)
                svc_id = f"service:{service or '?'}"
                b.node(
                    svc_id,
                    "all services" if service == "*" else service or "?",
                    "service",
                    detail={"kind": "service", "service": service},
                )
                b.edge(pid, svc_id, effect, conditional)
                prefix = "not" if negated_actions else ""
                aid = f"{prefix}action:{effect}:{action.lower()}"
                if aid not in b.nodes:
                    if action_nodes >= MAX_ACTION_NODES:
                        b.truncated += 1
                        continue
                    action_nodes += 1
                    expands = (
                        iam_actions.matching_actions(service, name)
                        if ("*" in name or "?" in name) and service not in ("", "*")
                        else []
                    )
                    b.node(
                        aid,
                        ("NOT " if negated_actions else "") + action,
                        "action",
                        effect=effect.lower(),
                        detail={
                            "kind": "action",
                            "action": action,
                            "effect": effect,
                            "negated": negated_actions,
                            "matches": expands,
                            "statements": [],
                        },
                    )
                b.nodes[aid]["detail"]["statements"].append({**ref, "resources": resources})
                b.edge(svc_id, aid, effect, conditional)
                for res in resources:
                    if resource_edges >= MAX_RESOURCE_EDGES:
                        b.truncated += 1
                        break
                    rid = f"{'not' if negated_res else ''}resource:{res}"
                    rnode = b.node(
                        rid,
                        ("NOT " if negated_res else "") + short_resource(res),
                        "resource",
                        detail={"kind": "resource", "resource": res, "statements": []},
                    )
                    entry = {**ref, "action": action}
                    if entry not in rnode["detail"]["statements"]:
                        rnode["detail"]["statements"].append(entry)
                    b.edge(aid, rid, effect, conditional)
                    resource_edges += 1

    elements = b.elements()
    counts: dict[str, int] = {}
    for el in elements:
        if el["group"] == "nodes":
            counts[el["data"]["type"]] = counts.get(el["data"]["type"], 0) + 1
    return {
        "elements": elements,
        "stats": {
            "principals": counts.get("principal", 0),
            "policies": counts.get("policy", 0),
            "services": counts.get("service", 0),
            "actions": counts.get("action", 0),
            "resources": counts.get("resource", 0),
            "deny_edges": sum(1 for e in b.edges.values() if e["effect"] == "Deny"),
            "truncated": b.truncated,
        },
    }
