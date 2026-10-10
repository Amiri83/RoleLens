"""Consolidation recommendations: duplicate and overlapping roles, and a merged role.

* **Duplicates**: roles with the same effective grants (:mod:`rolelens.effective`) and
  the same trust policy (compared as canonical JSON).
* **Overlaps**: pairs whose effective *action* sets have a Jaccard similarity
  ``|A ∩ B| / |A ∪ B|`` of at least the threshold (default :data:`DEFAULT_THRESHOLD`,
  configurable in Settings); each pair says whether one is a subset of the other.

Service-linked roles (AWS owns them) and roles without permissions are left out.
:func:`merged_model` builds a role model that holds both roles' permissions, ready for
the draft editor and the JSON / Terraform export of :mod:`rolelens.export`.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .effective import Grant, by_service, canonical
from .policy import statements

DEFAULT_THRESHOLD = 0.8
MIN_THRESHOLD, MAX_THRESHOLD = 0.5, 1.0
MAX_OVERLAPS = 200
MAX_ROLE_NAME = 64
MERGED_POLICY = "merged-inline"


def parse_threshold(value: Any, default: float = DEFAULT_THRESHOLD) -> float:
    """A threshold in [MIN_THRESHOLD, MAX_THRESHOLD]; anything else gives ``default``."""
    try:
        t = float(value)
    except (TypeError, ValueError):
        return default
    if t != t or not MIN_THRESHOLD <= t <= MAX_THRESHOLD:  # NaN or out of range
        return default
    return round(t, 2)


@dataclass(frozen=True)
class RolePerms:
    name: str
    grants: frozenset[Grant]
    actions: frozenset[str]
    trust: str  # canonical JSON


def jaccard(a: frozenset[str] | set[str], b: frozenset[str] | set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def relation(a: frozenset[str], b: frozenset[str]) -> str:
    """How ``a`` relates to ``b``: equal, subset, superset or overlap."""
    if a == b:
        return "equal"
    if a < b:
        return "subset"
    if a > b:
        return "superset"
    return "overlap"


def duplicates(roles: Iterable[RolePerms]) -> list[list[str]]:
    """Groups (2+ roles, sorted) with identical grants and trust policy."""
    groups: dict[tuple[frozenset[Grant], str], list[str]] = {}
    for r in roles:
        if r.grants:
            groups.setdefault((r.grants, r.trust), []).append(r.name)
    found = [sorted(names, key=str.lower) for names in groups.values() if len(names) > 1]
    return sorted(found, key=lambda g: (-len(g), g[0].lower()))


def overlaps(
    roles: Iterable[RolePerms], threshold: float = DEFAULT_THRESHOLD, limit: int = MAX_OVERLAPS
) -> list[dict[str, Any]]:
    """Pairs with action-set Jaccard >= ``threshold`` (duplicates excluded), most similar
    first. ``a`` / ``b`` are in name order; ``relation`` says how a relates to b."""
    items = sorted((r for r in roles if r.actions), key=lambda r: len(r.actions))
    out = []
    for i, a in enumerate(items):
        for b in items[i + 1 :]:
            # |A ∩ B| / |A ∪ B| <= |A| / |B| for |A| <= |B|: prune hopeless pairs.
            if len(a.actions) < threshold * len(b.actions):
                break
            if a.grants == b.grants and a.trust == b.trust:
                continue  # a duplicate, listed separately
            score = jaccard(a.actions, b.actions)
            if score < threshold:
                continue
            x, y = sorted((a, b), key=lambda r: r.name.lower())
            out.append(
                {
                    "a": x.name,
                    "b": y.name,
                    "jaccard": round(score, 3),
                    "relation": relation(x.actions, y.actions),
                    "same_trust": x.trust == y.trust,
                    "common": len(x.actions & y.actions),
                    "only_a": len(x.actions - y.actions),
                    "only_b": len(y.actions - x.actions),
                }
            )
    out.sort(key=lambda o: (-o["jaccard"], o["a"].lower(), o["b"].lower()))
    return out[:limit]


def compare(a: RolePerms, b: RolePerms) -> dict[str, Any]:
    """Side-by-side action diff, grouped by service."""
    services = sorted(by_service(a.actions | b.actions))
    rows = []
    for svc in services:
        in_a = set(by_service(a.actions).get(svc, []))
        in_b = set(by_service(b.actions).get(svc, []))
        rows.append(
            {
                "service": svc,
                "only_a": sorted(in_a - in_b),
                "common": sorted(in_a & in_b),
                "only_b": sorted(in_b - in_a),
            }
        )
    return {
        "jaccard": round(jaccard(a.actions, b.actions), 3),
        "relation": relation(a.actions, b.actions),
        "same_trust": a.trust == b.trust,
        "same_grants": a.grants == b.grants,
        "services": rows,
        "counts": {
            "only_a": len(a.actions - b.actions),
            "common": len(a.actions & b.actions),
            "only_b": len(b.actions - a.actions),
        },
    }


# -- merged role ---------------------------------------------------------------------


def _without_sid(st: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in st.items() if k != "Sid"}


def _union_statements(docs: Iterable[Any]) -> list[dict[str, Any]]:
    """Statements of ``docs``, duplicates (ignoring Sid) dropped, order kept."""
    seen: set[str] = set()
    out = []
    for doc in docs:
        for st in statements(doc):
            key = canonical(_without_sid(st))
            if key not in seen:
                seen.add(key)
                out.append(copy.deepcopy(st))
    return out


def _as_sorted_list(value: Any) -> list[str]:
    return sorted({str(v) for v in (value if isinstance(value, list) else [value])})


def merge_statements(sts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Statements with the same Effect, Resource and Condition (and only those keys plus
    Action / Sid) are combined into one with the union of their actions."""
    out: list[dict[str, Any]] = []
    index: dict[str, dict[str, Any]] = {}
    for st in sts:
        simple = set(st) <= {"Sid", "Effect", "Action", "Resource", "Condition"}
        if not simple or "Action" not in st or "Resource" not in st:
            out.append(st)
            continue
        key = canonical(
            [st.get("Effect"), _as_sorted_list(st["Resource"]), st.get("Condition") or {}]
        )
        target = index.get(key)
        if target is None:
            target = copy.deepcopy(st)
            target["Action"] = _as_sorted_list(st["Action"])
            index[key] = target
            out.append(target)
        else:
            target["Action"] = sorted(set(target["Action"]) | set(_as_sorted_list(st["Action"])))
    sids: set[str] = set()
    for st in out:
        if isinstance(st.get("Action"), list) and len(st["Action"]) == 1:
            st["Action"] = st["Action"][0]
        sid = st.get("Sid")
        if sid:
            n, unique = 2, sid
            while unique in sids:
                unique, n = f"{sid}{n}", n + 1
            st["Sid"] = unique
            sids.add(unique)
    return out


def merged_model(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """A role model holding the permissions of role models ``a`` and ``b``.

    Managed policies (customer and AWS) of both roles stay attached (union by ARN); the
    statements of all inline policies go into one inline policy :data:`MERGED_POLICY`
    (duplicates dropped, compatible statements combined). The trust policy is ``a``'s
    when both are equal, else the union of their statements.
    """
    if canonical(a.get("trust") or {}) == canonical(b.get("trust") or {}):
        trust = copy.deepcopy(a.get("trust") or {})
    else:
        trust = {
            "Version": "2012-10-17",
            "Statement": _union_statements([a.get("trust"), b.get("trust")]),
        }
    policies: list[dict[str, Any]] = []
    attached: set[str] = set()
    inline_docs = []
    for model in (a, b):
        for p in model.get("policies") or []:
            if p.get("kind") == "inline":
                inline_docs.append(p.get("document"))
                continue
            key = p.get("arn") or p.get("name", "")
            if key in attached:
                continue
            attached.add(key)
            policies.append(
                {
                    k: copy.deepcopy(p[k])
                    for k in ("name", "kind", "arn", "path", "document")
                    if k in p
                }
            )
    inline = merge_statements(_union_statements(inline_docs))
    if inline:
        policies.append(
            {
                "name": MERGED_POLICY,
                "kind": "inline",
                "document": {"Version": "2012-10-17", "Statement": inline},
            }
        )
    boundary_a, boundary_b = a.get("permissions_boundary", ""), b.get("permissions_boundary", "")
    return {
        "role_name": f"{a.get('role_name') or 'role'}-merged"[:MAX_ROLE_NAME],
        "path": a.get("path") or "/",
        "description": f"Merge of {a.get('role_name', '')} and {b.get('role_name', '')}"[:1000],
        "max_session_duration": max(
            int(a.get("max_session_duration") or 3600), int(b.get("max_session_duration") or 3600)
        ),
        "permissions_boundary": boundary_a if boundary_a == boundary_b else "",
        "trust": trust,
        "policies": policies,
    }
