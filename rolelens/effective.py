"""Effective permissions of a role: the union of all its policies, wildcards expanded.

Every ``Allow`` statement of every policy (inline, customer managed and AWS managed) is
expanded into **grants** ``(action, resource, condition)``:

* an action is a catalog action (``s3:GetObject``, see :mod:`rolelens.iam_actions`);
  a wildcard (``s3:Get*``, ``*``) expands to every catalog action it matches **and** is
  kept itself, because it also grants actions the catalog does not list; an action of a
  service outside the catalog is kept as written (service lower-cased);
* ``NotAction`` grants every catalog action it does not exclude, plus ``*``;
* ``NotResource`` becomes the resource ``NotResource:<value>``;
* ``condition`` is the statement's ``Condition`` as canonical JSON (``""`` without one).

An unconditional ``Deny`` on ``Resource: "*"`` removes the actions it names. Narrower
Deny statements and permissions boundaries are not evaluated, so the result can
overstate (never understate) what the policies allow.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, NamedTuple

from . import iam_actions
from .policy import as_list, statements


class Grant(NamedTuple):
    action: str
    resource: str
    condition: str  # canonical JSON of the statement's Condition, "" if none


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def normalise_action(action: str) -> str:
    """``s3:GetObject`` with catalog casing; other actions with a lower-case service."""
    if action == "*":
        return "*"
    service, sep, name = action.partition(":")
    if not sep:
        return action
    service = service.lower()
    if not any(c in action for c in "*?"):
        known = iam_actions.matching_actions(service, name)
        if known:
            return f"{service}:{known[0]}"
    return f"{service}:{name}"


def expand(patterns: Iterable[str]) -> set[str]:
    """Actions granted by ``Action`` values (catalog matches + non-exact patterns)."""
    out: set[str] = set()
    for raw in patterns:
        pattern = str(raw)
        found, more = iam_actions.expand_action(pattern)
        out |= found
        if more:
            out.add(normalise_action(pattern))
    return out


def expand_not_action(patterns: Iterable[str]) -> set[str]:
    """Actions granted by ``NotAction`` values: catalog actions they miss, plus ``*``."""
    excluded = expand(patterns)
    return {a for a in iam_actions.all_actions() if a not in excluded} | {"*"}


def statement_actions(st: dict[str, Any]) -> set[str]:
    if "NotAction" in st:
        return expand_not_action(as_list(st.get("NotAction")))
    return expand(as_list(st.get("Action")))


def statement_resources(st: dict[str, Any]) -> list[str]:
    if "NotResource" in st:
        return [f"NotResource:{r}" for r in as_list(st.get("NotResource"))]
    return [str(r) for r in as_list(st.get("Resource"))] or ["*"]


def effective_permissions(model: dict[str, Any]) -> dict[Grant, list[str]]:
    """``{grant: [policy names]}`` of a role model (see :mod:`rolelens.queries`)."""
    allowed: dict[Grant, set[str]] = {}
    denied: set[str] = set()
    for p in model.get("policies") or []:
        name = p.get("name", "")
        for st in statements(p.get("document")):
            effect = st.get("Effect")
            cond = canonical(st["Condition"]) if st.get("Condition") else ""
            if effect == "Deny":
                if not cond and "Action" in st and "*" in statement_resources(st):
                    denied |= expand(as_list(st.get("Action")))
                continue
            if effect != "Allow":
                continue
            resources = statement_resources(st)
            for action in statement_actions(st):
                for res in resources:
                    allowed.setdefault(Grant(action, res, cond), set()).add(name)
    if "*" in denied:
        return {}
    return {g: sorted(names) for g, names in sorted(allowed.items()) if g.action not in denied}


def action_set(grants: Iterable[Grant]) -> frozenset[str]:
    return frozenset(g.action for g in grants)


def by_service(actions: Iterable[str]) -> dict[str, list[str]]:
    """``{service: [actions]}``; ``*`` is listed under the service ``*``."""
    out: dict[str, list[str]] = {}
    for a in sorted(actions):
        service = "*" if a == "*" else a.partition(":")[0]
        out.setdefault(service, []).append(a)
    return out
