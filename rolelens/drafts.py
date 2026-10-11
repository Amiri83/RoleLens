"""Local drafts of a role, user or managed policy: clone a collected one, edit it, diff it
against the original.

Drafts live in SQLite only; RoleLens never writes them to AWS. A draft keeps the
**original** model frozen at clone time (the diff baseline, even after the snapshot is
deleted) and the edited **model** (see :mod:`rolelens.queries` for the role and user
shapes). The model's ``entity`` says what it is:

* ``role`` (the default, no ``entity`` key): role settings, trust policy and policies;
* ``user``: ``user_name``, ``path``, ``permissions_boundary``, ``groups`` (names; the
  group policies are not part of the draft) and the user's own ``policies``. Access keys,
  passwords and MFA are never part of a draft;
* ``policy``: a standalone managed policy, ``name``, ``path``, ``description``, ``arn``
  (of the collected policy, for the import note) and ``document``.

AWS managed policies are read-only in a draft: they can be detached, never edited.
"""

from __future__ import annotations

import copy
import difflib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .policy import dumps
from .queries import policy_detail, role_model, user_model
from .validate import ERROR, Issue, parse_json

ROLE_FIELDS = ("role_name", "path", "description", "max_session_duration", "permissions_boundary")
USER_FIELDS = ("user_name", "path", "permissions_boundary")
MANAGED_FIELDS = ("name", "path", "description", "arn")
POLICY_FIELDS = ("name", "kind", "arn", "path", "document")
ENTITIES = ("role", "user", "policy")
# The settings of each kind of draft (the diff's first section).
FIELDS = {"role": ROLE_FIELDS, "user": (*USER_FIELDS, "groups"), "policy": MANAGED_FIELDS[:3]}
NAME_FIELDS = {"role": "role_name", "user": "user_name", "policy": "name"}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def entity_of(model: dict[str, Any]) -> str:
    entity = model.get("entity", "role")
    return entity if entity in ENTITIES else "role"


def display_name(model: dict[str, Any]) -> str:
    """The name of the role, user or policy a draft model describes."""
    return str(model.get(NAME_FIELDS[entity_of(model)], "") or "")


def _policies(model: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {k: copy.deepcopy(p[k]) for k in POLICY_FIELDS if k in p}
        for p in model.get("policies") or []
    ]


def editable(model: dict[str, Any]) -> dict[str, Any]:
    """Only the fields a draft keeps (drops ARNs of the role, last used, access keys, ...)."""
    entity = entity_of(model)
    if entity == "user":
        out: dict[str, Any] = {"entity": "user", **{k: model.get(k, "") for k in USER_FIELDS}}
        out["groups"] = [
            g if isinstance(g, str) else g.get("group_name", "") for g in model.get("groups") or []
        ]
        out["policies"] = _policies(model)
        return out
    if entity == "policy":
        out = {"entity": "policy", **{k: model.get(k, "") or "" for k in MANAGED_FIELDS}}
        out["path"] = out["path"] or "/"
        out["document"] = copy.deepcopy(model.get("document"))
        return out
    out = {k: model.get(k, "") for k in ROLE_FIELDS}
    out["max_session_duration"] = int(model.get("max_session_duration") or 3600)
    out["trust"] = copy.deepcopy(model.get("trust") or {})
    out["policies"] = _policies(model)
    return out


def clone(
    conn: sqlite3.Connection,
    account_ref: int | None,
    snap_id: int,
    name: str,
    entity: str = "role",
) -> int | None:
    """Create a draft from a collected role, user or managed policy (``name`` is the
    policy's ARN); returns its id (None if the snapshot has no such thing)."""
    if entity == "user":
        model = user_model(conn, snap_id, name)
    elif entity == "policy":
        model = policy_detail(conn, snap_id, name)
        if model is not None:
            if model["aws_managed"]:
                return None  # AWS managed policies cannot be edited
            model = {**model, "entity": "policy"}
    else:
        model = role_model(conn, snap_id, name)
    if model is None:
        return None
    original = editable(model)
    return create(conn, account_ref, snap_id, display_name(original), original, original)


def create(
    conn: sqlite3.Connection,
    account_ref: int | None,
    snap_id: int,
    source_role: str,
    original: dict[str, Any],
    model: dict[str, Any],
) -> int:
    """Store a draft whose diff baseline is ``original`` (e.g. a merge of two roles:
    the first role as original, the merged role as model); returns its id.
    ``source_role`` is the name of the role, user or policy it was cloned from."""
    now = _now()
    cur = conn.execute(
        "INSERT INTO drafts(account_ref, snapshot_id, source_role, original, model, created_at, "
        "updated_at, entity) VALUES(?,?,?,?,?,?,?,?)",
        (
            account_ref,
            snap_id,
            source_role,
            json.dumps(editable(original)),
            json.dumps(editable(model)),
            now,
            now,
            entity_of(original),
        ),
    )
    return int(cur.lastrowid or 0)


def _row(r: sqlite3.Row) -> dict[str, Any]:
    model = json.loads(r["model"])
    return {
        "id": r["id"],
        "account_ref": r["account_ref"],
        "snapshot_id": r["snapshot_id"],
        "entity": r["entity"] or entity_of(model),
        "name": display_name(model),
        "source_role": r["source_role"],
        "original": json.loads(r["original"]),
        "model": model,
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def get(conn: sqlite3.Connection, draft_id: int, account_ref: int | None) -> dict[str, Any] | None:
    r = conn.execute(
        "SELECT * FROM drafts WHERE id=? AND account_ref IS ?", (draft_id, account_ref)
    ).fetchone()
    return _row(r) if r else None


def list_drafts(conn: sqlite3.Connection, account_ref: int | None) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM drafts WHERE account_ref IS ? ORDER BY updated_at DESC, id DESC",
        (account_ref,),
    ).fetchall()
    return [_row(r) for r in rows]


def save(conn: sqlite3.Connection, draft_id: int, model: dict[str, Any]) -> None:
    conn.execute(
        "UPDATE drafts SET model=?, updated_at=? WHERE id=?",
        (json.dumps(model), _now(), draft_id),
    )


def delete(conn: sqlite3.Connection, draft_id: int, account_ref: int | None) -> bool:
    cur = conn.execute(
        "DELETE FROM drafts WHERE id=? AND account_ref IS ?", (draft_id, account_ref)
    )
    return cur.rowcount > 0


def parse_model(raw: str, original: dict[str, Any]) -> tuple[dict[str, Any] | None, list[Issue]]:
    """Read the editor's model (JSON). Documents may be objects or the editor's raw text;
    text is parsed here so syntax errors are reported per document with line / column.
    AWS managed policy documents are taken from the original (they are read-only)."""
    entity = entity_of(original)
    data, issues = parse_json(raw, entity)
    if issues:
        return None, issues
    if not isinstance(data, dict):
        return None, [Issue(ERROR, entity, "", "the draft must be a JSON object")]

    def document(value: Any, where: str) -> Any:
        if isinstance(value, str):
            doc, errs = parse_json(value, where)
            issues.extend(errs)
            return doc
        return value

    model: dict[str, Any]
    if entity == "policy":
        model = {"entity": "policy"}
        for k in MANAGED_FIELDS:
            value = data.get(k, original.get(k, ""))
            model[k] = value.strip() if isinstance(value, str) and k != "description" else value
        model["arn"] = original.get("arn", "")  # the collected policy, never edited
        model["document"] = document(data.get("document"), f"policy:{model['name'] or 0}")
        return _parsed(model, issues)
    if entity == "user":
        model = {"entity": "user"}
        for k in USER_FIELDS:
            value = data.get(k, original.get(k, ""))
            model[k] = value.strip() if isinstance(value, str) else value
        groups = data.get("groups", original.get("groups", []))
        if isinstance(groups, str):
            groups = groups.split(",")
        if isinstance(groups, list):
            groups = [g.strip() if isinstance(g, str) else g for g in groups]
            groups = [g for g in groups if g != ""]
        model["groups"] = groups
    else:
        model = {k: data.get(k, original.get(k, "")) for k in ROLE_FIELDS}
        session = model["max_session_duration"]
        if isinstance(session, str) and session.strip().isdigit():
            model["max_session_duration"] = int(session)
        for k in ("role_name", "path", "permissions_boundary"):
            if isinstance(model[k], str):
                model[k] = model[k].strip()
        model["trust"] = document(data.get("trust"), "trust")

    aws_docs = {
        p.get("arn"): p.get("document")
        for p in original.get("policies") or []
        if p.get("kind") == "aws"
    }
    policies = []
    raw_policies = data.get("policies") or []
    if not isinstance(raw_policies, list):
        issues.append(Issue(ERROR, "role", "policies", "policies must be a list"))
        raw_policies = []
    for i, p in enumerate(raw_policies):
        if not isinstance(p, dict):
            issues.append(Issue(ERROR, "role", f"policies[{i}]", "a policy must be an object"))
            continue
        pol = {k: p[k] for k in ("name", "kind", "arn", "path") if k in p}
        pol["name"] = str(pol.get("name", "")).strip()
        pol.setdefault("kind", "inline")
        if pol["kind"] == "aws":
            pol["document"] = copy.deepcopy(aws_docs.get(pol.get("arn")))
        else:
            pol["document"] = document(p.get("document"), f"policy:{pol['name'] or i}")
        policies.append(pol)
    model["policies"] = policies
    return _parsed(model, issues)


def _parsed(model: dict[str, Any], issues: list[Issue]) -> tuple[dict[str, Any] | None, list]:
    if any(i.level == ERROR and i.message.startswith("invalid JSON") for i in issues):
        return None, issues
    return model, issues


# -- diff --------------------------------------------------------------------------


def _lines(value: Any) -> list[str]:
    return [] if value is None else dumps(value).splitlines()


def _unified(a: list[str], b: list[str]) -> list[dict[str, str]]:
    out = []
    for line in difflib.unified_diff(a, b, lineterm="", n=3):
        if line.startswith(("---", "+++")):
            continue
        cls = {"+": "add", "-": "del", "@": "hunk"}.get(line[:1], "ctx")
        out.append({"cls": cls, "text": line})
    return out


def _policy_key(p: dict[str, Any]) -> tuple[str, str]:
    return (p.get("kind", "inline"), p.get("name", ""))


def diff(original: dict[str, Any], model: dict[str, Any]) -> dict[str, Any]:
    """Section-by-section unified diff of a draft against its original."""
    sections = []

    def section(title: str, a: Any, b: Any) -> None:
        if a is None and b is None:
            return
        status = "added" if a is None else "removed" if b is None else "changed"
        lines = _unified(_lines(a), _lines(b))
        if status == "changed" and not lines:
            status = "unchanged"
        sections.append({"title": title, "status": status, "lines": lines})

    entity = entity_of(original)
    fields = FIELDS[entity]
    section(
        f"{entity.capitalize()} settings",
        {k: original.get(k) for k in fields},
        {k: model.get(k) for k in fields},
    )
    if entity == "policy":
        section("Policy document", original.get("document"), model.get("document"))
    if entity == "role":
        section("Trust policy", original.get("trust"), model.get("trust"))
    before = {_policy_key(p): p for p in original.get("policies") or []}
    after = {_policy_key(p): p for p in model.get("policies") or []}
    for key in sorted(set(before) | set(after), key=lambda k: (k[1].lower(), k[0])):
        kind, name = key
        a, b = before.get(key), after.get(key)
        section(
            f"{name} ({kind})",
            None if a is None else (a.get("document") or {}),
            None if b is None else (b.get("document") or {}),
        )
    changed = [s for s in sections if s["status"] != "unchanged"]
    return {
        "sections": sections,
        "changed": len(changed),
        "summary": {
            status: sum(1 for s in sections if s["status"] == status)
            for status in ("added", "removed", "changed", "unchanged")
        },
    }
