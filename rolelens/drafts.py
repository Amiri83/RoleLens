"""Local drafts of a role: clone a collected role, edit it, diff it against the original.

Drafts live in SQLite only; RoleLens never writes them to AWS. A draft keeps the
**original** role model frozen at clone time (the diff baseline, even after the snapshot
is deleted) and the edited **model** (see :mod:`rolelens.queries` for the shape).
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
from .queries import role_model
from .validate import ERROR, Issue, parse_json

ROLE_FIELDS = ("role_name", "path", "description", "max_session_duration", "permissions_boundary")
POLICY_FIELDS = ("name", "kind", "arn", "path", "document")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def editable(model: dict[str, Any]) -> dict[str, Any]:
    """Only the fields a draft keeps (drops ARNs of the role, last used, ...)."""
    out = {k: model.get(k, "") for k in ROLE_FIELDS}
    out["max_session_duration"] = int(model.get("max_session_duration") or 3600)
    out["trust"] = copy.deepcopy(model.get("trust") or {})
    out["policies"] = [
        {k: copy.deepcopy(p[k]) for k in POLICY_FIELDS if k in p}
        for p in model.get("policies") or []
    ]
    return out


def clone(
    conn: sqlite3.Connection, account_ref: int | None, snap_id: int, role_name: str
) -> int | None:
    """Create a draft from a collected role; returns its id (None if no such role)."""
    model = role_model(conn, snap_id, role_name)
    if model is None:
        return None
    original = editable(model)
    now = _now()
    cur = conn.execute(
        "INSERT INTO drafts(account_ref, snapshot_id, source_role, original, model, created_at, "
        "updated_at) VALUES(?,?,?,?,?,?,?)",
        (account_ref, snap_id, role_name, json.dumps(original), json.dumps(original), now, now),
    )
    return int(cur.lastrowid or 0)


def _row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": r["id"],
        "account_ref": r["account_ref"],
        "snapshot_id": r["snapshot_id"],
        "source_role": r["source_role"],
        "original": json.loads(r["original"]),
        "model": json.loads(r["model"]),
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
    data, issues = parse_json(raw, "role")
    if issues:
        return None, issues
    if not isinstance(data, dict):
        return None, [Issue(ERROR, "role", "", "the draft must be a JSON object")]
    model: dict[str, Any] = {k: data.get(k, original.get(k, "")) for k in ROLE_FIELDS}
    session = model["max_session_duration"]
    if isinstance(session, str) and session.strip().isdigit():
        model["max_session_duration"] = int(session)
    for k in ("role_name", "path", "permissions_boundary"):
        if isinstance(model[k], str):
            model[k] = model[k].strip()

    def document(value: Any, where: str) -> Any:
        if isinstance(value, str):
            doc, errs = parse_json(value, where)
            issues.extend(errs)
            return doc
        return value

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

    section(
        "Role settings",
        {k: original.get(k) for k in ROLE_FIELDS},
        {k: model.get(k) for k in ROLE_FIELDS},
    )
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
