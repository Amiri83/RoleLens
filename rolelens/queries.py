"""Read queries over collected snapshots: snapshot history, the Roles list and role models.

A **role model** is the plain dict the graph, the validator, drafts and exports share::

    {"role_name", "path", "description", "max_session_duration", "permissions_boundary",
     "trust": {...}, "policies": [{"name", "kind", "arn", "document"}, ...]}

``kind`` is ``inline``, ``managed`` (customer managed) or ``aws`` (AWS managed).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .findings import SEVERITIES
from .policy import is_aws_managed, principal_summary, role_account, trust_types

# Service-linked roles always live under this path (iam:CreateServiceLinkedRole).
SERVICE_LINKED_PATH = "/aws-service-role/"


def latest_snapshot(conn: sqlite3.Connection, account_ref: int | None) -> sqlite3.Row | None:
    """The account's newest successful snapshot."""
    if account_ref is None:
        return None
    return conn.execute(
        "SELECT * FROM snapshots WHERE account_ref=? AND status='ok' ORDER BY id DESC LIMIT 1",
        (account_ref,),
    ).fetchone()


def recent_snapshots(conn: sqlite3.Connection, account_ref: int, limit: int = 20) -> list[Any]:
    rows = conn.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM roles r WHERE r.snapshot_id = s.id) AS role_count "
        "FROM snapshots s WHERE account_ref=? ORDER BY id DESC LIMIT ?",
        (account_ref, limit),
    ).fetchall()
    return [{**dict(r), "warnings": json.loads(r["warnings"] or "[]")} for r in rows]


def days_since(value: str, now: datetime) -> int | None:
    """Whole days between an ISO timestamp and ``now`` (None if empty or unparseable)."""
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return max(0, (now - ts).days)


def role_list(
    conn: sqlite3.Connection, snap_id: int, q: str = "", now: datetime | None = None
) -> list[dict[str, Any]]:
    """Rows of the Roles page; ``q`` matches name, path, ARN or a trust principal.

    More filters (last used, trust type, flags, policy counts, findings) are applied to
    these rows by :class:`rolelens.filters.RoleFilters`. ``findings`` maps each risk rule
    of the role to its worst severity (empty until the snapshot is analysed, see
    :func:`rolelens.insights.ensure_analysis`); ``severity`` is the worst of them.
    """
    now = now or datetime.now(UTC)
    counts = {
        (r["role_name"], r["kind"]): r["n"]
        for r in conn.execute(
            "SELECT role_name, kind, COUNT(*) AS n FROM role_policies WHERE snapshot_id=? "
            "GROUP BY role_name, kind",
            (snap_id,),
        )
    }
    findings: dict[str, list[tuple[str, str]]] = {}
    for f in conn.execute(
        "SELECT role_name, rule, severity FROM role_findings WHERE snapshot_id=?", (snap_id,)
    ):
        findings.setdefault(f["role_name"], []).append((f["rule"], f["severity"]))
    needle = q.strip().lower()
    out = []
    for r in conn.execute(
        "SELECT * FROM roles WHERE snapshot_id=? ORDER BY role_name COLLATE NOCASE", (snap_id,)
    ):
        trust = json.loads(r["trust_doc"] or "{}")
        principals = principal_summary(trust)
        row = {
            "name": r["role_name"],
            "path": r["path"],
            "arn": r["arn"],
            "description": r["description"],
            "last_used_at": r["last_used_at"],
            "last_used_region": r["last_used_region"],
            "last_used_days": days_since(r["last_used_at"], now),
            "inline": counts.get((r["role_name"], "inline"), 0),
            "managed": counts.get((r["role_name"], "managed"), 0),
            "principals": principals,
            "trust_types": trust_types(trust, role_account(r["arn"])),
            "service_linked": r["path"].startswith(SERVICE_LINKED_PATH),
            "boundary": r["permissions_boundary"],
        }
        found = findings.get(r["role_name"], [])
        # rule -> worst severity, worst first (see rolelens.findings)
        by_rule: dict[str, str] = {}
        for rule, sev in sorted(found, key=lambda x: SEVERITIES.index(x[1])):
            by_rule.setdefault(rule, sev)
        row["findings"] = by_rule
        row["severity"] = next(iter(by_rule.values()), "")
        row["policies"] = row["inline"] + row["managed"]
        haystack = " ".join([r["role_name"], r["path"], r["arn"], *principals]).lower()
        if needle and needle not in haystack:
            continue
        out.append(row)
    return out


def role_model(conn: sqlite3.Connection, snap_id: int, role_name: str) -> dict[str, Any] | None:
    """The role model of a collected role (None if the snapshot has no such role)."""
    r = conn.execute(
        "SELECT * FROM roles WHERE snapshot_id=? AND role_name=?", (snap_id, role_name)
    ).fetchone()
    if r is None:
        return None
    managed = {
        m["arn"]: m
        for m in conn.execute("SELECT * FROM managed_policies WHERE snapshot_id=?", (snap_id,))
    }
    policies = []
    for p in conn.execute(
        "SELECT * FROM role_policies WHERE snapshot_id=? AND role_name=? "
        "ORDER BY kind DESC, policy_name COLLATE NOCASE",
        (snap_id, role_name),
    ):
        if p["kind"] == "inline":
            doc = json.loads(p["document"]) if p["document"] else None
            policies.append({"name": p["policy_name"], "kind": "inline", "document": doc})
            continue
        m = managed.get(p["policy_arn"])
        doc = json.loads(m["document"]) if m is not None and m["document"] else None
        aws = bool(m["aws_managed"]) if m is not None else is_aws_managed(p["policy_arn"])
        policies.append(
            {
                "name": p["policy_name"],
                "kind": "aws" if aws else "managed",
                "arn": p["policy_arn"],
                "path": m["path"] if m is not None else "/",
                "document": doc,
            }
        )
    return {
        "role_name": r["role_name"],
        "arn": r["arn"],
        "path": r["path"],
        "description": r["description"],
        "max_session_duration": r["max_session_duration"],
        "permissions_boundary": r["permissions_boundary"],
        "last_used_at": r["last_used_at"],
        "last_used_region": r["last_used_region"],
        "create_date": r["create_date"],
        "trust": json.loads(r["trust_doc"] or "{}"),
        "policies": policies,
    }
