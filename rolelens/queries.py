"""Read queries over collected snapshots: snapshot history, the Roles / Users / Groups /
Policies lists, role, user and group models and managed policy usage.

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


def _managed(conn: sqlite3.Connection, snap_id: int) -> dict[str, sqlite3.Row]:
    return {
        m["arn"]: m
        for m in conn.execute("SELECT * FROM managed_policies WHERE snapshot_id=?", (snap_id,))
    }


def _policies(rows: Any, managed: dict[str, sqlite3.Row]) -> list[dict[str, Any]]:
    """Policy dicts of ``role_policies`` / ``identity_policies`` rows."""
    policies = []
    for p in rows:
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
    return policies


def role_model(conn: sqlite3.Connection, snap_id: int, role_name: str) -> dict[str, Any] | None:
    """The role model of a collected role (None if the snapshot has no such role)."""
    r = conn.execute(
        "SELECT * FROM roles WHERE snapshot_id=? AND role_name=?", (snap_id, role_name)
    ).fetchone()
    if r is None:
        return None
    policies = _policies(
        conn.execute(
            "SELECT * FROM role_policies WHERE snapshot_id=? AND role_name=? "
            "ORDER BY kind DESC, policy_name COLLATE NOCASE",
            (snap_id, role_name),
        ),
        _managed(conn, snap_id),
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


# -- users and groups ----------------------------------------------------------------
#
# A **user model** / **group model** has the shape of a role model where it can (a
# ``policies`` list of the same policy dicts) plus::
#
#     user:  {"entity": "user", "user_name", "arn", "path", "permissions_boundary",
#             "create_date", "password_enabled", "password_last_used", "mfa_active",
#             "mfa_devices", "metadata_source", "access_keys": [...],
#             "groups": [group models without members], "policies": [direct policies]}
#     group: {"entity": "group", "group_name", "arn", "path", "create_date",
#             "members": [user names], "policies": [...]}
#
# ``password_enabled`` / ``mfa_active`` are None when unknown (not collected).


def _identity_policies(
    conn: sqlite3.Connection,
    snap_id: int,
    ptype: str,
    name: str,
    managed: dict[str, sqlite3.Row],
) -> list[dict[str, Any]]:
    return _policies(
        conn.execute(
            "SELECT * FROM identity_policies WHERE snapshot_id=? AND principal_type=? "
            "AND principal_name=? ORDER BY kind DESC, policy_name COLLATE NOCASE",
            (snap_id, ptype, name),
        ),
        managed,
    )


def _flag(value: Any) -> bool | None:
    return None if value is None else bool(value)


def group_model(
    conn: sqlite3.Connection,
    snap_id: int,
    group_name: str,
    managed: dict[str, sqlite3.Row] | None = None,
) -> dict[str, Any] | None:
    """The group model of a collected group (None if the snapshot has no such group)."""
    r = conn.execute(
        "SELECT * FROM iam_groups WHERE snapshot_id=? AND group_name=?", (snap_id, group_name)
    ).fetchone()
    if r is None:
        return None
    managed = managed if managed is not None else _managed(conn, snap_id)
    members = [
        m["user_name"]
        for m in conn.execute(
            "SELECT user_name FROM group_members WHERE snapshot_id=? AND group_name=? "
            "ORDER BY user_name COLLATE NOCASE",
            (snap_id, group_name),
        )
    ]
    return {
        "entity": "group",
        "group_name": r["group_name"],
        "arn": r["arn"],
        "path": r["path"],
        "create_date": r["create_date"],
        "members": members,
        "policies": _identity_policies(conn, snap_id, "group", group_name, managed),
    }


def user_model(conn: sqlite3.Connection, snap_id: int, user_name: str) -> dict[str, Any] | None:
    """The user model of a collected user (None if the snapshot has no such user)."""
    r = conn.execute(
        "SELECT * FROM users WHERE snapshot_id=? AND user_name=?", (snap_id, user_name)
    ).fetchone()
    if r is None:
        return None
    managed = _managed(conn, snap_id)
    groups = []
    for m in conn.execute(
        "SELECT group_name FROM group_members WHERE snapshot_id=? AND user_name=? "
        "ORDER BY group_name COLLATE NOCASE",
        (snap_id, user_name),
    ):
        g = group_model(conn, snap_id, m["group_name"], managed)
        if g is None:  # iam:ListGroups not allowed: the membership is all that is known
            g = {
                "entity": "group",
                "group_name": m["group_name"],
                "arn": "",
                "path": "/",
                "create_date": "",
                "policies": [],
            }
        g.pop("members", None)
        groups.append(g)
    keys = [
        {
            "key_id": k["key_id"],
            "status": k["status"],
            "create_date": k["create_date"],
            "last_used_at": k["last_used_at"],
            "last_used_service": k["last_used_service"],
            "last_used_region": k["last_used_region"],
            "last_used_known": bool(k["last_used_known"]),
        }
        for k in conn.execute(
            "SELECT * FROM user_access_keys WHERE snapshot_id=? AND user_name=? "
            "ORDER BY create_date, key_id",
            (snap_id, user_name),
        )
    ]
    return {
        "entity": "user",
        "user_name": r["user_name"],
        "arn": r["arn"],
        "path": r["path"],
        "create_date": r["create_date"],
        "permissions_boundary": r["permissions_boundary"],
        "password_enabled": _flag(r["password_enabled"]),
        "password_last_used": r["password_last_used"],
        "mfa_active": _flag(r["mfa_active"]),
        "mfa_devices": r["mfa_devices"],
        "metadata_source": r["metadata_source"],
        "access_keys": keys,
        "groups": groups,
        "policies": _identity_policies(conn, snap_id, "user", user_name, managed),
    }


def all_policies(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Every policy that applies to a user model: its own, then those of its groups.

    Group policies get ``via`` (the group) and a name that says so
    (``policy-a (group group-a)``), so effective permissions and findings name where a
    grant comes from. Role and group models give their own policies."""
    out = [dict(p, via="") for p in model.get("policies") or []]
    for g in model.get("groups") or []:
        for p in g.get("policies") or []:
            label = f"{p.get('name', '')} (group {g['group_name']})"
            out.append(dict(p, name=label, via=g["group_name"]))
    return out


def _findings_by_rule(found: list[tuple[str, str]]) -> dict[str, str]:
    """rule -> worst severity, worst first (see rolelens.findings)."""
    by_rule: dict[str, str] = {}
    for rule, sev in sorted(found, key=lambda x: SEVERITIES.index(x[1])):
        by_rule.setdefault(rule, sev)
    return by_rule


def _identity_findings(
    conn: sqlite3.Connection, snap_id: int, ptype: str
) -> dict[str, dict[str, str]]:
    found: dict[str, list[tuple[str, str]]] = {}
    for f in conn.execute(
        "SELECT principal_name, rule, severity FROM identity_findings "
        "WHERE snapshot_id=? AND principal_type=?",
        (snap_id, ptype),
    ):
        found.setdefault(f["principal_name"], []).append((f["rule"], f["severity"]))
    return {name: _findings_by_rule(items) for name, items in found.items()}


def _policy_counts(
    conn: sqlite3.Connection, snap_id: int, ptype: str
) -> dict[tuple[str, str], int]:
    return {
        (r["principal_name"], r["kind"]): r["n"]
        for r in conn.execute(
            "SELECT principal_name, kind, COUNT(*) AS n FROM identity_policies "
            "WHERE snapshot_id=? AND principal_type=? GROUP BY principal_name, kind",
            (snap_id, ptype),
        )
    }


def _permission_source(direct: int, via_group: int) -> str:
    if direct and via_group:
        return "both"
    if direct:
        return "direct"
    return "group" if via_group else "none"


def user_list(
    conn: sqlite3.Connection, snap_id: int, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Rows of the Users page (filtered by :class:`rolelens.filters.UserFilters`).

    ``console`` / ``mfa`` are None when unknown. Access keys: ``active_keys``,
    ``key_age_days`` (the oldest active key) and ``key_unused_days`` (the active key
    unused the longest: days since its last use, or since its creation if never used).
    ``last_activity`` is the latest console sign-in or access key use; ``idle_days`` the
    days since then (since the user's creation if it was never active). ``permissions``
    says where the user's policies come from: direct, group, both or none.
    """
    now = now or datetime.now(UTC)
    counts = _policy_counts(conn, snap_id, "user")
    group_counts = _policy_counts(conn, snap_id, "group")
    groups: dict[str, list[str]] = {}
    for m in conn.execute(
        "SELECT group_name, user_name FROM group_members WHERE snapshot_id=? "
        "ORDER BY group_name COLLATE NOCASE",
        (snap_id,),
    ):
        groups.setdefault(m["user_name"], []).append(m["group_name"])
    keys: dict[str, list[sqlite3.Row]] = {}
    for k in conn.execute("SELECT * FROM user_access_keys WHERE snapshot_id=?", (snap_id,)):
        keys.setdefault(k["user_name"], []).append(k)
    findings = _identity_findings(conn, snap_id, "user")
    out = []
    for r in conn.execute(
        "SELECT * FROM users WHERE snapshot_id=? ORDER BY user_name COLLATE NOCASE", (snap_id,)
    ):
        name = r["user_name"]
        user_keys = keys.get(name, [])
        active = [k for k in user_keys if k["status"] == "Active"]
        ages = [days_since(k["create_date"], now) for k in active]
        unused = [days_since(k["last_used_at"] or k["create_date"], now) for k in active]
        used = [r["password_last_used"], *(k["last_used_at"] for k in user_keys)]
        last = max((v for v in used if v), default="")
        inline = counts.get((name, "inline"), 0)
        managed = counts.get((name, "managed"), 0)
        member_of = groups.get(name, [])
        via_group = sum(
            group_counts.get((g, "inline"), 0) + group_counts.get((g, "managed"), 0)
            for g in member_of
        )
        by_rule = findings.get(name, {})
        out.append(
            {
                "name": name,
                "path": r["path"],
                "arn": r["arn"],
                "create_date": r["create_date"],
                "groups": member_of,
                "console": _flag(r["password_enabled"]),
                "password_last_used": r["password_last_used"],
                "mfa": _flag(r["mfa_active"]),
                "boundary": r["permissions_boundary"],
                "keys": len(user_keys),
                "active_keys": len(active),
                "key_age_days": max((a for a in ages if a is not None), default=None),
                "key_unused_days": max((u for u in unused if u is not None), default=None),
                "last_activity": last,
                "idle_days": days_since(last or r["create_date"], now),
                "inline": inline,
                "managed": managed,
                "group_policies": via_group,
                "policies": inline + managed + via_group,
                "permissions": _permission_source(inline + managed, via_group),
                "findings": by_rule,
                "severity": next(iter(by_rule.values()), ""),
                "source": r["metadata_source"],
            }
        )
    return out


def group_list(conn: sqlite3.Connection, snap_id: int) -> list[dict[str, Any]]:
    """Rows of the Groups page."""
    counts = _policy_counts(conn, snap_id, "group")
    members: dict[str, list[str]] = {}
    for m in conn.execute(
        "SELECT group_name, user_name FROM group_members WHERE snapshot_id=? "
        "ORDER BY user_name COLLATE NOCASE",
        (snap_id,),
    ):
        members.setdefault(m["group_name"], []).append(m["user_name"])
    findings = _identity_findings(conn, snap_id, "group")
    out = []
    for r in conn.execute(
        "SELECT * FROM iam_groups WHERE snapshot_id=? ORDER BY group_name COLLATE NOCASE",
        (snap_id,),
    ):
        name = r["group_name"]
        by_rule = findings.get(name, {})
        inline, managed = counts.get((name, "inline"), 0), counts.get((name, "managed"), 0)
        out.append(
            {
                "name": name,
                "path": r["path"],
                "arn": r["arn"],
                "create_date": r["create_date"],
                "members": members.get(name, []),
                "inline": inline,
                "managed": managed,
                "policies": inline + managed,
                "findings": by_rule,
                "severity": next(iter(by_rule.values()), ""),
            }
        )
    return out


# -- managed policies ----------------------------------------------------------------

ENTITY_TYPES = ("role", "user", "group")


def policy_usage(conn: sqlite3.Connection, snap_id: int) -> dict[str, dict[str, list[str]]]:
    """``{arn: {"role": [...], "user": [...], "group": [...]}}``: who each managed policy is
    attached to, from iam:ListEntitiesForPolicy and from the collected attachments (so
    it is complete even when one of the two sources was not allowed)."""
    found: dict[str, dict[str, set[str]]] = {}

    def add(arn: str, etype: str, name: str) -> None:
        found.setdefault(arn, {t: set() for t in ENTITY_TYPES})[etype].add(name)

    for r in conn.execute(
        "SELECT arn, entity_type, entity_name FROM policy_entities WHERE snapshot_id=?",
        (snap_id,),
    ):
        if r["entity_type"] in ENTITY_TYPES:
            add(r["arn"], r["entity_type"], r["entity_name"])
    for r in conn.execute(
        "SELECT role_name, policy_arn FROM role_policies WHERE snapshot_id=? AND kind='managed'",
        (snap_id,),
    ):
        add(r["policy_arn"], "role", r["role_name"])
    for r in conn.execute(
        "SELECT principal_type, principal_name, policy_arn FROM identity_policies "
        "WHERE snapshot_id=? AND kind='managed'",
        (snap_id,),
    ):
        add(r["policy_arn"], r["principal_type"], r["principal_name"])
    return {
        arn: {t: sorted(names, key=str.lower) for t, names in by_type.items()}
        for arn, by_type in found.items()
    }


def _policy_row(m: sqlite3.Row, usage: dict[str, list[str]]) -> dict[str, Any]:
    versions = json.loads(m["versions"] or "[]")
    attached = sum(len(v) for v in usage.values())
    count = m["attachment_count"]
    return {
        "arn": m["arn"],
        "name": m["name"],
        "path": m["path"],
        "description": m["description"],
        "aws_managed": bool(m["aws_managed"]),
        "kind": "aws" if m["aws_managed"] else "managed",
        "default_version": m["default_version"],
        "versions": versions,
        "version_count": len(versions),
        "create_date": m["create_date"],
        "update_date": m["update_date"],
        "attachment_count": count,
        "roles": usage.get("role", []),
        "users": usage.get("user", []),
        "groups": usage.get("group", []),
        "attached": attached,
        # AttachmentCount (iam:GetPolicy) also counts attachments RoleLens did not list.
        "unattached": not attached and not count,
        "document": json.loads(m["document"]) if m["document"] else None,
    }


def policy_list(conn: sqlite3.Connection, snap_id: int) -> list[dict[str, Any]]:
    """Rows of the Policies page: every collected managed policy and who uses it."""
    usage = policy_usage(conn, snap_id)
    return [
        _policy_row(m, usage.get(m["arn"], {}))
        for m in conn.execute(
            "SELECT * FROM managed_policies WHERE snapshot_id=? "
            "ORDER BY aws_managed, name COLLATE NOCASE",
            (snap_id,),
        )
    ]


def policy_detail(conn: sqlite3.Connection, snap_id: int, arn: str) -> dict[str, Any] | None:
    """One row of :func:`policy_list` (None if the snapshot has no such policy)."""
    m = conn.execute(
        "SELECT * FROM managed_policies WHERE snapshot_id=? AND arn=?", (snap_id, arn)
    ).fetchone()
    if m is None:
        return None
    return _policy_row(m, policy_usage(conn, snap_id).get(arn, {}))
