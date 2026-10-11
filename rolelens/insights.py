"""Insights of a snapshot: effective permissions, risk findings, recommendations, usage.

:func:`analyze` computes the effective permissions (:mod:`rolelens.effective`) and risk
findings (:mod:`rolelens.findings`) of every role, user and group from the collected
policies and stores them (tables ``role_permissions`` / ``role_findings`` and
``identity_permissions`` / ``identity_findings``); it runs at the end of every
collection and, through :func:`ensure_analysis`, for older snapshots the first time a
page needs them. A user's effective permissions are the union of its own policies and
those of its groups. Usage data comes from :mod:`rolelens.usage` (a separate, optional
job). Everything here reads SQLite only; nothing calls AWS.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import queries
from .db import closing
from .effective import Grant, canonical, effective_permissions
from .findings import (
    RULES,
    SEVERITIES,
    group_findings,
    policy_findings,
    risk_score,
    role_findings,
    rules_for,
    user_findings,
    worst,
)
from .recommend import RolePerms
from .usage import SOURCE_LABELS, WINDOW_DAYS

# Bump when the effective-permission expansion or a rule changes: stored analyses of an
# older version are recomputed.
ANALYSIS_VERSION = 2
TOP_ROLES = 10
TOP_UNUSED = 15


def _identity_model(
    conn: sqlite3.Connection, snap_id: int, ptype: str, name: str
) -> dict[str, Any] | None:
    if ptype == "user":
        return queries.user_model(conn, snap_id, name)
    return queries.group_model(conn, snap_id, name)


def analyze_identities(
    conn: sqlite3.Connection, snap_id: int, own: str | None, now: datetime | None = None
) -> tuple[int, int]:
    """Effective permissions and findings of every user and group: ``(grants, findings)``."""
    conn.execute("DELETE FROM identity_permissions WHERE snapshot_id=?", (snap_id,))
    conn.execute("DELETE FROM identity_findings WHERE snapshot_id=?", (snap_id,))
    grants = findings = 0
    for ptype, table, column in (
        ("user", "users", "user_name"),
        ("group", "iam_groups", "group_name"),
    ):
        names = [
            r[0]
            for r in conn.execute(
                f"SELECT {column} FROM {table} WHERE snapshot_id=?",  # noqa: S608 - fixed names
                (snap_id,),
            )
        ]
        for name in names:
            model = _identity_model(conn, snap_id, ptype, name)
            if model is None:
                continue
            perms = effective_permissions({"policies": queries.all_policies(model)})
            conn.executemany(
                "INSERT INTO identity_permissions(snapshot_id, principal_type, principal_name, "
                "action, resource, condition, policies) VALUES(?,?,?,?,?,?,?)",
                [(snap_id, ptype, name, *g, json.dumps(p)) for g, p in perms.items()],
            )
            found = (
                user_findings(model, own, now) if ptype == "user" else group_findings(model, own)
            )
            conn.executemany(
                "INSERT INTO identity_findings(snapshot_id, principal_type, principal_name, rule, "
                "severity, location, why, fix, statements) VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    (
                        snap_id,
                        ptype,
                        name,
                        f.rule,
                        f.severity,
                        f.where,
                        f.why,
                        f.fix,
                        json.dumps(f.statements),
                    )
                    for f in found
                ],
            )
            grants += len(perms)
            findings += len(found)
    return grants, findings


def analyze(conn: sqlite3.Connection, snap_id: int) -> dict[str, int]:
    """(Re)compute and store the snapshot's effective permissions and findings."""
    snap = conn.execute("SELECT account_id FROM snapshots WHERE id=?", (snap_id,)).fetchone()
    own = (snap["account_id"] if snap else "") or None
    conn.execute("DELETE FROM role_permissions WHERE snapshot_id=?", (snap_id,))
    conn.execute("DELETE FROM role_findings WHERE snapshot_id=?", (snap_id,))
    names = [
        r["role_name"]
        for r in conn.execute("SELECT role_name FROM roles WHERE snapshot_id=?", (snap_id,))
    ]
    grants = findings = 0
    for name in names:
        model = queries.role_model(conn, snap_id, name)
        if model is None:
            continue
        perms = effective_permissions(model)
        conn.executemany(
            "INSERT INTO role_permissions(snapshot_id, role_name, action, resource, condition, "
            "policies) VALUES(?,?,?,?,?,?)",
            [(snap_id, name, *g, json.dumps(p)) for g, p in perms.items()],
        )
        found = role_findings(model, own)
        conn.executemany(
            "INSERT INTO role_findings(snapshot_id, role_name, rule, severity, location, why, "
            "fix, statements) VALUES(?,?,?,?,?,?,?,?)",
            [
                (snap_id, name, f.rule, f.severity, f.where, f.why, f.fix, json.dumps(f.statements))
                for f in found
            ],
        )
        grants += len(perms)
        findings += len(found)
    identity_grants, identity_found = analyze_identities(conn, snap_id, own)
    conn.execute(
        "INSERT OR REPLACE INTO analysis(snapshot_id, version, analyzed_at) VALUES(?,?,?)",
        (snap_id, ANALYSIS_VERSION, datetime.now(UTC).isoformat(timespec="seconds")),
    )
    return {
        "roles": len(names),
        "grants": grants + identity_grants,
        "findings": findings + identity_found,
    }


def ensure_analysis(db_path: Path | str, snap_id: int) -> None:
    """Analyse the snapshot unless an analysis of the current version is stored."""
    with closing(db_path) as conn:
        row = conn.execute(
            "SELECT version FROM analysis WHERE snapshot_id=?", (snap_id,)
        ).fetchone()
        if row is None or row["version"] != ANALYSIS_VERSION:
            analyze(conn, snap_id)


# -- reads ---------------------------------------------------------------------------


def findings_by_role(conn: sqlite3.Connection, snap_id: int) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for r in conn.execute(
        "SELECT * FROM role_findings WHERE snapshot_id=? ORDER BY role_name", (snap_id,)
    ):
        out.setdefault(r["role_name"], []).append(_finding(r))
    for items in out.values():
        items.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["rule"], f["where"]))
    return out


def identity_findings(
    conn: sqlite3.Connection, snap_id: int, ptype: str
) -> dict[str, list[dict[str, Any]]]:
    """``{user or group: [finding]}`` (``ptype``: user | group), like findings_by_role."""
    out: dict[str, list[dict[str, Any]]] = {}
    for r in conn.execute(
        "SELECT * FROM identity_findings WHERE snapshot_id=? AND principal_type=? "
        "ORDER BY principal_name",
        (snap_id, ptype),
    ):
        out.setdefault(r["principal_name"], []).append(_finding(r, "principal_name"))
    for items in out.values():
        items.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["rule"], f["where"]))
    return out


def identity_insights(
    conn: sqlite3.Connection, snap_id: int, ptype: str, name: str
) -> dict[str, Any]:
    """Findings and effective permissions of one user or group (user and group pages)."""
    findings = identity_findings(conn, snap_id, ptype).get(name, [])
    perms = [
        {
            "action": r["action"],
            "resource": r["resource"],
            "condition": r["condition"],
            "policies": json.loads(r["policies"]),
        }
        for r in conn.execute(
            "SELECT * FROM identity_permissions WHERE snapshot_id=? AND principal_type=? "
            "AND principal_name=? ORDER BY action, resource",
            (snap_id, ptype, name),
        )
    ]
    return {
        "findings": findings,
        "score": risk_score(findings),
        "permissions": perms,
        "actions": sorted({p["action"] for p in perms}),
    }


def identity_perms(conn: sqlite3.Connection, snap_id: int, ptype: str) -> list[RolePerms]:
    """Every user or group with its grants and actions (recommendations). There is no
    trust policy: ``trust`` is empty, so duplicates are equal grants."""
    grants: dict[str, set[Grant]] = {}
    for r in conn.execute(
        "SELECT principal_name, action, resource, condition FROM identity_permissions "
        "WHERE snapshot_id=? AND principal_type=?",
        (snap_id, ptype),
    ):
        grants.setdefault(r["principal_name"], set()).add(
            Grant(r["action"], r["resource"], r["condition"])
        )
    table, column = ("users", "user_name") if ptype == "user" else ("iam_groups", "group_name")
    out = []
    for r in conn.execute(
        f"SELECT {column} AS name FROM {table} WHERE snapshot_id=? "  # noqa: S608 - fixed names
        "ORDER BY name COLLATE NOCASE",
        (snap_id,),
    ):
        g = frozenset(grants.get(r["name"], set()))
        out.append(RolePerms(r["name"], g, frozenset(x.action for x in g), ""))
    return out


def add_policy_findings(rows: list[dict[str, Any]], own: str | None) -> list[dict[str, Any]]:
    """Run the permission policy rules on each managed policy row (Policies page): sets
    ``findings`` (rule -> worst severity) and ``severity`` on the rows and returns every
    finding (dicts like :func:`findings_by_role`'s, ``role`` is the policy name)."""
    out = []
    for r in rows:
        found = [f.as_dict() for f in policy_findings(r, own)]
        by_rule: dict[str, str] = {}
        for f in found:
            by_rule.setdefault(f["rule"], f["severity"])  # worst first (sorted)
        r["findings"] = by_rule
        r["severity"] = next(iter(by_rule.values()), "")
        out += found
    return out


def _finding(r: sqlite3.Row, name_column: str = "role_name") -> dict[str, Any]:
    return {
        "role": r[name_column],
        "rule": r["rule"],
        "title": RULES[r["rule"]].title if r["rule"] in RULES else r["rule"],
        "severity": r["severity"],
        "where": r["location"],
        "why": r["why"],
        "fix": r["fix"],
        "statements": json.loads(r["statements"] or "[]"),
    }


def grants_by_role(conn: sqlite3.Connection, snap_id: int) -> dict[str, list[Grant]]:
    out: dict[str, list[Grant]] = {}
    for r in conn.execute(
        "SELECT role_name, action, resource, condition FROM role_permissions "
        "WHERE snapshot_id=? ORDER BY role_name, action, resource",
        (snap_id,),
    ):
        out.setdefault(r["role_name"], []).append(Grant(r["action"], r["resource"], r["condition"]))
    return out


def role_perms(conn: sqlite3.Connection, snap_id: int) -> list[RolePerms]:
    """Every non service-linked role with its grants, actions and trust (recommendations)."""
    grants = grants_by_role(conn, snap_id)
    out = []
    for r in conn.execute(
        "SELECT role_name, path, trust_doc FROM roles WHERE snapshot_id=? "
        "ORDER BY role_name COLLATE NOCASE",
        (snap_id,),
    ):
        if r["path"].startswith(queries.SERVICE_LINKED_PATH):
            continue
        g = frozenset(grants.get(r["role_name"], []))
        out.append(
            RolePerms(
                name=r["role_name"],
                grants=g,
                actions=frozenset(x.action for x in g),
                trust=canonical(json.loads(r["trust_doc"] or "{}")),
            )
        )
    return out


def usage_run(conn: sqlite3.Connection, snap_id: int) -> dict[str, Any] | None:
    r = conn.execute("SELECT * FROM usage_runs WHERE snapshot_id=?", (snap_id,)).fetchone()
    if r is None:
        return None
    sources = json.loads(r["sources"] or "{}")
    return {
        "collected_at": r["collected_at"],
        "window_days": r["window_days"],
        "sources": [(SOURCE_LABELS.get(k, k), v) for k, v in sources.items()],
        "status": sources,
        "warnings": json.loads(r["warnings"] or "[]"),
    }


def _stale(value: str, now: datetime, window: int) -> bool:
    days = queries.days_since(value, now)
    return days is None or days > window


def unused_services(
    conn: sqlite3.Connection, snap_id: int, now: datetime | None = None, window: int = WINDOW_DAYS
) -> dict[str, list[dict[str, Any]]]:
    """``{role: [{service, name, last_authenticated, actions}]}``: services the role's
    policies grant but it did not use within ``window`` days (service last accessed).
    ``actions`` counts the role's effective actions of that service."""
    now = now or datetime.now(UTC)
    counts: Counter[tuple[str, str]] = Counter()
    for r in conn.execute(
        "SELECT role_name, action FROM role_permissions WHERE snapshot_id=? "
        "GROUP BY role_name, action",
        (snap_id,),
    ):
        service = r["action"].partition(":")[0] if ":" in r["action"] else "*"
        counts[(r["role_name"], service.lower())] += 1
    out: dict[str, list[dict[str, Any]]] = {}
    for r in conn.execute(
        "SELECT * FROM service_last_accessed WHERE snapshot_id=? "
        "ORDER BY role_name, service_namespace",
        (snap_id,),
    ):
        if not _stale(r["last_authenticated"], now, window):
            continue
        out.setdefault(r["role_name"], []).append(
            {
                "service": r["service_namespace"],
                "name": r["service_name"],
                "last_authenticated": r["last_authenticated"],
                "actions": counts.get((r["role_name"], r["service_namespace"].lower()), 0),
            }
        )
    return out


def role_insights(
    conn: sqlite3.Connection, snap_id: int, role: str, now: datetime | None = None
) -> dict[str, Any]:
    """Findings, effective permissions and usage of one role (role page)."""
    now = now or datetime.now(UTC)
    findings = findings_by_role(conn, snap_id).get(role, [])
    perms = [
        {
            "action": r["action"],
            "resource": r["resource"],
            "condition": r["condition"],
            "policies": json.loads(r["policies"]),
        }
        for r in conn.execute(
            "SELECT * FROM role_permissions WHERE snapshot_id=? AND role_name=? "
            "ORDER BY action, resource",
            (snap_id, role),
        )
    ]
    services = []
    for r in conn.execute(
        "SELECT * FROM service_last_accessed WHERE snapshot_id=? AND role_name=? "
        "ORDER BY last_authenticated DESC, service_namespace",
        (snap_id, role),
    ):
        services.append(
            {
                "service": r["service_namespace"],
                "name": r["service_name"],
                "last_authenticated": r["last_authenticated"],
                "region": r["last_region"],
                "unused": _stale(r["last_authenticated"], now, WINDOW_DAYS),
            }
        )
    events = [
        dict(r)
        for r in conn.execute(
            "SELECT event_name, principal, principal_type, source, count, errors, last_time "
            "FROM assume_events WHERE snapshot_id=? AND role_name=? "
            "ORDER BY count DESC, last_time DESC",
            (snap_id, role),
        )
    ]
    unused = unused_services(conn, snap_id, now).get(role, [])
    return {
        "findings": findings,
        "score": risk_score(findings),
        "permissions": perms,
        "actions": sorted({p["action"] for p in perms}),
        "services": services,
        "unused": unused,
        "unused_actions": sum(u["actions"] for u in unused),
        "events": events,
        "usage": usage_run(conn, snap_id),
    }


def identity_dashboard(conn: sqlite3.Connection, snap_id: int) -> dict[str, Any]:
    """Users and groups: findings per rule and the riskiest of them."""
    by_type = {t: identity_findings(conn, snap_id, t) for t in ("user", "group")}
    rules = []
    for rule, meta in RULES.items():
        if "user" not in meta.applies and "group" not in meta.applies:
            continue
        counts = {}
        items = []
        for ptype, by_name in by_type.items():
            names = [n for n, fs in by_name.items() if any(f["rule"] == rule for f in fs)]
            counts[ptype] = len(names)
            items += [f for fs in by_name.values() for f in fs if f["rule"] == rule]
        rules.append(
            {
                "rule": rule,
                "title": meta.title,
                "summary": meta.summary,
                "severity": worst([f["severity"] for f in items]) or meta.severity,
                "findings": len(items),
                "users": counts["user"],
                "groups": counts["group"],
                "applies": meta.applies,
            }
        )
    risky = sorted(
        (
            {
                "type": ptype,
                "name": name,
                "score": risk_score(fs),
                "worst": worst([f["severity"] for f in fs]),
                "findings": len(fs),
                "rules": sorted({f["rule"] for f in fs}),
            }
            for ptype, by_name in by_type.items()
            for name, fs in by_name.items()
        ),
        key=lambda r: (-r["score"], r["type"], r["name"].lower()),
    )
    totals = {
        "users": conn.execute("SELECT COUNT(*) FROM users WHERE snapshot_id=?", (snap_id,)),
        "groups": conn.execute("SELECT COUNT(*) FROM iam_groups WHERE snapshot_id=?", (snap_id,)),
    }
    return {
        "rules": rules,
        "risky": [r for r in risky if r["score"]][:TOP_ROLES],
        "total_users": totals["users"].fetchone()[0],
        "total_groups": totals["groups"].fetchone()[0],
    }


def dashboard(
    conn: sqlite3.Connection, snap_id: int, now: datetime | None = None
) -> dict[str, Any]:
    """Counts per finding type, top risky roles, top unused permissions, analyzer findings."""
    by_role = findings_by_role(conn, snap_id)
    rule_counts = []
    for rule, meta in rules_for("role").items():
        roles = [r for r, fs in by_role.items() if any(f["rule"] == rule for f in fs)]
        items = [f for fs in by_role.values() for f in fs if f["rule"] == rule]
        rule_counts.append(
            {
                "rule": rule,
                "title": meta.title,
                "summary": meta.summary,
                "severity": worst([f["severity"] for f in items]) or meta.severity,
                "findings": len(items),
                "roles": len(roles),
            }
        )
    severity_counts = Counter(f["severity"] for fs in by_role.values() for f in fs)
    risky = sorted(
        (
            {
                "role": role,
                "score": risk_score(fs),
                "worst": worst([f["severity"] for f in fs]),
                "findings": len(fs),
                "rules": sorted({f["rule"] for f in fs}),
            }
            for role, fs in by_role.items()
        ),
        key=lambda r: (-r["score"], r["role"].lower()),
    )
    unused = unused_services(conn, snap_id, now)
    per_service: dict[str, dict[str, Any]] = {}
    for role, items in unused.items():
        for u in items:
            s = per_service.setdefault(
                u["service"],
                {"service": u["service"], "name": u["name"], "roles": [], "actions": 0},
            )
            s["roles"].append(role)
            s["actions"] += u["actions"]
    top_unused = sorted(
        per_service.values(), key=lambda s: (-len(s["roles"]), -s["actions"], s["service"])
    )[:TOP_UNUSED]
    unused_roles = sorted(
        (
            {"role": role, "services": len(items), "actions": sum(u["actions"] for u in items)}
            for role, items in unused.items()
        ),
        key=lambda r: (-r["actions"], -r["services"], r["role"].lower()),
    )[:TOP_UNUSED]
    analyzer = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM analyzer_findings WHERE snapshot_id=? "
            "ORDER BY resource_type, resource, finding_type",
            (snap_id,),
        )
    ]
    role_arns = {
        r["arn"]: r["role_name"]
        for r in conn.execute("SELECT role_name, arn FROM roles WHERE snapshot_id=?", (snap_id,))
    }
    for a in analyzer:
        a["role"] = role_arns.get(a["resource"], "")
    total_roles = conn.execute(
        "SELECT COUNT(*) FROM roles WHERE snapshot_id=?", (snap_id,)
    ).fetchone()[0]
    return {
        "identities": identity_dashboard(conn, snap_id),
        "rules": rule_counts,
        "severities": [(s, severity_counts.get(s, 0)) for s in SEVERITIES],
        "risky": [r for r in risky if r["score"]][:TOP_ROLES],
        "roles_with_findings": len(by_role),
        "total_roles": total_roles,
        "top_unused": top_unused,
        "unused_roles": unused_roles,
        "analyzer": analyzer,
        "usage": usage_run(conn, snap_id),
    }
