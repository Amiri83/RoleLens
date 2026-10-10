"""IAM validation of draft roles: JSON syntax, policy grammar and known action names.

Every problem is an :class:`Issue` (``error`` or ``warning``) that names where it is
(``trust``, ``policy:<name>`` or ``role``) and the JSON path inside that document, so
the editor can list it next to the right document.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any

from . import iam_actions
from .policy import PRINCIPAL_TYPES, as_list

ERROR, WARNING = "error", "warning"
VERSIONS = ("2012-10-17", "2008-10-17")
TOP_KEYS = frozenset({"Version", "Id", "Statement"})
STATEMENT_KEYS = frozenset(
    {
        "Sid",
        "Effect",
        "Principal",
        "NotPrincipal",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Condition",
    }
)
EFFECTS = ("Allow", "Deny")
POLICY_KINDS = ("inline", "managed", "aws")
# IAM quotas (characters, whitespace excluded): defaults, see the IAM quotas page.
SIZE_LIMITS = {"trust": 2048, "inline": 10240, "managed": 6144, "aws": 6144}
MAX_MANAGED_ATTACHED = 10
MIN_SESSION, MAX_SESSION = 3600, 43200

_ROLE_NAME_RX = re.compile(r"^[\w+=,.@-]{1,64}$")
_POLICY_NAME_RX = re.compile(r"^[\w+=,.@-]{1,128}$")
_PATH_RX = re.compile(r"^/(?:[\x21-\x7e]+/)?$")
_SID_RX = re.compile(r"^[A-Za-z0-9]*$")
_SERVICE_RX = re.compile(r"^[a-z0-9-]+$")
_ACTION_NAME_RX = re.compile(r"^[A-Za-z0-9*?]+$")
_ACCOUNT_RX = re.compile(r"^\d{12}$")

_CONDITION_BASE = frozenset(
    {
        "StringEquals",
        "StringNotEquals",
        "StringEqualsIgnoreCase",
        "StringNotEqualsIgnoreCase",
        "StringLike",
        "StringNotLike",
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        "Bool",
        "BinaryEquals",
        "IpAddress",
        "NotIpAddress",
        "ArnEquals",
        "ArnLike",
        "ArnNotEquals",
        "ArnNotLike",
        "Null",
    }
)


@dataclass(frozen=True)
class Issue:
    level: str  # error | warning
    where: str  # trust | policy:<name> | role
    path: str  # JSON path inside the document ('' = the whole document)
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "level": self.level,
            "where": self.where,
            "path": self.path,
            "message": self.message,
        }


def has_errors(issues: list[Issue]) -> bool:
    return any(i.level == ERROR for i in issues)


def parse_json(text: str, where: str) -> tuple[Any, list[Issue]]:
    """``(document, issues)``; a syntax error is reported with its line and column."""
    try:
        return json.loads(text), []
    except json.JSONDecodeError as exc:
        msg = f"invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        return None, [Issue(ERROR, where, "", msg)]


def compact_size(doc: Any) -> int:
    """Characters IAM counts against the size quota (whitespace outside strings excluded)."""
    return len(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))


def condition_operator_ok(op: str) -> bool:
    base = op
    for prefix in ("ForAnyValue:", "ForAllValues:"):
        if base.startswith(prefix):
            base = base[len(prefix) :]
            break
    if base.endswith("IfExists"):
        base = base[: -len("IfExists")]
        if base == "Null":  # Null has no ...IfExists form
            return False
    return base in _CONDITION_BASE


class _DocValidator:
    def __init__(self, where: str, kind: str):
        self.where = where
        self.kind = kind  # trust | inline | managed | aws
        self.trust = kind == "trust"
        self.issues: list[Issue] = []

    def add(self, level: str, path: str, message: str) -> None:
        self.issues.append(Issue(level, self.where, path, message))

    def run(self, doc: Any) -> list[Issue]:
        if not isinstance(doc, dict):
            self.add(ERROR, "", "a policy document must be a JSON object")
            return self.issues
        for key in doc:
            if key not in TOP_KEYS:
                self.add(ERROR, key, f"unknown top-level element {key!r}")
        version = doc.get("Version")
        if version is None:
            self.add(WARNING, "Version", 'no Version: add "2012-10-17" (policy variables need it)')
        elif version not in VERSIONS:
            self.add(ERROR, "Version", f'Version must be "2012-10-17" (got {version!r})')
        if "Statement" not in doc:
            self.add(ERROR, "Statement", "Statement is required")
        else:
            raw = doc["Statement"]
            if not isinstance(raw, list | dict):
                self.add(ERROR, "Statement", "Statement must be an object or a list of objects")
            else:
                items = as_list(raw)
                if not items:
                    self.add(ERROR, "Statement", "Statement must not be empty")
                sids: set[str] = set()
                for i, st in enumerate(items):
                    path = f"Statement[{i}]" if isinstance(raw, list) else "Statement"
                    self.statement(st, path, sids)
        limit = SIZE_LIMITS.get(self.kind)
        size = compact_size(doc)
        if limit and size > limit:
            self.add(
                WARNING,
                "",
                f"{size} characters (whitespace excluded) exceeds the default IAM quota of "
                f"{limit} for this kind of policy",
            )
        return self.issues

    def statement(self, st: Any, path: str, sids: set[str]) -> None:
        if not isinstance(st, dict):
            self.add(ERROR, path, "a statement must be a JSON object")
            return
        for key in st:
            if key not in STATEMENT_KEYS:
                self.add(ERROR, f"{path}.{key}", f"unknown statement element {key!r}")
        if "Sid" in st:
            sid = st["Sid"]
            if not isinstance(sid, str):
                self.add(ERROR, f"{path}.Sid", "Sid must be a string")
            else:
                if not self.trust and not _SID_RX.match(sid):
                    self.add(ERROR, f"{path}.Sid", "Sid may only contain letters and digits")
                if sid and sid in sids:
                    self.add(ERROR, f"{path}.Sid", f"duplicate Sid {sid!r}")
                sids.add(sid)
        effect = st.get("Effect")
        if effect is None:
            self.add(ERROR, f"{path}.Effect", "Effect is required")
        elif effect not in EFFECTS:
            self.add(ERROR, f"{path}.Effect", f'Effect must be "Allow" or "Deny" (got {effect!r})')
        self.exactly_one(st, path, "Action", "NotAction")
        for key in ("Action", "NotAction"):
            if key in st:
                self.actions(st[key], f"{path}.{key}")
        if self.trust:
            self.exactly_one(st, path, "Principal", "NotPrincipal")
            for key in ("Resource", "NotResource"):
                if key in st:
                    self.add(ERROR, f"{path}.{key}", f"a trust policy must not have {key}")
            for key in ("Principal", "NotPrincipal"):
                if key in st:
                    self.principal(st[key], f"{path}.{key}")
            if "NotPrincipal" in st and effect == "Allow":
                self.add(ERROR, f"{path}.NotPrincipal", "NotPrincipal is only allowed with Deny")
            if effect == "Allow" and st.get("Principal") == "*" and not st.get("Condition"):
                self.add(WARNING, f"{path}.Principal", "anyone can assume this role (no Condition)")
        else:
            for key in ("Principal", "NotPrincipal"):
                if key in st:
                    self.add(ERROR, f"{path}.{key}", f"an identity policy must not have {key}")
            self.exactly_one(st, path, "Resource", "NotResource")
            for key in ("Resource", "NotResource"):
                if key in st:
                    self.resources(st[key], f"{path}.{key}")
            if (
                effect == "Allow"
                and "*" in as_list(st.get("Action"))
                and "*" in as_list(st.get("Resource"))
            ):
                self.add(WARNING, path, 'grants every action on every resource ("*" / "*")')
        if "Condition" in st:
            self.condition(st["Condition"], f"{path}.Condition")

    def exactly_one(self, st: dict[str, Any], path: str, a: str, b: str) -> None:
        if a in st and b in st:
            self.add(ERROR, path, f"use either {a} or {b}, not both")
        elif a not in st and b not in st:
            self.add(ERROR, f"{path}.{a}", f"{a} (or {b}) is required")

    def _strings(self, value: Any, path: str, what: str) -> list[tuple[str, str]]:
        """``(path, value)`` of each string of a string-or-list field."""
        if isinstance(value, str):
            return [(path, value)]
        if not isinstance(value, list) or not value:
            self.add(ERROR, path, f"{what} must be a string or a non-empty list of strings")
            return []
        out = []
        for i, v in enumerate(value):
            if not isinstance(v, str):
                self.add(ERROR, f"{path}[{i}]", f"{what} entries must be strings")
            else:
                out.append((f"{path}[{i}]", v))
        return out

    def actions(self, value: Any, path: str) -> None:
        for p, action in self._strings(value, path, "Action"):
            self.action(action, p)

    def action(self, action: str, path: str) -> None:
        if action == "*":
            return
        service, sep, name = action.partition(":")
        if not sep or not service or not name:
            self.add(ERROR, path, f'{action!r} is not "service:Action"')
            return
        if not _SERVICE_RX.match(service.lower()) or not _ACTION_NAME_RX.match(name):
            self.add(ERROR, path, f"{action!r} contains invalid characters")
            return
        if self.trust:
            pattern = action.lower()
            if not any(fnmatch.fnmatchcase(t.lower(), pattern) for t in iam_actions.TRUST_ACTIONS):
                self.add(
                    ERROR,
                    path,
                    f"{action!r} is not a trust policy action (use sts:AssumeRole, "
                    "sts:AssumeRoleWithWebIdentity, sts:AssumeRoleWithSAML, sts:TagSession, ...)",
                )
            return
        if not iam_actions.is_known_service(service):
            self.add(WARNING, path, f"service {service!r} is not in the catalog; not checked")
        elif not iam_actions.is_known_action(service, name):
            self.add(ERROR, path, f"unknown action {action!r}")

    def resources(self, value: Any, path: str) -> None:
        for p, res in self._strings(value, path, "Resource"):
            if res == "*":
                continue
            if not res.startswith("arn:"):
                self.add(ERROR, p, f'{res!r} must be "*" or an ARN')
            elif res.count(":") < 5:
                self.add(ERROR, p, f"{res!r} is not a complete ARN (arn:partition:service:...)")

    def principal(self, value: Any, path: str) -> None:
        if value == "*":
            return
        if not isinstance(value, dict) or not value:
            self.add(ERROR, path, 'Principal must be "*" or an object such as {"Service": ...}')
            return
        for ptype, idents in value.items():
            p = f"{path}.{ptype}"
            if ptype not in PRINCIPAL_TYPES:
                self.add(ERROR, p, f"unknown principal type {ptype!r} (AWS, Service, Federated)")
                continue
            for pp, ident in self._strings(idents, p, "Principal"):
                if ptype == "AWS" and not (
                    ident == "*" or _ACCOUNT_RX.match(ident) or ident.startswith("arn:")
                ):
                    self.add(WARNING, pp, f"{ident!r} is not an account id or an ARN")
                if ptype == "Service" and not ident.endswith(".amazonaws.com"):
                    self.add(WARNING, pp, f"{ident!r} does not look like a service principal")

    def condition(self, value: Any, path: str) -> None:
        if not isinstance(value, dict):
            self.add(ERROR, path, "Condition must be an object of operator -> {key: values}")
            return
        for op, block in value.items():
            p = f"{path}.{op}"
            if not condition_operator_ok(op):
                self.add(ERROR, p, f"unknown condition operator {op!r}")
            if not isinstance(block, dict) or not block:
                self.add(ERROR, p, "a condition operator needs an object of key -> values")
                continue
            for key, vals in block.items():
                values = as_list(vals)
                if not values or not all(isinstance(v, str | bool | int | float) for v in values):
                    self.add(ERROR, f"{p}.{key}", "condition values: strings, numbers or booleans")


def validate_document(doc: Any, kind: str, where: str) -> list[Issue]:
    """Validate one policy document; ``kind`` is ``trust`` or a policy kind."""
    return _DocValidator(where, kind).run(doc)


def validate_model(model: dict[str, Any]) -> list[Issue]:
    """Validate a whole draft role model (see :mod:`rolelens.drafts`)."""
    issues: list[Issue] = []

    def role_issue(path: str, message: str, level: str = ERROR) -> None:
        issues.append(Issue(level, "role", path, message))

    name = model.get("role_name", "")
    if not isinstance(name, str) or not _ROLE_NAME_RX.match(name):
        role_issue("role_name", "role name: 1-64 characters of letters, digits and +=,.@_-")
    path = model.get("path", "/")
    if not isinstance(path, str) or len(path) > 512 or not _PATH_RX.match(path):
        role_issue("path", 'path must start and end with "/" (e.g. "/" or "/team-a/")')
    desc = model.get("description", "")
    if not isinstance(desc, str) or len(desc) > 1000:
        role_issue("description", "description: at most 1000 characters")
    elif any(ord(c) < 32 for c in desc):
        role_issue("description", "description must not contain control characters")
    session = model.get("max_session_duration", MIN_SESSION)
    if not isinstance(session, int) or not MIN_SESSION <= session <= MAX_SESSION:
        role_issue("max_session_duration", f"session duration: {MIN_SESSION}-{MAX_SESSION} seconds")

    issues += validate_document(model.get("trust"), "trust", "trust")

    seen: set[tuple[str, str]] = set()
    managed = 0
    for i, pol in enumerate(model.get("policies") or []):
        pname = str(pol.get("name", ""))
        kind = pol.get("kind", "inline")
        where = f"policy:{pname or i}"
        if kind not in POLICY_KINDS:
            issues.append(Issue(ERROR, where, "", f"unknown policy kind {kind!r}"))
            continue
        if not _POLICY_NAME_RX.match(pname):
            msg = "policy name: 1-128 characters of letters, digits and +=,.@_-"
            issues.append(Issue(ERROR, where, "", msg))
        if (kind, pname.lower()) in seen:
            issues.append(Issue(ERROR, where, "", f"duplicate {kind} policy name {pname!r}"))
        seen.add((kind, pname.lower()))
        if kind != "inline":
            managed += 1
        if pol.get("document") is None:
            if kind != "aws":
                issues.append(Issue(ERROR, where, "", "the policy document is missing"))
            continue
        issues += validate_document(pol["document"], kind, where)
    if managed > MAX_MANAGED_ATTACHED:
        role_issue(
            "policies",
            f"{managed} managed policies attached; the default IAM quota is {MAX_MANAGED_ATTACHED}",
            WARNING,
        )
    return issues
