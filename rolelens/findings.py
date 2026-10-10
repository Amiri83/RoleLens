"""Risk findings of a role: each with a severity, why it matters and a suggested fix.

Rules (:data:`RULES`) look at the collected trust and permission policies only; they
never call AWS. A rule reports at most one finding per policy (or per trust policy),
listing every statement it matched, so the counts stay readable.

Severities: ``critical`` > ``high`` > ``medium`` > ``low``. A statement with a
``Condition`` is reported one level lower (the condition may already narrow it).
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, field
from typing import Any, NamedTuple

from .policy import as_list, principal_account, role_account, statements, trust_principals

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}
SERVICE_LINKED_PATH = "/aws-service-role/"
ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"
ACCOUNT_PLACEHOLDER = "<account-id>"


class Rule(NamedTuple):
    title: str
    severity: str  # default severity (some findings raise or lower it)
    summary: str


RULES: dict[str, Rule] = {
    "admin": Rule(
        "Admin-equivalent permissions",
        "critical",
        "Allows every action (*), every IAM action (iam:*) or a whole service on every resource.",
    ),
    "wildcard": Rule(
        "Wildcard action or resource",
        "medium",
        'An Allow statement uses a wildcard action and/or Resource "*".',
    ),
    "passrole": Rule(
        "iam:PassRole on any role",
        "high",
        'iam:PassRole is allowed on Resource "*".',
    ),
    "cross-account-no-external-id": Rule(
        "Cross-account trust without ExternalId",
        "high",
        "Another account (or anyone) may assume the role without an sts:ExternalId condition.",
    ),
    "root-trust": Rule(
        "Trust to another account's root",
        "medium",
        "The trust policy names the root of another account.",
    ),
    "oidc-no-sub": Rule(
        "OIDC trust without a sub condition",
        "high",
        "A web identity (OIDC) provider may assume the role without a condition on :sub.",
    ),
    "no-boundary": Rule(
        "No permissions boundary",
        "low",
        "The role has no permissions boundary.",
    ),
    "inline-only": Rule(
        "Only inline policies",
        "low",
        "Every policy of the role is inline.",
    ),
}


@dataclass
class Finding:
    rule: str
    severity: str
    role: str
    where: str  # "policy <name>", "trust policy", "role"
    why: str
    fix: str  # suggested snippet (JSON or HCL)
    statements: list[str] = field(default_factory=list)  # "#0 (Sid)" of matched statements

    @property
    def title(self) -> str:
        return RULES[self.rule].title

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "title": self.title}


def lower(severity: str) -> str:
    i = SEVERITIES.index(severity)
    return SEVERITIES[min(i + 1, len(SEVERITIES) - 1)]


def worst(severities: list[str]) -> str:
    return min(severities, key=SEVERITIES.index) if severities else ""


def _pretty(doc: Any) -> str:
    return json.dumps(doc, indent=2)


def _label(i: int, st: dict[str, Any]) -> str:
    return f"#{i} ({st['Sid']})" if st.get("Sid") else f"#{i}"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _condition_keys(st: dict[str, Any]) -> dict[str, list[str]]:
    """``{lower-case key: values}`` over every operator of the statement's Condition."""
    out: dict[str, list[str]] = {}
    for block in (st.get("Condition") or {}).values():
        if isinstance(block, dict):
            for key, values in block.items():
                out.setdefault(str(key).lower(), []).extend(str(v) for v in as_list(values))
    return out


class _Collector:
    """Groups matched statements into one finding per (rule, where)."""

    def __init__(self, role: str):
        self.role = role
        self.found: dict[tuple[str, str], Finding] = {}

    def add(self, rule: str, severity: str, where: str, why: str, fix: str, label: str = ""):
        key = (rule, where)
        f = self.found.get(key)
        if f is None:
            f = self.found[key] = Finding(rule, severity, self.role, where, why, fix)
        elif SEVERITIES.index(severity) < SEVERITIES.index(f.severity):
            f.severity, f.why, f.fix = severity, why, fix
        if label and label not in f.statements:
            f.statements.append(label)


# -- permission policies -------------------------------------------------------------


def _admin(st: dict[str, Any], actions: list[str], resources: list[str]) -> tuple[str, str] | None:
    """``(severity, why)`` if an Allow statement is admin-equivalent."""
    if "NotAction" in st and "*" in resources:
        return "high", (
            'Allow with NotAction on Resource "*" grants every action except the listed '
            "ones, including services added later."
        )
    for a in actions:
        if a in ("*", "*:*"):
            return "critical", 'Action "*" grants every action on every service: full admin.'
    for a in actions:
        if a.lower() == "iam:*":
            return "critical", (
                "iam:* lets the role create or change any policy and role, so it can grant "
                "itself any permission (privilege escalation to full admin)."
            )
    if "*" in resources:
        for a in actions:
            service, _sep, name = a.partition(":")
            if name == "*":
                return "high", (
                    f'{a} on Resource "*" grants full control of every {service} resource '
                    "in the account (service admin)."
                )
    return None


def _scoped_actions(actions: list[str]) -> list[str]:
    """A suggested replacement for wildcard actions: the listed ones or a placeholder."""
    out = []
    for a in actions:
        if _has_wildcard(a):
            service = a.partition(":")[0] if ":" in a else "<service>"
            out.append(f"{service if service != '*' else '<service>'}:<SpecificAction>")
        else:
            out.append(a)
    return sorted(set(out))


def _scoped_resource(actions: list[str], account: str) -> str:
    services = {a.partition(":")[0] for a in actions if ":" in a} - {"*"}
    service = next(iter(services)) if len(services) == 1 else "<service>"
    return f"arn:aws:{service}:<region>:{account}:<resource>"


def _policy_rules(c: _Collector, policy: dict[str, Any], account: str) -> None:
    name = policy.get("name", "")
    where = f"policy {name}"
    if policy.get("document") is None:
        if str(policy.get("arn", "")).endswith(ADMIN_POLICY_SUFFIX):
            c.add(
                "admin",
                "critical",
                where,
                "AdministratorAccess grants every action on every resource.",
                _pretty({"Detach": policy.get("arn"), "Attach": "a least-privilege policy"}),
            )
        return
    for i, st in enumerate(statements(policy.get("document"))):
        if st.get("Effect") != "Allow":
            continue
        label = _label(i, st)
        conditional = bool(st.get("Condition"))
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        star_resource = "*" in resources and "NotResource" not in st

        admin = _admin(st, actions, resources)
        if admin:
            severity, why = admin
            fix = {
                "Effect": "Allow",
                "Action": _scoped_actions(actions or ["<service>:*"]),
                "Resource": [_scoped_resource(actions, account)],
            }
            c.add(
                "admin",
                lower(severity) if conditional else severity,
                where,
                why,
                _pretty(fix),
                label,
            )
        else:
            wild_actions = [a for a in actions if _has_wildcard(a)]
            if wild_actions or star_resource or "NotAction" in st:
                if (wild_actions or "NotAction" in st) and star_resource:
                    severity = "high"
                    why = (
                        f"Wildcard action(s) {', '.join(wild_actions) or 'NotAction'} on "
                        'Resource "*": grants more actions than needed on every resource.'
                    )
                elif wild_actions or "NotAction" in st:
                    severity = "medium"
                    why = (
                        f"Wildcard action(s) {', '.join(wild_actions) or 'NotAction'} also grant "
                        "actions added to the service later."
                    )
                else:
                    severity = "low"
                    why = (
                        'Resource "*" applies the actions to every resource in the account; '
                        "fine only for actions without resource-level permissions (List*, "
                        "Describe*)."
                    )
                fix = {"Effect": "Allow", "Action": _scoped_actions(actions)}
                fix["Resource"] = (
                    [_scoped_resource(actions, account)] if star_resource else resources
                )
                if st.get("Condition"):
                    fix["Condition"] = st["Condition"]
                c.add(
                    "wildcard",
                    lower(severity) if conditional else severity,
                    where,
                    why,
                    _pretty(fix),
                    label,
                )

        if star_resource and any(_matches(a, "iam:PassRole") for a in actions):
            fix = {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::{account}:role/<role-to-pass>",
                "Condition": {"StringEquals": {"iam:PassedToService": "<service>.amazonaws.com"}},
            }
            c.add(
                "passrole",
                "medium" if conditional else "high",
                where,
                'iam:PassRole on Resource "*" lets the role hand any role (including admin '
                "roles) to a service it can configure: privilege escalation.",
                _pretty(fix),
                label,
            )


# -- trust policy --------------------------------------------------------------------


def _is_oidc(p: dict[str, Any]) -> bool:
    if p["type"] != "Federated" or ":saml-provider/" in p["id"]:
        return False
    return not any(a.lower() == "sts:assumerolewithsaml" for a in p["actions"])


def _is_root(ident: str) -> bool:
    return ident.isdigit() or ident.endswith(":root")


def _trust_rules(c: _Collector, trust: Any, own: str | None) -> None:
    where = "trust policy"
    docs = statements(trust)
    for p in trust_principals(trust):
        if p["effect"] != "Allow" or p["negated"]:
            continue
        st = docs[p["statement"]]
        label = _label(p["statement"], st)
        keys = _condition_keys(st)
        if p["type"] in ("AWS", "*"):
            anyone = p["id"] == "*"
            account = None if anyone else principal_account(p["id"])
            if not anyone and (account is None or account == own):
                continue
            if "sts:externalid" not in keys:
                fixed = {
                    **st,
                    "Condition": {
                        **(st.get("Condition") or {}),
                        "StringEquals": {"sts:ExternalId": "<external-id>"},
                    },
                }
                who = 'anyone (Principal "*")' if anyone else f"account {account}"
                c.add(
                    "cross-account-no-external-id",
                    "critical" if anyone else "high",
                    where,
                    f"{who} can assume the role without an sts:ExternalId condition; a third "
                    "party acting for several customers can be tricked into using it "
                    "(confused deputy).",
                    _pretty(fixed),
                    label,
                )
            if account and _is_root(p["id"]):
                fixed = {
                    **st,
                    "Principal": {"AWS": f"arn:aws:iam::{account}:role/<role-that-assumes>"},
                }
                c.add(
                    "root-trust",
                    "medium",
                    where,
                    f"Trusting the root of account {account} delegates the decision to every "
                    "principal that account allows to call sts:AssumeRole; name the role(s) "
                    "that need access instead.",
                    _pretty(fixed),
                    label,
                )
        elif _is_oidc(p):
            provider = p["id"].rsplit("oidc-provider/", 1)[-1]
            if provider == "cognito-identity.amazonaws.com" and any(
                k.endswith(":aud") for k in keys
            ):
                continue
            subs = [v for k, v in keys.items() if k.endswith(":sub")]
            values = [v for vs in subs for v in vs]
            if subs and not any(v.strip() == "*" for v in values):
                continue
            fixed = {
                **st,
                "Condition": {
                    **(st.get("Condition") or {}),
                    "StringEquals": {
                        f"{provider}:aud": "<audience>",
                        f"{provider}:sub": "<subject, e.g. repo:<org>/<repo>:ref:refs/heads/main>",
                    },
                },
            }
            why = (
                f"Any identity issued by {provider} can assume the role: without a :sub "
                "condition every user, repository or service account of that provider is "
                "trusted."
            )
            if subs:
                why = f'The :sub condition of {provider} matches every subject ("*").'
            c.add("oidc-no-sub", "high", where, why, _pretty(fixed), label)


# -- role ----------------------------------------------------------------------------


def role_findings(model: dict[str, Any], own_account: str | None = None) -> list[Finding]:
    """Every finding of a role model (see :mod:`rolelens.queries`)."""
    name = model.get("role_name", "")
    own = own_account or role_account(model.get("arn", ""))
    account = own or ACCOUNT_PLACEHOLDER
    c = _Collector(name)
    for p in model.get("policies") or []:
        _policy_rules(c, p, account)
    _trust_rules(c, model.get("trust"), own)

    service_linked = (model.get("path") or "").startswith(SERVICE_LINKED_PATH)
    if not service_linked and not model.get("permissions_boundary"):
        c.add(
            "no-boundary",
            "low",
            "role",
            "Without a permissions boundary nothing caps what the role's policies may grant, "
            "including policies added later.",
            f'resource "aws_iam_role" "{name}" {{\n'
            "  # ...\n"
            f'  permissions_boundary = "arn:aws:iam::{account}:policy/<boundary-policy>"\n'
            "}",
        )
    policies = model.get("policies") or []
    if policies and all(p.get("kind") == "inline" for p in policies) and not service_linked:
        first = policies[0].get("name", "policy")
        c.add(
            "inline-only",
            "low",
            "role",
            "Inline policies cannot be reused, versioned or attached elsewhere, and are easy "
            "to miss in reviews; prefer customer managed policies.",
            f'resource "aws_iam_policy" "{first}" {{\n'
            f'  name   = "{first}"\n'
            "  policy = data.aws_iam_policy_document.<document>.json\n"
            "}\n\n"
            f'resource "aws_iam_role_policy_attachment" "{name}_{first}" {{\n'
            f'  role       = "{name}"\n'
            f"  policy_arn = aws_iam_policy.{first}.arn\n"
            "}",
        )
    return sorted(c.found.values(), key=lambda f: (SEVERITIES.index(f.severity), f.rule, f.where))


def risk_score(findings: list[Any]) -> int:
    return sum(SEVERITY_WEIGHT.get(_get(f, "severity"), 0) for f in findings)


def _get(f: Any, key: str) -> Any:
    return f[key] if isinstance(f, dict) else getattr(f, key)
