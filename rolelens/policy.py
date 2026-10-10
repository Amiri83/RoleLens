"""Helpers for IAM policy documents: decoding, statements, principals and actions."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

PRINCIPAL_TYPES = ("AWS", "Service", "Federated", "CanonicalUser")
_ACCOUNT_RX = re.compile(r"^\d{12}$")
_IAM_ARN_RX = re.compile(r"^arn:aws[\w-]*:iam::(\d{12}|aws):(.+)$")
_STS_ARN_RX = re.compile(r"^arn:aws[\w-]*:sts::(\d{12}):(.+)$")


def as_list(value: Any) -> list[Any]:
    """IAM fields are a single value or a list of them."""
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def decode_document(value: Any) -> dict[str, Any]:
    """A policy document as a dict. boto3 already decodes IAM documents; a raw
    (URL-encoded) JSON string from another source is decoded here."""
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    text = str(value)
    if text.lstrip().startswith("%7B") or "%22" in text:
        text = urllib.parse.unquote(text)
    doc = json.loads(text)
    return doc if isinstance(doc, dict) else {}


def statements(doc: Any) -> list[dict[str, Any]]:
    """The statement objects of a document (anything malformed is skipped)."""
    if not isinstance(doc, dict):
        return []
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def is_aws_managed(arn: str) -> bool:
    return ":iam::aws:policy/" in arn


def dumps(doc: Any) -> str:
    """Stable pretty JSON used for display, diffs and exports."""
    return json.dumps(doc, indent=2, ensure_ascii=False)


def principal_entries(principal: Any) -> list[tuple[str, str]]:
    """``(type, identifier)`` pairs of a ``Principal`` value; ``"*"`` -> ``("*", "*")``."""
    if principal == "*":
        return [("*", "*")]
    if not isinstance(principal, dict):
        return []
    out: list[tuple[str, str]] = []
    for ptype, idents in principal.items():
        for ident in as_list(idents):
            out.append((str(ptype), str(ident)))
    return out


def trust_principals(trust: Any) -> list[dict[str, Any]]:
    """Every principal named by a trust policy, with its effect and statement."""
    out: list[dict[str, Any]] = []
    for i, st in enumerate(statements(trust)):
        effect = st.get("Effect", "Allow")
        for key, negated in (("Principal", False), ("NotPrincipal", True)):
            for ptype, ident in principal_entries(st.get(key)):
                out.append(
                    {
                        "effect": effect,
                        "type": ptype,
                        "id": ident,
                        "negated": negated,
                        "statement": i,
                        "sid": st.get("Sid", ""),
                        "actions": [str(a) for a in as_list(st.get("Action"))],
                        "conditions": st.get("Condition") or {},
                    }
                )
    return out


def principal_label(ptype: str, ident: str) -> str:
    """Short, readable label of a principal (the full identifier stays in the detail)."""
    if ptype == "*" or ident == "*":
        return "* (anyone)"
    if ptype == "AWS":
        if _ACCOUNT_RX.match(ident):
            return f"account {ident}"
        m = _IAM_ARN_RX.match(ident) or _STS_ARN_RX.match(ident)
        if m:
            account, resource = m.groups()
            if resource == "root":
                return f"account {account}"
            return f"{resource} ({account})"
        return ident
    if ptype == "Federated":
        m = _IAM_ARN_RX.match(ident)
        return m.group(2) if m else ident
    return ident


def split_action(action: str) -> tuple[str, str]:
    """``("s3", "GetObject")`` for ``"s3:GetObject"``; ``("*", "*")`` for ``"*"``."""
    if action == "*":
        return "*", "*"
    service, sep, name = action.partition(":")
    if not sep:
        return "", action
    return service.lower(), name


def principal_summary(trust: Any) -> list[str]:
    """Labels of the principals a trust policy allows (Roles page column)."""
    seen: list[str] = []
    for p in trust_principals(trust):
        if p["effect"] != "Allow" or p["negated"]:
            continue
        label = principal_label(p["type"], p["id"])
        if label not in seen:
            seen.append(label)
    return seen
