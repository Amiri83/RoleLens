"""Export a draft role: policy JSON files and Terraform HCL (both local only).

Terraform: ``aws_iam_role`` with its trust policy as an ``aws_iam_policy_document`` data
source; inline policies as ``aws_iam_role_policy``; customer managed policies as
``aws_iam_policy`` + ``aws_iam_role_policy_attachment``; AWS managed policies as an
attachment by ARN. The output is ``terraform fmt`` style (aligned ``=``). RoleLens never
runs Terraform.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

from .policy import as_list, principal_entries, statements

ZIP_DATE = (2000, 1, 1, 0, 0, 0)  # fixed timestamps: identical drafts give identical zips
_IDENT_RX = re.compile(r"[^a-z0-9_]+")


# -- JSON files --------------------------------------------------------------------


def _file_safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9+=,.@_-]+", "_", name) or "policy"


def json_files(model: dict[str, Any]) -> dict[str, str]:
    """``{path: content}``: role settings, the trust policy and one file per editable policy."""
    files: dict[str, str] = {}
    role = {
        "RoleName": model.get("role_name", ""),
        "Path": model.get("path", "/"),
        "Description": model.get("description", ""),
        "MaxSessionDuration": model.get("max_session_duration", 3600),
        "PermissionsBoundary": model.get("permissions_boundary", "") or None,
        "InlinePolicies": [],
        "ManagedPolicyArns": [],
    }
    files["trust-policy.json"] = _pretty(model.get("trust") or {})
    for p in model.get("policies") or []:
        kind, name = p.get("kind", "inline"), p.get("name", "")
        if kind == "inline":
            role["InlinePolicies"].append(name)
        else:
            role["ManagedPolicyArns"].append(p.get("arn", "") or f"(new) {name}")
        if kind != "aws" and p.get("document") is not None:
            files[f"policies/{kind}-{_file_safe(name)}.json"] = _pretty(p["document"])
    files["role.json"] = _pretty(role)
    return dict(sorted(files.items()))


def _pretty(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def zip_bytes(files: dict[str, str], folder: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(f"{folder}/{path}", date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, content)
    return buf.getvalue()


# -- HCL ---------------------------------------------------------------------------


def hcl_string(value: Any) -> str:
    """A quoted HCL string. ``${`` / ``%{`` are escaped so IAM policy variables such as
    ``${aws:username}`` reach the policy literally instead of being interpolated."""
    if isinstance(value, bool):
        value = "true" if value else "false"
    text = str(value)
    text = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )
    return f'"{text}"'


def hcl_list(values: list[Any]) -> str:
    return "[" + ", ".join(hcl_string(v) for v in values) + "]"


@dataclass
class Block:
    type: str
    labels: tuple[str, ...] = ()
    items: list[tuple[str, str] | Block] = field(default_factory=list)

    def attr(self, key: str, raw_value: str) -> None:
        """Add ``key = raw_value`` (``raw_value`` is already HCL: quoted or an expression)."""
        self.items.append((key, raw_value))

    def block(self, child: Block) -> None:
        self.items.append(child)

    def render(self, indent: int = 0) -> list[str]:
        pad = "  " * indent
        head = " ".join([self.type, *(f'"{label}"' for label in self.labels)])
        lines = [f"{pad}{head} {{"]
        group: list[tuple[str, str]] = []

        def flush() -> None:
            width = max((len(k) for k, _ in group), default=0)
            for k, v in group:
                lines.append(f"{pad}  {k.ljust(width)} = {v}")
            group.clear()

        for item in self.items:
            if isinstance(item, Block):
                flush()
                lines.extend(item.render(indent + 1))
            else:
                group.append(item)
        flush()
        lines.append(f"{pad}}}")
        return lines


def identifier(name: str, taken: set[str]) -> str:
    """A unique Terraform resource name derived from ``name``."""
    base = _IDENT_RX.sub("_", name.lower()).strip("_") or "item"
    if base[0].isdigit():
        base = f"r_{base}"
    ident, n = base, 2
    while ident in taken:
        ident, n = f"{base}_{n}", n + 1
    taken.add(ident)
    return ident


def _statement_block(st: dict[str, Any]) -> Block:
    b = Block("statement")
    if st.get("Sid"):
        b.attr("sid", hcl_string(st["Sid"]))
    if "Effect" in st:
        b.attr("effect", hcl_string(st["Effect"]))
    for key, attr in (
        ("Action", "actions"),
        ("NotAction", "not_actions"),
        ("Resource", "resources"),
        ("NotResource", "not_resources"),
    ):
        if key in st:
            b.attr(attr, hcl_list(as_list(st[key])))
    for key, block_type in (("Principal", "principals"), ("NotPrincipal", "not_principals")):
        grouped: dict[str, list[str]] = {}
        for ptype, ident in principal_entries(st.get(key)):
            grouped.setdefault(ptype, []).append(ident)
        for ptype, idents in grouped.items():
            items = [("type", hcl_string(ptype)), ("identifiers", hcl_list(idents))]
            b.block(Block(block_type, (), items))
    for test, block in (st.get("Condition") or {}).items():
        for variable, values in (block or {}).items():
            items = [
                ("test", hcl_string(test)),
                ("variable", hcl_string(variable)),
                ("values", hcl_list(as_list(values))),
            ]
            b.block(Block("condition", (), items))
    return b


def policy_document(name: str, doc: dict[str, Any]) -> Block:
    """An ``aws_iam_policy_document`` data source for ``doc``."""
    b = Block("data", ("aws_iam_policy_document", name))
    if doc.get("Version") and doc["Version"] != "2012-10-17":
        b.attr("version", hcl_string(doc["Version"]))
    if doc.get("Id"):
        b.attr("policy_id", hcl_string(doc["Id"]))
    for st in statements(doc):
        b.block(_statement_block(st))
    return b


def terraform(model: dict[str, Any], header: str = "") -> str:
    """Terraform HCL for a draft role model."""
    taken: set[str] = set()
    role_id = identifier(model.get("role_name", "role"), taken)
    trust_id = identifier(f"{role_id}_trust", taken)
    blocks: list[tuple[str, Block]] = []

    blocks.append(("", policy_document(trust_id, model.get("trust") or {})))
    role = Block("resource", ("aws_iam_role", role_id))
    role.attr("name", hcl_string(model.get("role_name", "")))
    role.attr("path", hcl_string(model.get("path", "/") or "/"))
    if model.get("description"):
        role.attr("description", hcl_string(model["description"]))
    role.attr("max_session_duration", str(int(model.get("max_session_duration") or 3600)))
    role.attr("assume_role_policy", f"data.aws_iam_policy_document.{trust_id}.json")
    if model.get("permissions_boundary"):
        role.attr("permissions_boundary", hcl_string(model["permissions_boundary"]))
    blocks.append(("", role))

    for p in model.get("policies") or []:
        kind, name = p.get("kind", "inline"), p.get("name", "")
        if kind == "inline":
            doc_id = identifier(f"{role_id}_{name}", taken)
            blocks.append(("", policy_document(doc_id, p.get("document") or {})))
            items = [
                ("name", hcl_string(name)),
                ("role", f"aws_iam_role.{role_id}.id"),
                ("policy", f"data.aws_iam_policy_document.{doc_id}.json"),
            ]
            blocks.append(("", Block("resource", ("aws_iam_role_policy", doc_id), items)))
            continue
        if kind == "managed":
            pol_id = identifier(name, taken)
            note = ""
            if p.get("arn"):
                note = (
                    f"# Customer managed policy {name} exists already; import it before "
                    f"applying:\n#   terraform import aws_iam_policy.{pol_id} {p['arn']}"
                )
            blocks.append(("", policy_document(pol_id, p.get("document") or {})))
            items = [
                ("name", hcl_string(name)),
                ("path", hcl_string(p.get("path") or "/")),
                ("policy", f"data.aws_iam_policy_document.{pol_id}.json"),
            ]
            blocks.append((note, Block("resource", ("aws_iam_policy", pol_id), items)))
            policy_arn = f"aws_iam_policy.{pol_id}.arn"
        else:  # AWS managed: attached by ARN
            policy_arn = hcl_string(p.get("arn", ""))
        attach_id = identifier(f"{role_id}_{name}", taken)
        items = [("role", f"aws_iam_role.{role_id}.name"), ("policy_arn", policy_arn)]
        labels = ("aws_iam_role_policy_attachment", attach_id)
        blocks.append(("", Block("resource", labels, items)))

    parts = []
    if header:
        parts.append("\n".join(f"# {line}".rstrip() for line in header.splitlines()))
    for note, block in blocks:
        text = "\n".join(block.render())
        parts.append(f"{note}\n{text}" if note else text)
    return "\n\n".join(parts) + "\n"
