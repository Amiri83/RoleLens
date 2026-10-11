"""Export a draft role, user or managed policy: policy JSON files and Terraform HCL (both
local only).

Terraform: ``aws_iam_role`` with its trust policy as an ``aws_iam_policy_document`` data
source (``aws_iam_user`` for a user, with ``aws_iam_user_group_membership`` for its
groups); inline policies as ``aws_iam_role_policy`` / ``aws_iam_user_policy``; customer
managed policies as ``aws_iam_policy`` + ``aws_iam_role_policy_attachment`` /
``aws_iam_user_policy_attachment``; AWS managed policies as an attachment by ARN. A
standalone managed policy is one ``aws_iam_policy``. Access keys and console passwords
are never exported. The output is ``terraform fmt`` style (aligned ``=``). RoleLens
never runs Terraform.
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


def _policy_files(files: dict[str, str], policies: list[dict[str, Any]]) -> tuple[list, list]:
    """One file per editable policy; returns the (inline names, managed ARNs) lists."""
    inline: list[str] = []
    managed: list[str] = []
    for p in policies:
        kind, name = p.get("kind", "inline"), p.get("name", "")
        if kind == "inline":
            inline.append(name)
        else:
            managed.append(p.get("arn", "") or f"(new) {name}")
        if kind != "aws" and p.get("document") is not None:
            files[f"policies/{kind}-{_file_safe(name)}.json"] = _pretty(p["document"])
    return inline, managed


def json_files(model: dict[str, Any]) -> dict[str, str]:
    """``{path: content}``: role settings, the trust policy and one file per editable policy
    (user: user settings and its policies; managed policy: its settings and document)."""
    entity = model.get("entity", "role")
    files: dict[str, str] = {}
    if entity == "user":
        inline, managed = _policy_files(files, model.get("policies") or [])
        files["user.json"] = _pretty(
            {
                "UserName": model.get("user_name", ""),
                "Path": model.get("path", "/"),
                "PermissionsBoundary": model.get("permissions_boundary", "") or None,
                "Groups": list(model.get("groups") or []),
                "InlinePolicies": inline,
                "ManagedPolicyArns": managed,
            }
        )
        return dict(sorted(files.items()))
    if entity == "policy":
        name = model.get("name", "")
        files["policy.json"] = _pretty(
            {
                "PolicyName": name,
                "Path": model.get("path", "/"),
                "Description": model.get("description", ""),
                "Arn": model.get("arn", "") or None,
            }
        )
        if model.get("document") is not None:
            files[f"policies/managed-{_file_safe(name)}.json"] = _pretty(model["document"])
        return dict(sorted(files.items()))
    files["trust-policy.json"] = _pretty(model.get("trust") or {})
    inline, managed = _policy_files(files, model.get("policies") or [])
    files["role.json"] = _pretty(
        {
            "RoleName": model.get("role_name", ""),
            "Path": model.get("path", "/"),
            "Description": model.get("description", ""),
            "MaxSessionDuration": model.get("max_session_duration", 3600),
            "PermissionsBoundary": model.get("permissions_boundary", "") or None,
            "InlinePolicies": inline,
            "ManagedPolicyArns": managed,
        }
    )
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


def _managed_policy_blocks(
    blocks: list[tuple[str, Block]],
    taken: set[str],
    p: dict[str, Any],
    description: str = "",
) -> str:
    """``aws_iam_policy`` (and its document) of a customer managed policy; returns its id."""
    name = p.get("name", "")
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
    ]
    if description:
        items.append(("description", hcl_string(description)))
    items.append(("policy", f"data.aws_iam_policy_document.{pol_id}.json"))
    blocks.append((note, Block("resource", ("aws_iam_policy", pol_id), items)))
    return pol_id


def _policy_blocks(
    blocks: list[tuple[str, Block]],
    taken: set[str],
    owner: str,
    owner_id: str,
    policies: list[dict[str, Any]],
) -> None:
    """Inline policies and attachments of a role or user (``owner``: role | user)."""
    # The inline policy names its owner by id (role, as before) or name (user).
    ref = f"aws_iam_{owner}.{owner_id}." + ("id" if owner == "role" else "name")
    for p in policies:
        kind, name = p.get("kind", "inline"), p.get("name", "")
        if kind == "inline":
            doc_id = identifier(f"{owner_id}_{name}", taken)
            blocks.append(("", policy_document(doc_id, p.get("document") or {})))
            items = [
                ("name", hcl_string(name)),
                (owner, ref),
                ("policy", f"data.aws_iam_policy_document.{doc_id}.json"),
            ]
            blocks.append(("", Block("resource", (f"aws_iam_{owner}_policy", doc_id), items)))
            continue
        if kind == "managed":
            policy_arn = f"aws_iam_policy.{_managed_policy_blocks(blocks, taken, p)}.arn"
        else:  # AWS managed: attached by ARN
            policy_arn = hcl_string(p.get("arn", ""))
        attach_id = identifier(f"{owner_id}_{name}", taken)
        items = [(owner, f"aws_iam_{owner}.{owner_id}.name"), ("policy_arn", policy_arn)]
        labels = (f"aws_iam_{owner}_policy_attachment", attach_id)
        blocks.append(("", Block("resource", labels, items)))


def _render(blocks: list[tuple[str, Block]], header: str) -> str:
    parts = []
    if header:
        parts.append("\n".join(f"# {line}".rstrip() for line in header.splitlines()))
    for note, block in blocks:
        text = "\n".join(block.render())
        parts.append(f"{note}\n{text}" if note else text)
    return "\n\n".join(parts) + "\n"


def terraform(model: dict[str, Any], header: str = "") -> str:
    """Terraform HCL for a draft role, user or managed policy model."""
    entity = model.get("entity", "role")
    if entity == "user":
        return _user_terraform(model, header)
    if entity == "policy":
        blocks: list[tuple[str, Block]] = []
        policy = {**model, "kind": "managed"}
        _managed_policy_blocks(blocks, set(), policy, model.get("description", ""))
        return _render(blocks, header)
    return _role_terraform(model, header)


def _user_terraform(model: dict[str, Any], header: str) -> str:
    taken: set[str] = set()
    user_id = identifier(model.get("user_name", "user"), taken)
    blocks: list[tuple[str, Block]] = []
    user = Block("resource", ("aws_iam_user", user_id))
    user.attr("name", hcl_string(model.get("user_name", "")))
    user.attr("path", hcl_string(model.get("path", "/") or "/"))
    if model.get("permissions_boundary"):
        user.attr("permissions_boundary", hcl_string(model["permissions_boundary"]))
    blocks.append(("", user))
    _policy_blocks(blocks, taken, "user", user_id, model.get("policies") or [])
    groups = [g for g in model.get("groups") or [] if g]
    if groups:
        items = [("user", f"aws_iam_user.{user_id}.name"), ("groups", hcl_list(groups))]
        labels = ("aws_iam_user_group_membership", identifier(f"{user_id}_groups", taken))
        blocks.append(("", Block("resource", labels, items)))
    return _render(blocks, header)


def _role_terraform(model: dict[str, Any], header: str) -> str:
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
    _policy_blocks(blocks, taken, "role", role_id, model.get("policies") or [])
    return _render(blocks, header)
