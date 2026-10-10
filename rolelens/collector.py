"""Read-only collection of IAM roles and their policies into an SQLite snapshot.

API calls (all read-only, see :mod:`rolelens.aws`): ``sts:GetCallerIdentity``,
``iam:ListRoles``, ``iam:GetRole`` (trust policy, last used), ``iam:ListAttachedRolePolicies``,
``iam:ListRolePolicies``, ``iam:GetRolePolicy``, ``iam:GetPolicy`` and
``iam:GetPolicyVersion`` (the default version of every attached managed policy).
The finished snapshot is analysed locally (effective permissions and risk findings, see
:mod:`rolelens.insights`).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from . import insights
from .aws import AwsGateway, error_code, iso_time
from .db import closing
from .jobs import JobCancelled, NullProgress, Progress
from .policy import decode_document, is_aws_managed

log = logging.getLogger(__name__)


@dataclass
class CollectResult:
    snapshot_id: int
    account_id: str = ""
    roles: int = 0
    inline_policies: int = 0
    managed_policies: int = 0
    warnings: list[str] = field(default_factory=list)


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[Any]:
    out: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


class Collector:
    def __init__(
        self,
        gateway: AwsGateway,
        db_path: Path,
        account_ref: int | None = None,
        account_name: str = "",
        progress: Progress | None = None,
    ):
        self.gw = gateway
        self.db_path = db_path
        self.account_ref = account_ref  # RoleLens account record the snapshot belongs to
        # The record's display name, frozen on the snapshot (later renames do not apply).
        self.account_name = account_name
        # Background job reporting; cancellation is checked between API calls.
        self.progress: Progress = progress or NullProgress()

    def run(self) -> CollectResult:
        started = datetime.now(UTC).isoformat(timespec="seconds")
        with closing(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO snapshots(taken_at, status, account_ref, account_name) "
                "VALUES(?, 'running', ?, ?)",
                (started, self.account_ref, self.account_name),
            )
            snap_id = int(cur.lastrowid or 0)
        log.info("collection started snapshot=%s account=%s", snap_id, self.account_ref)
        try:
            result = self._collect(snap_id)
        except Exception as exc:
            if isinstance(exc, JobCancelled):
                log.info("collection cancelled snapshot=%s", snap_id)
                error = "cancelled"
            else:
                log.exception("collection failed snapshot=%s", snap_id)
                error = type(exc).__name__
            with closing(self.db_path) as conn:
                conn.execute(
                    "UPDATE snapshots SET status='failed', error=? WHERE id=?", (error, snap_id)
                )
            raise
        log.info(
            "collection finished snapshot=%s roles=%d inline=%d managed=%d warnings=%d",
            snap_id,
            result.roles,
            result.inline_policies,
            result.managed_policies,
            len(result.warnings),
        )
        return result

    def _collect(self, snap_id: int) -> CollectResult:
        iam = self.gw.client("iam")
        result = CollectResult(snapshot_id=snap_id)

        self.progress.check()
        self.progress.step("sts:GetCallerIdentity")
        try:
            result.account_id = self.gw.caller_identity()["account"]
        except (BotoCoreError, ClientError) as exc:
            result.warnings.append(f"sts:GetCallerIdentity unavailable ({error_code(exc)})")

        self.progress.check()
        self.progress.step("iam:ListRoles")
        listed = _paginate(iam, "list_roles", "Roles")
        # One step per role plus one per managed policy (added once they are known).
        total = len(listed) + 1
        self.progress.step(f"iam:ListRoles: {len(listed)} roles", done=1, total=total)

        role_rows: list[tuple[Any, ...]] = []
        policy_rows: list[tuple[Any, ...]] = []
        attached_arns: dict[str, str] = {}  # arn -> name
        for i, summary in enumerate(listed, start=2):
            self.progress.check()
            name = summary["RoleName"]
            self.progress.step(f"role {name}", done=i, total=total)
            role_rows.append(self._role_row(iam, snap_id, summary, result))
            for att in self._optional(
                result,
                f"iam:ListAttachedRolePolicies ({name})",
                lambda n=name: _paginate(
                    iam, "list_attached_role_policies", "AttachedPolicies", RoleName=n
                ),
            ):
                arn = att.get("PolicyArn", "")
                attached_arns[arn] = att.get("PolicyName", arn.rsplit("/", 1)[-1])
                policy_rows.append((snap_id, name, "managed", attached_arns[arn], arn, None))
            for pname in self._optional(
                result,
                f"iam:ListRolePolicies ({name})",
                lambda n=name: _paginate(iam, "list_role_policies", "PolicyNames", RoleName=n),
            ):
                doc = self._inline_document(iam, name, pname, result)
                policy_rows.append(
                    (snap_id, name, "inline", pname, "", None if doc is None else json.dumps(doc))
                )
                result.inline_policies += 1
        result.roles = len(role_rows)

        total += len(attached_arns)
        self.progress.set_total(total)
        managed_rows = []
        for j, (arn, pname) in enumerate(sorted(attached_arns.items()), start=len(listed) + 2):
            self.progress.check()
            self.progress.step(f"managed policy {pname}", done=j, total=total)
            managed_rows.append(self._managed_row(iam, snap_id, arn, pname, result))
        result.managed_policies = len(managed_rows)

        with closing(self.db_path) as conn:
            conn.executemany(
                "INSERT INTO roles(snapshot_id, role_name, role_id, arn, path, description, "
                "create_date, max_session_duration, permissions_boundary, last_used_at, "
                "last_used_region, trust_doc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                role_rows,
            )
            conn.executemany(
                "INSERT OR REPLACE INTO role_policies(snapshot_id, role_name, kind, policy_name, "
                "policy_arn, document) VALUES(?,?,?,?,?,?)",
                policy_rows,
            )
            conn.executemany(
                "INSERT INTO managed_policies(snapshot_id, arn, name, path, default_version, "
                "aws_managed, document) VALUES(?,?,?,?,?,?,?)",
                managed_rows,
            )
            self.progress.step("analysing effective permissions and findings")
            try:
                insights.analyze(conn, snap_id)
            except Exception:  # noqa: BLE001 - the snapshot is useful without insights
                log.exception("analysis of snapshot %s failed", snap_id)
                result.warnings.append("insights analysis failed (see the log)")
            conn.execute(
                "UPDATE snapshots SET status='ok', account_id=?, warnings=? WHERE id=?",
                (result.account_id, json.dumps(result.warnings), snap_id),
            )
        self.progress.step("finished", done=total, total=total)
        return result

    def _role_row(
        self, iam: Any, snap_id: int, summary: dict[str, Any], result: CollectResult
    ) -> tuple[Any, ...]:
        name = summary["RoleName"]
        role = summary
        try:
            role = iam.get_role(RoleName=name)["Role"]
        except (BotoCoreError, ClientError) as exc:
            msg = f"iam:GetRole ({name}) skipped ({error_code(exc)}); ListRoles data used"
            log.warning(msg)
            result.warnings.append(msg)
        last_used = role.get("RoleLastUsed") or {}
        boundary = role.get("PermissionsBoundary") or {}
        try:
            trust = decode_document(role.get("AssumeRolePolicyDocument"))
        except ValueError:
            result.warnings.append(f"trust policy of {name} could not be decoded")
            trust = {}
        return (
            snap_id,
            name,
            role.get("RoleId", ""),
            role.get("Arn", ""),
            role.get("Path", "/"),
            role.get("Description", "") or "",
            iso_time(role.get("CreateDate")),
            int(role.get("MaxSessionDuration") or 3600),
            boundary.get("PermissionsBoundaryArn", ""),
            iso_time(last_used.get("LastUsedDate")),
            last_used.get("Region", "") or "",
            json.dumps(trust),
        )

    def _inline_document(
        self, iam: Any, role: str, policy: str, result: CollectResult
    ) -> dict[str, Any] | None:
        try:
            raw = iam.get_role_policy(RoleName=role, PolicyName=policy)["PolicyDocument"]
            return decode_document(raw)
        except (BotoCoreError, ClientError, ValueError) as exc:
            msg = f"iam:GetRolePolicy ({role}/{policy}) skipped ({error_code(exc)})"
            log.warning(msg)
            result.warnings.append(msg)
            return None

    def _managed_row(
        self, iam: Any, snap_id: int, arn: str, name: str, result: CollectResult
    ) -> tuple[Any, ...]:
        path, version, doc = "/", "", None
        try:
            pol = iam.get_policy(PolicyArn=arn)["Policy"]
            name = pol.get("PolicyName", name)
            path = pol.get("Path", "/")
            version = pol.get("DefaultVersionId", "")
            raw = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]
            doc = decode_document(raw.get("Document"))
        except (BotoCoreError, ClientError, ValueError) as exc:
            msg = f"iam:GetPolicy/GetPolicyVersion ({name}) skipped ({error_code(exc)})"
            log.warning(msg)
            result.warnings.append(msg)
        return (
            snap_id,
            arn,
            name,
            path,
            version,
            int(is_aws_managed(arn)),
            None if doc is None else json.dumps(doc),
        )

    @staticmethod
    def _optional(result: CollectResult, what: str, fn: Any) -> list[Any]:
        """Per-role calls: a missing permission downgrades to a warning."""
        try:
            return fn()
        except (BotoCoreError, ClientError) as exc:
            msg = f"{what} skipped ({error_code(exc)})"
            log.warning(msg)
            result.warnings.append(msg)
            return []
