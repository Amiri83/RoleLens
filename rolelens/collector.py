"""Read-only collection of IAM roles, users, groups and managed policies into SQLite.

API calls (all read-only, see :mod:`rolelens.aws`):

* roles (required): ``sts:GetCallerIdentity``, ``iam:ListRoles``, ``iam:GetRole`` (trust
  policy, last used), ``iam:ListAttachedRolePolicies``, ``iam:ListRolePolicies``,
  ``iam:GetRolePolicy``;
* users (optional): ``iam:ListUsers``, ``iam:GetUser``, ``iam:ListGroupsForUser``,
  ``iam:ListAttachedUserPolicies``, ``iam:ListUserPolicies`` + ``iam:GetUserPolicy``,
  ``iam:ListAccessKeys`` + ``iam:GetAccessKeyLastUsed`` (key id, age and last use only),
  and either the credential report (``iam:GenerateCredentialReport`` +
  ``iam:GetCredentialReport``) or ``iam:GetLoginProfile`` (existence only) +
  ``iam:ListMFADevices`` for console access and MFA;
* groups (optional): ``iam:ListGroups``, ``iam:GetGroup`` (members),
  ``iam:ListAttachedGroupPolicies``, ``iam:ListGroupPolicies`` + ``iam:GetGroupPolicy``;
* managed policies: ``iam:ListPolicies`` (``Scope=Local``, and attached AWS managed),
  ``iam:GetPolicy``, ``iam:GetPolicyVersion`` (default version), ``iam:ListPolicyVersions``
  and ``iam:ListEntitiesForPolicy``.

Every optional call that fails (typically a missing permission) becomes a warning of the
snapshot; the rest of the collection goes on. The finished snapshot is analysed locally
(effective permissions and risk findings, see :mod:`rolelens.insights`).
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from collections.abc import Callable
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

# The credential report is built asynchronously: GenerateCredentialReport is polled until
# the report is COMPLETE (at most REPORT_ATTEMPTS times, at most REPORT_WAIT seconds apart).
REPORT_ATTEMPTS = 10
REPORT_WAIT = 2.0
# Credential report values that mean "no value" (never used, not applicable, ...).
_REPORT_EMPTY = frozenset({"", "N/A", "no_information", "not_supported"})


@dataclass
class CollectResult:
    snapshot_id: int
    account_id: str = ""
    roles: int = 0
    inline_policies: int = 0
    managed_policies: int = 0
    users: int = 0
    groups: int = 0
    credential_report: bool = False  # user metadata came from the credential report
    warnings: list[str] = field(default_factory=list)


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[Any]:
    out: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


# -- credential report -------------------------------------------------------------------


def _report_bool(value: str | None) -> bool | None:
    value = (value or "").strip().lower()
    return True if value == "true" else False if value == "false" else None


def _report_time(value: str | None) -> str:
    value = (value or "").strip()
    return "" if value in _REPORT_EMPTY else iso_time(_parse_time(value))


def _parse_time(value: str) -> datetime | str:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return ""


def parse_credential_report(content: bytes | str) -> dict[str, dict[str, Any]]:
    """``{user: metadata}`` from a credential report (CSV).

    Only what RoleLens shows is kept: console password enabled and last used, MFA active,
    and per access key slot whether it is active, when it was last rotated and when, where
    and for which service it was last used. Every other column is dropped here, and the
    report itself is never stored or logged (it holds no secret values either way).
    The root account row is skipped.
    """
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
    out: dict[str, dict[str, Any]] = {}
    for row in csv.DictReader(io.StringIO(text)):
        name = (row.get("user") or "").strip()
        if not name or name == "<root_account>":
            continue
        keys = []
        for slot in (1, 2):
            prefix = f"access_key_{slot}_"
            rotated = _report_time(row.get(prefix + "last_rotated"))
            if not rotated:
                continue
            keys.append(
                {
                    "active": _report_bool(row.get(prefix + "active")),
                    "last_rotated": rotated,
                    "last_used_at": _report_time(row.get(prefix + "last_used_date")),
                    "last_used_service": _report_value(row.get(prefix + "last_used_service")),
                    "last_used_region": _report_value(row.get(prefix + "last_used_region")),
                }
            )
        out[name] = {
            "password_enabled": _report_bool(row.get("password_enabled")),
            "password_last_used": _report_time(row.get("password_last_used")),
            "mfa_active": _report_bool(row.get("mfa_active")),
            "keys": keys,
        }
    return out


def _report_value(value: str | None) -> str:
    value = (value or "").strip()
    return "" if value in _REPORT_EMPTY else value


class Collector:
    def __init__(
        self,
        gateway: AwsGateway,
        db_path: Path,
        account_ref: int | None = None,
        account_name: str = "",
        progress: Progress | None = None,
        *,
        report_wait: float = REPORT_WAIT,
    ):
        self.gw = gateway
        self.db_path = db_path
        self.account_ref = account_ref  # RoleLens account record the snapshot belongs to
        # The record's display name, frozen on the snapshot (later renames do not apply).
        self.account_name = account_name
        # Background job reporting; cancellation is checked between API calls.
        self.progress: Progress = progress or NullProgress()
        self.report_wait = report_wait

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
            "collection finished snapshot=%s roles=%d users=%d groups=%d inline=%d managed=%d "
            "warnings=%d",
            snap_id,
            result.roles,
            result.users,
            result.groups,
            result.inline_policies,
            result.managed_policies,
            len(result.warnings),
        )
        return result

    def _collect(self, snap_id: int) -> CollectResult:
        iam = self.gw.client("iam")
        result = CollectResult(snapshot_id=snap_id)
        rows = _Rows(snap_id)

        self.progress.check()
        self.progress.step("sts:GetCallerIdentity")
        try:
            result.account_id = self.gw.caller_identity()["account"]
        except (BotoCoreError, ClientError) as exc:
            result.warnings.append(f"sts:GetCallerIdentity unavailable ({error_code(exc)})")

        self.progress.check()
        self.progress.step("iam:ListRoles")
        listed = _paginate(iam, "list_roles", "Roles")
        self.progress.check()
        self.progress.step("iam:ListUsers")
        users = self._optional(
            result, "iam:ListUsers", lambda: _paginate(iam, "list_users", "Users")
        )
        self.progress.check()
        self.progress.step("iam:ListGroups")
        groups = self._optional(
            result, "iam:ListGroups", lambda: _paginate(iam, "list_groups", "Groups")
        )
        # One step per role, user and group plus one per managed policy (added once known).
        self.total = len(listed) + len(users) + len(groups) + 1
        self.done = 1
        self.progress.step(
            f"{len(listed)} roles, {len(users)} users, {len(groups)} groups",
            done=self.done,
            total=self.total,
        )

        for summary in listed:
            self._next(f"role {summary['RoleName']}")
            self._role(iam, summary, rows, result)
        result.roles = len(rows.roles)

        report = self._credential_report(iam, result) if users else None
        result.credential_report = report is not None
        for summary in users:
            self._next(f"user {summary['UserName']}")
            self._user(iam, summary, report or {}, rows, result)
        result.users = len(rows.users)

        for summary in groups:
            self._next(f"group {summary['GroupName']}")
            self._group(iam, summary, rows, result)
        result.groups = len(rows.groups)

        policies = self._policy_list(iam, rows, result)
        self.total += len(policies)
        self.progress.set_total(self.total)
        for arn, info in sorted(policies.items()):
            self._next(f"managed policy {info.get('PolicyName') or arn.rsplit('/', 1)[-1]}")
            rows.managed.append(self._managed_row(iam, snap_id, arn, info, result))
            rows.entities.extend(self._entities(iam, snap_id, arn, result))
        result.managed_policies = len(rows.managed)

        with closing(self.db_path) as conn:
            rows.store(conn)
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
        self.progress.step("finished", done=self.total, total=self.total)
        return result

    def _next(self, text: str) -> None:
        self.progress.check()
        self.done += 1
        self.progress.step(text, done=self.done, total=self.total)

    # -- roles -------------------------------------------------------------------------

    def _role(self, iam: Any, summary: dict[str, Any], rows: _Rows, result: CollectResult):
        name = summary["RoleName"]
        rows.roles.append(self._role_row(iam, rows.snap_id, summary, result))
        for att in self._optional(
            result,
            f"iam:ListAttachedRolePolicies ({name})",
            lambda: _paginate(
                iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name
            ),
        ):
            arn = rows.attach(att)
            rows.role_policies.append(
                (rows.snap_id, name, "managed", rows.attached[arn], arn, None)
            )
        for pname in self._optional(
            result,
            f"iam:ListRolePolicies ({name})",
            lambda: _paginate(iam, "list_role_policies", "PolicyNames", RoleName=name),
        ):
            doc = self._inline_document(
                result,
                f"iam:GetRolePolicy ({name}/{pname})",
                lambda p=pname: iam.get_role_policy(RoleName=name, PolicyName=p),
            )
            rows.role_policies.append((rows.snap_id, name, "inline", pname, "", doc))
            result.inline_policies += 1

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

    # -- users -------------------------------------------------------------------------

    def _credential_report(
        self, iam: Any, result: CollectResult
    ) -> dict[str, dict[str, Any]] | None:
        """The parsed credential report, or None (then per-user calls are used)."""
        self.progress.check()
        self.progress.step("iam:GenerateCredentialReport")
        try:
            for attempt in range(REPORT_ATTEMPTS):
                state = iam.generate_credential_report().get("State", "")
                if state == "COMPLETE":
                    break
                if attempt + 1 < REPORT_ATTEMPTS:
                    self.progress.check()
                    # 0.25s, 0.5s, 1s, ... up to report_wait: small reports are quick.
                    time.sleep(min(self.report_wait, 0.25 * 2**attempt))
            else:
                msg = "credential report not ready in time; per-user calls used instead"
                log.warning(msg)
                result.warnings.append(msg)
                return None
            content = iam.get_credential_report().get("Content", b"")
            return parse_credential_report(content)
        except (BotoCoreError, ClientError, ValueError, csv.Error) as exc:
            msg = (
                f"iam:GenerateCredentialReport/GetCredentialReport skipped ({error_code(exc)}); "
                "per-user calls used instead"
            )
            log.warning(msg)
            result.warnings.append(msg)
            return None

    def _user(
        self,
        iam: Any,
        summary: dict[str, Any],
        report: dict[str, dict[str, Any]],
        rows: _Rows,
        result: CollectResult,
    ) -> None:
        name = summary["UserName"]
        snap_id = rows.snap_id
        user = summary
        try:
            user = iam.get_user(UserName=name)["User"]
        except (BotoCoreError, ClientError) as exc:
            msg = f"iam:GetUser ({name}) skipped ({error_code(exc)}); ListUsers data used"
            log.warning(msg)
            result.warnings.append(msg)
        boundary = (user.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn", "")

        for g in self._optional(
            result,
            f"iam:ListGroupsForUser ({name})",
            lambda: _paginate(iam, "list_groups_for_user", "Groups", UserName=name),
        ):
            rows.members.add((snap_id, g["GroupName"], name))
        self._identity_policies(iam, "user", name, rows, result)

        meta = report.get(name)
        if meta is not None:
            source = "report"
            password, mfa, mfa_devices = meta["password_enabled"], meta["mfa_active"], None
            password_used = meta["password_last_used"]
        else:
            source = "api"
            password = self._login_profile(iam, name, result)
            devices = self._optional(
                result,
                f"iam:ListMFADevices ({name})",
                lambda: _paginate(iam, "list_mfa_devices", "MFADevices", UserName=name),
                missing=None,
            )
            mfa_devices = None if devices is None else len(devices)
            mfa = None if devices is None else bool(devices)
            password_used = iso_time(user.get("PasswordLastUsed"))
        rows.users.append(
            (
                snap_id,
                name,
                user.get("UserId", ""),
                user.get("Arn", ""),
                user.get("Path", "/"),
                iso_time(user.get("CreateDate")),
                boundary,
                _flag(password),
                password_used or iso_time(user.get("PasswordLastUsed")),
                _flag(mfa),
                mfa_devices,
                source,
            )
        )
        slots = list((meta or {}).get("keys") or [])
        for key in self._optional(
            result,
            f"iam:ListAccessKeys ({name})",
            lambda: _paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=name),
        ):
            rows.keys.append(self._key_row(iam, snap_id, name, key, slots, result))

    def _login_profile(self, iam: Any, name: str, result: CollectResult) -> bool | None:
        """Whether the user has a console password (the profile's existence only)."""
        try:
            iam.get_login_profile(UserName=name)
        except ClientError as exc:
            if error_code(exc) == "NoSuchEntity":
                return False
            self._warn(result, f"iam:GetLoginProfile ({name}) skipped ({error_code(exc)})")
            return None
        except BotoCoreError as exc:
            self._warn(result, f"iam:GetLoginProfile ({name}) skipped ({error_code(exc)})")
            return None
        return True

    def _key_row(
        self,
        iam: Any,
        snap_id: int,
        user: str,
        key: dict[str, Any],
        slots: list[dict[str, Any]],
        result: CollectResult,
    ) -> tuple[Any, ...]:
        """Id, status, age and last use of an access key. Last use comes from the
        credential report slot rotated at the key's creation time, else from
        iam:GetAccessKeyLastUsed."""
        key_id = key.get("AccessKeyId", "")
        created = iso_time(key.get("CreateDate"))
        slot = next((s for s in slots if s["last_rotated"] == created), None)
        used_at = service = region = ""
        known = True
        if slot is not None:
            slots.remove(slot)
            used_at = slot["last_used_at"]
            service, region = slot["last_used_service"], slot["last_used_region"]
        else:
            try:
                last = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed")
                last = last or {}
                used_at = iso_time(last.get("LastUsedDate"))
                service = _report_value(last.get("ServiceName"))
                region = _report_value(last.get("Region"))
            except (BotoCoreError, ClientError) as exc:
                # The key id stays out of warnings and logs: the user name is enough.
                self._warn(result, f"iam:GetAccessKeyLastUsed ({user}) skipped ({error_code(exc)})")
                known = False
        return (
            snap_id,
            user,
            key_id,
            key.get("Status", ""),
            created,
            used_at,
            service,
            region,
            int(known),
        )

    # -- groups ------------------------------------------------------------------------

    def _group(self, iam: Any, summary: dict[str, Any], rows: _Rows, result: CollectResult):
        name = summary["GroupName"]
        rows.groups.append(
            (
                rows.snap_id,
                name,
                summary.get("GroupId", ""),
                summary.get("Arn", ""),
                summary.get("Path", "/"),
                iso_time(summary.get("CreateDate")),
            )
        )
        for u in self._optional(
            result,
            f"iam:GetGroup ({name})",
            lambda: _paginate(iam, "get_group", "Users", GroupName=name),
        ):
            rows.members.add((rows.snap_id, name, u["UserName"]))
        self._identity_policies(iam, "group", name, rows, result)

    # -- user and group policies -------------------------------------------------------

    def _identity_policies(
        self, iam: Any, ptype: str, name: str, rows: _Rows, result: CollectResult
    ) -> None:
        """Attached and inline policies of a user or group (iam:*User* / iam:*Group*)."""
        label = ptype.capitalize()  # User | Group
        key = f"{label}Name"
        snake = ptype  # user | group
        for att in self._optional(
            result,
            f"iam:ListAttached{label}Policies ({name})",
            lambda: _paginate(
                iam, f"list_attached_{snake}_policies", "AttachedPolicies", **{key: name}
            ),
        ):
            arn = rows.attach(att)
            rows.identity.append(
                (rows.snap_id, ptype, name, "managed", rows.attached[arn], arn, None)
            )
        get_inline = getattr(iam, f"get_{snake}_policy")
        for pname in self._optional(
            result,
            f"iam:List{label}Policies ({name})",
            lambda: _paginate(iam, f"list_{snake}_policies", "PolicyNames", **{key: name}),
        ):
            doc = self._inline_document(
                result,
                f"iam:Get{label}Policy ({name}/{pname})",
                lambda p=pname: get_inline(**{key: name}, PolicyName=p),
            )
            rows.identity.append((rows.snap_id, ptype, name, "inline", pname, "", doc))
            result.inline_policies += 1

    def _inline_document(self, result: CollectResult, what: str, fn: Callable[[], Any]) -> Any:
        """The JSON text of an inline policy document (None if it could not be read)."""
        try:
            return json.dumps(decode_document(fn()["PolicyDocument"]))
        except (BotoCoreError, ClientError, ValueError) as exc:
            self._warn(result, f"{what} skipped ({error_code(exc)})")
            return None

    # -- managed policies --------------------------------------------------------------

    def _policy_list(
        self, iam: Any, rows: _Rows, result: CollectResult
    ) -> dict[str, dict[str, Any]]:
        """``{arn: ListPolicies entry}``: every customer managed policy (attached or not),
        every attached AWS managed policy and anything the roles, users and groups attach
        (an empty entry when ListPolicies is not allowed)."""
        out: dict[str, dict[str, Any]] = {
            arn: {"PolicyName": n} for arn, n in rows.attached.items()
        }
        for what, kwargs in (
            ("iam:ListPolicies (Scope=Local)", {"Scope": "Local"}),
            ("iam:ListPolicies (Scope=AWS, attached)", {"Scope": "AWS", "OnlyAttached": True}),
        ):
            self.progress.check()
            self.progress.step(what)
            for p in self._optional(
                result, what, lambda kw=kwargs: _paginate(iam, "list_policies", "Policies", **kw)
            ):
                out[p["Arn"]] = p
        return out

    def _managed_row(
        self, iam: Any, snap_id: int, arn: str, info: dict[str, Any], result: CollectResult
    ) -> tuple[Any, ...]:
        name = info.get("PolicyName") or arn.rsplit("/", 1)[-1]
        pol, doc = dict(info), None
        try:
            pol.update(iam.get_policy(PolicyArn=arn)["Policy"])
            name = pol.get("PolicyName", name)
            version = pol.get("DefaultVersionId", "")
            raw = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]
            doc = decode_document(raw.get("Document"))
        except (BotoCoreError, ClientError, ValueError) as exc:
            self._warn(
                result, f"iam:GetPolicy/GetPolicyVersion ({name}) skipped ({error_code(exc)})"
            )
        versions = [
            {
                "id": v.get("VersionId", ""),
                "default": bool(v.get("IsDefaultVersion")),
                "created": iso_time(v.get("CreateDate")),
            }
            for v in self._optional(
                result,
                f"iam:ListPolicyVersions ({name})",
                lambda: _paginate(iam, "list_policy_versions", "Versions", PolicyArn=arn),
            )
        ]
        count = pol.get("AttachmentCount")
        return (
            snap_id,
            arn,
            name,
            pol.get("Path", "/"),
            pol.get("DefaultVersionId", ""),
            int(is_aws_managed(arn)),
            None if doc is None else json.dumps(doc),
            pol.get("Description", "") or "",
            iso_time(pol.get("CreateDate")),
            iso_time(pol.get("UpdateDate")),
            None if count is None else int(count),
            json.dumps(versions),
        )

    def _entities(
        self, iam: Any, snap_id: int, arn: str, result: CollectResult
    ) -> list[tuple[Any, ...]]:
        """iam:ListEntitiesForPolicy: the roles, users and groups the policy is attached to."""
        out: list[tuple[Any, ...]] = []
        try:
            for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=arn):
                for etype, key, name_key in (
                    ("role", "PolicyRoles", "RoleName"),
                    ("user", "PolicyUsers", "UserName"),
                    ("group", "PolicyGroups", "GroupName"),
                ):
                    out.extend((snap_id, arn, etype, e[name_key]) for e in page.get(key, []))
        except (BotoCoreError, ClientError) as exc:
            name = arn.rsplit("/", 1)[-1]
            self._warn(result, f"iam:ListEntitiesForPolicy ({name}) skipped ({error_code(exc)})")
        return out

    # -- helpers -----------------------------------------------------------------------

    @staticmethod
    def _warn(result: CollectResult, msg: str) -> None:
        log.warning(msg)
        result.warnings.append(msg)

    @classmethod
    def _optional(
        cls, result: CollectResult, what: str, fn: Callable[[], Any], missing: Any = ()
    ) -> Any:
        """Optional calls: a missing permission downgrades to a warning (``missing`` is
        returned instead, an empty list by default)."""
        try:
            return fn()
        except (BotoCoreError, ClientError) as exc:
            cls._warn(result, f"{what} skipped ({error_code(exc)})")
            return [] if missing == () else missing


def _flag(value: bool | None) -> int | None:
    return None if value is None else int(value)


class _Rows:
    """Rows collected for one snapshot, written in one transaction at the end."""

    def __init__(self, snap_id: int):
        self.snap_id = snap_id
        self.roles: list[tuple[Any, ...]] = []
        self.role_policies: list[tuple[Any, ...]] = []
        self.users: list[tuple[Any, ...]] = []
        self.keys: list[tuple[Any, ...]] = []
        self.groups: list[tuple[Any, ...]] = []
        self.members: set[tuple[Any, ...]] = set()
        self.identity: list[tuple[Any, ...]] = []
        self.managed: list[tuple[Any, ...]] = []
        self.entities: list[tuple[Any, ...]] = []
        self.attached: dict[str, str] = {}  # managed policy arn -> name

    def attach(self, att: dict[str, Any]) -> str:
        arn = att.get("PolicyArn", "")
        self.attached[arn] = att.get("PolicyName", arn.rsplit("/", 1)[-1])
        return arn

    def store(self, conn: Any) -> None:
        conn.executemany(
            "INSERT INTO roles(snapshot_id, role_name, role_id, arn, path, description, "
            "create_date, max_session_duration, permissions_boundary, last_used_at, "
            "last_used_region, trust_doc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            self.roles,
        )
        conn.executemany(
            "INSERT OR REPLACE INTO role_policies(snapshot_id, role_name, kind, policy_name, "
            "policy_arn, document) VALUES(?,?,?,?,?,?)",
            self.role_policies,
        )
        conn.executemany(
            "INSERT INTO users(snapshot_id, user_name, user_id, arn, path, create_date, "
            "permissions_boundary, password_enabled, password_last_used, mfa_active, "
            "mfa_devices, metadata_source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            self.users,
        )
        conn.executemany(
            "INSERT OR REPLACE INTO user_access_keys(snapshot_id, user_name, key_id, status, "
            "create_date, last_used_at, last_used_service, last_used_region, last_used_known) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            self.keys,
        )
        conn.executemany(
            "INSERT INTO iam_groups(snapshot_id, group_name, group_id, arn, path, create_date) "
            "VALUES(?,?,?,?,?,?)",
            self.groups,
        )
        conn.executemany(
            "INSERT INTO group_members(snapshot_id, group_name, user_name) VALUES(?,?,?)",
            sorted(self.members),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO identity_policies(snapshot_id, principal_type, "
            "principal_name, kind, policy_name, policy_arn, document) VALUES(?,?,?,?,?,?,?)",
            self.identity,
        )
        conn.executemany(
            "INSERT INTO managed_policies(snapshot_id, arn, name, path, default_version, "
            "aws_managed, document, description, create_date, update_date, attachment_count, "
            "versions) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            self.managed,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO policy_entities(snapshot_id, arn, entity_type, entity_name) "
            "VALUES(?,?,?,?)",
            self.entities,
        )
