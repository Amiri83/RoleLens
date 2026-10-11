"""Column filters of the Roles, Users and Policies pages, shared by each page and its
Excel export.

The filters travel as query parameters (roles: ``q``, ``used``, ``trust``, ``slr``,
``boundary``, ``inline``, ``pmin``, ``pmax``, ``finding``; see :class:`UserFilters` and
:class:`PolicyFilters` for the others), so the page, its no-JavaScript form, a bookmarked
URL and the ``.xlsx`` export always agree on what "the current view" is. Unknown values
are ignored.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from typing import Any

from .findings import rules_for
from .policy import TRUST_TYPES

LAST_USED = {
    "never": "never used",
    "30": "last used > 30 days ago",
    "90": "last used > 90 days ago",
    "180": "last used > 180 days ago",
}
YES_NO = {"yes": "yes", "no": "no"}


def _finding_choices(principal: str) -> dict[str, str]:
    """Risk finding filter: a rule id, "any" (at least one finding) or "none"."""
    rules = rules_for(principal)
    return {"any": "any finding", "none": "no finding", **{k: r.title for k, r in rules.items()}}


FINDINGS = _finding_choices("role")
USER_FINDINGS = _finding_choices("user")
KEY_AGE = {
    "90": "active key > 90 days old",
    "180": "active key > 180 days old",
    "365": "active key > 365 days old",
}
IDLE = {
    "30": "no activity > 30 days",
    "90": "no activity > 90 days",
    "180": "no activity > 180 days",
}
PERMISSION_SOURCES = {
    "direct": "only direct policies",
    "group": "only via groups",
    "both": "direct and via groups",
    "has-direct": "has direct policies",
    "none": "no policies",
}
POLICY_TYPES = {"managed": "customer managed", "aws": "AWS managed"}
USED_BY = {"role": "used by a role", "user": "used by a user", "group": "used by a group"}
MAX_POLICIES = 10_000
MAX_QUERY = 200


def _choice(value: str | None, allowed: Mapping[str, str]) -> str:
    value = (value or "").strip()
    return value if value in allowed else ""


def _count(value: str | None) -> int | None:
    value = (value or "").strip()
    if not value.isdigit():
        return None
    return min(int(value), MAX_POLICIES)


def _tri(flag: bool | None, wanted: str) -> bool:
    """``wanted`` (yes | no | '') against a flag; an unknown flag (None) never matches."""
    if not wanted:
        return True
    return flag is not None and flag == (wanted == "yes")


def _finding_matches(wanted: str, found: Mapping[str, str]) -> bool:
    if not wanted:
        return True
    if wanted == "any":
        return bool(found)
    if wanted == "none":
        return not found
    return wanted in found


class _Filters:
    """Query-string helpers of the filter dataclasses below."""

    def apply(self, rows: Iterable[Mapping[str, Any]]) -> list[Any]:
        return [r for r in rows if self.matches(r)]  # type: ignore[attr-defined]

    def query(self) -> dict[str, str]:
        """The non-empty filters as query parameters (for links and the export URL)."""
        out = {}
        for f in fields(self):  # type: ignore[arg-type]
            value = getattr(self, f.name)
            if value not in ("", None):
                out[f.name] = str(value)
        return out

    @property
    def active(self) -> bool:
        return bool(self.query())


@dataclass(frozen=True)
class RoleFilters(_Filters):
    q: str = ""  # name, path, ARN or trusted principal (substring, case-insensitive)
    used: str = ""  # LAST_USED key
    trust: str = ""  # TRUST_TYPES key
    slr: str = ""  # service-linked: yes | no
    boundary: str = ""  # has a permissions boundary: yes | no
    inline: str = ""  # has inline policies: yes | no
    pmin: int | None = None  # number of policies (managed + inline), inclusive
    pmax: int | None = None
    finding: str = ""  # FINDINGS key

    @classmethod
    def from_args(cls, args: Mapping[str, str]) -> RoleFilters:
        return cls(
            q=(args.get("q") or "").strip()[:MAX_QUERY],
            used=_choice(args.get("used"), LAST_USED),
            trust=_choice(args.get("trust"), TRUST_TYPES),
            slr=_choice(args.get("slr"), YES_NO),
            boundary=_choice(args.get("boundary"), YES_NO),
            inline=_choice(args.get("inline"), YES_NO),
            pmin=_count(args.get("pmin")),
            pmax=_count(args.get("pmax")),
            finding=_choice(args.get("finding"), FINDINGS),
        )

    def matches(self, row: Mapping[str, Any]) -> bool:
        if self.q:
            haystack = " ".join([row["name"], row["path"], row["arn"], *row["principals"]])
            if self.q.lower() not in haystack.lower():
                return False
        days = row["last_used_days"]
        if self.used == "never" and row["last_used_at"]:
            return False
        if self.used.isdigit() and (days is None or days <= int(self.used)):
            return False
        if self.trust and self.trust not in row["trust_types"]:
            return False
        if not (
            _tri(row["service_linked"], self.slr)
            and _tri(bool(row["boundary"]), self.boundary)
            and _tri(row["inline"] > 0, self.inline)
        ):
            return False
        if self.pmin is not None and row["policies"] < self.pmin:
            return False
        if self.pmax is not None and row["policies"] > self.pmax:
            return False
        return _finding_matches(self.finding, row.get("findings") or {})

    def describe(self) -> list[tuple[str, str]]:
        """``(filter, value)`` pairs of the active filters, for people (Excel export)."""
        out = []
        if self.q:
            out.append(("Search", self.q))
        if self.used:
            out.append(("Last used", LAST_USED[self.used]))
        if self.trust:
            out.append(("Trust type", TRUST_TYPES[self.trust]))
        for label, value in (
            ("Service-linked", self.slr),
            ("Permissions boundary", self.boundary),
            ("Inline policies", self.inline),
        ):
            if value:
                out.append((label, value))
        if self.pmin is not None or self.pmax is not None:
            low = "0" if self.pmin is None else str(self.pmin)
            high = "any" if self.pmax is None else str(self.pmax)
            out.append(("Number of policies", f"{low} to {high}"))
        if self.finding:
            out.append(("Finding", FINDINGS[self.finding]))
        return out


@dataclass(frozen=True)
class UserFilters(_Filters):
    """Filters of the Users page (rows of :func:`rolelens.queries.user_list`)."""

    q: str = ""  # name, path, ARN or group (substring, case-insensitive)
    console: str = ""  # has a console password: yes | no
    mfa: str = ""  # MFA active: yes | no
    key_age: str = ""  # KEY_AGE key: an active access key older than that many days
    idle: str = ""  # IDLE key: no console sign-in or key use for that many days
    inline: str = ""  # has inline policies of its own: yes | no
    perms: str = ""  # PERMISSION_SOURCES key
    finding: str = ""  # USER_FINDINGS key

    @classmethod
    def from_args(cls, args: Mapping[str, str]) -> UserFilters:
        return cls(
            q=(args.get("q") or "").strip()[:MAX_QUERY],
            console=_choice(args.get("console"), YES_NO),
            mfa=_choice(args.get("mfa"), YES_NO),
            key_age=_choice(args.get("key_age"), KEY_AGE),
            idle=_choice(args.get("idle"), IDLE),
            inline=_choice(args.get("inline"), YES_NO),
            perms=_choice(args.get("perms"), PERMISSION_SOURCES),
            finding=_choice(args.get("finding"), USER_FINDINGS),
        )

    def matches(self, row: Mapping[str, Any]) -> bool:
        if self.q:
            haystack = " ".join([row["name"], row["path"], row["arn"], *row["groups"]])
            if self.q.lower() not in haystack.lower():
                return False
        if not (
            _tri(row["console"], self.console)
            and _tri(row["mfa"], self.mfa)
            and _tri(row["inline"] > 0, self.inline)
        ):
            return False
        age = row["key_age_days"]
        if self.key_age and (age is None or age <= int(self.key_age)):
            return False
        idle = row["idle_days"]
        if self.idle and (idle is None or idle <= int(self.idle)):
            return False
        if self.perms == "has-direct":
            if row["permissions"] not in ("direct", "both"):
                return False
        elif self.perms and row["permissions"] != self.perms:
            return False
        return _finding_matches(self.finding, row.get("findings") or {})

    def describe(self) -> list[tuple[str, str]]:
        out = []
        if self.q:
            out.append(("Search", self.q))
        for label, value in (
            ("Console access", self.console),
            ("MFA", self.mfa),
            ("Inline policies", self.inline),
        ):
            if value:
                out.append((label, value))
        if self.key_age:
            out.append(("Access keys", KEY_AGE[self.key_age]))
        if self.idle:
            out.append(("Activity", IDLE[self.idle]))
        if self.perms:
            out.append(("Permissions", PERMISSION_SOURCES[self.perms]))
        if self.finding:
            out.append(("Finding", USER_FINDINGS[self.finding]))
        return out


@dataclass(frozen=True)
class PolicyFilters(_Filters):
    """Filters of the Policies page (rows of :func:`rolelens.queries.policy_list`)."""

    q: str = ""  # name, path, ARN, description or an entity using it
    type: str = ""  # POLICY_TYPES key
    unattached: str = ""  # attached to nothing: yes | no
    used_by: str = ""  # USED_BY key

    @classmethod
    def from_args(cls, args: Mapping[str, str]) -> PolicyFilters:
        return cls(
            q=(args.get("q") or "").strip()[:MAX_QUERY],
            type=_choice(args.get("type"), POLICY_TYPES),
            unattached=_choice(args.get("unattached"), YES_NO),
            used_by=_choice(args.get("used_by"), USED_BY),
        )

    def matches(self, row: Mapping[str, Any]) -> bool:
        if self.q:
            haystack = " ".join(
                [row["name"], row["path"], row["arn"], row["description"]]
                + row["roles"]
                + row["users"]
                + row["groups"]
            )
            if self.q.lower() not in haystack.lower():
                return False
        if self.type and row["kind"] != self.type:
            return False
        if not _tri(row["unattached"], self.unattached):
            return False
        return not self.used_by or bool(row[f"{self.used_by}s"])

    def describe(self) -> list[tuple[str, str]]:
        out = []
        if self.q:
            out.append(("Search", self.q))
        if self.type:
            out.append(("Type", POLICY_TYPES[self.type]))
        if self.unattached:
            out.append(("Unattached", self.unattached))
        if self.used_by:
            out.append(("Used by", USED_BY[self.used_by]))
        return out
