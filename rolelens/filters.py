"""Column filters of the Roles page, shared by the page and its Excel export.

The filters travel as query parameters (``q``, ``used``, ``trust``, ``slr``,
``boundary``, ``inline``, ``pmin``, ``pmax``, ``finding``), so the page, its no-JavaScript
form, a bookmarked URL and ``/roles.xlsx`` always agree on what "the current view" is.
Unknown values are ignored.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from typing import Any

from .findings import RULES
from .policy import TRUST_TYPES

LAST_USED = {
    "never": "never used",
    "30": "last used > 30 days ago",
    "90": "last used > 90 days ago",
    "180": "last used > 180 days ago",
}
YES_NO = {"yes": "yes", "no": "no"}
# Risk finding filter: a rule id, "any" (at least one finding) or "none".
FINDINGS = {"any": "any finding", "none": "no finding", **{k: r.title for k, r in RULES.items()}}
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


def _tri(flag: bool, wanted: str) -> bool:
    return not wanted or flag == (wanted == "yes")


@dataclass(frozen=True)
class RoleFilters:
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
        if self.finding:
            found = row.get("findings") or {}
            if self.finding == "any":
                return bool(found)
            if self.finding == "none":
                return not found
            return self.finding in found
        return True

    def apply(self, rows: Iterable[Mapping[str, Any]]) -> list[Any]:
        return [r for r in rows if self.matches(r)]

    def query(self) -> dict[str, str]:
        """The non-empty filters as query parameters (for links and the export URL)."""
        out = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if value not in ("", None):
                out[f.name] = str(value)
        return out

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

    @property
    def active(self) -> bool:
        return bool(self.query())
