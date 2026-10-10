"""Excel export of the Roles page (openpyxl): the rows of the current filtered view.

Sheet "Roles" has a bold, frozen header row and an autofilter over every column; sheet
"Export" records the account, the snapshot time and the filters that were applied.
Every text cell is written as a string, so a value such as ``=cmd`` taken from a role
description can never become a formula.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

from .filters import RoleFilters
from .policy import TRUST_TYPES

DATE_FORMAT = "yyyy-mm-dd hh:mm"
HEADER_FILL = PatternFill("solid", fgColor="E8EDF3")


def _utc_naive(value: str) -> datetime | None:
    """Excel has no time zones: timestamps are written as naive UTC."""
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    if ts.tzinfo is not None:
        ts = ts.astimezone(UTC).replace(tzinfo=None)
    return ts


def _yes_no(flag: Any) -> str:
    return "yes" if flag else "no"


Column = tuple[str, int, Callable[[Mapping[str, Any]], Any]]
COLUMNS: list[Column] = [
    ("Role", 32, lambda r: r["name"]),
    ("Path", 18, lambda r: r["path"]),
    ("ARN", 48, lambda r: r["arn"]),
    ("Description", 36, lambda r: r["description"]),
    ("Last used (UTC)", 18, lambda r: _utc_naive(r["last_used_at"])),
    ("Last used region", 14, lambda r: r["last_used_region"]),
    ("Days since last use", 12, lambda r: r["last_used_days"]),
    ("Trust types", 22, lambda r: ", ".join(TRUST_TYPES[t] for t in r["trust_types"])),
    ("Trusted principals", 40, lambda r: ", ".join(r["principals"])),
    ("Service-linked", 10, lambda r: _yes_no(r["service_linked"])),
    ("Permissions boundary", 40, lambda r: r["boundary"]),
    ("Managed policies", 10, lambda r: r["managed"]),
    ("Inline policies", 10, lambda r: r["inline"]),
    ("Policies", 10, lambda r: r["policies"]),
]
HEADERS = [c[0] for c in COLUMNS]


def _put(ws: Any, row: int, col: int, value: Any) -> None:
    if isinstance(value, str):
        value = ILLEGAL_CHARACTERS_RE.sub("", value)
    cell = ws.cell(row=row, column=col, value=value)
    if isinstance(value, str):
        cell.data_type = "s"  # never a formula
    elif isinstance(value, datetime):
        cell.number_format = DATE_FORMAT


def roles_workbook(
    rows: Sequence[Mapping[str, Any]],
    filters: RoleFilters,
    *,
    account: str,
    taken_at: str,
    total: int,
    now: datetime | None = None,
) -> bytes:
    """The ``.xlsx`` file of ``rows`` (already filtered by ``filters``)."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Roles"
    bold = Font(bold=True)
    for col, (title, width, _get) in enumerate(COLUMNS, start=1):
        _put(ws, 1, col, title)
        ws.cell(row=1, column=col).font = bold
        ws.cell(row=1, column=col).fill = HEADER_FILL
        ws.column_dimensions[get_column_letter(col)].width = width
    for r, row in enumerate(rows, start=2):
        for col, (_title, _width, get) in enumerate(COLUMNS, start=1):
            _put(ws, r, col, get(row))
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{len(rows) + 1}"

    info = wb.create_sheet("Export")
    now = now or datetime.now(UTC)
    lines: list[tuple[str, Any]] = [
        ("Account", account),
        ("Collected (UTC)", _utc_naive(taken_at)),
        ("Exported (UTC)", _utc_naive(now.isoformat())),
        ("Roles", f"{len(rows)} of {total}"),
        ("Filters", "none" if not filters.active else ""),
        *filters.describe(),
    ]
    for r, (label, value) in enumerate(lines, start=1):
        _put(info, r, 1, label)
        info.cell(row=r, column=1).font = bold
        _put(info, r, 2, value)
    info.column_dimensions["A"].width = 22
    info.column_dimensions["B"].width = 48

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
