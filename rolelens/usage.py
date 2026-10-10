"""Usage data of a snapshot's roles, from three optional, read-only sources.

* **Service last accessed** — ``iam:GenerateServiceLastAccessedDetails`` (service level)
  per role, read back with ``iam:GetServiceLastAccessedDetails``: which services the
  role's policies grant and when the role last used each.
* **CloudTrail** — ``cloudtrail:LookupEvents`` for ``AssumeRole``,
  ``AssumeRoleWithWebIdentity`` and ``AssumeRoleWithSAML`` over the last
  :data:`WINDOW_DAYS` days (the account region and ``us-east-1``, where calls to the
  global STS endpoint are logged), aggregated per role, caller and source IP / service.
* **Access Analyzer** — ``access-analyzer:ListAnalyzers`` and ``ListFindings`` /
  ``ListFindingsV2`` (active findings) when an analyzer exists in the account region.

A source the credentials may not use becomes a warning; the others still run. These are
the only calls made (the guard of :mod:`rolelens.aws` refuses anything else). Source IP
addresses are stored in the local database only, never logged.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .aws import AwsGateway, error_code, iso_time
from .db import closing
from .jobs import NullProgress, Progress

log = logging.getLogger(__name__)

WINDOW_DAYS = 90
ASSUME_EVENTS = ("AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML")
GLOBAL_REGION = "us-east-1"
MAX_EVENTS = 20_000  # per event name and region; the rest is reported as truncated
MAX_ANALYZER_FINDINGS = 2_000
POLL_INTERVAL = 2.0  # seconds between GetServiceLastAccessedDetails rounds
POLL_TIMEOUT = 300.0  # seconds for every report of one run together
SOURCES = ("access_advisor", "cloudtrail", "access_analyzer")
SOURCE_LABELS = {
    "access_advisor": "Service last accessed (iam:GenerateServiceLastAccessedDetails)",
    "cloudtrail": "CloudTrail AssumeRole events (cloudtrail:LookupEvents)",
    "access_analyzer": "IAM Access Analyzer (access-analyzer:ListFindings)",
}
DENIED_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnrecognizedClient"}
)


@dataclass
class UsageResult:
    snapshot_id: int
    services: int = 0
    events: int = 0
    analyzer_findings: int = 0
    sources: dict[str, str] = field(default_factory=dict)  # source -> ok | unavailable (...)
    warnings: list[str] = field(default_factory=list)


class SourceUnavailable(Exception):  # noqa: N818 - a control-flow signal
    """The credentials may not use a source at all: skip it with a warning."""


# -- CloudTrail aggregation (pure) ---------------------------------------------------


def _caller(record: dict[str, Any]) -> tuple[str, str]:
    """``(principal, type)`` of the identity that called sts:AssumeRole*."""
    ui = record.get("userIdentity") or {}
    ptype = str(ui.get("type", ""))
    if ptype == "AWSService":
        return str(ui.get("invokedBy") or record.get("sourceIPAddress") or "AWS service"), ptype
    if ptype == "AssumedRole":
        issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
        return str(issuer or ui.get("arn") or ui.get("principalId", "")), ptype
    if ptype in ("WebIdentityUser", "SAMLUser"):
        provider = str(ui.get("identityProvider", ""))
        user = str(ui.get("userName", ""))
        return (f"{provider} ({user})" if user else provider or "federated user"), ptype
    if ptype == "AWSAccount":
        return f"account {ui.get('accountId', '')}".strip(), ptype
    return str(ui.get("arn") or ui.get("principalId") or ptype or "unknown"), ptype


def aggregate_assume_events(
    records: Iterable[dict[str, Any]], role_names: dict[str, str]
) -> list[dict[str, Any]]:
    """Rows ``{role_name, event_name, principal, principal_type, source, count, errors,
    last_time}`` from CloudTrail records (``CloudTrailEvent`` decoded).

    ``role_names`` maps role ARNs to names; an unknown ARN keeps its last path segment.
    Records are counted once per ``eventID``.
    """
    rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    seen: set[str] = set()
    for rec in records:
        event_id = str(rec.get("eventID", ""))
        if event_id:
            if event_id in seen:
                continue
            seen.add(event_id)
        params = rec.get("requestParameters") or {}
        arn = str(params.get("roleArn", "")) if isinstance(params, dict) else ""
        if not arn:
            continue
        role = role_names.get(arn) or arn.rsplit("/", 1)[-1]
        event_name = str(rec.get("eventName", ""))
        principal, ptype = _caller(rec)
        source = str(rec.get("sourceIPAddress", ""))
        key = (role, event_name, principal, source)
        row = rows.get(key)
        if row is None:
            row = rows[key] = {
                "role_name": role,
                "event_name": event_name,
                "principal": principal,
                "principal_type": ptype,
                "source": source,
                "count": 0,
                "errors": 0,
                "last_time": "",
            }
        row["count"] += 1
        if rec.get("errorCode"):
            row["errors"] += 1
        when = iso_time(_parse_time(rec.get("eventTime")))
        row["last_time"] = max(row["last_time"], when)
    return sorted(
        rows.values(), key=lambda r: (r["role_name"].lower(), -r["count"], r["principal"])
    )


def _parse_time(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    return value


# -- collection ----------------------------------------------------------------------


def _denied(exc: Exception) -> bool:
    return isinstance(exc, ClientError) and error_code(exc) in DENIED_CODES


class UsageCollector:
    def __init__(
        self,
        gateway: AwsGateway,
        db_path: Path,
        snapshot_id: int,
        progress: Progress | None = None,
        *,
        now: datetime | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.gw = gateway
        self.db_path = db_path
        self.snap_id = snapshot_id
        self.progress: Progress = progress or NullProgress()
        self.now = now or datetime.now(UTC)
        self.sleep = sleep
        self.clock = clock

    def run(self) -> UsageResult:
        result = UsageResult(snapshot_id=self.snap_id)
        with closing(self.db_path) as conn:
            roles = [
                (r["role_name"], r["arn"])
                for r in conn.execute(
                    "SELECT role_name, arn FROM roles WHERE snapshot_id=? ORDER BY role_name",
                    (self.snap_id,),
                )
            ]
        log.info("usage collection started snapshot=%s roles=%d", self.snap_id, len(roles))
        total = len(roles) * 2 + len(ASSUME_EVENTS) * 2 + 2
        self.progress.set_total(total)
        services = self._source(result, "access_advisor", lambda: self._access_advisor(roles))
        events = self._source(result, "cloudtrail", lambda: self._cloudtrail(roles, result))
        findings = self._source(result, "access_analyzer", lambda: self._analyzer(result))
        with closing(self.db_path) as conn:
            for table in (
                "service_last_accessed",
                "assume_events",
                "analyzer_findings",
                "usage_runs",
            ):
                conn.execute(f"DELETE FROM {table} WHERE snapshot_id=?", (self.snap_id,))  # noqa: S608
            conn.executemany(
                "INSERT OR REPLACE INTO service_last_accessed(snapshot_id, role_name, "
                "service_namespace, service_name, last_authenticated, last_region) "
                "VALUES(?,?,?,?,?,?)",
                [(self.snap_id, *row) for row in services or []],
            )
            conn.executemany(
                "INSERT INTO assume_events(snapshot_id, role_name, event_name, principal, "
                "principal_type, source, count, errors, last_time) VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    (
                        self.snap_id,
                        e["role_name"],
                        e["event_name"],
                        e["principal"],
                        e["principal_type"],
                        e["source"],
                        e["count"],
                        e["errors"],
                        e["last_time"],
                    )
                    for e in events or []
                ],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO analyzer_findings(snapshot_id, analyzer, finding_id, "
                "resource, resource_type, finding_type, status, detail, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                [(self.snap_id, *row) for row in findings or []],
            )
            conn.execute(
                "INSERT INTO usage_runs(snapshot_id, collected_at, window_days, sources, "
                "warnings) VALUES(?,?,?,?,?)",
                (
                    self.snap_id,
                    self.now.isoformat(timespec="seconds"),
                    WINDOW_DAYS,
                    json.dumps(result.sources),
                    json.dumps(result.warnings),
                ),
            )
        result.services = len(services or [])
        result.events = sum(e["count"] for e in events or [])
        result.analyzer_findings = len(findings or [])
        self.progress.step("finished", done=total, total=total)
        log.info(
            "usage collection finished snapshot=%s services=%d events=%d findings=%d warnings=%d",
            self.snap_id,
            result.services,
            result.events,
            result.analyzer_findings,
            len(result.warnings),
        )
        return result

    def _source(self, result: UsageResult, source: str, fn: Callable[[], Any]) -> Any:
        """Run one source; a missing permission (or the source failing) is a warning."""
        self.progress.check()
        try:
            out = fn()
        except SourceUnavailable as exc:
            result.sources[source] = f"unavailable ({exc})"
            result.warnings.append(f"{SOURCE_LABELS[source]} skipped ({exc})")
            log.warning("usage source %s skipped (%s)", source, exc)
            return None
        except (BotoCoreError, ClientError) as exc:
            code = error_code(exc)
            result.sources[source] = f"unavailable ({code})"
            result.warnings.append(f"{SOURCE_LABELS[source]} skipped ({code})")
            log.warning("usage source %s skipped (%s)", source, code)
            return None
        result.sources.setdefault(source, "ok")
        return out

    # -- service last accessed -------------------------------------------------------

    def _access_advisor(self, roles: list[tuple[str, str]]) -> list[tuple[Any, ...]]:
        iam = self.gw.client("iam")
        jobs: dict[str, str] = {}  # role -> job id
        for name, arn in roles:
            self.progress.check()
            self.progress.step(f"iam:GenerateServiceLastAccessedDetails {name}")
            try:
                resp = iam.generate_service_last_accessed_details(
                    Arn=arn, Granularity="SERVICE_LEVEL"
                )
            except ClientError as exc:
                if _denied(exc):
                    raise SourceUnavailable(error_code(exc)) from None
                log.warning(
                    "service last accessed report of %s skipped (%s)", name, error_code(exc)
                )
                continue
            jobs[name] = resp["JobId"]
            self.progress.advance()
        rows: list[tuple[Any, ...]] = []
        deadline = self.clock() + POLL_TIMEOUT
        while jobs:
            for name, job_id in list(jobs.items()):
                self.progress.check()
                services = self._report(iam, job_id)
                if services is None:
                    continue
                del jobs[name]
                self.progress.step(f"iam:GetServiceLastAccessedDetails {name}")
                self.progress.advance()
                for s in services:
                    rows.append(
                        (
                            name,
                            s.get("ServiceNamespace", ""),
                            s.get("ServiceName", ""),
                            iso_time(s.get("LastAuthenticated")),
                            s.get("LastAuthenticatedRegion", "") or "",
                        )
                    )
            if not jobs:
                break
            if self.clock() >= deadline:
                raise SourceUnavailable(f"{len(jobs)} report(s) not ready in time")
            self.sleep(POLL_INTERVAL)
        return rows

    @staticmethod
    def _report(iam: Any, job_id: str) -> list[dict[str, Any]] | None:
        """The services of a finished report; None while it is still in progress."""
        services: list[dict[str, Any]] = []
        marker = None
        while True:
            kwargs: dict[str, Any] = {"JobId": job_id}
            if marker:
                kwargs["Marker"] = marker
            resp = iam.get_service_last_accessed_details(**kwargs)
            status = resp.get("JobStatus", "")
            if status == "IN_PROGRESS":
                return None
            if status == "FAILED":
                log.warning("service last accessed report failed (job %s)", job_id)
                return []
            services.extend(resp.get("ServicesLastAccessed", []))
            if not resp.get("IsTruncated"):
                return services
            marker = resp.get("Marker")

    # -- CloudTrail ------------------------------------------------------------------

    def _cloudtrail(
        self, roles: list[tuple[str, str]], result: UsageResult
    ) -> list[dict[str, Any]]:
        names = {arn: name for name, arn in roles if arn}
        start = self.now - timedelta(days=WINDOW_DAYS)
        regions = list(dict.fromkeys([self.gw.region or GLOBAL_REGION, GLOBAL_REGION]))
        records: list[dict[str, Any]] = []
        for region in regions:
            ct = self.gw.client("cloudtrail", region=region)
            for event_name in ASSUME_EVENTS:
                self.progress.check()
                self.progress.step(f"cloudtrail:LookupEvents {event_name} ({region})")
                n = 0
                pages = ct.get_paginator("lookup_events").paginate(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                    StartTime=start,
                    EndTime=self.now,
                )
                try:
                    for page in pages:
                        self.progress.check()
                        for ev in page.get("Events", []):
                            try:
                                records.append(json.loads(ev.get("CloudTrailEvent") or "{}"))
                            except ValueError:
                                continue
                            n += 1
                        if n >= MAX_EVENTS:
                            result.warnings.append(
                                f"CloudTrail {event_name} ({region}): only the latest "
                                f"{MAX_EVENTS} events were read"
                            )
                            break
                except ClientError as exc:
                    if _denied(exc):
                        raise SourceUnavailable(error_code(exc)) from None
                    raise
                self.progress.advance()
        return aggregate_assume_events(records, names)

    # -- Access Analyzer -------------------------------------------------------------

    def _analyzer(self, result: UsageResult) -> list[tuple[Any, ...]]:
        aa = self.gw.client("accessanalyzer")
        self.progress.step("access-analyzer:ListAnalyzers")
        try:
            analyzers = [
                a
                for page in aa.get_paginator("list_analyzers").paginate()
                for a in page.get("analyzers", [])
            ]
        except ClientError as exc:
            if _denied(exc):
                raise SourceUnavailable(error_code(exc)) from None
            raise
        active = [a for a in analyzers if a.get("status", "ACTIVE") == "ACTIVE"]
        if not active:
            result.sources["access_analyzer"] = "no analyzer"
            return []
        rows: list[tuple[Any, ...]] = []
        for a in active:
            self.progress.check()
            arn, name = a.get("arn", ""), a.get("name", "")
            unused = str(a.get("type", "")).endswith("UNUSED_ACCESS")
            op = "list_findings_v2" if unused else "list_findings"
            self.progress.step(
                f"access-analyzer:{'ListFindingsV2' if unused else 'ListFindings'} {name}"
            )
            try:
                pages = aa.get_paginator(op).paginate(
                    analyzerArn=arn, filter={"status": {"eq": ["ACTIVE"]}}
                )
                for page in pages:
                    for f in page.get("findings", []):
                        rows.append(self._finding_row(name, f))
                    if len(rows) >= MAX_ANALYZER_FINDINGS:
                        break
            except ClientError as exc:
                if _denied(exc):
                    raise SourceUnavailable(error_code(exc)) from None
                result.warnings.append(
                    f"Access Analyzer findings of {name} skipped ({error_code(exc)})"
                )
            if len(rows) >= MAX_ANALYZER_FINDINGS:
                result.warnings.append(
                    f"Access Analyzer: only the first {MAX_ANALYZER_FINDINGS} findings were read"
                )
                break
        return rows[:MAX_ANALYZER_FINDINGS]

    @staticmethod
    def _finding_row(analyzer: str, f: dict[str, Any]) -> tuple[Any, ...]:
        parts = []
        if f.get("principal"):
            parts.append("principal " + ", ".join(f"{k}={v}" for k, v in f["principal"].items()))
        if f.get("action"):
            parts.append("actions " + ", ".join(map(str, f["action"])))
        if f.get("condition"):
            parts.append("condition " + json.dumps(f["condition"], sort_keys=True))
        if f.get("isPublic"):
            parts.append("public")
        return (
            analyzer,
            str(f.get("id", "")),
            str(f.get("resource", "")),
            str(f.get("resourceType", "")),
            str(f.get("findingType", "") or ("ExternalAccess" if f.get("principal") else "")),
            str(f.get("status", "")),
            "; ".join(parts),
            iso_time(f.get("updatedAt")),
        )
