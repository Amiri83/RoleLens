"""Usage data: service last accessed, CloudTrail AssumeRole aggregation, Access Analyzer.

Real boto3 clients from :class:`AwsGateway` (so the read-only guard runs) with botocore
Stubber responses; nothing reaches AWS. Placeholder data only: account 123456789012,
role-a / role-b, documentation IP 192.0.2.10, oidc.example.com."""

import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.stub import Stubber

from rolelens.aws import AwsGateway, ReadOnlyViolation, is_read_only_operation
from rolelens.db import closing
from rolelens.usage import (
    ASSUME_EVENTS,
    WINDOW_DAYS,
    UsageCollector,
    aggregate_assume_events,
)

ACCOUNT = "123456789012"
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
ROLE_A = f"arn:aws:iam::{ACCOUNT}:role/role-a"
ROLE_B = f"arn:aws:iam::{ACCOUNT}:role/service/role-b"
CALLER = f"arn:aws:iam::{ACCOUNT}:role/role-ci"
IP = "192.0.2.10"
JOB_A = "00000000-0000-0000-0000-00000000000a"
JOB_B = "00000000-0000-0000-0000-00000000000b"


class StubGateway(AwsGateway):
    """One stubbed client per (service, region)."""

    def __init__(self, region="us-east-1"):
        super().__init__(boto3.session.Session(region_name=region))
        self.clients = {}
        self.stubs = {}

    def client(self, service, *, region=None, config=None):
        key = (service, region or self.region)
        if key not in self.clients:
            c = super().client(service, region=region, config=config)
            self.stubs[key] = Stubber(c)
            self.stubs[key].activate()
            self.clients[key] = c
        return self.clients[key]

    def stub(self, service, region=None):
        self.client(service, region=region)
        return self.stubs[(service, region or self.region)]


@pytest.fixture
def snap(db_path):
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO snapshots(id, taken_at, status, account_id) VALUES(1, ?, 'ok', ?)",
            (NOW.isoformat(), ACCOUNT),
        )
        for name, arn in (("role-a", ROLE_A), ("role-b", ROLE_B)):
            conn.execute(
                "INSERT INTO roles(snapshot_id, role_name, arn) VALUES(1, ?, ?)", (name, arn)
            )
    return 1


def _record(role_arn, *, event="AssumeRole", identity=None, source=IP, when=NOW, eid="e1", **kw):
    rec = {
        "eventID": eid,
        "eventName": event,
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sourceIPAddress": source,
        "userIdentity": identity
        or {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/role-ci/session-a",
            "sessionContext": {"sessionIssuer": {"arn": CALLER}},
        },
        "requestParameters": {"roleArn": role_arn, "roleSessionName": "session-a"},
    }
    rec.update(kw)
    return rec


# -- CloudTrail aggregation ----------------------------------------------------------


def test_aggregate_assume_events_counts_last_time_and_callers():
    lambda_identity = {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}
    web_identity = {
        "type": "WebIdentityUser",
        "identityProvider": "oidc.example.com",
        "userName": "repo:example/role-a:ref:refs/heads/main",
    }
    records = [
        _record(ROLE_A, eid="e1", when=NOW - timedelta(days=3)),
        _record(ROLE_A, eid="e2", when=NOW - timedelta(days=1)),
        _record(ROLE_A, eid="e2", when=NOW - timedelta(days=1)),  # same event twice
        _record(ROLE_A, eid="e3", errorCode="AccessDenied"),
        _record(ROLE_A, eid="e4", identity=lambda_identity, source="lambda.amazonaws.com"),
        _record(ROLE_B, eid="e5", event="AssumeRoleWithWebIdentity", identity=web_identity),
        _record(f"arn:aws:iam::{ACCOUNT}:role/role-gone", eid="e6"),  # not in the snapshot
        {"eventID": "e7", "eventName": "AssumeRole", "requestParameters": None},  # no role
    ]
    names = {ROLE_A: "role-a", ROLE_B: "role-b"}
    rows = aggregate_assume_events(records, names)
    by_key = {(r["role_name"], r["principal"]): r for r in rows}
    ci = by_key[("role-a", CALLER)]
    assert (ci["count"], ci["errors"], ci["source"]) == (3, 1, IP)
    assert ci["last_time"] == NOW.isoformat(timespec="seconds")
    assert ci["principal_type"] == "AssumedRole"
    svc = by_key[("role-a", "lambda.amazonaws.com")]
    assert (svc["count"], svc["source"], svc["principal_type"]) == (
        1,
        "lambda.amazonaws.com",
        "AWSService",
    )
    web = by_key[("role-b", "oidc.example.com (repo:example/role-a:ref:refs/heads/main)")]
    assert web["event_name"] == "AssumeRoleWithWebIdentity"
    assert ("role-gone", CALLER) in by_key
    assert sum(r["count"] for r in rows) == 6
    # most frequent caller first within a role
    assert rows[0]["principal"] == CALLER


# -- the collector -------------------------------------------------------------------


def _job(status, services=(), truncated=False, marker=None):
    resp = {
        "JobStatus": status,
        "JobCreationDate": NOW,
        "JobCompletionDate": NOW,  # required by the API model, even while in progress
        "ServicesLastAccessed": list(services),
        "IsTruncated": truncated,
    }
    if marker:
        resp["Marker"] = marker
    return resp


def _service(namespace, last=None):
    s = {"ServiceName": f"Amazon {namespace}", "ServiceNamespace": namespace}
    if last:
        s.update(LastAuthenticated=last, LastAuthenticatedRegion="us-east-1")
    return s


def _stub_access_advisor(gw):
    iam = gw.stub("iam")
    for arn, job in ((ROLE_A, JOB_A), (ROLE_B, JOB_B)):
        iam.add_response(
            "generate_service_last_accessed_details",
            {"JobId": job},
            {"Arn": arn, "Granularity": "SERVICE_LEVEL"},
        )
    # round 1: role-a still running, role-b done; round 2: role-a done over two pages
    iam.add_response("get_service_last_accessed_details", _job("IN_PROGRESS"), {"JobId": JOB_A})
    iam.add_response(
        "get_service_last_accessed_details",
        _job("COMPLETED", [_service("sqs", NOW - timedelta(days=200))]),
        {"JobId": JOB_B},
    )
    iam.add_response(
        "get_service_last_accessed_details",
        _job("COMPLETED", [_service("s3", NOW - timedelta(days=2))], True, "page-2"),
        {"JobId": JOB_A},
    )
    iam.add_response(
        "get_service_last_accessed_details",
        _job("COMPLETED", [_service("ec2")]),
        {"JobId": JOB_A, "Marker": "page-2"},
    )


def _stub_cloudtrail(gw, region=None):
    ct = gw.stub("cloudtrail", region)
    for name in ASSUME_EVENTS:
        events = []
        if name == "AssumeRole":
            events = [
                {"EventId": "e1", "CloudTrailEvent": json.dumps(_record(ROLE_A, eid="e1"))},
                {"EventId": "e2", "CloudTrailEvent": json.dumps(_record(ROLE_A, eid="e2"))},
            ]
        ct.add_response(
            "lookup_events",
            {"Events": events},
            {
                "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": name}],
                "StartTime": NOW - timedelta(days=WINDOW_DAYS),
                "EndTime": NOW,
            },
        )


def _stub_analyzer(gw, analyzers=True):
    aa = gw.stub("accessanalyzer")
    analyzer_arn = f"arn:aws:access-analyzer:us-east-1:{ACCOUNT}:analyzer/analyzer-a"
    items = []
    if analyzers:
        items = [
            {
                "arn": analyzer_arn,
                "name": "analyzer-a",
                "type": "ACCOUNT",
                "createdAt": NOW,
                "status": "ACTIVE",
            }
        ]
    aa.add_response("list_analyzers", {"analyzers": items}, {})
    if analyzers:
        aa.add_response(
            "list_findings",
            {
                "findings": [
                    {
                        "id": "finding-a",
                        "principal": {"AWS": "111122223333"},
                        "action": ["sts:AssumeRole"],
                        "resource": ROLE_A,
                        "isPublic": False,
                        "resourceType": "AWS::IAM::Role",
                        "condition": {},
                        "createdAt": NOW,
                        "analyzedAt": NOW,
                        "updatedAt": NOW,
                        "status": "ACTIVE",
                        "resourceOwnerAccount": ACCOUNT,
                    }
                ]
            },
            {"analyzerArn": analyzer_arn, "filter": {"status": {"eq": ["ACTIVE"]}}},
        )


def _run(gw, db_path, snap, **kw):
    sleeps = []
    result = UsageCollector(gw, db_path, snap, now=NOW, sleep=sleeps.append, **kw).run()
    return result, sleeps


def test_usage_collection_from_every_source(db_path, snap):
    gw = StubGateway()
    _stub_access_advisor(gw)
    _stub_cloudtrail(gw)
    _stub_analyzer(gw)
    result, sleeps = _run(gw, db_path, snap)
    for stub in gw.stubs.values():
        stub.assert_no_pending_responses()
    assert result.sources == {"access_advisor": "ok", "cloudtrail": "ok", "access_analyzer": "ok"}
    assert result.warnings == []
    assert (result.services, result.events, result.analyzer_findings) == (3, 2, 1)
    assert sleeps == [2.0]  # one wait for the report still in progress
    with closing(db_path) as conn:
        services = {
            (r["role_name"], r["service_namespace"]): r["last_authenticated"]
            for r in conn.execute("SELECT * FROM service_last_accessed")
        }
        events = [dict(r) for r in conn.execute("SELECT * FROM assume_events")]
        analyzer = conn.execute("SELECT * FROM analyzer_findings").fetchone()
        run = conn.execute("SELECT * FROM usage_runs").fetchone()
    assert services == {
        ("role-a", "s3"): (NOW - timedelta(days=2)).isoformat(),
        ("role-a", "ec2"): "",
        ("role-b", "sqs"): (NOW - timedelta(days=200)).isoformat(),
    }
    assert [(e["role_name"], e["principal"], e["source"], e["count"]) for e in events] == [
        ("role-a", CALLER, IP, 2)
    ]
    assert analyzer["resource"] == ROLE_A and analyzer["finding_type"] == "ExternalAccess"
    assert "principal AWS=111122223333" in analyzer["detail"]
    assert run["window_days"] == WINDOW_DAYS and json.loads(run["warnings"]) == []


def test_each_source_is_optional(db_path, snap):
    gw = StubGateway()
    gw.stub("iam").add_client_error(
        "generate_service_last_accessed_details", "AccessDenied", "example"
    )
    gw.stub("cloudtrail").add_client_error("lookup_events", "AccessDeniedException", "example")
    _stub_analyzer(gw, analyzers=False)
    result, _sleeps = _run(gw, db_path, snap)
    assert result.sources == {
        "access_advisor": "unavailable (AccessDenied)",
        "cloudtrail": "unavailable (AccessDeniedException)",
        "access_analyzer": "no analyzer",
    }
    assert len(result.warnings) == 2
    assert "iam:GenerateServiceLastAccessedDetails" in result.warnings[0]
    # a rerun replaces the snapshot's previous usage data
    gw = StubGateway()
    _stub_access_advisor(gw)
    _stub_cloudtrail(gw)
    gw.stub("accessanalyzer").add_client_error("list_analyzers", "AccessDeniedException", "x")
    result, _sleeps = _run(gw, db_path, snap)
    assert result.sources["access_analyzer"] == "unavailable (AccessDeniedException)"
    with closing(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM usage_runs").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM service_last_accessed").fetchone()[0] == 3


def test_reports_not_ready_in_time_become_a_warning(db_path, snap, monkeypatch):
    gw = StubGateway()
    iam = gw.stub("iam")
    for _role in (ROLE_A, ROLE_B):
        iam.add_response("generate_service_last_accessed_details", {"JobId": JOB_A}, None)
    for _ in range(4):
        iam.add_response("get_service_last_accessed_details", _job("IN_PROGRESS"), None)
    _stub_cloudtrail(gw)
    _stub_analyzer(gw, analyzers=False)
    ticks = iter([0.0, 10.0, 400.0])
    result, _sleeps = _run(gw, db_path, snap, clock=lambda: next(ticks))
    assert result.sources["access_advisor"].startswith("unavailable (")
    assert "not ready in time" in result.sources["access_advisor"]
    assert result.sources["cloudtrail"] == "ok"


def test_cloudtrail_reads_the_account_region_and_us_east_1(db_path, snap):
    gw = StubGateway(region="eu-west-1")
    gw.stub("iam").add_client_error("generate_service_last_accessed_details", "AccessDenied", "x")
    _stub_cloudtrail(gw, "eu-west-1")
    _stub_cloudtrail(gw, "us-east-1")
    gw.stub("accessanalyzer").add_response("list_analyzers", {"analyzers": []}, {})
    result, _sleeps = _run(gw, db_path, snap)
    for stub in gw.stubs.values():
        stub.assert_no_pending_responses()
    assert result.events == 2  # the same event ids in both regions count once


@pytest.mark.parametrize(
    "service, op, allowed",
    [
        ("iam", "GenerateServiceLastAccessedDetails", True),
        ("iam", "GetServiceLastAccessedDetails", True),
        ("cloudtrail", "LookupEvents", True),
        ("accessanalyzer", "ListAnalyzers", True),
        ("accessanalyzer", "ListFindings", True),
        ("accessanalyzer", "ListFindingsV2", True),
        ("iam", "GenerateCredentialReport", False),
        ("iam", "GenerateOrganizationsAccessReport", False),
        ("cloudtrail", "StopLogging", False),
        ("cloudtrail", "LookupSomethingElse", False),
        ("accessanalyzer", "CreateAnalyzer", False),
        ("accessanalyzer", "StartResourceScan", False),
    ],
)
def test_read_only_guard_allows_exactly_the_usage_reports(service, op, allowed):
    assert is_read_only_operation(service, op) is allowed


def test_guard_still_refuses_writes_on_usage_clients():
    gw = AwsGateway(boto3.session.Session(region_name="us-east-1"))
    with pytest.raises(ReadOnlyViolation):
        gw.client("cloudtrail").stop_logging(Name="trail-a")
    with pytest.raises(ReadOnlyViolation):
        gw.client("accessanalyzer").create_analyzer(analyzerName="analyzer-a", type="ACCOUNT")
    with pytest.raises(ReadOnlyViolation):
        gw.client("iam").generate_credential_report()
