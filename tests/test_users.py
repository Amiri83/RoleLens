"""Users, groups and managed policies: collection (moto), effective permissions, risk
findings, duplicates / overlaps and policy usage.

Placeholder data only (user-a, group-a, policy-a, role-a, 123456789012, bucket-a)."""

import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from rolelens import insights, queries, recommend
from rolelens.aws import AwsGateway
from rolelens.collector import Collector, parse_credential_report
from rolelens.db import closing, connect
from rolelens.findings import group_findings, policy_findings, user_findings

from .conftest import ADMIN_DOC, INLINE_A, POLICY_A, seed_iam, seed_identities

ACCOUNT = "123456789012"
NOW = datetime(2026, 10, 10, tzinfo=UTC)


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name="us-east-1"))


def _collect(db_path, gw=None):
    arns = seed_iam()
    ids = seed_identities(arns["policy_arn"])
    result = Collector(gw or _gateway(), db_path, report_wait=0).run()
    return result, {**arns, **ids}


def _denied(op: str):
    def fail(**_kw):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "example"}}, op)

    return fail


def _patched_gateway(monkeypatch, **denied_ops):
    """A gateway whose IAM client refuses the given operations (method name -> API name)."""
    gw = _gateway()
    real_client = gw.client

    def client(service, **kw):
        c = real_client(service, **kw)
        if service == "iam":
            for method, op in denied_ops.items():
                setattr(c, method, _denied(op))
        return c

    monkeypatch.setattr(gw, "client", client)
    return gw


# -- collection ---------------------------------------------------------------------------


@mock_aws
def test_collect_users_groups_and_policies(db_path):
    result, seed = _collect(db_path)

    assert (result.roles, result.users, result.groups) == (2, 4, 2)
    assert result.credential_report  # moto serves the credential report
    assert result.warnings == []
    # policy-a (attached) and policy-unused (Scope=Local, attached to nothing)
    assert result.managed_policies == 2
    conn = connect(db_path)
    try:
        snap = result.snapshot_id
        user = queries.user_model(conn, snap, "user-a")
        assert user["password_enabled"] is True
        assert user["mfa_active"] is False
        assert user["metadata_source"] == "report"
        assert [g["group_name"] for g in user["groups"]] == ["group-a"]
        assert [(p["name"], p["kind"]) for p in user["policies"]] == [("user-inline-a", "inline")]
        assert user["policies"][0]["document"] == POLICY_A
        [key] = user["access_keys"]
        assert key["key_id"] == seed["key_id"]
        assert key["status"] == "Active"
        assert key["last_used_at"] == ""  # never used
        assert key["last_used_known"]

        group = queries.group_model(conn, snap, "group-a")
        assert group["members"] == ["user-a", "user-b", "user-c"]
        assert [(p["name"], p["kind"]) for p in group["policies"]] == [
            ("policy-a", "managed"),
            ("group-inline-a", "inline"),
        ]
        assert group["policies"][1]["document"] == INLINE_A

        b = queries.user_model(conn, snap, "user-b")
        assert b["password_enabled"] is False and b["access_keys"] == []
    finally:
        conn.close()


@mock_aws
def test_no_secret_value_is_stored_or_logged(db_path, caplog):
    caplog.set_level("DEBUG", logger="rolelens")
    result, seed = _collect(db_path)
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert seed["secret"] not in logged and seed["key_id"] not in logged
    with closing(db_path) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            for row in conn.execute(f"SELECT * FROM {table}"):  # noqa: S608 - test
                text = json.dumps([str(v) for v in tuple(row)])
                assert seed["secret"] not in text, table
                assert "Example-Placeholder-0" not in text, table
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(user_access_keys)")}
    assert not any("secret" in c for c in cols)
    # key ids stay out of the snapshot's warnings
    assert all(seed["key_id"] not in w for w in result.warnings)


@mock_aws
def test_credential_report_denied_falls_back_to_per_user_calls(db_path, monkeypatch):
    gw = _patched_gateway(
        monkeypatch,
        generate_credential_report="GenerateCredentialReport",
    )
    result, _seed = _collect(db_path, gw)

    assert not result.credential_report
    assert result.users == 4
    expected = (
        "iam:GenerateCredentialReport/GetCredentialReport skipped (AccessDenied); "
        "per-user calls used instead"
    )
    assert result.warnings == [expected]
    conn = connect(db_path)
    try:
        user = queries.user_model(conn, result.snapshot_id, "user-a")
        assert user["metadata_source"] == "api"
        assert user["password_enabled"] is True  # iam:GetLoginProfile found a profile
        assert user["mfa_active"] is False and user["mfa_devices"] == 0
        assert queries.user_model(conn, result.snapshot_id, "user-b")["password_enabled"] is False
    finally:
        conn.close()


@mock_aws
def test_each_optional_source_degrades_to_a_warning(db_path, monkeypatch):
    gw = _patched_gateway(
        monkeypatch,
        generate_credential_report="GenerateCredentialReport",
        get_login_profile="GetLoginProfile",
        list_mfa_devices="ListMFADevices",
        get_access_key_last_used="GetAccessKeyLastUsed",
        list_entities_for_policy="ListEntitiesForPolicy",
        get_group_policy="GetGroupPolicy",
    )
    result, seed = _collect(db_path, gw)

    assert result.users == 4 and result.groups == 2 and result.roles == 2
    assert "iam:GetLoginProfile (user-a) skipped (AccessDenied)" in result.warnings
    assert "iam:GetAccessKeyLastUsed (user-a) skipped (AccessDenied)" in result.warnings
    assert "iam:GetGroupPolicy (group-a/group-inline-a) skipped (AccessDenied)" in result.warnings
    assert "iam:ListEntitiesForPolicy (policy-a) skipped (AccessDenied)" in result.warnings
    assert all(seed["key_id"] not in w for w in result.warnings)
    conn = connect(db_path)
    try:
        user = queries.user_model(conn, result.snapshot_id, "user-a")
        assert user["password_enabled"] is None and user["mfa_active"] is None
        assert user["access_keys"][0]["last_used_known"] is False
        # unknown is not reported as "no MFA" or "unused key"
        rules = {f.rule for f in user_findings(user, ACCOUNT, NOW + timedelta(days=400))}
        assert "no-mfa" not in rules and "unused-access-key" not in rules
        # policy usage still comes from the collected attachments
        usage = queries.policy_usage(conn, result.snapshot_id)[seed["policy_arn"]]
        assert usage == {"role": ["role-a"], "user": [], "group": ["group-a"]}
    finally:
        conn.close()


@mock_aws
def test_list_users_denied_keeps_the_roles(db_path, monkeypatch):
    seed_iam()
    gw = _gateway()
    real_client = gw.client

    def client(service, **kw):
        c = real_client(service, **kw)
        if service == "iam":
            real_paginator = c.get_paginator

            def get_paginator(op):
                if op in ("list_users", "list_groups"):
                    raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, op)
                return real_paginator(op)

            c.get_paginator = get_paginator
        return c

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path, report_wait=0).run()
    assert (result.roles, result.users, result.groups) == (2, 0, 0)
    assert "iam:ListUsers skipped (AccessDenied)" in result.warnings
    assert "iam:ListGroups skipped (AccessDenied)" in result.warnings


def test_parse_credential_report_keeps_only_the_needed_fields():
    header = (
        "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
        "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
        "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
        "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,"
        "cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
    )
    rows = [
        f"<root_account>,arn:aws:iam::{ACCOUNT}:root,2020-01-01T00:00:00+00:00,not_supported,"
        "2026-01-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,"
        "false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        f"user-a,arn:aws:iam::{ACCOUNT}:user/user-a,2025-01-01T00:00:00+00:00,true,"
        "2026-09-01T10:00:00+00:00,2025-01-01T00:00:00+00:00,N/A,false,true,"
        "2025-01-02T00:00:00+00:00,2026-09-30T08:00:00+00:00,us-east-1,s3,"
        "false,2025-02-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A",
        f"user-b,arn:aws:iam::{ACCOUNT}:user/user-b,2025-01-01T00:00:00+00:00,false,"
        "N/A,N/A,N/A,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
    ]
    report = parse_credential_report(("\n".join([header, *rows]) + "\n").encode())

    assert set(report) == {"user-a", "user-b"}  # the root account row is skipped
    assert report["user-a"] == {
        "password_enabled": True,
        "password_last_used": "2026-09-01T10:00:00+00:00",
        "mfa_active": False,
        "keys": [
            {
                "active": True,
                "last_rotated": "2025-01-02T00:00:00+00:00",
                "last_used_at": "2026-09-30T08:00:00+00:00",
                "last_used_service": "s3",
                "last_used_region": "us-east-1",
            },
            {
                "active": False,
                "last_rotated": "2025-02-01T00:00:00+00:00",
                "last_used_at": "",
                "last_used_service": "",
                "last_used_region": "",
            },
        ],
    }
    assert report["user-b"] == {
        "password_enabled": False,
        "password_last_used": "",
        "mfa_active": False,
        "keys": [],
    }


# -- effective permissions and findings ---------------------------------------------------


@mock_aws
def test_user_effective_permissions_include_group_policies(db_path):
    result, _seed = _collect(db_path)
    conn = connect(db_path)
    try:
        info = insights.identity_insights(conn, result.snapshot_id, "user", "user-a")
        assert info["actions"] == ["s3:GetObject", "sqs:SendMessage"]
        by_action = {p["action"]: p["policies"] for p in info["permissions"]}
        assert by_action["s3:GetObject"] == ["group-inline-a (group group-a)"]
        assert by_action["sqs:SendMessage"] == ["policy-a (group group-a)", "user-inline-a"]
        # the group's Deny s3:DeleteObject on "*" is applied to its members too
        assert "s3:DeleteObject" not in info["actions"]

        group = insights.identity_insights(conn, result.snapshot_id, "group", "group-a")
        assert group["actions"] == ["s3:GetObject", "sqs:SendMessage"]
        admin = insights.identity_insights(conn, result.snapshot_id, "user", "user-admin")
        assert "*" in admin["actions"]
    finally:
        conn.close()


@mock_aws
def test_user_and_group_findings_are_stored(db_path):
    result, _seed = _collect(db_path)
    conn = connect(db_path)
    try:
        users = insights.identity_findings(conn, result.snapshot_id, "user")
        groups = insights.identity_findings(conn, result.snapshot_id, "group")
    finally:
        conn.close()
    rules_a = {f["rule"]: f for f in users["user-a"]}
    assert rules_a["no-mfa"]["severity"] == "high"
    assert rules_a["direct-attachment"]["where"] == "user"
    assert "inline-only" not in rules_a  # policy-a (managed) comes via group-a
    admin = {f["rule"]: f for f in users["user-admin"]}
    assert admin["admin"]["severity"] == "critical"
    assert admin["admin"]["where"] == "policy admin-inline (group group-admin)"
    assert "no-mfa" not in admin and "direct-attachment" not in admin
    assert {f["rule"] for f in groups["group-admin"]} >= {"admin", "inline-only"}
    assert "group-a" not in groups  # scoped policies, one managed: nothing to report


def _user(**kw):
    model = {
        "entity": "user",
        "user_name": "user-a",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/user-a",
        "path": "/",
        "permissions_boundary": "",
        "password_enabled": False,
        "mfa_active": False,
        "access_keys": [],
        "groups": [],
        "policies": [],
    }
    model.update(kw)
    return model


def _key(
    created_days: int, used_days: int | None, status: str = "Active", key_id="AKIAEXAMPLE0000KEYA"
):
    def ago(days):
        return (NOW - timedelta(days=days)).isoformat()

    return {
        "key_id": key_id,
        "status": status,
        "create_date": ago(created_days),
        "last_used_at": "" if used_days is None else ago(used_days),
        "last_used_known": True,
    }


def test_key_age_and_unused_key_findings():
    found = user_findings(
        _user(
            access_keys=[
                _key(200, 1, key_id="AKIAEXAMPLE0000KEYA"),  # old, recently used
                _key(30, None, key_id="AKIAEXAMPLE0000KEYB"),  # new, never used: fine
                _key(120, None, key_id="AKIAEXAMPLE0000KEYC"),  # never used for 120 days
                _key(400, 365, "Inactive", key_id="AKIAEXAMPLE0000KEYD"),  # inactive: ignored
            ]
        ),
        ACCOUNT,
        NOW,
    )
    by = {(f.rule, f.where): f for f in found}
    assert ("old-access-key", "access key …KEYA") in by
    assert ("unused-access-key", "access key …KEYA") not in by
    assert ("old-access-key", "access key …KEYC") in by
    assert ("unused-access-key", "access key …KEYC") in by
    assert "never used (created 120 days ago)" in by[("unused-access-key", "access key …KEYC")].why
    assert not any(w.endswith(("KEYB", "KEYD")) for _r, w in by)
    # the full key id never appears in a finding (a placeholder in the fix)
    assert not any("AKIAEXAMPLE0000KEY" in f.fix + f.why + f.where for f in found)


def test_mfa_finding_needs_console_access():
    assert "no-mfa" in {f.rule for f in user_findings(_user(password_enabled=True), ACCOUNT, NOW)}
    assert "no-mfa" not in {f.rule for f in user_findings(_user(), ACCOUNT, NOW)}
    with_mfa = _user(password_enabled=True, mfa_active=True)
    assert "no-mfa" not in {f.rule for f in user_findings(with_mfa, ACCOUNT, NOW)}
    unknown = _user(password_enabled=True, mfa_active=None)
    assert "no-mfa" not in {f.rule for f in user_findings(unknown, ACCOUNT, NOW)}


def test_admin_inline_only_and_direct_attachment_findings():
    admin = {"name": "admin-inline", "kind": "inline", "document": ADMIN_DOC}
    found = {f.rule: f for f in user_findings(_user(policies=[admin]), ACCOUNT, NOW)}
    assert found["admin"].severity == "critical"
    assert found["inline-only"].where == "user"
    assert "aws_iam_user_policy_attachment" in found["inline-only"].fix
    assert "aws_iam_user_group_membership" in found["direct-attachment"].fix
    assert found["no-boundary"].where == "user"

    via_group = _user(groups=[{"group_name": "group-a", "policies": [admin]}])
    found = {f.rule: f for f in user_findings(via_group, ACCOUNT, NOW)}
    assert found["admin"].where == "policy admin-inline (group group-a)"
    assert "direct-attachment" not in found

    group = {"entity": "group", "group_name": "group-a", "arn": "", "policies": [admin]}
    rules = {f.rule for f in group_findings(group, ACCOUNT)}
    # Action "*" covers iam:PassRole too; no trust or boundary rules for groups
    assert rules == {"admin", "passrole", "inline-only"}


def test_old_key_findings_through_the_analysis(db_path):
    """analyze_identities stores key findings computed at ``now``."""
    with mock_aws():
        result, _seed = _collect(db_path)
    with closing(db_path) as conn:
        insights.analyze_identities(conn, result.snapshot_id, ACCOUNT, NOW + timedelta(days=500))
        found = insights.identity_findings(conn, result.snapshot_id, "user")["user-a"]
    rules = {f["rule"] for f in found}
    assert {"old-access-key", "unused-access-key"} <= rules


def test_policy_findings_of_a_standalone_policy():
    pol = {"name": "policy-a", "kind": "managed", "arn": "", "document": ADMIN_DOC}
    assert [f.rule for f in policy_findings(pol, ACCOUNT)] == ["admin", "passrole"]
    pol = {"name": "policy-a", "kind": "managed", "arn": "", "document": POLICY_A}
    assert policy_findings(pol, ACCOUNT) == []


def test_init_db_migrates_an_existing_database(tmp_path):
    """A database created before users / policies existed gains the new columns."""
    import sqlite3

    from rolelens.db import init_db

    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE managed_policies (snapshot_id INTEGER NOT NULL, arn TEXT NOT NULL, "
        "name TEXT NOT NULL, path TEXT NOT NULL DEFAULT '/', default_version TEXT NOT NULL "
        "DEFAULT '', aws_managed INTEGER NOT NULL DEFAULT 0, document TEXT, "
        "PRIMARY KEY (snapshot_id, arn));"
        "CREATE TABLE drafts (id INTEGER PRIMARY KEY AUTOINCREMENT, account_ref INTEGER, "
        "snapshot_id INTEGER, source_role TEXT NOT NULL, original TEXT NOT NULL, "
        "model TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);"
        "INSERT INTO drafts(source_role, original, model, created_at, updated_at) "
        "VALUES('role-a', '{}', '{}', '', '');"
    )
    old.commit()
    old.close()
    init_db(path)
    init_db(path)  # idempotent
    with closing(path) as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(managed_policies)")}
        assert {"description", "attachment_count", "versions"} <= cols
        assert conn.execute("SELECT entity FROM drafts").fetchone()[0] == "role"


# -- duplicates and overlaps --------------------------------------------------------------


@mock_aws
def test_duplicate_and_overlapping_users(db_path):
    result, _seed = _collect(db_path)
    conn = connect(db_path)
    try:
        users = insights.identity_perms(conn, result.snapshot_id, "user")
        groups = insights.identity_perms(conn, result.snapshot_id, "group")
    finally:
        conn.close()
    # user-a's own inline policy repeats what group-a already grants
    assert recommend.duplicates(users) == [["user-a", "user-b", "user-c"]]
    assert recommend.duplicates(groups) == []
    assert recommend.overlaps(users, 0.8) == []  # duplicates are not listed again


def test_overlaps_with_a_configurable_threshold():
    from rolelens.effective import Grant

    def perms(name, actions):
        grants = frozenset(Grant(a, "*", "") for a in actions)
        return recommend.RolePerms(name, grants, frozenset(actions), "")

    a = perms("user-a", ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "sqs:SendMessage"])
    b = perms("user-b", ["s3:GetObject", "s3:PutObject", "s3:ListBucket"])
    [pair] = recommend.overlaps([a, b], 0.75)
    assert (pair["a"], pair["b"], pair["relation"]) == ("user-a", "user-b", "superset")
    assert pair["jaccard"] == 0.75
    assert recommend.overlaps([a, b], 0.8) == []


# -- policy usage -------------------------------------------------------------------------


@mock_aws
def test_policy_usage_and_unattached_flag(db_path):
    result, seed = _collect(db_path)
    conn = connect(db_path)
    try:
        rows = {r["name"]: r for r in queries.policy_list(conn, result.snapshot_id)}
        detail = queries.policy_detail(conn, result.snapshot_id, seed["policy_arn"])
    finally:
        conn.close()
    assert set(rows) == {"policy-a", "policy-unused"}
    used = rows["policy-a"]
    assert (used["roles"], used["users"], used["groups"]) == (["role-a"], [], ["group-a"])
    assert used["unattached"] is False and used["attached"] == 2
    assert used["versions"][0]["id"] == "v1" and used["versions"][0]["default"]
    assert used["document"] == POLICY_A
    unused = rows["policy-unused"]
    assert unused["unattached"] is True
    assert unused["attachment_count"] == 0
    assert detail["arn"] == seed["policy_arn"]


@mock_aws
def test_user_list_rows(db_path):
    result, _seed = _collect(db_path)
    conn = connect(db_path)
    try:
        rows = {r["name"]: r for r in queries.user_list(conn, result.snapshot_id)}
    finally:
        conn.close()
    a = rows["user-a"]
    assert a["console"] is True and a["mfa"] is False
    assert a["groups"] == ["group-a"]
    assert (a["inline"], a["managed"], a["group_policies"]) == (1, 0, 2)
    assert a["permissions"] == "both"
    assert a["active_keys"] == 1 and a["key_age_days"] == 0
    assert a["findings"]["no-mfa"] == "high"
    assert rows["user-b"]["permissions"] == "group"
    assert rows["user-b"]["console"] is False


@pytest.mark.parametrize(
    "args, expected",
    [
        ({}, ["user-a", "user-admin", "user-b", "user-c"]),
        ({"mfa": "no", "console": "yes"}, ["user-a"]),
        ({"perms": "has-direct"}, ["user-a"]),
        ({"perms": "group"}, ["user-admin", "user-b", "user-c"]),
        ({"inline": "yes"}, ["user-a"]),
        ({"finding": "admin"}, ["user-admin"]),
        ({"q": "group-admin"}, ["user-admin"]),
        ({"key_age": "90"}, []),
        ({"idle": "30"}, []),
    ],
)
def test_user_filters(db_path, args, expected):
    from rolelens.filters import UserFilters

    with mock_aws():
        result, _seed = _collect(db_path)
    conn = connect(db_path)
    try:
        rows = queries.user_list(conn, result.snapshot_id)
    finally:
        conn.close()
    names = [r["name"] for r in UserFilters.from_args(args).apply(rows)]
    assert names == expected


def test_user_filters_on_key_age_and_activity():
    from rolelens.filters import UserFilters

    rows = [
        {"name": "user-a", "path": "/", "arn": "", "groups": [], "console": False, "mfa": False,
         "inline": 0, "key_age_days": 120, "idle_days": 100, "permissions": "none", "findings": {}},
        {"name": "user-b", "path": "/", "arn": "", "groups": [], "console": None, "mfa": None,
         "inline": 0, "key_age_days": None, "idle_days": 10, "permissions": "none", "findings": {}},
    ]  # fmt: skip
    assert [r["name"] for r in UserFilters.from_args({"key_age": "90"}).apply(rows)] == ["user-a"]
    assert [r["name"] for r in UserFilters.from_args({"idle": "90"}).apply(rows)] == ["user-a"]
    # an unknown flag never matches yes or no
    assert [r["name"] for r in UserFilters.from_args({"mfa": "no"}).apply(rows)] == ["user-a"]
    assert UserFilters.from_args({"key_age": "7", "perms": "bogus"}).query() == {}
