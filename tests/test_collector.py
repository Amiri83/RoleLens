"""IAM collection into SQLite (moto, placeholder roles and policies)."""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from rolelens import queries
from rolelens.aws import AwsGateway
from rolelens.collector import Collector
from rolelens.db import closing, connect
from rolelens.jobs import JobCancelled

from .conftest import ACCOUNT_TRUST, INLINE_A, LAMBDA_TRUST, POLICY_A, seed_iam


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name="us-east-1"))


@mock_aws
def test_collect_snapshots_roles_trust_and_policies(db_path):
    arns = seed_iam()
    result = Collector(_gateway(), db_path).run()

    assert result.account_id == "123456789012"
    assert (result.roles, result.inline_policies, result.managed_policies) == (2, 1, 1)
    assert result.warnings == []
    with closing(db_path) as conn:
        snap = conn.execute("SELECT * FROM snapshots WHERE id=?", (result.snapshot_id,)).fetchone()
        assert snap["status"] == "ok"
        rows = conn.execute("SELECT * FROM roles WHERE snapshot_id=?", (snap["id"],)).fetchall()
        roles = {r["role_name"]: r for r in rows}
        assert set(roles) == {"role-a", "role-b"}
        assert roles["role-a"]["path"] == "/service/"
        assert roles["role-a"]["description"] == "Example service role"
        # the trust policy is stored decoded (iam:GetRole)
        assert json.loads(roles["role-a"]["trust_doc"]) == LAMBDA_TRUST
        assert json.loads(roles["role-b"]["trust_doc"]) == ACCOUNT_TRUST
        managed = conn.execute("SELECT * FROM managed_policies").fetchone()
        assert managed["arn"] == arns["policy_arn"]
        assert managed["default_version"] == "v1"
        assert not managed["aws_managed"]
        assert json.loads(managed["document"]) == POLICY_A

    conn = connect(db_path)
    try:
        model = queries.role_model(conn, result.snapshot_id, "role-a")
        rows = queries.role_list(conn, result.snapshot_id)
    finally:
        conn.close()
    assert [(p["name"], p["kind"]) for p in model["policies"]] == [
        ("policy-a", "managed"),
        ("policy-inline-a", "inline"),
    ]
    assert model["policies"][1]["document"] == INLINE_A
    by_name = {r["name"]: r for r in rows}
    assert by_name["role-a"]["policies"] == 2
    assert by_name["role-a"]["principals"] == ["lambda.amazonaws.com"]
    assert by_name["role-b"]["principals"] == ["account 123456789012"]


@mock_aws
def test_role_list_search(db_path):
    seed_iam()
    snap_id = Collector(_gateway(), db_path).run().snapshot_id
    conn = connect(db_path)
    try:
        assert [r["name"] for r in queries.role_list(conn, snap_id, "lambda")] == ["role-a"]
        assert [r["name"] for r in queries.role_list(conn, snap_id, "/service/")] == ["role-a"]
        assert [r["name"] for r in queries.role_list(conn, snap_id, "123456789012")] == [
            "role-a",
            "role-b",
        ]  # role-a's ARN carries the account id too
        assert queries.role_list(conn, snap_id, "no-such-role") == []
    finally:
        conn.close()


@mock_aws
def test_missing_permission_on_one_call_is_a_warning(db_path, monkeypatch):
    seed_iam()
    gw = _gateway()
    real_client = gw.client

    def client(service, **kw):
        c = real_client(service, **kw)
        if service == "iam":

            def denied(**_kw):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "example"}}, "GetRolePolicy"
                )

            c.get_role_policy = denied
        return c

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path).run()
    assert result.roles == 2
    expected = "iam:GetRolePolicy (role-a/policy-inline-a) skipped (AccessDenied)"
    assert expected in result.warnings
    with closing(db_path) as conn:
        row = conn.execute("SELECT document FROM role_policies WHERE kind='inline'").fetchone()
        assert row["document"] is None


@mock_aws
def test_cancelled_collection_marks_the_snapshot_failed(db_path):
    seed_iam()

    class Cancelled:
        cancelled = True

        def check(self):
            raise JobCancelled()

        def step(self, *a, **k):
            return None

    with pytest.raises(JobCancelled):
        Collector(_gateway(), db_path, progress=Cancelled()).run()
    with closing(db_path) as conn:
        snap = conn.execute("SELECT status, error FROM snapshots").fetchone()
    assert (snap["status"], snap["error"]) == ("failed", "cancelled")
