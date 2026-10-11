"""The read-only guard, session construction and the connection test (moto, placeholders)."""

import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from rolelens.accounts import Account, CredentialError
from rolelens.aws import (
    AwsGateway,
    ReadOnlyViolation,
    build_session,
    check_connection,
    is_credential_failure,
    is_read_only_operation,
)

from .conftest import LAMBDA_TRUST

FAKE_SECRET = "example/secret/value/for/tests/only/0000"
FAKE_TEMP_KEY_ID = "ASIAEXAMPLEEXAMPLE00"
FAKE_SESSION_TOKEN = "FakeSessionTokenForTestsOnly0000000000000000000000Example"


@mock_aws
def test_read_only_guard_blocks_every_iam_write():
    iam = AwsGateway(boto3.session.Session(region_name="us-east-1")).client("iam")
    assert iam.list_roles()["Roles"] == []
    with pytest.raises(ReadOnlyViolation):
        iam.create_role(RoleName="role-a", AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST))
    with pytest.raises(ReadOnlyViolation):
        iam.put_role_policy(RoleName="role-a", PolicyName="policy-a", PolicyDocument="{}")
    with pytest.raises(ReadOnlyViolation):
        iam.update_assume_role_policy(RoleName="role-a", PolicyDocument="{}")
    with pytest.raises(ReadOnlyViolation):
        iam.delete_role(RoleName="role-a")
    # nothing was created
    assert boto3.client("iam", region_name="us-east-1").list_roles()["Roles"] == []


@mock_aws
def test_read_only_guard_allows_paginators():
    iam = AwsGateway(boto3.session.Session(region_name="us-east-1")).client("iam")
    assert list(iam.get_paginator("list_roles").paginate())


@pytest.mark.parametrize(
    "service, op, allowed",
    [
        ("iam", "ListRoles", True),
        ("iam", "GetPolicyVersion", True),
        ("iam", "CreateRole", False),
        ("iam", "AttachRolePolicy", False),
        # the credential report: an optional, allowlisted source of user metadata
        ("iam", "GenerateCredentialReport", True),
        ("iam", "GetCredentialReport", True),
        # ... while user writes and every other secret-returning call stay refused
        ("iam", "CreateAccessKey", False),
        ("iam", "CreateLoginProfile", False),
        ("iam", "UpdateAccessKey", False),
        ("iam", "GenerateOrganizationsAccessReport", False),
        ("sts", "AssumeRole", False),
        ("sts", "GetSessionToken", False),
        ("sts", "GetFederationToken", False),
        ("secretsmanager", "GetSecretValue", False),
        ("secretsmanager", "BatchGetSecretValue", False),
        ("ssm", "GetParameter", False),
        ("ssm", "GetParametersByPath", False),
        ("ecr", "GetAuthorizationToken", False),
    ],
)
def test_is_read_only_operation(service, op, allowed):
    assert is_read_only_operation(service, op) is allowed


def test_build_session_keys_and_env():
    s = build_session(
        Account(
            auth_mode="keys",
            region="eu-west-1",
            access_key_id="AKIAEXAMPLE000000000",
            secret_access_key=FAKE_SECRET,
        )
    )
    assert s.get_credentials().access_key == "AKIAEXAMPLE000000000"
    assert s.region_name == "eu-west-1"
    assert build_session(Account(auth_mode="env", region="us-west-2")).region_name == "us-west-2"
    with pytest.raises(ValueError):
        build_session(Account(auth_mode="keys", access_key_id="AKIAEXAMPLE000000000"))


def test_build_session_temporary_uses_session_token():
    s = build_session(
        Account(
            auth_mode="temporary",
            access_key_id=FAKE_TEMP_KEY_ID,
            secret_access_key=FAKE_SECRET,
            session_token=FAKE_SESSION_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    creds = s.get_credentials()
    assert (creds.access_key, creds.token) == (FAKE_TEMP_KEY_ID, FAKE_SESSION_TOKEN)


def test_build_session_refuses_expired_credentials():
    expired = Account(
        auth_mode="temporary",
        access_key_id=FAKE_TEMP_KEY_ID,
        secret_access_key=FAKE_SECRET,
        session_token=FAKE_SESSION_TOKEN,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    with pytest.raises(CredentialError, match="credentials expired, paste new ones"):
        build_session(expired)


@mock_aws
def test_check_connection_ok():
    result = check_connection(Account(auth_mode="env", region="us-east-1"))
    assert result.ok and not result.credentials_problem
    assert result.account_id == "123456789012"


def test_check_connection_failure_does_not_leak_secret():
    def boom(_account):
        raise ValueError("bad")

    result = check_connection(
        Account(
            auth_mode="keys", access_key_id="AKIAEXAMPLE000000000", secret_access_key=FAKE_SECRET
        ),
        boom,
    )
    assert not result.ok
    assert FAKE_SECRET not in result.message


def test_check_connection_flags_expired_token():
    def expired(_account):
        raise ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "The security token is expired"}},
            "GetCallerIdentity",
        )

    result = check_connection(Account(auth_mode="env"), expired)
    assert not result.ok and result.credentials_problem
    assert is_credential_failure(CredentialError("example"))
