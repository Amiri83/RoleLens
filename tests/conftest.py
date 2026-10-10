"""Shared fixtures.

All data here is synthetic: the moto default account 123456789012 and made-up names
(role-a, policy-a, bucket-a, queue-a). Nothing reaches real AWS.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import boto3
import pytest

from rolelens.db import init_db

ACCOUNT = "123456789012"

LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
ACCOUNT_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CrossAccount",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "example-external-id"}},
        }
    ],
}
POLICY_A = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sqs:SendMessage",
            "Resource": f"arn:aws:sqs:us-east-1:{ACCOUNT}:queue-a",
        }
    ],
}
INLINE_A = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Read",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::bucket-a/*",
        },
        {"Sid": "NoDelete", "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
    ],
}


@pytest.fixture(autouse=True)
def _hermetic_aws(monkeypatch, tmp_path):
    """Never let a test reach real AWS or the developer's AWS config."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # An endpoint override (e.g. a local emulator) makes boto3 bypass moto's interception.
    for var in list(os.environ):
        if var.startswith("AWS_ENDPOINT_URL") or var == "AWS_S3_ENDPOINT":
            monkeypatch.delenv(var)
    monkeypatch.setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
    monkeypatch.delenv("ROLELENS_SECRET_KEY", raising=False)
    monkeypatch.setenv("ROLELENS_HOME", str(tmp_path / "rolelens-home"))
    yield
    logger = logging.getLogger("rolelens")
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()


@pytest.fixture
def home(tmp_path) -> Path:
    return tmp_path / "home"


@pytest.fixture
def db_path(tmp_path) -> Path:
    p = tmp_path / "test.db"
    init_db(p)
    return p


def seed_iam() -> dict[str, Any]:
    """Create placeholder roles and policies in moto (call inside ``mock_aws``).

    * role-a (path /service/): trusted by Lambda, customer managed policy-a attached,
      inline policy-inline-a (Allow s3:GetObject, Deny s3:DeleteObject);
    * role-b: trusted by account 123456789012 with an external id, no policies.
    """
    iam = boto3.client("iam", region_name="us-east-1")
    created = iam.create_policy(PolicyName="policy-a", PolicyDocument=json.dumps(POLICY_A))
    policy_arn = created["Policy"]["Arn"]
    iam.create_role(
        RoleName="role-a",
        Path="/service/",
        AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST),
        Description="Example service role",
    )
    iam.attach_role_policy(RoleName="role-a", PolicyArn=policy_arn)
    iam.put_role_policy(
        RoleName="role-a", PolicyName="policy-inline-a", PolicyDocument=json.dumps(INLINE_A)
    )
    iam.create_role(RoleName="role-b", AssumeRolePolicyDocument=json.dumps(ACCOUNT_TRUST))
    return {"policy_arn": policy_arn}
