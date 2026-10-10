"""Roles page column filters and trust types. Placeholder data only (role-a, 123456789012)."""

from datetime import UTC, datetime

import pytest

from rolelens.filters import RoleFilters
from rolelens.policy import trust_types
from rolelens.queries import days_since

from .conftest import ACCOUNT, ACCOUNT_TRUST, LAMBDA_TRUST

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _row(name="role-a", **kw):
    row = {
        "name": name,
        "path": "/",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "description": "",
        "last_used_at": "",
        "last_used_region": "",
        "last_used_days": None,
        "inline": 0,
        "managed": 0,
        "principals": [],
        "trust_types": [],
        "service_linked": False,
        "boundary": "",
    }
    row.update(kw)
    row["policies"] = row["inline"] + row["managed"]
    return row


def _statement(principal, action="sts:AssumeRole"):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": action}],
    }


def test_trust_types():
    assert trust_types(LAMBDA_TRUST, ACCOUNT) == ["service"]
    assert trust_types(ACCOUNT_TRUST, ACCOUNT) == ["account"]
    # an account RoleLens cannot confirm as the role's own is treated as cross-account
    assert trust_types(ACCOUNT_TRUST, None) == ["cross-account"]
    assert trust_types(_statement("*"), ACCOUNT) == ["cross-account"]
    assert trust_types(_statement({"AWS": "AROAEXAMPLEEXAMPLE00"}), ACCOUNT) == ["cross-account"]
    oidc = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.example.com"
    saml = f"arn:aws:iam::{ACCOUNT}:saml-provider/example-idp"
    assert trust_types(
        _statement({"Federated": oidc}, "sts:AssumeRoleWithWebIdentity"), ACCOUNT
    ) == ["oidc"]
    assert trust_types(_statement({"Federated": saml}, "sts:AssumeRoleWithSAML"), ACCOUNT) == [
        "saml"
    ]
    both = {
        "Version": "2012-10-17",
        "Statement": LAMBDA_TRUST["Statement"] + ACCOUNT_TRUST["Statement"],
    }
    assert trust_types(both, ACCOUNT) == ["service", "account"]
    deny = {"Version": "2012-10-17", "Statement": [{**LAMBDA_TRUST["Statement"][0]}]}
    deny["Statement"][0]["Effect"] = "Deny"
    assert trust_types(deny, ACCOUNT) == []


def test_days_since():
    assert days_since("", NOW) is None
    assert days_since("not a date", NOW) is None
    assert days_since("2026-05-01T12:00:00+00:00", NOW) == 30
    assert days_since("2026-05-31T23:00:00", NOW) == 0  # naive values are UTC


def test_from_args_ignores_unknown_values():
    f = RoleFilters.from_args(
        {"q": "  role-a ", "used": "7", "trust": "nobody", "slr": "maybe", "pmin": "-1"}
    )
    assert f == RoleFilters(q="role-a")
    assert f.query() == {"q": "role-a"}
    assert RoleFilters.from_args({}).active is False
    f = RoleFilters.from_args({"used": "90", "trust": "oidc", "pmin": "2", "pmax": "5"})
    assert f.query() == {"used": "90", "trust": "oidc", "pmin": "2", "pmax": "5"}
    assert ("Number of policies", "2 to 5") in f.describe()


ROWS = [
    _row("role-a", path="/service/", trust_types=["service"], principals=["lambda.amazonaws.com"],
         inline=1, managed=1, last_used_at="2026-05-25T00:00:00+00:00", last_used_days=7),
    _row("role-b", trust_types=["account"], principals=[f"account {ACCOUNT}"],
         last_used_at="2025-12-01T00:00:00+00:00", last_used_days=182,
         boundary=f"arn:aws:iam::{ACCOUNT}:policy/boundary-a"),
    _row("role-c", path="/aws-service-role/", service_linked=True, trust_types=["service"],
         managed=3),
    _row("role-d", trust_types=["oidc", "cross-account"], last_used_at="2026-03-01T00:00:00Z",
         last_used_days=92, inline=2),
]  # fmt: skip


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({}, ["role-a", "role-b", "role-c", "role-d"]),
        ({"q": "SERVICE"}, ["role-a", "role-c"]),  # name / path / ARN / principal, any case
        ({"q": "lambda"}, ["role-a"]),
        ({"used": "never"}, ["role-c"]),
        ({"used": "30"}, ["role-b", "role-d"]),
        ({"used": "90"}, ["role-b", "role-d"]),
        ({"used": "180"}, ["role-b"]),
        ({"trust": "service"}, ["role-a", "role-c"]),
        ({"trust": "account"}, ["role-b"]),
        ({"trust": "cross-account"}, ["role-d"]),
        ({"trust": "oidc"}, ["role-d"]),
        ({"trust": "saml"}, []),
        ({"slr": "yes"}, ["role-c"]),
        ({"slr": "no"}, ["role-a", "role-b", "role-d"]),
        ({"boundary": "yes"}, ["role-b"]),
        ({"inline": "yes"}, ["role-a", "role-d"]),
        ({"inline": "no"}, ["role-b", "role-c"]),
        ({"pmin": "2"}, ["role-a", "role-c", "role-d"]),
        ({"pmax": "0"}, ["role-b"]),
        ({"pmin": "2", "pmax": "2"}, ["role-a", "role-d"]),
        ({"trust": "service", "inline": "no", "used": "never"}, ["role-c"]),
    ],
)
def test_filters(args, expected):
    assert [r["name"] for r in RoleFilters.from_args(args).apply(ROWS)] == expected
