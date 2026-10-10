"""Risk rules: one test per rule, positive and negative cases.

Placeholder data only: own account 123456789012, other account 111122223333 (the AWS
documentation example), role-a, bucket-a, oidc.example.com."""

import json

import pytest

from rolelens.findings import RULES, risk_score, role_findings

from .conftest import ACCOUNT, ACCOUNT_TRUST, LAMBDA_TRUST

OTHER = "111122223333"
BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/boundary-a"
OIDC = f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.example.com"


def _role(*statements, trust=None, kind="managed", boundary=BOUNDARY, path="/", doc=True):
    policies = []
    if statements:
        policies.append(
            {
                "name": "policy-a",
                "kind": kind,
                "arn": f"arn:aws:iam::{ACCOUNT}:policy/policy-a",
                "document": {"Version": "2012-10-17", "Statement": list(statements)}
                if doc
                else None,
            }
        )
    return {
        "role_name": "role-a",
        "arn": f"arn:aws:iam::{ACCOUNT}:role{path}role-a",
        "path": path,
        "permissions_boundary": boundary,
        "trust": trust if trust is not None else LAMBDA_TRUST,
        "policies": policies,
    }


def _allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def _trust(principal, action="sts:AssumeRole", condition=None):
    st = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        st["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [st]}


def _rules(model):
    return {f.rule: f for f in role_findings(model)}


def test_clean_role_has_no_findings():
    assert role_findings(_role(_allow("s3:GetObject", "arn:aws:s3:::bucket-a/*"))) == []


def test_every_finding_has_severity_why_and_fix():
    model = _role(_allow("*"), _allow("iam:PassRole"), trust=_trust({"AWS": "*"}), boundary="")
    found = role_findings(model)
    assert {f.rule for f in found} == {
        "admin",
        "wildcard",  # iam:PassRole on Resource "*"
        "passrole",
        "cross-account-no-external-id",
        "no-boundary",
    }
    for f in found:
        assert f.severity in ("critical", "high", "medium", "low")
        assert f.why and f.fix and f.title == RULES[f.rule].title
        assert f.role == "role-a"
    # sorted worst first
    assert found[0].severity == "critical"


@pytest.mark.parametrize(
    "statement, severity",
    [
        (_allow("*"), "critical"),
        (_allow("*:*"), "critical"),
        (_allow("iam:*", f"arn:aws:iam::{ACCOUNT}:role/*"), "critical"),
        (_allow("ec2:*"), "high"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, "high"),
        # a Condition lowers the severity one level
        (_allow("*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}), "high"),
    ],
)
def test_admin_equivalent(statement, severity):
    found = _rules(_role(statement))
    assert found["admin"].severity == severity
    assert "wildcard" not in found  # the admin finding covers the statement
    assert found["admin"].statements == ["#0"]
    fix = json.loads(found["admin"].fix)
    assert "*" not in fix["Resource"][0].split(":")[-1:]


def test_admin_from_unreadable_administrator_access():
    model = _role(_allow("s3:GetObject", "arn:aws:s3:::bucket-a/*"))
    model["policies"].append(
        {
            "name": "AdministratorAccess",
            "kind": "aws",
            "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "document": None,
        }
    )
    assert _rules(model)["admin"].where == "policy AdministratorAccess"


def test_service_wildcard_on_one_resource_is_not_admin():
    found = _rules(_role(_allow("s3:*", "arn:aws:s3:::bucket-a/*")))
    assert "admin" not in found
    assert found["wildcard"].severity == "medium"


@pytest.mark.parametrize(
    "statement, severity",
    [
        (_allow("s3:Get*"), "high"),  # wildcard action on "*"
        (_allow("s3:Get*", "arn:aws:s3:::bucket-a/*"), "medium"),  # wildcard action only
        (_allow("s3:GetObject"), "low"),  # Resource "*" only
        (_allow("s3:GetObject", Condition={"StringEquals": {"aws:ResourceTag/team": "a"}}), "low"),
        (_allow("s3:Get*", Condition={"StringEquals": {"aws:ResourceTag/team": "a"}}), "medium"),
    ],
)
def test_wildcard_action_and_or_resource(statement, severity):
    found = _rules(_role(statement))
    assert found["wildcard"].severity == severity
    fix = json.loads(found["wildcard"].fix)
    assert all("*" not in a for a in fix["Action"])


def test_wildcard_is_one_finding_per_policy_with_every_statement():
    found = _rules(_role(_allow("s3:Get*", Sid="Read"), _allow("sqs:SendMessage")))
    assert found["wildcard"].statements == ["#0 (Read)", "#1"]
    assert found["wildcard"].severity == "high"  # the worst statement wins
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*"}
    assert "wildcard" not in _rules(_role(deny))  # Deny statements are never findings


@pytest.mark.parametrize(
    "statement, expected",
    [
        (_allow("iam:PassRole"), "high"),
        (_allow(["iam:Pass*", "s3:GetObject"]), "high"),
        (
            _allow("iam:PassRole", Condition={"StringEquals": {"iam:PassedToService": "x"}}),
            "medium",
        ),
        (_allow("iam:PassRole", f"arn:aws:iam::{ACCOUNT}:role/role-a"), None),
        (_allow("iam:GetRole"), None),
    ],
)
def test_passrole_on_star(statement, expected):
    found = _rules(_role(statement))
    if expected is None:
        assert "passrole" not in found
    else:
        assert found["passrole"].severity == expected
        assert json.loads(found["passrole"].fix)["Condition"]["StringEquals"]


@pytest.mark.parametrize(
    "principal, condition, severity",
    [
        ({"AWS": f"arn:aws:iam::{OTHER}:role/role-b"}, None, "high"),
        ({"AWS": OTHER}, None, "high"),
        ({"AWS": "*"}, None, "critical"),
        (
            {"AWS": f"arn:aws:iam::{OTHER}:role/role-b"},
            {"StringEquals": {"sts:ExternalId": "x"}},
            None,
        ),
        ({"AWS": f"arn:aws:iam::{ACCOUNT}:role/role-b"}, None, None),  # same account
        ({"Service": "lambda.amazonaws.com"}, None, None),
    ],
)
def test_cross_account_without_external_id(principal, condition, severity):
    found = _rules(_role(trust=_trust(principal, condition=condition)))
    if severity is None:
        assert "cross-account-no-external-id" not in found
    else:
        f = found["cross-account-no-external-id"]
        assert f.severity == severity and f.where == "trust policy"
        fixed = json.loads(f.fix)
        assert fixed["Condition"]["StringEquals"]["sts:ExternalId"] == "<external-id>"


def test_trust_to_another_accounts_root():
    for principal in (f"arn:aws:iam::{OTHER}:root", OTHER):
        found = _rules(_role(trust=_trust({"AWS": principal})))
        assert found["root-trust"].severity == "medium"
        fixed = json.loads(found["root-trust"].fix)
        assert fixed["Principal"]["AWS"] == f"arn:aws:iam::{OTHER}:role/<role-that-assumes>"
    # own account root (with an ExternalId, as in the shared fixture): no finding
    assert _rules(_role(trust=ACCOUNT_TRUST)) == {}
    assert "root-trust" not in _rules(_role(trust=_trust({"AWS": f"arn:aws:iam::{OTHER}:role/r"})))


@pytest.mark.parametrize(
    "condition, flagged",
    [
        (None, True),
        ({"StringEquals": {"oidc.example.com:aud": "sts.amazonaws.com"}}, True),
        ({"StringLike": {"oidc.example.com:sub": "*"}}, True),
        ({"StringLike": {"oidc.example.com:sub": "repo:example/role-a:*"}}, False),
        ({"StringEquals": {"oidc.example.com:sub": "system:serviceaccount:a:b"}}, False),
    ],
)
def test_oidc_trust_without_sub(condition, flagged):
    trust = _trust({"Federated": OIDC}, "sts:AssumeRoleWithWebIdentity", condition)
    found = _rules(_role(trust=trust))
    assert ("oidc-no-sub" in found) is flagged
    if flagged:
        fixed = json.loads(found["oidc-no-sub"].fix)
        assert "oidc.example.com:sub" in fixed["Condition"]["StringEquals"]


def test_saml_and_cognito_with_aud_are_not_oidc_findings():
    saml = f"arn:aws:iam::{ACCOUNT}:saml-provider/example"
    assert _rules(_role(trust=_trust({"Federated": saml}, "sts:AssumeRoleWithSAML"))) == {}
    cognito = _trust(
        {"Federated": "cognito-identity.amazonaws.com"},
        "sts:AssumeRoleWithWebIdentity",
        {"StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east-1:example"}},
    )
    assert _rules(_role(trust=cognito)) == {}


def test_no_permissions_boundary():
    assert _rules(_role(boundary=""))["no-boundary"].severity == "low"
    assert "no-boundary" not in _rules(_role())
    # service-linked roles cannot have one
    assert "no-boundary" not in _rules(_role(boundary="", path="/aws-service-role/"))


def test_only_inline_policies():
    statement = _allow("s3:GetObject", "arn:aws:s3:::bucket-a/*")
    found = _rules(_role(statement, kind="inline"))
    assert found["inline-only"].severity == "low"
    assert 'resource "aws_iam_policy"' in found["inline-only"].fix
    assert "inline-only" not in _rules(_role(statement, kind="managed"))
    assert "inline-only" not in _rules(_role())  # no policies at all


def test_risk_score():
    found = role_findings(_role(_allow("*"), boundary=""))
    # admin (critical) + passrole ("*" includes iam:PassRole, high) + no-boundary (low)
    assert [f.rule for f in found] == ["admin", "passrole", "no-boundary"]
    assert risk_score(found) == 10 + 5 + 1
    assert risk_score([{"severity": "high"}, {"severity": "medium"}]) == 7
