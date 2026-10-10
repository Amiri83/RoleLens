"""IAM validation: JSON syntax, structure, Effect / Action / Resource and known action names."""

import copy

import pytest

from rolelens.validate import (
    ERROR,
    WARNING,
    condition_operator_ok,
    has_errors,
    parse_json,
    validate_document,
    validate_model,
)

from .conftest import INLINE_A, LAMBDA_TRUST

LAMBDA = {"Service": "lambda.amazonaws.com"}


def _identity(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _msgs(issues, level=ERROR):
    return [(i.path, i.message) for i in issues if i.level == level]


def test_valid_documents_have_no_issues():
    assert validate_document(INLINE_A, "inline", "policy:policy-inline-a") == []
    assert validate_document(LAMBDA_TRUST, "trust", "trust") == []


def test_json_syntax_error_reports_line_and_column():
    doc, issues = parse_json('{\n  "Version": "2012-10-17",\n  "Statement": [\n}', "trust")
    assert doc is None
    assert len(issues) == 1 and issues[0].level == ERROR
    assert "line 4" in issues[0].message


@pytest.mark.parametrize(
    "statement, path, fragment",
    [
        (
            {"Action": "s3:GetObject", "Resource": "*"},
            "Statement[0].Effect",
            "Effect is required",
        ),
        (
            {"Effect": "allow", "Action": "s3:GetObject", "Resource": "*"},
            "Statement[0].Effect",
            'Effect must be "Allow" or "Deny"',
        ),
        (
            {"Effect": "Allow", "Resource": "*"},
            "Statement[0].Action",
            "Action (or NotAction) is required",
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObject", "NotAction": "s3:Put*", "Resource": "*"},
            "Statement[0]",
            "use either Action or NotAction",
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObject"},
            "Statement[0].Resource",
            "Resource (or NotResource)",
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObjekt", "Resource": "*"},
            "Statement[0].Action",
            "unknown action 's3:GetObjekt'",
        ),
        (
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:Fly*"], "Resource": "*"},
            "Statement[0].Action[1]",
            "unknown action 's3:Fly*'",
        ),
        (
            {"Effect": "Allow", "Action": "GetObject", "Resource": "*"},
            "Statement[0].Action",
            "is not",
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "bucket-a"},
            "Statement[0].Resource",
            'must be "*" or an ARN',
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3"},
            "Statement[0].Resource",
            "not a complete ARN",
        ),
        (
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"},
            "Statement[0].Principal",
            "must not have Principal",
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Resources": "*"},
            "Statement[0].Resources",
            "unknown statement element",
        ),
        (
            {"Sid": "has space", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            "Statement[0].Sid",
            "letters and digits",
        ),
        (
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEqualz": {"aws:PrincipalTag/team": "team-a"}},
            },
            "Statement[0].Condition.StringEqualz",
            "unknown condition operator",
        ),
    ],
)
def test_identity_policy_errors(statement, path, fragment):
    issues = validate_document(_identity(statement), "inline", "policy:policy-a")
    assert any(p == path and fragment in m for p, m in _msgs(issues)), _msgs(issues)


def test_document_level_errors():
    assert _msgs(validate_document([], "inline", "policy:p")) == [
        ("", "a policy document must be a JSON object")
    ]
    issues = validate_document({"Version": "2012-10-17"}, "inline", "policy:p")
    assert ("Statement", "Statement is required") in _msgs(issues)
    issues = validate_document({"Version": "2020-01-01", "Statement": []}, "inline", "policy:p")
    assert {p for p, _ in _msgs(issues)} == {"Version", "Statement"}
    issues = validate_document({"Statement": INLINE_A["Statement"]}, "inline", "policy:p")
    assert _msgs(issues) == [] and _msgs(issues, WARNING)[0][0] == "Version"


def test_duplicate_sids():
    st = {"Sid": "A", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    issues = validate_document(_identity(st, dict(st)), "inline", "policy:p")
    assert ("Statement[1].Sid", "duplicate Sid 'A'") in _msgs(issues)


def test_known_actions_are_case_insensitive_and_wildcards_resolve():
    actions = ["S3:getobject", "sqs:Send*", "dynamodb:*", "*"]
    doc = _identity({"Effect": "Allow", "Action": actions, "Resource": "*"})
    issues = validate_document(doc, "inline", "policy:p")
    assert _msgs(issues) == []
    # "*" / "*" is valid but flagged
    assert any("every action" in m for _, m in _msgs(issues, WARNING))


def test_unknown_service_is_only_a_warning():
    doc = _identity({"Effect": "Allow", "Action": "examplesvc:DoThing", "Resource": "*"})
    issues = validate_document(doc, "inline", "policy:p")
    assert not has_errors(issues)
    assert _msgs(issues, WARNING) == [
        ("Statement[0].Action", "service 'examplesvc' is not in the catalog; not checked")
    ]


def test_trust_policy_rules():
    base = {"Effect": "Allow", "Principal": LAMBDA, "Action": "sts:AssumeRole"}

    def errors(**changes):
        st = {k: v for k, v in {**base, **changes}.items() if v is not None}
        return [m for _, m in _msgs(validate_document(_identity(st), "trust", "trust"))]

    def has(fragment, messages):
        return any(fragment in m for m in messages)

    assert errors() == []
    assert has("Principal (or NotPrincipal) is required", errors(Principal=None))
    assert has("must not have Resource", errors(Resource="*"))
    assert has("not a trust policy action", errors(Action="s3:GetObject"))
    assert has("unknown principal type", errors(Principal={"User": "role-a"}))
    assert has("only allowed with Deny", errors(Principal=None, NotPrincipal={"AWS": "*"}))
    assert errors(Action=["sts:AssumeRole", "sts:TagSession"]) == []
    assert errors(Action="sts:*") == []
    open_trust = validate_document(_identity({**base, "Principal": "*"}), "trust", "trust")
    assert any("anyone can assume" in m for _, m in _msgs(open_trust, WARNING))


def test_condition_operators():
    for op in ("StringEquals", "ForAnyValue:StringLike", "ArnLikeIfExists", "Null", "Bool"):
        assert condition_operator_ok(op), op
    for op in ("StringEqualz", "ForSomeValues:StringLike", "NullIfExists"):
        assert not condition_operator_ok(op), op


def _model(**changes):
    model = {
        "role_name": "role-a",
        "path": "/",
        "description": "",
        "max_session_duration": 3600,
        "permissions_boundary": "",
        "trust": copy.deepcopy(LAMBDA_TRUST),
        "policies": [
            {"name": "policy-inline-a", "kind": "inline", "document": copy.deepcopy(INLINE_A)}
        ],
    }
    model.update(changes)
    return model


def test_model_validation():
    assert validate_model(_model()) == []
    issues = validate_model(_model(role_name="role a!", path="team-a", max_session_duration=60))
    assert {i.path for i in issues if i.where == "role"} == {
        "role_name",
        "path",
        "max_session_duration",
    }
    dup = _model()
    dup["policies"].append(copy.deepcopy(dup["policies"][0]))
    assert any("duplicate inline policy name" in i.message for i in validate_model(dup))
    incomplete = {"name": "policy-x", "kind": "inline", "document": {"Version": "2012-10-17"}}
    issues = validate_model(_model(policies=[incomplete]))
    assert [(i.where, i.path) for i in issues if i.level == ERROR] == [
        ("policy:policy-x", "Statement")
    ]


def test_aws_managed_policy_without_document_is_fine():
    model = _model()
    arn = "arn:aws:iam::aws:policy/policy-b"
    model["policies"].append({"name": "policy-b", "kind": "aws", "arn": arn, "document": None})
    assert validate_model(model) == []
