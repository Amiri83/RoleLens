"""Effective permissions: union of every policy, wildcard expansion, Deny subtraction.

Placeholder data only (role-a, 123456789012, bucket-a)."""

from rolelens import iam_actions
from rolelens.effective import Grant, action_set, by_service, effective_permissions, expand

from .conftest import ACCOUNT, INLINE_A, POLICY_A

BUCKET = "arn:aws:s3:::bucket-a/*"


def _model(*docs, kinds=None):
    kinds = kinds or ["inline"] * len(docs)
    return {
        "role_name": "role-a",
        "policies": [
            {"name": f"policy-{i}", "kind": kind, "document": doc}
            for i, (doc, kind) in enumerate(zip(docs, kinds, strict=True))
        ],
    }


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def test_expand_exact_wildcard_and_unknown_service():
    assert expand(["s3:GetObject"]) == {"s3:GetObject"}
    assert expand(["S3:getobject"]) == {"s3:GetObject"}  # IAM matching is case-insensitive
    gets = expand(["s3:Get*"])
    assert "s3:Get*" in gets  # kept: it also grants actions the catalog does not list
    assert {"s3:GetObject", "s3:GetBucketPolicy"} <= gets
    assert not any(a.startswith("s3:Put") for a in gets)
    # a service outside the catalog is kept as written (service lower-cased)
    assert expand(["Example-Svc:DoThing"]) == {"example-svc:DoThing"}
    everything = expand(["*"])
    assert "*" in everything and iam_actions.all_actions() <= everything
    assert expand(["*:Get*"]) >= {"s3:GetObject", "iam:GetRole", "*:Get*"}


def test_union_of_inline_customer_and_aws_managed_policies():
    model = _model(
        INLINE_A,
        POLICY_A,
        _doc(_allow("ec2:DescribeInstances")),
        kinds=["inline", "managed", "aws"],
    )
    perms = effective_permissions(model)
    assert action_set(perms) == {"s3:GetObject", "sqs:SendMessage", "ec2:DescribeInstances"}
    assert perms[Grant("s3:GetObject", BUCKET, "")] == ["policy-0"]
    queue = f"arn:aws:sqs:us-east-1:{ACCOUNT}:queue-a"
    assert perms[Grant("sqs:SendMessage", queue, "")] == ["policy-1"]
    # the same grant from two policies lists both
    twice = effective_permissions(_model(POLICY_A, POLICY_A))
    assert twice[Grant("sqs:SendMessage", queue, "")] == ["policy-0", "policy-1"]


def test_unconditional_deny_on_star_is_subtracted_narrow_deny_is_not():
    allow = _allow(["s3:GetObject", "s3:PutObject", "sqs:SendMessage"])
    deny_star = {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}
    assert action_set(effective_permissions(_model(_doc(allow, deny_star)))) == {
        "s3:GetObject",
        "sqs:SendMessage",
    }
    deny_bucket = {"Effect": "Deny", "Action": "s3:PutObject", "Resource": BUCKET}
    deny_cond = {
        "Effect": "Deny",
        "Action": "s3:PutObject",
        "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    for deny in (deny_bucket, deny_cond):
        assert "s3:PutObject" in action_set(effective_permissions(_model(_doc(allow, deny))))
    # a Deny in another policy applies too; Deny "*" leaves nothing
    other = _doc({"Effect": "Deny", "Action": "s3:*", "Resource": "*"})
    assert action_set(effective_permissions(_model(_doc(allow), other))) == {"sqs:SendMessage"}
    assert effective_permissions(_model(_doc(allow), _doc({**deny_star, "Action": "*"}))) == {}


def test_not_action_not_resource_and_conditions():
    not_iam = {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    actions = action_set(effective_permissions(_model(_doc(not_iam))))
    assert "*" in actions and "s3:GetObject" in actions
    assert not any(a.startswith("iam:") for a in actions)

    not_res = {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": BUCKET}
    assert list(effective_permissions(_model(_doc(not_res)))) == [
        Grant("s3:GetObject", f"NotResource:{BUCKET}", "")
    ]

    cond = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
    grants = effective_permissions(_model(_doc(_allow("sqs:SendMessage", Condition=cond))))
    (grant,) = grants
    assert grant.condition == '{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}'


def test_unreadable_documents_and_deny_only_policies():
    model = {
        "role_name": "role-a",
        "policies": [
            {"name": "policy-a", "kind": "managed", "document": None},
            {"name": "policy-b", "kind": "inline", "document": _doc(INLINE_A["Statement"][1])},
        ],
    }
    assert effective_permissions(model) == {}


def test_by_service():
    assert by_service(["s3:GetObject", "*", "sqs:SendMessage", "s3:PutObject"]) == {
        "*": ["*"],
        "s3": ["s3:GetObject", "s3:PutObject"],
        "sqs": ["sqs:SendMessage"],
    }
