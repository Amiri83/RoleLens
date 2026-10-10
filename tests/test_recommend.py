"""Duplicate / overlap math and the merged role. Placeholder data only (role-a, bucket-a)."""

import itertools
import random

import pytest

from rolelens.effective import Grant, canonical
from rolelens.recommend import (
    RolePerms,
    compare,
    duplicates,
    jaccard,
    merge_statements,
    merged_model,
    overlaps,
    parse_threshold,
    relation,
)
from rolelens.validate import has_errors, validate_model

from .conftest import ACCOUNT, ACCOUNT_TRUST, LAMBDA_TRUST

AWS_RO = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def _perms(name, actions, trust=LAMBDA_TRUST, resource="*"):
    grants = frozenset(Grant(a, resource, "") for a in actions)
    return RolePerms(name, grants, frozenset(actions), canonical(trust))


def _actions(n, prefix="s3:Action"):
    return [f"{prefix}{i}" for i in range(n)]


def test_jaccard_and_relation():
    a, b = frozenset({"x", "y"}), frozenset({"y", "z"})
    assert jaccard(a, b) == pytest.approx(1 / 3)
    assert jaccard(a, a) == 1.0
    assert jaccard(frozenset(), frozenset()) == 0.0
    assert relation(a, a) == "equal"
    assert relation(frozenset({"x"}), a) == "subset"
    assert relation(a, frozenset({"x"})) == "superset"
    assert relation(a, b) == "overlap"


def test_duplicates_need_same_grants_and_trust():
    roles = [
        _perms("role-b", ["s3:GetObject", "sqs:SendMessage"]),
        _perms("role-a", ["s3:GetObject", "sqs:SendMessage"]),
        _perms("role-c", ["s3:GetObject", "sqs:SendMessage"], trust=ACCOUNT_TRUST),
        _perms("role-d", ["s3:GetObject", "sqs:SendMessage"], resource="arn:aws:s3:::bucket-a"),
        _perms("role-e", []),
        _perms("role-f", []),  # roles without permissions are never duplicates
    ]
    assert duplicates(roles) == [["role-a", "role-b"]]


def test_overlaps_threshold_relation_and_counts():
    base = _actions(10)
    roles = [
        _perms("role-a", base),
        _perms("role-b", base[:9]),  # subset, Jaccard 0.9
        _perms("role-c", base[:8] + ["sqs:SendMessage", "sqs:ReceiveMessage"]),
        _perms("role-d", ["ec2:DescribeInstances"]),
    ]
    (pair,) = overlaps(roles, 0.8)
    assert (pair["a"], pair["b"]) == ("role-a", "role-b")
    assert pair["jaccard"] == 0.9 and pair["relation"] == "superset"
    assert (pair["only_a"], pair["common"], pair["only_b"]) == (1, 9, 0)
    assert pair["same_trust"]

    def scores(t):
        return {(p["a"], p["b"]): p["jaccard"] for p in overlaps(roles, t)}

    # role-b / role-c: 8 common of 11; role-a / role-c: 8 common of 12
    assert scores(0.7) == {("role-a", "role-b"): 0.9, ("role-b", "role-c"): 0.727}
    assert scores(0.6)[("role-a", "role-c")] == 0.667
    assert overlaps(roles, 1.0) == []


def test_overlaps_exclude_duplicates_but_keep_same_perms_other_trust():
    roles = [
        _perms("role-a", ["s3:GetObject"]),
        _perms("role-b", ["s3:GetObject"]),
        _perms("role-c", ["s3:GetObject"], trust=ACCOUNT_TRUST),
    ]
    pairs = overlaps(roles, 0.8)
    assert {(p["a"], p["b"]) for p in pairs} == {("role-a", "role-c"), ("role-b", "role-c")}
    assert all(p["relation"] == "equal" and not p["same_trust"] for p in pairs)


def test_overlap_pruning_matches_brute_force():
    rng = random.Random(7)  # noqa: S311 - reproducible test data, not cryptography
    pool = _actions(30)
    roles = [_perms(f"role-{i}", rng.sample(pool, rng.randint(1, 30))) for i in range(25)]
    for t in (0.5, 0.8, 0.95):
        expected = {
            tuple(sorted((a.name, b.name)))
            for a, b in itertools.combinations(roles, 2)
            if jaccard(a.actions, b.actions) >= t and a.grants != b.grants
        }
        assert {(p["a"], p["b"]) for p in overlaps(roles, t, limit=10_000)} == expected


def test_compare_side_by_side():
    a = _perms("role-a", ["s3:GetObject", "s3:PutObject", "sqs:SendMessage"])
    b = _perms("role-b", ["s3:GetObject", "ec2:DescribeInstances"])
    cmp = compare(a, b)
    assert cmp["counts"] == {"only_a": 2, "common": 1, "only_b": 1}
    rows = {r["service"]: r for r in cmp["services"]}
    assert rows["s3"] == {
        "service": "s3",
        "only_a": ["s3:PutObject"],
        "common": ["s3:GetObject"],
        "only_b": [],
    }
    assert rows["ec2"]["only_b"] == ["ec2:DescribeInstances"]
    assert cmp["jaccard"] == 0.25 and cmp["relation"] == "overlap"


@pytest.mark.parametrize(
    "value, expected",
    [("0.9", 0.9), (0.75, 0.75), ("1", 1.0), ("0.2", 0.8), ("x", 0.8), (None, 0.8), ("nan", 0.8)],
)
def test_parse_threshold(value, expected):
    assert parse_threshold(value) == expected


def test_merge_statements_combines_compatible_statements():
    sts = [
        {
            "Sid": "Read",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::bucket-a/*",
        },
        {
            "Sid": "Read",
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": "arn:aws:s3:::bucket-a",
        },
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": ["arn:aws:s3:::bucket-a/*"]},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
    ]
    merged = merge_statements(sts)
    assert merged[0]["Action"] == ["s3:GetObject", "s3:PutObject"]
    assert merged[1]["Sid"] == "Read2" and merged[1]["Action"] == "s3:ListBucket"  # unique Sids
    assert merged[2] == sts[3]  # NotAction statements are kept as they are


def _model(name, trust, policies, **kw):
    return {
        "role_name": name,
        "path": "/",
        "description": "",
        "max_session_duration": kw.get("session", 3600),
        "permissions_boundary": kw.get("boundary", ""),
        "trust": trust,
        "policies": policies,
    }


def test_merged_model_unions_policies_and_exports():
    shared = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-a/*"}
    a = _model(
        "role-a",
        LAMBDA_TRUST,
        [
            {
                "name": "inline-a",
                "kind": "inline",
                "document": {"Version": "2012-10-17", "Statement": [shared]},
            },
            {"name": "ReadOnlyAccess", "kind": "aws", "arn": AWS_RO, "document": None},
        ],
    )
    b = _model(
        "role-b",
        ACCOUNT_TRUST,
        [
            {
                "name": "inline-b",
                "kind": "inline",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {**shared, "Sid": "Same"},
                        {
                            "Effect": "Allow",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::bucket-a/*",
                        },
                    ],
                },
            },
            {"name": "ReadOnlyAccess", "kind": "aws", "arn": AWS_RO, "document": None},
            {
                "name": "policy-a",
                "kind": "managed",
                "arn": f"arn:aws:iam::{ACCOUNT}:policy/policy-a",
                "document": {"Version": "2012-10-17", "Statement": [shared]},
            },
        ],
        session=7200,
    )
    m = merged_model(a, b)
    assert m["role_name"] == "role-a-merged" and m["max_session_duration"] == 7200
    kinds = [(p["name"], p["kind"]) for p in m["policies"]]
    assert kinds == [
        ("ReadOnlyAccess", "aws"),
        ("policy-a", "managed"),
        ("merged-inline", "inline"),
    ]
    (inline,) = m["policies"][-1]["document"]["Statement"]
    assert inline["Action"] == ["s3:GetObject", "s3:PutObject"]  # duplicate dropped, combined
    # different trust policies: the union of their statements
    assert len(m["trust"]["Statement"]) == 2
    assert not has_errors(validate_model(m))
    # same trust: kept as it is
    assert merged_model(a, {**b, "trust": LAMBDA_TRUST})["trust"] == LAMBDA_TRUST
