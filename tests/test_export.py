"""Export snapshots: Terraform HCL and policy JSON files of a placeholder draft.

Set ROLELENS_UPDATE_SNAPSHOTS=1 to rewrite the files under tests/snapshots/ after an
intended change of the output (then review the diff).
"""

import io
import json
import os
import zipfile
from pathlib import Path

from rolelens.export import hcl_string, identifier, json_files, terraform, zip_bytes

SNAPSHOTS = Path(__file__).parent / "snapshots"
UPDATE = os.environ.get("ROLELENS_UPDATE_SNAPSHOTS") == "1"

MODEL = {
    "role_name": "role-a",
    "path": "/team-a/",
    "description": "Example role for tests",
    "max_session_duration": 3600,
    "permissions_boundary": "arn:aws:iam::123456789012:policy/boundary-a",
    "trust": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Sid": "CrossAccount",
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
                "Condition": {"StringEquals": {"sts:ExternalId": "example-external-id"}},
            },
        ],
    },
    "policies": [
        {
            "name": "policy-inline-a",
            "kind": "inline",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ReadBucket",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            "arn:aws:s3:::bucket-a",
                            "arn:aws:s3:::bucket-a/${aws:username}/*",
                        ],
                    },
                    {
                        "Effect": "Deny",
                        "NotAction": "s3:*",
                        "NotResource": "arn:aws:s3:::bucket-a/*",
                    },
                ],
            },
        },
        {
            "name": "policy-a",
            "kind": "managed",
            "arn": "arn:aws:iam::123456789012:policy/policy-a",
            "path": "/",
            "document": {
                "Version": "2012-10-17",
                "Statement": {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
            },
        },
        {
            "name": "policy-b",
            "kind": "aws",
            "arn": "arn:aws:iam::aws:policy/policy-b",
            "document": {"Version": "2012-10-17", "Statement": []},
        },
    ],
}


def _check(name: str, actual: str) -> None:
    path = SNAPSHOTS / name
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    assert actual == path.read_text(encoding="utf-8")


def test_terraform_snapshot():
    _check("role-a.tf", terraform(MODEL, "Generated for tests."))


def test_json_files_snapshot():
    files = json_files(MODEL)
    assert list(files) == [
        "policies/inline-policy-inline-a.json",
        "policies/managed-policy-a.json",
        "role.json",
        "trust-policy.json",
    ]
    parsed = {p: json.loads(c) for p, c in files.items()}
    _check("role-a.files.json", json.dumps(parsed, indent=2) + "\n")
    # every file is pretty-printed (2 spaces) and ends with a newline
    for content in files.values():
        assert content == json.dumps(json.loads(content), indent=2) + "\n"
    # AWS managed policies are referenced, not exported
    assert json.loads(files["role.json"])["ManagedPolicyArns"] == [
        "arn:aws:iam::123456789012:policy/policy-a",
        "arn:aws:iam::aws:policy/policy-b",
    ]


def test_zip_is_deterministic_and_complete():
    files = json_files(MODEL)
    data = zip_bytes(files, "role_a")
    assert data == zip_bytes(files, "role_a")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert zf.namelist() == [f"role_a/{p}" for p in sorted(files)]
        assert zf.read("role_a/trust-policy.json").decode() == files["trust-policy.json"]


def test_hcl_string_escapes_interpolation_and_quotes():
    assert hcl_string("${aws:username}") == '"$${aws:username}"'
    assert hcl_string('say "hi"\n') == '"say \\"hi\\"\\n"'
    assert hcl_string("%{ if }") == '"%%{ if }"'
    assert hcl_string(True) == '"true"'


USER_MODEL = {
    "entity": "user",
    "user_name": "user-a",
    "path": "/",
    "permissions_boundary": "arn:aws:iam::123456789012:policy/boundary-a",
    "groups": ["group-a"],
    "policies": [
        {
            "name": "user-inline-a",
            "kind": "inline",
            "document": MODEL["policies"][0]["document"],
        },
        {
            "name": "policy-a",
            "kind": "managed",
            "arn": "arn:aws:iam::123456789012:policy/policy-a",
            "path": "/",
            "document": MODEL["policies"][0]["document"],
        },
        {"name": "policy-b", "kind": "aws", "arn": "arn:aws:iam::aws:policy/policy-b"},
    ],
}


def test_user_terraform():
    tf = terraform(USER_MODEL, "header line")
    assert tf.startswith("# header line\n\n")
    assert (
        'resource "aws_iam_user" "user_a" {\n'
        '  name                 = "user-a"\n'
        '  path                 = "/"\n'
        '  permissions_boundary = "arn:aws:iam::123456789012:policy/boundary-a"\n'
        "}"
    ) in tf
    assert (
        'resource "aws_iam_user_policy" "user_a_user_inline_a" {\n'
        '  name   = "user-inline-a"\n'
        "  user   = aws_iam_user.user_a.name\n"
        "  policy = data.aws_iam_policy_document.user_a_user_inline_a.json\n"
        "}"
    ) in tf
    assert (
        'resource "aws_iam_user_policy_attachment" "user_a_policy_a" {\n'
        "  user       = aws_iam_user.user_a.name\n"
        "  policy_arn = aws_iam_policy.policy_a.arn\n"
        "}"
    ) in tf
    assert 'policy_arn = "arn:aws:iam::aws:policy/policy-b"' in tf
    assert (
        'resource "aws_iam_user_group_membership" "user_a_groups" {\n'
        "  user   = aws_iam_user.user_a.name\n"
        '  groups = ["group-a"]\n'
        "}"
    ) in tf
    assert "aws_iam_role" not in tf and "assume_role_policy" not in tf


def test_user_and_policy_json_files():
    files = json_files(USER_MODEL)
    assert sorted(files) == [
        "policies/inline-user-inline-a.json",
        "policies/managed-policy-a.json",
        "user.json",
    ]
    user = json.loads(files["user.json"])
    assert user["Groups"] == ["group-a"]
    assert user["ManagedPolicyArns"] == [
        "arn:aws:iam::123456789012:policy/policy-a",
        "arn:aws:iam::aws:policy/policy-b",
    ]
    policy = {
        "entity": "policy",
        "name": "policy-a",
        "path": "/",
        "description": "",
        "arn": "",
        "document": MODEL["policies"][0]["document"],
    }
    tf = terraform(policy)
    assert tf.count('resource "aws_iam_policy"') == 1
    assert "terraform import" not in tf and "description" not in tf
    assert sorted(json_files(policy)) == ["policies/managed-policy-a.json", "policy.json"]


def test_identifiers_are_unique_and_valid():
    taken: set[str] = set()
    assert identifier("role-a", taken) == "role_a"
    assert identifier("role.a", taken) == "role_a_2"
    assert identifier("9role", taken) == "r_9role"
    assert identifier("---", taken) == "item"
