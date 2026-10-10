"""Drafts: clone a collected role, parse the editor's model, diff against the original."""

import copy
import json

import boto3
from moto import mock_aws

from rolelens import drafts
from rolelens.aws import AwsGateway
from rolelens.collector import Collector
from rolelens.db import closing

from .conftest import INLINE_A, LAMBDA_TRUST, seed_iam


@mock_aws
def _collected(db_path) -> int:
    seed_iam()
    gw = AwsGateway(boto3.session.Session(region_name="us-east-1"))
    return Collector(gw, db_path, account_ref=None).run().snapshot_id


def test_clone_freezes_the_original(db_path):
    snap_id = _collected(db_path)
    with closing(db_path) as conn:
        draft_id = drafts.clone(conn, None, snap_id, "role-a")
        assert drafts.clone(conn, None, snap_id, "no-such-role") is None
    with closing(db_path) as conn:
        draft = drafts.get(conn, draft_id, None)
        assert drafts.get(conn, draft_id, 99) is None  # another account's draft
    assert draft["source_role"] == "role-a"
    assert draft["model"] == draft["original"]
    model = draft["model"]
    assert model["role_name"] == "role-a"
    assert model["path"] == "/service/"
    assert model["trust"] == LAMBDA_TRUST
    assert [p["kind"] for p in model["policies"]] == ["managed", "inline"]
    # role ARN / last-used details are not part of a draft
    assert "arn" not in model and "last_used_at" not in model

    # deleting the snapshot keeps the draft and its baseline
    with closing(db_path) as conn:
        conn.execute("DELETE FROM snapshots")
    with closing(db_path) as conn:
        assert drafts.get(conn, draft_id, None)["original"]["role_name"] == "role-a"


def _original():
    return {
        "role_name": "role-a",
        "path": "/",
        "description": "",
        "max_session_duration": 3600,
        "permissions_boundary": "",
        "trust": copy.deepcopy(LAMBDA_TRUST),
        "policies": [
            {"name": "policy-inline-a", "kind": "inline", "document": copy.deepcopy(INLINE_A)},
            {
                "name": "policy-b",
                "kind": "aws",
                "arn": "arn:aws:iam::aws:policy/policy-b",
                "document": {"Version": "2012-10-17", "Statement": []},
            },
        ],
    }


def test_parse_model_accepts_editor_text_and_keeps_aws_policies_read_only():
    original = _original()
    raw = json.dumps(
        {
            **original,
            "max_session_duration": "7200",
            "trust": json.dumps(LAMBDA_TRUST, indent=2),
            "policies": [
                {"name": " policy-inline-a ", "kind": "inline", "document": json.dumps(INLINE_A)},
                {
                    "name": "policy-b",
                    "kind": "aws",
                    "arn": "arn:aws:iam::aws:policy/policy-b",
                    "document": '{"Statement": "tampered"}',
                },
            ],
        }
    )
    model, issues = drafts.parse_model(raw, original)
    assert issues == []
    assert model["max_session_duration"] == 7200
    assert model["trust"] == LAMBDA_TRUST
    assert model["policies"][0]["name"] == "policy-inline-a"
    assert model["policies"][0]["document"] == INLINE_A
    assert model["policies"][1]["document"] == original["policies"][1]["document"]


def test_parse_model_reports_json_errors_per_document():
    original = _original()
    raw = json.dumps({**original, "trust": '{"Version": "2012-10-17",\n  "Statement": [}'})
    model, issues = drafts.parse_model(raw, original)
    assert model is None
    assert [(i.where, i.level) for i in issues] == [("trust", "error")]
    assert "line 2" in issues[0].message
    model, issues = drafts.parse_model("{not json", original)
    assert model is None and issues[0].where == "role"


def test_diff_sections():
    original = _original()
    edited = copy.deepcopy(original)
    edited["description"] = "Edited"
    edited["policies"][0]["document"]["Statement"][0]["Action"] = ["s3:GetObject", "s3:ListBucket"]
    edited["policies"].pop(1)  # detach policy-b
    edited["policies"].append(
        {"name": "policy-new", "kind": "inline", "document": {"Version": "2012-10-17"}}
    )
    result = drafts.diff(original, edited)
    status = {s["title"]: s["status"] for s in result["sections"]}
    assert status == {
        "Role settings": "changed",
        "Trust policy": "unchanged",
        "policy-b (aws)": "removed",
        "policy-inline-a (inline)": "changed",
        "policy-new (inline)": "added",
    }
    assert result["changed"] == 4
    lines = next(s for s in result["sections"] if s["title"] == "Role settings")["lines"]
    assert {"cls": "del", "text": '-  "description": "",'} in lines
    assert {"cls": "add", "text": '+  "description": "Edited",'} in lines
    assert drafts.diff(original, original)["changed"] == 0
