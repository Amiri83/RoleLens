"""Role graph: principals -> role -> policies -> services -> actions -> resources."""

from rolelens.graph import build_graph, short_resource

from .conftest import ACCOUNT_TRUST, INLINE_A, LAMBDA_TRUST, POLICY_A

MODEL = {
    "role_name": "role-a",
    "path": "/",
    "trust": {
        "Version": "2012-10-17",
        "Statement": LAMBDA_TRUST["Statement"] + ACCOUNT_TRUST["Statement"],
    },
    "policies": [
        {"name": "policy-inline-a", "kind": "inline", "document": INLINE_A},
        {
            "name": "policy-a",
            "kind": "managed",
            "arn": "arn:aws:iam::123456789012:policy/policy-a",
            "document": POLICY_A,
        },
    ],
}


def _split(graph):
    nodes, edges = {}, {}
    for e in graph["elements"]:
        if e["group"] == "nodes":
            nodes[e["data"]["id"]] = e
        else:
            edges[(e["data"]["source"], e["data"]["target"])] = e
    return nodes, edges


def test_graph_chain_from_principals_to_resources():
    graph = build_graph(MODEL)
    nodes, edges = _split(graph)

    assert nodes["role"]["data"]["label"] == "role-a"
    lam = "principal:Service:lambda.amazonaws.com"
    acct = "principal:AWS:arn:aws:iam::123456789012:root"
    assert nodes[lam]["data"]["label"] == "lambda.amazonaws.com"
    assert nodes[acct]["data"]["label"] == "account 123456789012"
    assert (lam, "role") in edges and (acct, "role") in edges
    # the trust condition makes that edge conditional (dashed)
    assert "conditional" in edges[(acct, "role")]["classes"]
    assert "conditional" not in edges[(lam, "role")]["classes"]

    assert ("role", "policy:inline:policy-inline-a") in edges
    assert ("policy:inline:policy-inline-a", "service:s3") in edges
    assert ("service:s3", "action:Allow:s3:getobject") in edges
    assert ("action:Allow:s3:getobject", "resource:arn:aws:s3:::bucket-a/*") in edges
    assert ("service:sqs", "action:Allow:sqs:sendmessage") in edges

    assert graph["stats"] == {
        "principals": 2,
        "roles": 1,
        "users": 0,
        "groups": 0,
        "policies": 2,
        "services": 2,
        "actions": 3,
        "resources": 3,
        "deny_edges": 3,
        "truncated": 0,
    }


def test_allow_and_deny_are_styled_apart():
    nodes, edges = _split(build_graph(MODEL))
    deny = nodes["action:Deny:s3:deleteobject"]
    assert deny["classes"] == "action deny"
    assert nodes["action:Allow:s3:getobject"]["classes"] == "action allow"
    assert edges[("service:s3", "action:Deny:s3:deleteobject")]["classes"] == "deny"
    # s3 is reached by an Allow and a Deny statement
    assert nodes["service:s3"]["data"]["effect"] == "mixed"
    assert nodes["service:sqs"]["data"]["effect"] == "allow"
    # attaching a policy is neither Allow nor Deny
    assert edges[("role", "policy:managed:policy-a")]["classes"] == "attached"


def test_node_detail_lists_the_statements_behind_it():
    nodes, _ = _split(build_graph(MODEL))
    detail = nodes["action:Deny:s3:deleteobject"]["data"]["detail"]
    assert detail["statements"] == [
        {
            "policy": "policy-inline-a",
            "sid": "NoDelete",
            "effect": "Deny",
            "condition": {},
            "resources": ["*"],
        }
    ]
    principal = nodes["principal:AWS:arn:aws:iam::123456789012:root"]["data"]["detail"]
    assert principal["statements"][0]["condition"] == {
        "StringEquals": {"sts:ExternalId": "example-external-id"}
    }


def test_not_action_not_resource_and_wildcards():
    model = {
        "role_name": "role-b",
        "trust": LAMBDA_TRUST,
        "policies": [
            {
                "name": "policy-b",
                "kind": "inline",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "NotAction": "iam:*",
                            "NotResource": "arn:aws:s3:::bucket-a",
                        },
                        {"Effect": "Allow", "Action": "sqs:Send*", "Resource": "*"},
                    ],
                },
            }
        ],
    }
    nodes, _ = _split(build_graph(model))
    assert nodes["notaction:Deny:iam:*"]["data"]["label"] == "NOT iam:*"
    assert nodes["notresource:arn:aws:s3:::bucket-a"]["data"]["label"] == "NOT s3:::bucket-a"
    # a wildcard action lists the catalog actions it matches
    assert nodes["action:Allow:sqs:send*"]["data"]["detail"]["matches"] == ["SendMessage"]


def test_empty_and_malformed_documents_do_not_break_the_graph():
    model = {"role_name": "role-c", "trust": {}, "policies": [{"name": "p", "document": None}]}
    graph = build_graph(model)
    nodes, _ = _split(graph)
    assert set(nodes) == {"role", "policy:inline:p"}
    assert nodes["policy:inline:p"]["data"]["detail"]["document_missing"] is True


def test_short_resource():
    assert short_resource("arn:aws:s3:::bucket-a/*") == "s3:::bucket-a/*"
    assert short_resource("*") == "*"
