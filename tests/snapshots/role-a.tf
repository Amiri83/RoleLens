# Generated for tests.

data "aws_iam_policy_document" "role_a_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
  statement {
    sid     = "CrossAccount"
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["example-external-id"]
    }
  }
}

resource "aws_iam_role" "role_a" {
  name                 = "role-a"
  path                 = "/team-a/"
  description          = "Example role for tests"
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.role_a_trust.json
  permissions_boundary = "arn:aws:iam::123456789012:policy/boundary-a"
}

data "aws_iam_policy_document" "role_a_policy_inline_a" {
  statement {
    sid       = "ReadBucket"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::bucket-a", "arn:aws:s3:::bucket-a/$${aws:username}/*"]
  }
  statement {
    effect        = "Deny"
    not_actions   = ["s3:*"]
    not_resources = ["arn:aws:s3:::bucket-a/*"]
  }
}

resource "aws_iam_role_policy" "role_a_policy_inline_a" {
  name   = "policy-inline-a"
  role   = aws_iam_role.role_a.id
  policy = data.aws_iam_policy_document.role_a_policy_inline_a.json
}

data "aws_iam_policy_document" "policy_a" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = ["*"]
  }
}

# Customer managed policy policy-a exists already; import it before applying:
#   terraform import aws_iam_policy.policy_a arn:aws:iam::123456789012:policy/policy-a
resource "aws_iam_policy" "policy_a" {
  name   = "policy-a"
  path   = "/"
  policy = data.aws_iam_policy_document.policy_a.json
}

resource "aws_iam_role_policy_attachment" "role_a_policy_a" {
  role       = aws_iam_role.role_a.name
  policy_arn = aws_iam_policy.policy_a.arn
}

resource "aws_iam_role_policy_attachment" "role_a_policy_b" {
  role       = aws_iam_role.role_a.name
  policy_arn = "arn:aws:iam::aws:policy/policy-b"
}
