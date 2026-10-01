# Same shape as the trust policy the Snyk UI shows: Snyk's principal may assume the role only when
# it presents one of the allowed Snyk org IDs as sts:ExternalId (AWS's documented third-party
# pattern against the confused-deputy problem). IAM stores a user principal as that user's unique
# ID, so if Snyk ever recreated the user the trust would stop matching until it is re-saved
# (terraform apply); see AWS's "IAM user principals" documentation.
data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "SnykAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.snyk_aws_principal]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = var.snyk_org_ids
    }
  }
}

# Read-only ECR actions, as listed in the Snyk documentation for ECR access.
data "aws_iam_policy_document" "ecr_read" {
  statement {
    sid    = "SnykAllowPull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetRepositoryPolicy",
      "ecr:ListImages",
      "ecr:ListTagsForResource",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "snyk_ecr_read" {
  name                 = var.role_name
  description          = "Read-only access to ECR for Snyk Container registry integration."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

resource "aws_iam_role_policy" "ecr_read" {
  name   = "snyk-ecr-read"
  role   = aws_iam_role.snyk_ecr_read.id
  policy = data.aws_iam_policy_document.ecr_read.json
}
