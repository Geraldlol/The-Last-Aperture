############################################################################
# C-009 — clean fixture. Expected findings at Low or above: ZERO.
#
# Four decoys, one per cloud-and-iac false-positive entry, in one file:
#
#   1. `Resource = "*"` in an IAM statement.        (false positive 1)
#   2. `Principal = "*"` in a resource policy.      (false positive 2)
#   3. `kms:*` granted to a `:root` ARN.            (false positive 3)
#   4. A bucket with no server-side-encryption block, and a bucket policy whose
#      only grant is to `cloudfront.amazonaws.com`. (false positives 4 and 7)
#
# Each is the shape a scanner flags and none is the finding it looks like. Read
# the per-resource comments: the discriminator is different in every case, which
# is the point — a single "it's fine, it's AWS boilerplate" reading clears none
# of them, and a single grep clears none of them either.
############################################################################

data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "current" {}

variable "distribution_arn" {
  description = "ARN of the one CloudFront distribution allowed to read the origin"
  type        = string
}

# --------------------------------------------------------------------------
# (1) Resource = "*" — on actions that cannot be resource-scoped.
#
# `ec2:Describe*`, `cloudwatch:PutMetricData` and `s3:ListAllMyBuckets` do not
# support resource-level permissions: an ARN in the Resource element makes the
# statement deny-by-construction rather than least-privilege. Least privilege for
# these is expressed with condition keys, which is what the Condition block does.
# The second statement is the contrast: `s3:GetObject` IS resource-scopable, so
# it is scoped, and a `*` there would be the finding.
# --------------------------------------------------------------------------
data "aws_iam_policy_document" "agent" {
  statement {
    sid    = "DescribeAndMetricsCannotBeResourceScoped"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "cloudwatch:PutMetricData",
      "s3:ListAllMyBuckets",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["us-east-1"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/team"
      values   = ["platform"]
    }
  }

  statement {
    sid       = "ObjectReadIsScopedBecauseItCanBe"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site_origin.arn}/releases/*"]
  }
}

resource "aws_iam_policy" "agent" {
  name   = "metrics-agent"
  policy = data.aws_iam_policy_document.agent.json
}

# --------------------------------------------------------------------------
# (3) kms:* to a `:root` ARN — the AWS default key policy.
#
# `arn:aws:iam::<account>:root` does not mean the root USER. It means "delegate
# authorization for this key to this account's IAM policies", and without it
# IAM-based access to the key does not work at all; removing it can leave the key
# unmanageable. The twelve digits come from `aws_caller_identity`, so this is
# provably the account the configuration deploys to and not a different account's
# root — which is the case this entry most often gets wrong in the dangerous
# direction. The second statement is scoped by `kms:ViaService`.
# --------------------------------------------------------------------------
data "aws_iam_policy_document" "log_key" {
  statement {
    sid    = "EnableIAMPoliciesForThisAccount"
    effect = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "LogsServiceUseOnly"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.us-east-1.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["logs.us-east-1.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "CloudWatch log group encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.log_key.json
}

# --------------------------------------------------------------------------
# (4) A bucket with NO aws_s3_bucket_server_side_encryption_configuration.
#
# Since January 2023 S3 applies SSE-S3 (AES-256) to every object upload in every
# bucket and it cannot be turned off, so the absence of that resource does not
# mean unencrypted. This origin holds public static assets — no classification
# and no contract requires customer-managed key ownership, so the narrower claim
# ("no CMK where key ownership is required") does not apply either. Public access
# is blocked on all four flags, versioning is on, and access logging is on.
# --------------------------------------------------------------------------
resource "aws_s3_bucket" "site_origin" {
  bucket = "example-site-origin"
}

resource "aws_s3_bucket_public_access_block" "site_origin" {
  bucket                  = aws_s3_bucket.site_origin.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "site_origin" {
  bucket = aws_s3_bucket.site_origin.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --------------------------------------------------------------------------
# (7) A bucket policy whose only grant is to the CloudFront service principal.
#
# This is origin access control, and it is what makes the bucket PRIVATE: the
# bucket's own endpoint grants nothing, and reads must arrive through the named
# distribution. The `AWS:SourceArn` condition is present and names ONE
# distribution — without it, any CloudFront distribution in any account could
# read the bucket, and that is the version that is a finding.
# --------------------------------------------------------------------------
data "aws_iam_policy_document" "site_origin" {
  statement {
    sid       = "AllowOneDistributionOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site_origin.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [var.distribution_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site_origin" {
  bucket = aws_s3_bucket.site_origin.id
  policy = data.aws_iam_policy_document.site_origin.json
}

# --------------------------------------------------------------------------
# (2) Principal = "*" in a resource policy.
#
# Judged together with the Condition in the SAME statement. The condition key is
# identity-bearing — `aws:PrincipalOrgID` resolved from the organization data
# source — so the wildcard resolves to "any principal in this organization", which
# is how a vendor-integration or shared-artifact policy is legitimately written.
# `aws:SecureTransport`, `aws:RequestedRegion` and `aws:UserAgent` would NOT clear
# it, and a `StringLike` wildcard in a load-bearing segment would be the finding.
# `StringEquals` on a single org id is neither.
# --------------------------------------------------------------------------
data "aws_iam_policy_document" "artifact_share" {
  statement {
    sid       = "OrgMembersMayReadReleases"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.site_origin.arn,
      "${aws_s3_bucket.site_origin.arn}/releases/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
  }
}

output "artifact_share_policy_json" {
  description = "Rendered for review; attached by the account that owns the share bucket."
  value       = data.aws_iam_policy_document.artifact_share.json
}
