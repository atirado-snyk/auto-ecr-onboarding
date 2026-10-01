# Example: the IAM role Snyk assumes to read one ECR registry (one AWS account).
# Both inputs come from your Snyk tenant: the org ID (Settings > General) and the Principal from the
# trust policy shown under Integrations > Amazon ECR.
#
#   terraform init && terraform apply -var snyk_org_id=<snyk-org-uuid> -var snyk_aws_principal=<principal-arn>
#   uv run ../scripts/onboard_ecr.py apply --org-id <snyk-org-uuid> --region ap-southeast-2 \
#       --role-arn "$(terraform output -raw role_arn)" --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'

variable "snyk_org_id" {
  description = "Snyk org UUID the role trusts (also the sts:ExternalId)."
  type        = string
}

variable "snyk_aws_principal" {
  description = "Principal from the trust policy your Snyk tenant shows under Integrations > Amazon ECR."
  type        = string
}

provider "aws" {
  region = "ap-southeast-2"

  # Assume a deploy role in the target account; adapt to the existing pipeline.
  # assume_role { role_arn = "arn:aws:iam::111111111111:role/terraform-deploy" }
}

module "snyk_ecr" {
  source = "../terraform/modules/snyk-ecr-role"

  snyk_org_ids       = [var.snyk_org_id]
  snyk_aws_principal = var.snyk_aws_principal

  tags = {
    managed-by = "terraform"
    purpose    = "snyk-container-registry-integration"
  }
}

output "role_arn" {
  value = module.snyk_ecr.role_arn
}
