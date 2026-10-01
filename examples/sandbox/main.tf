# Product under test: the IAM role Snyk assumes, created with the module exactly as a consumer would.
# Applied and destroyed by e2e.sh (up / down). Test infrastructure (the ECR repo) is in ./fixture.

variable "snyk_org_id" {
  description = "Snyk org UUID the role trusts (also the sts:ExternalId)."
  type        = string
}

variable "snyk_aws_principal" {
  description = "Principal from the trust policy your Snyk tenant shows under Integrations > Amazon ECR."
  type        = string
}

variable "role_name" {
  description = "Distinct from the module default so the harness never touches a real snyk-ecr-read role."
  type        = string
  default     = "snyk-ecr-e2e"
}

variable "region" {
  type    = string
  default = "ap-southeast-2"
}

provider "aws" {
  region = var.region
}

module "snyk_ecr" {
  source = "../../terraform/modules/snyk-ecr-role"

  snyk_org_ids       = [var.snyk_org_id]
  snyk_aws_principal = var.snyk_aws_principal
  role_name          = var.role_name

  tags = {
    managed-by = "terraform"
    purpose    = "snyk-ecr-onboarding-e2e"
  }
}

output "role_arn" {
  value = module.snyk_ecr.role_arn
}
