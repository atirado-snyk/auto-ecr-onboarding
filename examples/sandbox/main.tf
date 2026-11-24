# Product under test: the IAM role Snyk assumes, created with the module exactly as a consumer would.
# Same inputs as examples/main.tf (a region => Snyk org ID map, given as a -var switch or in
# snyk-orgs.auto.tfvars), plus a distinct role name. Applied and destroyed by e2e.sh. Test
# infrastructure (the ECR repositories) is in ./fixture.

variable "snyk_orgs" {
  description = "ECR registry region => Snyk org ID, one entry per registry in this account."
  type        = map(string)

  validation {
    condition     = length(var.snyk_orgs) > 0
    error_message = "snyk_orgs needs at least one entry: region = \"<snyk-org-id>\"."
  }

  validation {
    condition     = alltrue([for region in keys(var.snyk_orgs) : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", region))])
    error_message = "snyk_orgs keys must be AWS regions such as \"ap-southeast-2\": the region of each ECR registry."
  }

  validation {
    condition     = length(distinct(values(var.snyk_orgs))) == length(var.snyk_orgs)
    error_message = "A Snyk org can hold only one ECR integration (one region), so an org ID must not appear under two regions."
  }
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
  description = "IAM is global; this region only selects the API endpoint Terraform calls."
  type        = string
  default     = "ap-southeast-2"
}

provider "aws" {
  region = var.region
}

module "snyk_ecr" {
  source = "../../terraform/modules/snyk-ecr-role"

  snyk_org_ids       = values(var.snyk_orgs)
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

output "snyk_orgs" {
  value = var.snyk_orgs
}
