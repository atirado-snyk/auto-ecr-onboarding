# Example: the IAM role Snyk assumes to read the ECR registries of one AWS account.
#
# Default mode, one Snyk org per registry: Snyk allows one ECR integration per Snyk org, and an
# integration covers one account and one region, so every region you onboard needs its own Snyk org.
# List those orgs in snyk_orgs, by region.
#
# Profiles mode: an org where Snyk has turned on its multiple profiles feature holds any number of ECR
# connections, to any region of this account. List such orgs in snyk_profile_orgs, with no region:
# connecting another of this account's registries to an org already listed changes nothing in AWS.
#
# All of them share this one role (IAM roles are global to the account): the role trusts every org ID
# in either input, once.
#
#   1. terraform init
#   2. terraform apply -var 'snyk_orgs={"ap-southeast-2"="<org-id>"}' -var snyk_aws_principal=<principal>
#   3. For each region in snyk_orgs:
#        uv run ../scripts/onboard_ecr.py apply --org-id <org-id> --region <region> \
#          --role-arn "$(terraform output -raw role_arn)" --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'
#
# Adding a region later: list every org in snyk-orgs.auto.tfvars (copy snyk-orgs.auto.tfvars.example; Terraform
# loads *.auto.tfvars automatically, also in Terraform Enterprise) and stop passing snyk_orgs as -var, which
# would override the file. Check that `terraform plan` shows only an in-place update of the role's trust
# policy, apply, then run step 3 for the new region only. Keep every existing entry: Terraform writes the
# trust policy exactly as listed, so removing an entry removes that org's access.

variable "snyk_orgs" {
  description = "Default-mode orgs: ECR registry region => Snyk org ID, one entry per registry in this account."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for region in keys(var.snyk_orgs) : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", region))])
    error_message = "snyk_orgs keys must be AWS regions such as \"ap-southeast-2\": the region of each ECR registry."
  }

  validation {
    condition     = length(distinct(values(var.snyk_orgs))) == length(var.snyk_orgs)
    error_message = "A Snyk org can hold only one ECR integration (one region), so an org ID must not appear under two regions."
  }
}

variable "snyk_profile_orgs" {
  description = "Profiles-mode orgs (Snyk's multiple profiles feature on): Snyk org IDs that read this account's ECR registries, in any region."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.snyk_profile_orgs : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "snyk_profile_orgs entries must be Snyk org IDs (UUIDs)."
  }

  validation {
    condition     = length(distinct(var.snyk_profile_orgs)) == length(var.snyk_profile_orgs)
    error_message = "snyk_profile_orgs lists an org twice; list each org once."
  }
}

locals {
  # Every org the role trusts, once, whichever input lists it (FR-016). Default-mode orgs come first, in the
  # order they always had, so an existing trust policy does not change.
  trusted_org_ids = distinct(concat(values(var.snyk_orgs), var.snyk_profile_orgs))
  # With both inputs empty, the precondition on output.trusted_org_ids stops the plan with this example's
  # own message; the placeholder only keeps the module's own check from reporting first. It is never applied.
  module_org_ids = length(local.trusted_org_ids) > 0 ? local.trusted_org_ids : ["00000000-0000-0000-0000-000000000000"]
}

variable "snyk_aws_principal" {
  description = "Principal from the trust policy your Snyk tenant shows under Integrations > Amazon ECR."
  type        = string
}

provider "aws" {
  # IAM is global; this region only selects the API endpoint Terraform calls.
  region = "ap-southeast-2"

  # Assume a deploy role in the target account; adapt to the existing pipeline.
  # assume_role { role_arn = "arn:aws:iam::111111111111:role/terraform-deploy" }
}

module "snyk_ecr" {
  source = "../terraform/modules/snyk-ecr-role"

  snyk_org_ids       = local.module_org_ids
  snyk_aws_principal = var.snyk_aws_principal

  tags = {
    managed-by = "terraform"
    purpose    = "snyk-container-registry-integration"
  }
}

output "role_arn" {
  description = "Pass as --role-arn to onboard_ecr.py, for every region in snyk_orgs."
  value       = module.snyk_ecr.role_arn
}

output "snyk_orgs" {
  description = "The registries this role serves for default-mode orgs: region => Snyk org ID (the --region and --org-id pairs)."
  value       = var.snyk_orgs
}

output "trusted_org_ids" {
  description = "Every Snyk org ID the role trusts, sorted: the orgs of snyk_orgs and snyk_profile_orgs, once each."
  value       = sort(local.trusted_org_ids)

  precondition {
    condition     = length(local.trusted_org_ids) > 0
    error_message = "snyk_orgs needs at least one entry: region = \"<snyk-org-id>\" (or list profiles-mode orgs in snyk_profile_orgs)."
  }
}
