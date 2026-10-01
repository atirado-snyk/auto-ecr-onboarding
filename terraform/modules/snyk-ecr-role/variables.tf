variable "snyk_aws_principal" {
  description = <<-EOT
    ARN of the AWS principal Snyk assumes the role from. Required, with no default: copy the
    "Principal" from the trust policy your Snyk tenant shows under Integrations > Amazon ECR, as
    Snyk's documentation instructs. It differs per Snyk tenant and is Snyk's to change, so it is not
    baked in here. (Prefer that specific principal over trusting Snyk's whole account with ":root",
    which is broader and which Snyk IaC flags as SNYK-CC-TF-118.)
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(root|role/.+|user/.+)$", var.snyk_aws_principal))
    error_message = "snyk_aws_principal must be an IAM ARN such as arn:aws:iam::123456789012:role/name."
  }
}

variable "snyk_org_ids" {
  description = <<-EOT
    Snyk organization IDs allowed to assume this role. Each is used as an
    sts:ExternalId value. One role can serve several Snyk orgs, but note that
    a Snyk org can hold only one ECR integration (one account + region).
  EOT
  type        = list(string)

  validation {
    condition = length(var.snyk_org_ids) > 0 && alltrue([
      for id in var.snyk_org_ids :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))
    ])
    error_message = "snyk_org_ids must be a non-empty list of Snyk org UUIDs."
  }
}

variable "role_name" {
  description = "Name of the IAM role Snyk will assume."
  type        = string
  default     = "snyk-ecr-read"
}

variable "permissions_boundary_arn" {
  description = "Optional permissions boundary to attach to the role, if the organisation requires one."
  type        = string
  default     = null
}

variable "max_session_duration" {
  description = "Maximum session duration in seconds for the role."
  type        = number
  default     = 3600
}

variable "tags" {
  description = "Tags applied to the role."
  type        = map(string)
  default     = {}
}
