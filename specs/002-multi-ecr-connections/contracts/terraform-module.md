# Contract: Terraform for profiles-mode orgs

What 002 changes in the baseline's [Terraform contract](../../001-ecr-onboarding-baseline/contracts/terraform-module.md).

## Module `terraform/modules/snyk-ecr-role`

Unchanged. Its `snyk_org_ids` input is already a list of orgs with no regions in it, which is what
FR-016 asks for.

## Example root `examples/main.tf`

| Variable | Type | Default | Validation |
|----------|------|---------|------------|
| `snyk_orgs` | map(string), region → org ID | `{}` (was required) | Keys match `^[a-z]{2}(-[a-z]+)+-[0-9]$`; no org ID under two regions |
| `snyk_profile_orgs` (new) | list(string) | `[]` | Every entry a UUID; no duplicates |
| `snyk_aws_principal` | string | required | Validated by the module |

Across both inputs at least one org is required, with the same error the empty map gives today. The
check must not raise the example's Terraform minimum (research R8).

The module receives `snyk_org_ids = distinct(concat(values(var.snyk_orgs), var.snyk_profile_orgs))`.

| Output | Value |
|--------|-------|
| `role_arn` | Unchanged |
| `snyk_orgs` | Unchanged |
| `trusted_org_ids` (new) | The org IDs the role trusts, sorted |

## Behavior on change

| Change | Effect |
|--------|--------|
| Connect another ECR for an org already in either input | No change in AWS (FR-016, SC-005) |
| Add an org to `snyk_profile_orgs` | In-place update of the trust, as for adding a map entry |
| Move an org from `snyk_orgs` to `snyk_profile_orgs` | No change in AWS: the trusted set is the same |
| An org in both inputs | Trusted once |

## Tests

`examples/snyk_orgs.tftest.hcl` keeps its five runs passing unchanged in effect and adds runs for:
profiles-mode orgs only; an org in both inputs (trusted once); a non-UUID in `snyk_profile_orgs`
(rejected); both inputs empty (rejected).
