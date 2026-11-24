# Contract: Terraform module `snyk-ecr-role` and the example root

The AWS side of the tool, as delivered at `f035a43`. The module is what other Terraform
configurations reuse; `examples/main.tf` is a minimal, working call of it.

## Module `terraform/modules/snyk-ecr-role`

**Requires**: Terraform 1.5 or later; provider `hashicorp/aws` 5.0 or later.

### Inputs

| Variable | Type | Default | Validation and meaning |
|----------|------|---------|------------------------|
| `snyk_aws_principal` | string | required | IAM ARN matching `^arn:aws[a-z-]*:iam::[0-9]{12}:(root\|role/.+\|user/.+)$`. Copy the `Principal` from the trust policy your Snyk tenant shows under Integrations → Amazon ECR. |
| `snyk_org_ids` | list(string) | required | Non-empty; every entry a UUID. Each becomes an allowed `sts:ExternalId`. |
| `role_name` | string | `snyk-ecr-read` | Name of the role. |
| `permissions_boundary_arn` | string | `null` | Optional permissions boundary. |
| `max_session_duration` | number | `3600` | Seconds. |
| `tags` | map(string) | `{}` | Tags on the role. |

### Outputs

| Output | Value | Used as |
|--------|-------|---------|
| `role_arn` | The role's ARN | `onboard_ecr.py --role-arn`, for every org of the account |
| `role_name` | The role's name | `aws iam get-role --role-name` |

### Resources

| Address | What |
|---------|------|
| `aws_iam_role.snyk_ecr_read` | The role, with the trust policy below as `assume_role_policy` |
| `aws_iam_role_policy.ecr_read` | Inline policy named `snyk-ecr-read`, with the permissions below |

**Trust policy** (`data.aws_iam_policy_document.trust`), one statement `SnykAssumeRole`:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Principal": { "AWS": "<snyk_aws_principal>" },
  "Condition": { "StringEquals": { "sts:ExternalId": ["<snyk_org_ids>…"] } }
}
```

**Permissions** (`data.aws_iam_policy_document.ecr_read`), one statement `SnykAllowPull` on
`Resource: "*"`, read-only: `ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage`,
`ecr:DescribeImages`, `ecr:DescribeRepositories`, `ecr:GetAuthorizationToken`,
`ecr:GetDownloadUrlForLayer`, `ecr:GetLifecyclePolicy`, `ecr:GetLifecyclePolicyPreview`,
`ecr:GetRepositoryPolicy`, `ecr:ListImages`, `ecr:ListTagsForResource`.

### Behavior on change

| Change | Effect | Note |
|--------|--------|------|
| Add or remove an ID in `snyk_org_ids` | In-place update of `assume_role_policy` | Needs `iam:UpdateAssumeRolePolicy`. The plan was verified live; the apply was not. A removed org loses access at Snyk's next sync. |
| Change `snyk_aws_principal` | In-place update of `assume_role_policy` | Needed if Snyk changes its principal. Re-applying also re-saves a recreated IAM user principal. |
| Change `role_name` | The role is replaced, with a new ARN | Every org's integration then needs `apply --update-credentials` with the new ARN. |
| A role with the same name exists outside this state | Apply fails with `EntityAlreadyExists` | Import it, or choose another `role_name` (`docs/USAGE.md`, "Existing roles"). |

To adopt an existing role, import both addresses: `module.<name>.aws_iam_role.snyk_ecr_read` with ID
`<role-name>`, and `module.<name>.aws_iam_role_policy.ecr_read` with ID `<role-name>:snyk-ecr-read`
(the latter only if that inline policy exists).

## Example root `examples/main.tf`

| Variable | Type | Validation |
|----------|------|------------|
| `snyk_orgs` | map(string), region → org ID | Non-empty; keys match `^[a-z]{2}(-[a-z]+)+-[0-9]$`; no org ID under two regions |
| `snyk_aws_principal` | string | Validated by the module |

| Output | Value |
|--------|-------|
| `role_arn` | `module.snyk_ecr.role_arn` |
| `snyk_orgs` | The map, as the `--region` and `--org-id` pairs for the script |

The provider's region (`ap-southeast-2`) only selects the API endpoint, because IAM is global. For
more than one region, the map lives in `snyk-orgs.auto.tfvars` in the operator's own repository
(template: `examples/snyk-orgs.auto.tfvars.example`); this repository gitignores `*.auto.tfvars`.

`examples/snyk_orgs.tftest.hcl` tests the map's validations with the AWS provider mocked, which needs
Terraform 1.7 or later ([research O4](../research.md#open-items)). It does not check the policy
documents, because the mock computes them ([research O7](../research.md#open-items)).
