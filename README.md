# ECR → Snyk onboarding

Connects an **existing** Amazon ECR registry (one AWS account, one region) to an **existing** Snyk org
so Snyk can scan it, sets up Snyk's automatic image sync, and tears both down again. The org and the
registry are the starting state; this tool never creates or deletes them.

Standard tooling only: **Terraform** for the IAM role, a dependency-free **Python script** (run with
`uv`) for the Snyk API calls, and Snyk's native **container registry sync** for ongoing imports.
No Lambda, no EventBridge, no custom Terraform provider.

```
terraform apply  ──►  IAM role "snyk-ecr-read"   (trust: the Snyk principal from your tenant's UI + ExternalId = the Snyk org IDs)
                              │ role ARN
scripts/onboard_ecr.py apply ◄┘   (once per registry: --org-id, --region, --role-arn)
   1. connectivity  v1   find or create the ECR integration
                    REST dry run: Snyk lists the registry (imports nothing)
   2. sync          REST preview, then apply the registry sync policy
```

Two steps, kept apart: **Terraform creates the AWS resources** (one role per AWS account), then **the script
connects Snyk** (one run per registry). Snyk allows one ECR integration per Snyk org, so every registry, meaning
every region of every account, has its own Snyk org; the orgs of one account share its role, which trusts each
of their IDs. You choose the registry each time you run the script.

The exception is an org where Snyk has turned on its multiple profiles feature (a closed beta): it holds any
number of named ECR connections, one per registry, and the script manages them one at a time. The script
detects the feature on every run; see [docs/USAGE.md](docs/USAGE.md#orgs-with-several-ecr-connections-profiles-mode).

## Scenarios

Each scenario starts from a Snyk org (with Snyk Container) and an ECR registry that already exist. Export
`SNYK_TOKEN` (a service account token; `SNYK_API_BASE` for non-US tenants) in your shell, never on the
command line. The examples use `--import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'` as the sync policy.

### 1. New account, one region

```bash
# AWS: the role Snyk assumes. snyk_orgs maps the registry's region to its Snyk org.
terraform -chdir=examples init
terraform -chdir=examples apply -var 'snyk_orgs={"ap-southeast-2"="<org-a>"}' \
    -var snyk_aws_principal=<Principal from the Snyk UI: Integrations → Amazon ECR>

# Snyk: connectivity + sync
uv run scripts/onboard_ecr.py apply --org-id <org-a> --region ap-southeast-2 \
    --role-arn "$(terraform -chdir=examples output -raw role_arn)" \
    --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'
```

`apply` creates the integration, proves Snyk can read the registry (retrying while a new role propagates),
previews what the sync would import (and stops above `--max-images`, default 1000), then applies the sync
policy. `plan` with the same flags writes nothing. The policy is stated in Snyk's own terms: `--import-policy`
with one of Snyk's types (`ImportAll`, `ImportAllNew`, `Regex`, `Recent`, `LastNObserved`) and its fields, or
`--policy-file` with Snyk's policy JSON. There is no default; `--no-sync` connects only. Re-running is safe.

After this, nothing runs on your side: Snyk syncs the registry on its schedule (new matching images become
projects) and retests imported images. Re-run `apply` only to change the policy.

### 2. Add a region to that account

From now on the account has several orgs, and every `terraform apply` must list **all** of them: Terraform
writes the role's trust policy exactly as listed, so a missing org loses its access. Keep the list in a file:

1. Create the new Snyk org (org B).
2. Copy `examples/snyk-orgs.auto.tfvars.example` to `examples/snyk-orgs.auto.tfvars` (Terraform loads it
   automatically), list both orgs, keep it in your own repository, and stop passing `snyk_orgs` as `-var`
   (a switch overrides the file):
   ```hcl
   snyk_orgs = {
     "ap-southeast-2" = "<org-a>"
     "us-east-1"      = "<org-b>"
   }
   ```
3. `terraform -chdir=examples plan` must show only an **in-place update** of the role's trust policy, adding
   org B. If it plans to create the role, stop
   ([existing roles](docs/USAGE.md#existing-roles)). Then `terraform -chdir=examples apply`, with
   `-var snyk_aws_principal=…` as before unless the file holds it. Changing the trust policy needs
   `iam:UpdateAssumeRolePolicy`, which an identity allowed to create roles may not have
   ([Permissions](docs/USAGE.md#permissions)).
4. Connect the new region only; region A is untouched:
   ```bash
   uv run scripts/onboard_ecr.py apply --org-id <org-b> --region us-east-1 \
       --role-arn "$(terraform -chdir=examples output -raw role_arn)" \
       --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'
   ```

If org B is not yet in the role's trust policy, the connection test fails after its retries and says so;
after `terraform apply`, re-run `apply` with `--update-credentials`.

### 3. New account, several regions in one go

Start with the file: create one Snyk org per region, list them all in `examples/snyk-orgs.auto.tfvars`,
run one `terraform apply` (one role trusting every org), then run the script once per region with the same
role ARN. The script does not loop over the file, by design; loop in your own shell or CI over
`terraform -chdir=examples output snyk_orgs` (the region and org ID pairs) if you want to. A second account
repeats this with its own Terraform state, AWS credentials and orgs.

### 4. Check status

All read-only, per org:

| Command | Shows |
|---|---|
| `onboard_ecr.py status --org-id <org>` | The integration, the sync policy and the org's ECR projects (`--all-origins`: every project). |
| `onboard_ecr.py plan --org-id <org> --region <region> --role-arn … <policy flags>` | The connection test and the sync preview: can Snyk still read the registry, and what the policy matches. |
| `aws iam get-role --role-name snyk-ecr-read --query 'Role.AssumeRolePolicyDocument'` | Which org IDs the role trusts. |
| `terraform -chdir=examples output snyk_orgs` | Which regions and orgs this Terraform state manages. |

### 5. Teardown

Per org; a dry run unless `--yes`:

```bash
uv run scripts/onboard_ecr.py teardown --org-id <org> --repo-prefix 'team-a/' --delete-projects --delete-credentials
```

This removes the sync policy, the imported projects under the prefix, and the role and region stored in the
integration (Snyk is disconnected). Then the AWS side:

- **One region, others stay:** remove its entry from `snyk-orgs.auto.tfvars`, check that `plan` shows only the
  trust policy losing that org, and `apply`. Not `destroy`: the other regions share the role.
- **The whole account:** teardown every org, then `terraform -chdir=examples destroy`.

To pause instead, `teardown --yes` without the other flags removes only the sync policy; `apply` resumes it.
The Snyk org and the registry are never touched; the empty integration entry has no delete API and can only
be removed in the UI.

Set it up with a service account, not a personal token (see [Running it over time](docs/USAGE.md#running-it-over-time)).

## Documentation
- [docs/USAGE.md](docs/USAGE.md): step by step, another region in the same account, prerequisites,
  permissions, constraints, security notes, troubleshooting.
- [docs/TESTING.md](docs/TESTING.md): offline checks (`make check`, no credentials needed) and the from-scratch
  end-to-end harness (`examples/sandbox/e2e.sh`), which runs these scenarios against throwaway Snyk orgs and
  ECR repositories in two regions, and removes them again.

## Constraints in one glance
- **One ECR registry per Snyk org** (one account + region); strictly one-to-one. Snyk allows one ECR
  integration per org, so a second region of the same account needs its own org; both share the role.
- The Snyk AWS principal is a **required input**, copied from your tenant's Snyk UI (it differs per tenant).
- Integration create/list/update exist only in the **v1** API (flagged deprecated); sync and projects are **REST**.
- `us-east-2` must be enabled for STS. Registry sync is generally available.

## Status
88 unit tests (fake Snyk API; request shapes from the published v1 OpenAPI spec and REST spec
`2026-03-25`) and 5 `terraform test` runs of the example's inputs (AWS provider mocked). **Verified live end
to end** on the US tenant with a PAT, by the from-scratch harness (docs/TESTING.md), for one region:
connectivity with the UI-prescribed principal, the connection test and its propagation retry, Regex sync
importing exactly the matching tag, and teardown of everything the product created. Repeated with an
org-level service account (access token, Org Admin). The scenarios above, two regions of one account
(`ap-southeast-2`, `us-east-1`), were run live on 2026-10-19: scenarios 1, 3 and 4 and the whole-account
teardown passed; in scenario 2 the plan was exactly the in-place trust update and an org the role did not yet
trust failed with the expected hint, but applying the update was refused by the test identity's IAM
permissions (`iam:UpdateAssumeRolePolicy`, see [Permissions](docs/USAGE.md#permissions)), so that apply and the
one-region teardown are not yet verified live. On 2026-11-24, scenario 1 and the whole-account teardown
passed again from scratch, before and after the fix that stops the token from following redirects.
OAuth 2.0 service accounts (bearer tokens) are not supported yet.

## License
MIT. See [LICENSE](LICENSE).
