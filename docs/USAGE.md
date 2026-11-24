# Onboarding an ECR registry to Snyk: step by step

This tool connects **one** Amazon ECR registry (one AWS account in one AWS region) to **one** Snyk
organization so Snyk can scan it, and sets up Snyk's automatic image sync for it.

> **Mapping is strictly one-to-one.** One Snyk org holds one ECR integration, which points at
> one registry (account + region). To onboard N registries, use N Snyk orgs and run the
> steps below N times. See [Constraints](#constraints).

## Scope

**Starting state (prerequisites, never created or deleted by this tool):** a Snyk org, an ECR
registry with its repositories and images, and working credentials for both.

**What the tool sets up, and its teardown removes again:**

| | Created by | Removed by |
|---|---|---|
| IAM role Snyk assumes (read-only ECR) | Terraform module | `terraform destroy` |
| ECR integration in the Snyk org: the **connectivity** | `onboard_ecr.py apply` | `teardown --delete-credentials` (see [Teardown](#teardown)) |
| Registry **sync policy** | `onboard_ecr.py apply` | `teardown` |
| Projects the sync imports | Snyk, driven by the policy | `teardown --delete-projects` |

A from-scratch test harness that also creates and removes the starting state lives in
`examples/sandbox`; see [TESTING.md](TESTING.md).

## How it works

```
Terraform ─► IAM role "snyk-ecr-read"
              trust:  the Snyk principal from your tenant's UI  +  sts:ExternalId = your Snyk org ID
              perms:  read-only ECR
                       │ role ARN
onboard_ecr.py apply ◄─┘
  1. connectivity  v1 API: find or create the ECR integration
                   REST dry run: Snyk lists the registry (proves it can read it; imports nothing)
  2. sync          REST dry run of the sync policy (preview), then apply it
Snyk then syncs on a schedule and creates a project per imported repository:tag.
```

There is no Lambda, EventBridge rule or custom Terraform provider. New images are picked up by
Snyk's own scheduled sync (at least 2 hours apart), not by push events.

## Prerequisites

| Need | Detail |
|---|---|
| Tools | `terraform` >= 1.5, `uv` (runs the script; it has no dependencies), `aws` CLI. |
| AWS | The account with the ECR registry, credentials that can create IAM roles (see [Permissions](#permissions)), and the **`us-east-2` region enabled** for STS (Snyk's requirement). |
| Snyk org | An org with **Snyk Container**, and no other ECR integration you want to keep (an org holds one). Registry sync is generally available ([Snyk blog: GA launch of Container Registry Sync](https://snyk.io/blog/scale-container-security-effortlessly/)); the docs page carries no plan restriction. |
| Snyk org ID | Snyk UI → the org → Settings → General → *Organization ID* (a UUID). |
| Snyk AWS principal | Snyk UI → the org → Integrations → Amazon ECR: the `Principal` in the trust policy shown there. Required, with no built-in value: Snyk shows it only to authenticated users of your tenant, it differs per tenant, and Snyk may change it. Treat it as configuration you supply, and keep it out of public repositories. |
| Snyk token | An org-level service account with an **access token** (verified with the Org Admin role), or a personal access token for testing; exported as `SNYK_TOKEN`, never passed as an argument or committed. Sent as `Authorization: token …`, as the v1 API documents. OAuth 2.0 service accounts, whose tokens are sent as `Authorization: bearer …`, are not supported yet. |
| Tenant | The US tenant needs nothing extra. For EU/AU set `SNYK_API_BASE` (for example `https://api.au.snyk.io`), and take the principal from that tenant's UI. |

## Step by step

### 1. Create the AWS role (Terraform)

Use the module in your own Terraform; `examples/main.tf` is a minimal, working call. It takes the
orgs as `snyk_orgs`, a region => Snyk org ID map with one entry per registry, and passes the IDs to the
module as `snyk_org_ids`. For one region, switches are enough:

```bash
terraform apply -var 'snyk_orgs={"ap-southeast-2"="<snyk-org-uuid>"}' -var snyk_aws_principal=<Principal from the Snyk UI>
```

With more than one region, keep the map in a file instead (see
[Another region in the same account](#another-region-in-the-same-account)).

```hcl
module "snyk_ecr" {
  source             = "path/to/terraform/modules/snyk-ecr-role"
  snyk_org_ids       = ["<snyk-org-uuid>"]
  snyk_aws_principal = "<Principal from the Snyk UI trust policy>"
}
output "role_arn" { value = module.snyk_ecr.role_arn }
```

```bash
terraform init && terraform plan && terraform apply
```

- `snyk_aws_principal` is **required**: copy the `Principal` from the trust policy the Snyk UI shows
  under Integrations → Amazon ECR. It is not a credential, but Snyk shows it only to authenticated
  users of your tenant, it is tenant-specific, and Snyk may change it, so it is an input you supply
  (for example from your pipeline's configuration), never a value committed to a public repository. A wrong
  principal is the most common failure, and the connection test catches it. Prefer that specific
  principal over trusting Snyk's whole account (`…:root`, as Snyk's AWS Partner Solution does): that
  is broader, and Snyk IaC flags it as SNYK-CC-TF-118.
- Several Snyk orgs may share one role: each ID in `snyk_org_ids` is an allowed `sts:ExternalId`.
  For a second region of the same account, see [Another region in the same account](#another-region-in-the-same-account).
- If your organisation enforces a permissions boundary, pass `permissions_boundary_arn`.

### 2. Export the Snyk token

```bash
export SNYK_TOKEN=...        # in your own shell
export SNYK_API_BASE=...     # only for non-US tenants
```

### 3. Connect and set up the sync

```bash
uv run scripts/onboard_ecr.py plan  --org-id <snyk-org-uuid> --region <aws-region> --role-arn "$(terraform output -raw role_arn)" \
    --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'
uv run scripts/onboard_ecr.py apply ...same flags...
```

`plan` writes nothing. `apply` does two things:

1. **Connectivity.** Creates the ECR integration if it is missing, then runs a connection test: a
   dry run in which Snyk lists the registry's repositories and images without importing anything,
   printed as `Snyk can read the registry: 12 repositories, 87 images visible`. Right after the IAM
   role or the credentials are new, both the create and the connection test are retried (about 2.5
   minutes): AWS documents that IAM changes are eventually consistent and should be verified as
   propagated before anything depends on them ([IAM troubleshooting](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency)).
2. **Sync.** Applies the sync policy you state in step 4, after previewing which repositories and
   tags it would import. There is **no default policy**: without one, `apply` stops and lists Snyk's
   options. As a safeguard of this script (not a Snyk setting), it refuses to apply a policy whose
   preview exceeds `--max-images` (default 1000). Snyk runs the policy immediately and then every
   `schedule_frequency_hours`.

The org's Projects page then shows a target per repository and a project per `repository:tag`.

### 4. Choose what the sync imports: Snyk's policy types

The sync is Snyk's *container registry sync*. Each scheduled run lists every repository and tag in the
registry, imports the images that match the policy and are not imported yet, and, if `delete_images`
is true, deletes the projects whose images no longer match. The policy is stated with Snyk's own
types and field names ([Snyk docs: Sync your container registry](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-container/use-snyk-container/sync-your-container-registry)):

| Snyk policy type | Imports (per Snyk's docs) | Flags |
|---|---|---|
| `ImportAll` | Every image in the registry | `--import-policy ImportAll` |
| `ImportAllNew` | Only images pushed after the policy is created; the images present at that point are recorded as a baseline and not imported | `--import-policy ImportAllNew` |
| `Regex` | Images whose repository and/or tag match the patterns (`repo`, `tag`) | `--import-policy Regex --repo '^team-a/' --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'` |
| `Recent` | Images pushed in the last `maxAgeDays` days, per repository | `--import-policy Recent --max-age-days 30` |
| `LastNObserved` | The `limitNewestImages` most recently pushed images, per repository | `--import-policy LastNObserved --limit-newest-images 5` |
| `And`, `Or`, `RuntimeIntegrations` | Combinations of the above; images running in a cluster (needs a runtime integration) | `--policy-file policy.json` |

Policy settings, also Snyk's fields:

| Flag | Snyk field | Notes |
|---|---|---|
| `--schedule-frequency-hours H` | `schedule_frequency_hours` | Minimum 2. Omitted means Snyk's default, 24. |
| `--delete-images` | `delete_images` | Default false. Snyk documents that `Recent` and `LastNObserved` only add images unless it is true, so older projects then stay indefinitely; the script warns about that. |
| `--policy-name NAME` | `name` | A label; defaults to `ecr-onboarding`. |

`--policy-file` takes a policy object exactly as Snyk documents it, and the script sends it unchanged.
For example, Snyk's "recent semantic version releases" scenario (semver tags, newest 5 per
repository, rotated):

```json
{
  "name": "semver releases, newest 5 per repository",
  "schedule_frequency_hours": 12,
  "delete_images": true,
  "import_policy": {
    "name": "semver AND newest 5",
    "type": "And",
    "sub_policies": [
      {"name": "semver tags", "type": "Regex", "policy": {"repo": ".*", "tag": "^v?[0-9]+\\.[0-9]+\\.[0-9]+$"}},
      {"name": "newest 5", "type": "LastNObserved", "policy": {"limitNewestImages": 5}}
    ]
  }
}
```

Snyk evaluates the patterns with **RE2**, which has no lookahead or lookbehind; the script rejects
those up front, including inside a policy file. The policy is an allow-list: to leave out
pull-through-cache repositories, write the `repo` pattern so they do not match. Use `--no-sync` to
set up connectivity only and import images yourself from the Snyk UI.

### 5. Re-running and changing the policy

`apply` is idempotent: re-run it with a different policy to replace the current one. An existing
integration is **reused as is**; pass `--update-credentials` to point it at a different role or
region (needed after `teardown --delete-credentials`).

### 6. Check progress

```bash
uv run scripts/onboard_ecr.py status --org-id <snyk-org-uuid>
```

Read-only: shows the integration, the active sync policy and the ECR projects created so far.
Projects appear once the first sync has run, which can take a few minutes. `--all-origins` also lists
every project in the org with its origin.

### All flags

| Flag | Meaning |
|---|---|
| `--import-policy`, `--repo`, `--tag`, `--max-age-days`, `--limit-newest-images` | The sync policy, as one Snyk policy type and its fields (step 4). |
| `--policy-file FILE` | The sync policy as Snyk's policy JSON (combinations, runtime). |
| `--schedule-frequency-hours`, `--delete-images`, `--policy-name` | Snyk's policy settings (step 4). |
| `--no-sync` | Connectivity only, no sync policy. |
| `--max-images N`, `--force` | This script's safeguard on what one apply may import (default 1000). |
| `--update-credentials` | Point an existing integration at this role/region. |
| `--connect-retries`, `--connect-delay` | Propagation retries (default 10 × 15s). |
| `--api-base`, `--api-version` | Snyk tenant host (or `SNYK_API_BASE`) and REST version. |

Exit codes: `0` success, `1` error, `2` apply refused by `--max-images`.

## Another region in the same account

Snyk allows one ECR integration per Snyk org: "To integrate with multiple registries, create a unique
Organization for each one" ([Snyk docs: Configure integration for Amazon ECR](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-container/container-registry-integrations/integrate-with-amazon-elastic-container-registry-ecr/configure-integration-for-amazon-elastic-container-registry-ecr)).
So a second region needs a second Snyk org. The IAM role is global to the account, so both orgs share it:
the role trusts every org ID you list. The tool still maps one registry to one org; you choose the region
and the org each time you run it.

1. **Create the new Snyk org** (with Snyk Container), in the Snyk UI or however you create orgs today.
   This tool does not create orgs.
2. **List every org in a file.** Copy `examples/snyk-orgs.auto.tfvars.example` to
   `snyk-orgs.auto.tfvars` next to your Terraform (Terraform loads `*.auto.tfvars` files automatically),
   keep it in your own repository, and stop passing `snyk_orgs` as a `-var` switch: a switch takes
   precedence over the file. List the existing org and add the new one:

   ```hcl
   snyk_orgs = {
     "ap-southeast-2" = "<snyk-org-id-a>"
     "us-east-1"      = "<snyk-org-id-b>"   # new
   }
   ```

3. **Plan and check it.** `terraform plan` must show only an in-place update (`~`) of the role's trust
   policy (`assume_role_policy`), with the new ID added to the `sts:ExternalId` list. If it plans to
   **create** the role, stop: this state does not track the role (see [Existing roles](#existing-roles)).
4. **Apply:** `terraform apply`. This changes the trust policy in place, with `iam:UpdateAssumeRolePolicy`; an
   identity that could create the role may still lack it (see [Permissions](#permissions)).
5. **Connect the new region**, with the new org and region and the same role ARN:

   ```bash
   uv run scripts/onboard_ecr.py plan  --org-id <snyk-org-id-b> --region us-east-1 \
       --role-arn "$(terraform output -raw role_arn)" --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'
   uv run scripts/onboard_ecr.py apply ...same flags...
   ```

   The existing region needs nothing: its org stays in the trust policy and its integration is unchanged.

**Keep every entry.** Terraform writes the trust policy exactly as listed, so removing an entry (or an ID from
`snyk_org_ids`) removes that org's access and breaks its integration at Snyk's next sync. Remove an entry
only to retire that region, after its `teardown`.

If the new region's connection test still fails after the retries, the script lists the likely causes; the
first to check is that the new org ID reached the role's `sts:ExternalId` list (step 4 applied). The failed run
has already created the integration, so after the fix re-run `apply` with `--update-credentials`: a plain
re-run reuses the integration as stored and tests the connection once, while `--update-credentials` stores
the role and region again and retries while the change propagates.

### Existing roles

Before the first plan, you can see which orgs a role already trusts, read-only:

```bash
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'
```

What `terraform apply` does depends on whether this Terraform state already tracks the role:

| Situation | Result |
|---|---|
| The role was created by this configuration (same state) | In-place update of the trust policy: the expected path. |
| A role with the same name exists but this state does not track it | Apply fails with `EntityAlreadyExists`; nothing changes. Adopt it (below) or use another `role_name`. |
| The existing role has a different name | Terraform creates a second role; pass its ARN to the script for the new org. |

### Adopting a role that already exists

To manage an existing role with this module, import it rather than recreate it. Set `role_name` on the
module to the existing name, list **every** org ID it already trusts in `snyk_orgs` (from the `get-role`
output above), then import (an `import` block needs Terraform 1.5 or later):

```hcl
import {
  to = module.snyk_ecr.aws_iam_role.snyk_ecr_read
  id = "<role-name>"
}
import {
  to = module.snyk_ecr.aws_iam_role_policy.ecr_read
  id = "<role-name>:snyk-ecr-read"
}
```

or on the command line: `terraform import module.snyk_ecr.aws_iam_role.snyk_ecr_read <role-name>` and
`terraform import module.snyk_ecr.aws_iam_role_policy.ecr_read <role-name>:snyk-ecr-read`
([AWS provider: aws_iam_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role#import),
[aws_iam_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#import)).
Import the inline policy only if the role has one named `snyk-ecr-read`. A role made by following Snyk's UI
instructions (for example `SnykServiceRole`, with the managed policy `AmazonEC2ContainerRegistryReadOnlyForSnyk`)
has none: Terraform adds the inline policy, and the managed policy stays attached and is not managed by
this module. Review the plan before applying: it should not drop any org ID or change the principal.

### Terraform Enterprise

Keep `snyk-orgs.auto.tfvars` in the workspace's VCS repository; Terraform Enterprise loads `*.auto.tfvars`
files from it, so adding a region is a reviewed pull request whose speculative plan shows the trust-policy
change. Do not also set a `snyk_orgs` workspace variable or variable set: those take precedence over
`*.auto.tfvars` files, so the list must live in one place only. The Snyk principal can be a workspace
variable instead of a line in the file. The script runs outside Terraform Enterprise (in CI or on a
workstation), with the role ARN from the workspace outputs or built as `arn:aws:iam::<account-id>:role/<role-name>`.

## Running it over time

You run the tool when something changes: to set up, to change the policy, and to stop. Between those
times nothing of this tool runs. There is no Lambda, scheduled job or daemon; Snyk does the ongoing work.

| When | What happens | What you do |
|---|---|---|
| **Set up** (once) | The role, the integration and the sync policy are created; the first sync starts immediately. | Steps 1 to 3 above. |
| **Every day after** | Snyk's registry sync runs every `schedule_frequency_hours` (default 24): newly pushed images that match the policy become projects, and with `delete_images` projects whose images no longer match are removed. Snyk also retests imported images on its own schedule ([Snyk: rescans imported images daily](https://docs.snyk.io/implementation-guides/enterprise-implementation-guide/create-a-template-organization/connect-your-development-tools)), so newly disclosed vulnerabilities appear without anyone acting; alerts follow the org's notification settings. | Nothing. Look at the results in Snyk, or run `status`. |
| **When needs change** | | Re-run `apply` with a different policy (it replaces the current one). After a role or region change, `apply --update-credentials`. If Snyk changes its principal, `terraform apply` with the new value. |
| **To pause** | No new images are imported; the connection and the existing projects stay. | `teardown --yes` (removes only the sync policy). Resume later with `apply`. |
| **To stop for good** | Everything the tool set up is removed; the Snyk org and the registry are untouched. | [Teardown](#teardown), then `terraform destroy`. |

**Which identity sets it up.** Snyk's documentation does not say whether the scheduled sync depends on the
token that applied the policy. Use a service account, not a personal token: Snyk recommends service
accounts for any automation, so that it keeps working when people change roles or leave
([Snyk: Authentication for API](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api)).
Track the token's expiry: a service account access token lasts at most one year, a personal access
token at most 90 days ([Snyk: service account types](https://docs.snyk.io/platform-administration/service-accounts/choose-a-service-account-type-to-use-with-snyk-apis)).

## Teardown

Removes what `apply` and Terraform created, in order: stop the sync, remove the projects it
imported, disconnect, then remove the role. To only pause the sync, run `teardown --yes` without the
other flags: it removes just the sync policy, and `apply` resumes it.

```bash
# 1. dry run: shows exactly what would be removed
uv run scripts/onboard_ecr.py teardown --org-id <uuid> --repo-prefix 'team-a/' --delete-projects --delete-credentials
# 2. execute
uv run scripts/onboard_ecr.py teardown --org-id <uuid> --repo-prefix 'team-a/' --delete-projects --delete-credentials --yes
# 3. AWS: remove the role (when this was the account's last region; otherwise see below)
terraform destroy
# 4. Optional, UI only: Integrations → Amazon ECR → remove the empty integration entry
```

| Removed | By | Notes |
|---|---|---|
| Sync policy (stops auto-import) | always | Done first, so deleted projects are not re-imported by the next sync. |
| Imported projects | `--delete-projects` + `--repo-prefix` | Only projects with origin `ecr` whose repository name starts with the literal prefix. |
| Role ARN / region stored in the integration | `--delete-credentials` | Snyk can no longer assume your role. Uses the v1 "Delete credentials" call. |
| IAM role | `terraform destroy` | Only when no other region of the account uses it. |

**Retiring one region of several.** The orgs of one account share the role, so do not destroy it. Run the
teardown above for that region's org, remove its entry from `snyk-orgs.auto.tfvars`, check that
`terraform plan` shows only an in-place update of the trust policy dropping that org ID, and apply. The other
regions keep working.

**Never touched:** the Snyk org (members, settings, other integrations, projects outside the
prefix), the ECR registry and its images, and the AWS account. The script contains no org-level
or registry-level delete, and a unit test enforces it.

Verified live: after `--delete-credentials`, Snyk's sync API reports the integration as not found, so
Snyk can no longer read the registry, even while the IAM role still exists.

**What remains:** the empty ECR integration entry. Neither the v1 nor the REST API can delete an
integration. It holds no credentials after `--delete-credentials`, so it is inert; remove it in the
UI (step 4) if you want it gone. Re-onboarding the same org reuses it with `apply --update-credentials`.

## Permissions

**AWS (whoever runs Terraform)**: permission to create, read, tag, update and delete an IAM role and its
inline policy (the module manages one `aws_iam_role` and one `aws_iam_role_policy`). If Service Control
Policies or a permissions boundary restrict IAM, allow those operations for this role.

Adding or removing a region (an org ID) later changes the role's trust policy in place, which is its own IAM
action: `iam:UpdateAssumeRolePolicy`, which "updates the policy that grants an IAM entity permission to assume a
role" ([AWS IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html)).
An identity allowed to create the role does not necessarily have it: in the e2e run, an SSO role that created
the role was refused this call (`AccessDenied`), and the trust policy stayed as it was. Grant it, scoped to
the role, to whoever will maintain the list.

**What Snyk gets in AWS**: assume the role (only with your org ID as ExternalId), and read-only ECR:
`ecr:BatchCheckLayerAvailability`, `BatchGetImage`, `DescribeImages`, `DescribeRepositories`,
`GetAuthorizationToken`, `GetDownloadUrlForLayer`, `GetLifecyclePolicy`,
`GetLifecyclePolicyPreview`, `GetRepositoryPolicy`, `ListImages`, `ListTagsForResource`, on all
resources. It cannot push, delete or modify anything.

**Snyk token**:

| Action | API | Permission |
|---|---|---|
| List the integrations | v1 | *View Organization*, *View Integrations* |
| Create / update the ECR integration, delete its credentials | v1 | *View Organization*, *View Integrations*, *Edit Integrations*; the spec also notes the token needs admin access to the org |
| Connection test, sync preview, sync policy create / update / delete | REST | `integration.edit` (registry sync docs) |
| Status / teardown: list projects | REST | *View Projects* (`org.project.read`) |
| Teardown: delete projects | REST | *View Organization*, *View Projects*, *Remove Projects* (`org.project.delete`) |

(Permissions as listed in the v1 OpenAPI spec and REST spec `2026-03-25`.)

Prefer a dedicated service account scoped to the org. A personal access token acts with all of
that person's permissions, so use one only for testing.

## Security notes

- **Trust policy.** The role trusts the one Snyk principal your tenant's UI prescribes (a specific IAM
  principal in Snyk's account) and requires `sts:ExternalId` to equal your Snyk org ID, which stops any other Snyk org from using the role (AWS's documented confused-deputy protection for third-party access).
  IAM stores a user principal as the user's unique ID, so if Snyk ever recreated that user the trust
  would stop matching until the policy is saved again; re-running `terraform apply` does that
  ([AWS: IAM user principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-users)).
- **Least privilege.** Read-only ECR actions only, on all repositories. To restrict it to specific
  repositories, scope `Resource` in the inline policy; `ecr:GetAuthorizationToken` only supports `*`.
- **Secrets.** The token is read from `SNYK_TOKEN` only, is sent only to `https://*.snyk.io`, and is
  never logged. It never appears in Terraform state.
- **User-supplied regexes** are never compiled or run locally; Snyk evaluates them (RE2) and the preview
  reports errors. Teardown is scoped by a literal prefix for the same reason, and is a dry run unless `--yes`.
- **Scans.** `make scan` runs `snyk code test` (no issues) and `snyk iac test` (no issues on the module;
  two accepted low findings on each of the two test fixture repositories: mutable tags and AWS-managed
  encryption).

## Constraints

1. **One registry per Snyk org.** An org's ECR integration has a single region and role. Two
   accounts, or two regions of one account, need two orgs (see
   [Another region in the same account](#another-region-in-the-same-account)).
   Snyk has a closed beta that lets one org hold several ECR integrations ("profiles"). Do not run this
   tool against an org that has it enabled: the tool finds the org's ECR integration through the v1 list,
   which then names only one of them, so `status`, `apply` and `teardown` can act on the wrong
   integration (verified in a test org, November 2026).
2. **One-to-one by design.** The tool maps one registry to one org; it does not loop over
   accounts or regions. Drive it with one module call (one role) per AWS account, listing that account's
   orgs, and one script run per registry, for example from CI.
3. **Snyk principal is tenant-specific** and Snyk's to change. It is a required input, taken from your
   tenant's Snyk UI; the connection test proves it.
4. **v1 API dependency.** Integration create/list/update/credential delete exist only in the v1 API,
   which Snyk marks deprecated; there is no REST equivalent. Sync policy and projects are REST.
5. **Import paths.** The sync imports matching images on its schedule (at least 2 hours apart); with
   `--no-sync`, images are imported from the Snyk UI. Snyk's docs give two limits for one run (10,000 images in one place, 1,000 in another); either way
   the remainder is imported in later runs.
   Images over 2 GB are not imported. Application-level (non-OS) vulnerabilities in an already
   imported image need a re-import to refresh.
6. **The integration entry cannot be deleted by API**, only disconnected (credentials removed).
   Projects deleted by hand are not re-imported by the sync.
7. **Direct registry scanning suits smaller estates** (Snyk's guidance is roughly under 1,000
   images). For large or fast-moving registries add `snyk container monitor` to CI as well.
8. **STS region.** `us-east-2` must be enabled in the AWS account; a Service Control Policy that
   denies that region breaks the integration.
9. **Allow-list filters only.** The sync policy selects what to include; there is no exclude.
10. **Behaviours Snyk does not document, verified in the from-scratch e2e run** (US tenant, 2026-10-01):
    a dry run on credentials Snyk cannot use fails with *"Container registry authentication or configuration
    failed"*, and right after a new role this clears on retry; the v1 integration create does not validate
    the connection; after `--delete-credentials` the sync API reports *"Integration not found"* while the v1
    integration list still returns the entry; ECR projects have origin `ecr` and are named `repository:tag`;
    omitting `schedule_frequency_hours` gives 24. `status --all-origins` shows project origins if in doubt.
11. **Validation status.** Verified live end to end on the US tenant with a personal access token
    ([TESTING.md](TESTING.md)): role with the UI-prescribed principal, integration create, connection test
    (including the propagation retry), Regex sync preview and apply, the import of exactly the matching tag,
    teardown of policy, projects and credentials, and the disconnect; repeated with an org-level service
    account (access token, Org Admin) in place of the personal access token. Two regions of one account
    (2026-10-19, `ap-southeast-2` and `us-east-1`, personal access token): a role from `-var` switches, and a
    role from `snyk-orgs.auto.tfvars` trusting two orgs from the start, each connecting and syncing exactly the
    matching tag in its own region; the plan for adding a region was exactly an in-place update of the trust
    policy; an org the role did not trust yet failed after the retries with the `sts:ExternalId` hint;
    teardown of every org and the role. Not yet verified live: applying the in-place update (adding or
    retiring a region), which the test identity was not allowed to do (`iam:UpdateAssumeRolePolicy`).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `terraform apply` when adding or removing a region: `AccessDenied` … `iam:UpdateAssumeRolePolicy` | The identity running Terraform may create roles but not change their trust policy. Nothing changed (existing regions keep working); grant that action for the role ([Permissions](#permissions)) and apply again. |
| `HTTP 401` | Token wrong, expired, or for another tenant (check `SNYK_API_BASE`). |
| `HTTP 403` on create | Token lacks Org Admin / *Edit Integrations*. |
| `cannot reach … certificate verify failed` | Network, proxy or TLS interception between you and `api.snyk.io`. |
| Connection test fails right after a new role, even after retries | This org ID missing from the role's trust (`snyk_orgs` / `snyk_org_ids`, then `terraform apply`), wrong Snyk principal for the tenant, wrong `--region`, or `us-east-2` STS disabled. The script lists these causes; after the fix, re-run `apply --update-credentials`. |
| Connection test fails on an existing integration | It was disconnected (`teardown --delete-credentials`) or points at another role/region: re-run `apply --update-credentials`. |
| Preview shows 0 images | The policy matches nothing (`repo` and `tag` apply separately), the registry/region has no images, or `ImportAllNew` (which never imports images that already exist). |
| `Refusing to apply: N images…` | Above `--max-images`. Narrow the policy or pass `--force`. |
| No projects after apply | The first sync may still be running; check `status` again, and confirm the integration's region matches the repositories. |
