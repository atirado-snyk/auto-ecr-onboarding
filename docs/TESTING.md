# Testing

## Offline (no credentials)

```bash
make check     # unit tests (fake Snyk API, fake registries), terraform fmt/validate, script syntax, terraform test of examples/ (AWS mocked)
make scan      # Snyk Code + Snyk IaC (needs `snyk auth`)
```

## From-scratch end-to-end test (`examples/sandbox/e2e.sh`)

Starts from the bare minimum and ends there again. It creates its own test infrastructure, runs the product
through the scenarios in the README, checks every step, then removes everything it created.

### Bare-minimum prerequisites

| Need | Detail |
|---|---|
| AWS account + credentials | A **sandbox** account; `AWS_PROFILE` (or other credentials) that can create IAM roles, change their trust policy (`iam:UpdateAssumeRolePolicy`, needed by `add-region` and `retire-region`; an identity that can create roles may lack it) and create ECR repositories in two regions: `AWS_REGION` (region A, default `ap-southeast-2`) and `E2E_REGION_B` (region B, default `us-east-1`). |
| Snyk account + credentials | `SNYK_TOKEN` that may **create and delete orgs** in a group, and that group's ID in `SNYK_GROUP_ID` (find it with `uv run harness.py groups`). `SNYK_AWS_PRINCIPAL`: the `Principal` from the trust policy your tenant's UI shows under Integrations → Amazon ECR (the same for every org in the tenant). Non-US tenants: `SNYK_API_BASE`. |
| Tools | `terraform`, `aws`, `jq`, `uv`. `docker` is optional: when no Docker engine runs (a cloud session, CI), `infra-up` copies the test image into ECR with `push_image.py` over the registry API instead, from Docker Hub, or from AWS's public mirror when Docker Hub refuses anonymous pulls. |
| Profiles mode only | `E2E_PROFILE_ORG_ID`: an existing org where Snyk has turned on its multiple profiles feature, with no ECR connection. It is never created or deleted. Snyk advises a test org for the beta; the owner uses his own org by choice ([research R10](../specs/002-multi-ecr-connections/research.md#r10-where-the-profile-mode-live-test-runs)). |

### Layers: each removes exactly what it created

| Layer | Creates | Removed by |
|---|---|---|
| Test infrastructure (harness) | throwaway Snyk orgs `ecr-e2e-<timestamp>-<a\|b\|n\|c\|d>` (in `SNYK_GROUP_ID`, no settings copied); ECR repo `snyk-e2e/app` in region A and in region B, each with an `alpine:3.18` image tagged `v1.0.0` and `latest` | `infra-down` |
| Product under test | IAM role `snyk-ecr-e2e` (the module, with the same `snyk_orgs` input as `examples/main.tf`); ECR integrations, sync policies, synced projects (the script); `snyk-orgs.auto.tfvars` in `examples/sandbox` | `down` (the script's teardown for every org, then `terraform destroy`) |

The harness uses its own names (`snyk-ecr-e2e`, `snyk-e2e/`, `ecr-e2e-*`), so it never touches a
real `snyk-ecr-read` role, other repositories, or any org it did not create.

### Run

```bash
cd examples/sandbox
export AWS_PROFILE=<sandbox-profile> AWS_PAGER="" SNYK_GROUP_ID=<group-uuid> SNYK_AWS_PRINCIPAL=<principal-arn>
export SNYK_TOKEN=...
./e2e.sh full      # every scenario (about 30 to 60 minutes, mostly waiting for Snyk's syncs)
./e2e.sh single    # scenario 1 and the whole-account teardown only (org a, region A)
E2E_PROFILE_ORG_ID=<org-with-profiles> ./e2e.sh profiles   # several connections in one org (feature 002)
```

Unattended: add `E2E_PAUSE=0` (no pause in `full` and `single`); `profiles` never pauses. To repeat a run in
the same org, give the test repository a fresh name with `E2E_REPO_NAME=snyk-e2e/app-<suffix>`: Snyk's sync
did not import the same image again in an org where an earlier connection had imported it (2026-11-24).

### Snyk's closed-beta rate limits

Every run of the tool first asks Snyk's closed-beta Integrations API for the org's mode, and Snyk allows
1 closed-beta call a second, 10 a minute, and 100 an hour per token, shared by every closed-beta API
([research R12](../specs/002-multi-ecr-connections/research.md#r12-rate-limits-and-paging-on-the-closed-beta-tier)).
The e2e logs one line per tool run in `.e2e/closed_beta.log`, warns above 80 calls in the last hour, stops
before a step above 100, and prints the total at the end. Waiting for a sync, it checks `status` every
`E2E_POLL_SECONDS` (60). Expect about 20 calls for `single`, 50 to 70 for `full`, and 25 to 40 for
`profiles`, so run them in different hours rather than back to back.

One org per registry, as in the product: org a (region A) and org b (region B) for scenarios 1 and 2, org n
(region B, never trusted) for the hint check, orgs c (region A) and d (region B) for scenario 3. `full` runs:

| Step | Scenario | Asserts |
|---|---|---|
| `infra-up` | | creates the orgs and both ECR repos, pushes the test images |
| `preflight` | | AWS credentials work; every org is reachable and has no ECR integration; both images exist; the role and `snyk-orgs.auto.tfvars` do not |
| `new` | 1. new account, one region | `terraform apply -var 'snyk_orgs={…}'` (switches, no file): the plan creates exactly the role and its inline policy; the role trusts exactly org a; `plan` reports the integration as missing; `apply` creates it, the connection test lists `snyk-e2e/app`, the sync preview selects exactly `v1.0.0`, the policy is applied; the sync imports `v1.0.0` and not `latest` within `VERIFY_TIMEOUT` (600s) |
| `add-region` | 2. add a region | first the mistake: `apply` for org n before the role trusts it fails only after its 3 attempts, and the error names org n as missing from the role's `sts:ExternalId` list (then org n is disconnected). Then `snyk-orgs.auto.tfvars` lists orgs a and b and no `-var` is passed: the plan is **only an in-place update of the role**; the role trusts exactly a and b; org b connects and syncs as in `new`; org a still connects |
| `status` | 4. check status | prints `terraform output snyk_orgs`, the trust from `aws iam get-role`, and `status` for every org; orgs a and b have the policy, the `v1.0.0` project, and a passing connection test |
| pause | | inspect AWS and orgs a and b (two regions, one role), then press Enter (`E2E_PAUSE=0` skips) |
| `retire-region` | 5. teardown, one region | teardown of org b (dry run, then `--yes`); the file lists only org a; the plan is only an in-place update; the role trusts exactly org a; org b is disconnected; org a still connects |
| `down` | 5. teardown, whole account | teardown of every org; with the role still present every connection test fails (proves the disconnects); `terraform destroy`; the role is gone |
| `multi` | 3. several regions in one go | `snyk-orgs.auto.tfvars` lists orgs c and d from the start: one plan creates exactly the role and its policy; the role trusts exactly c and d; both connect and sync |
| `status`, `down` | 4, 5 | as above, for orgs c and d |
| `postcheck` | | role and file gone; no policies or `snyk-e2e/` projects in any org; every org and both images untouched |
| `infra-down` | | ECR repos destroyed; throwaway orgs deleted |
| `final` | | role and repos gone, and every throwaway org gone: not found by ID, or no longer listed in the group (polls up to `FINAL_TIMEOUT`, 180s) |

Run steps one at a time with `./e2e.sh <step>`; `./e2e.sh status` shows the current state at any time. If a
sync check times out, it also prints every project with its origin (`status --all-origins`), so a wrong `ecr`
origin assumption shows up directly instead of as a plain timeout. After a failure, the message lists exactly
what is still outstanding (read from the Terraform state files, `snyk-orgs.auto.tfvars` and the recorded
orgs) and the command that removes it; `down` and `infra-down` are safe to re-run. Logs of each run are in
`examples/sandbox/.e2e/`.

Observed in the first full run: the org disappeared from the Snyk UI as soon as Snyk accepted the delete,
but a lookup by ID (`GET /rest/orgs/{id}`) kept finding it for a few minutes before answering not found.
`final` therefore also checks the group's org list and polls for up to `FINAL_TIMEOUT` before failing.

Observed in the two-region run (2026-10-19):
- The connection test lists every repository the role can read in that region (15 in `us-east-1` of the
  sandbox account, most of them other teams'); the `Regex` policy imported only `snyk-e2e/app:v1.0.0`. The
  role is read-only on all repositories, as Snyk's instructions set it up, so the sync policy is what scopes
  the import.
- The SSO identity could create and destroy the role but was refused `iam:UpdateAssumeRolePolicy`, so
  `add-region` stopped at its apply with the trust policy unchanged. The first part of `add-region` (the
  check for an org the role does not trust) records that it passed, so re-running the step with an identity
  that has the permission continues from the trust update.
- A brand-new role needed one connection retry in `ap-southeast-2` and none in `us-east-1`.

### Profiles mode (`./e2e.sh profiles`)

Validates feature 002 ([quickstart.md, section 3](../specs/002-multi-ecr-connections/quickstart.md#3-profiles-mode-live-constitution-principle-vii))
in one org that holds several connections. It uses the test repositories in regions A and B and no
throwaway org, spaces its tool runs at least 6 seconds apart, and takes about 15 to 25 minutes, most of it
waiting for Snyk's syncs.

| Step | Asserts |
|---|---|
| `infra-up` | the ECR repos and test images only (`E2E_SLOTS=none`) |
| `profiles-preflight` | the org is reachable, `status` prints `Mode: profiles`, the org has no ECR connection and no `snyk-e2e/` projects; both images exist; the role and `snyk-orgs.auto.tfvars` do not |
| `profiles-new` | `terraform apply` with `snyk_orgs={}` and `snyk_profile_orgs=["<org>"]`: the plan creates exactly the role and its policy; the role trusts exactly that org |
| `profiles-scenario` | `apply` without a name in region A creates `<account>.dkr.ecr.<A>.amazonaws.com`; `--connection e2e-b` in region B creates `e2e-b <account>.dkr.ecr.<B>.amazonaws.com`; re-running the first reaches the same connection; `e2e-b` with region A is refused; `snyk-e2e/app:v1.0.0` appears once under each connection (live check L4); `teardown` without a name is refused; pausing `e2e-b` keeps its project; disconnecting the first deletes it and leaves `e2e-b` alone, and the step records whether Snyk deleted or orphaned the project (live check L8); `--update-credentials` repoints and renames `e2e-b` to region A (live check L1); disconnecting `e2e-b` |
| `profiles-down` | deletes any connection this step made (names `<account>.dkr.ecr.<A>.amazonaws.com` or `e2e-b …`), keeps every other, destroys the role; safe to re-run after a failure |
| `infra-down` | ECR repos destroyed |
| `profiles-final` | role and repos gone; the org holds no ECR connection and no orphaned `snyk-e2e/` project |

### If the AWS session expires mid-run

Every step that needs AWS first checks the session and stops with `run aws sso login …` before changing
anything. Steps are idempotent, so after logging in, re-run the step that stopped and continue with the next
ones in the order above.

### Using an existing org instead

`E2E_ORG_ID=<uuid> ./e2e.sh single` uses that org as org a and skips org creation. Use it to test with an
org-level service account, which cannot create orgs (so the multi-org scenarios need a group-level token):
create an empty org in the UI, create a service account in it (Org Admin, access token), and export its token
as `SNYK_TOKEN`. That org is **never deleted**; it must have no ECR integration (the product teardown leaves
an empty integration entry behind, so a second run against the same org needs that entry removed in the UI
first).

### Safety guards

- The harness deletes an org only if its name starts with `ecr-e2e-`, it is not passed via
  `--protect` (the harness protects `SNYK_ORG_ID` if set), and Snyk itself only deletes orgs with
  no projects, so the product teardown must have succeeded first.
- The onboarding script itself has no org or registry delete calls (enforced by a unit test); org
  creation and deletion exist only in `examples/sandbox/harness.py`.
- Product teardown is scoped to projects under `snyk-e2e/` and to the throwaway orgs. In profiles mode it is
  scoped to the connections the step made in `E2E_PROFILE_ORG_ID`, by name; that org itself is never
  created, deleted, or recorded as a throwaway slot.
