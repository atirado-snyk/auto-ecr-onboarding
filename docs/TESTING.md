# Testing

## Offline (no credentials)

```bash
make check     # unit tests (fake Snyk API), terraform fmt/validate, script syntax
make scan      # Snyk Code + Snyk IaC (needs `snyk auth`)
```

## From-scratch end-to-end test (`examples/sandbox/e2e.sh`)

Starts from the bare minimum and ends there again. It creates its own test infrastructure, runs
the product against it, checks every step, then removes everything it created.

### Bare-minimum prerequisites

| Need | Detail |
|---|---|
| AWS account + credentials | A **sandbox** account; `AWS_PROFILE` (or other credentials) that can create IAM roles and ECR repositories. `AWS_REGION` defaults to `ap-southeast-2`. |
| Snyk account + credentials | `SNYK_TOKEN` that may **create and delete orgs** in a group, and that group's ID in `SNYK_GROUP_ID` (find it with `uv run harness.py groups`). `SNYK_AWS_PRINCIPAL`: the `Principal` from the trust policy your tenant's UI shows under Integrations → Amazon ECR (the same for every org in the tenant). Non-US tenants: `SNYK_API_BASE`. |
| Tools | `terraform`, `aws`, `docker` (running), `uv`. |

### Layers: each removes exactly what it created

| Layer | Creates | Removed by |
|---|---|---|
| Test infrastructure (harness) | throwaway Snyk org `ecr-e2e-<timestamp>` (in `SNYK_GROUP_ID`, no settings copied); ECR repo `snyk-e2e/app` with an `alpine:3.18` image tagged `v1.0.0` and `latest` | `infra-down` |
| Product under test | IAM role `snyk-ecr-e2e` (the module); ECR integration, sync policy, synced projects (the script) | `down` (the script's teardown, then `terraform destroy`) |

The harness uses its own names (`snyk-ecr-e2e`, `snyk-e2e/`, `ecr-e2e-*`), so it never touches a
real `snyk-ecr-read` role, other repositories, or any org it did not create.

### Run

```bash
cd examples/sandbox
export AWS_PROFILE=<sandbox-profile> AWS_PAGER="" SNYK_TOKEN=... SNYK_GROUP_ID=<group-uuid> SNYK_AWS_PRINCIPAL=<principal-arn>
./e2e.sh full
```

| Step | Asserts |
|---|---|
| `infra-up` | creates the org and the ECR repo, pushes the test image |
| `preflight` | AWS credentials work; the org is reachable and has no ECR integration; the image exists; the role does not |
| `up` | role applied; `plan` reports the integration as missing; `apply` (with a Snyk `Regex` policy: repo `^snyk-e2e/`, semver tags) creates the integration, the connection test lists `snyk-e2e/app`, the sync preview selects exactly `v1.0.0`, the policy is applied |
| `verify` | within `VERIFY_TIMEOUT` (600s) the sync imports `snyk-e2e/app:v1.0.0` and not `:latest`, and the policy is active |
| pause | inspect AWS and the Snyk org, then press Enter (`E2E_PAUSE=0` skips) |
| `down` | product teardown (policy, projects, credentials); with the role still present the connection test must now fail (proves the disconnect); role destroyed |
| `postcheck` | role, policy and projects gone; the org and the image untouched |
| `infra-down` | ECR repo destroyed; throwaway org deleted |
| `final` | role and repo gone, and the throwaway org gone: not found by ID, or no longer listed in the group (polls up to `FINAL_TIMEOUT`, 180s) |

Run steps one at a time with `./e2e.sh <step>`; `./e2e.sh status` shows the org's state. If `verify`
times out, it also prints every project with its origin (`status --all-origins`), so a wrong `ecr`
origin assumption shows up directly instead of as a plain timeout. After a
failure, the message lists exactly what is still outstanding (read from the Terraform state files and the
recorded org) and the command that removes it; `down` and `infra-down` are safe to re-run. Logs of each run
are in `examples/sandbox/.e2e/`.

Observed in the first full run: the org disappeared from the Snyk UI as soon as Snyk accepted the delete,
but a lookup by ID (`GET /rest/orgs/{id}`) kept finding it for a few minutes before answering not found.
`final` therefore also checks the group's org list and polls for up to `FINAL_TIMEOUT` before failing.

### If the AWS session expires mid-run

Every step that needs AWS first checks the session and stops with `run aws sso login …` before changing
anything. Steps are idempotent, so after logging in, re-run the step that stopped and continue with the next
ones (`down`, `postcheck`, `infra-down`, `final`).

### Using an existing org instead

`E2E_ORG_ID=<uuid>` skips org creation. Use it to test with an org-level service account, which cannot
create orgs: create an empty org in the UI, create a service account in it (Org Admin, access token), and
export its token as `SNYK_TOKEN`. That org is **never deleted**; it must have no ECR
integration (the product teardown leaves an empty integration entry behind, so a second run
against the same org needs that entry removed in the UI first).

### Safety guards

- The harness deletes an org only if its name starts with `ecr-e2e-`, it is not passed via
  `--protect` (the harness protects `SNYK_ORG_ID` if set), and Snyk itself only deletes orgs with
  no projects, so the product teardown must have succeeded first.
- The onboarding script itself has no org or registry delete calls (enforced by a unit test); org
  creation and deletion exist only in `examples/sandbox/harness.py`.
- Product teardown is scoped to projects under `snyk-e2e/` and to the throwaway org.
