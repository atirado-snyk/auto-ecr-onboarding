# Quickstart: prove profiles mode works

How to check the delivered feature against [spec.md](spec.md), offline first and then live. Usage for
real orgs goes into `docs/USAGE.md` during implementation; this guide only validates.

## 1. Offline (Constitution Principle V)

**Needs**: `uv`, Terraform 1.7 or later, `bash`.

```bash
make check
```

**Expected**: every unit test passes, including the profiles-mode ones: mode detection on each answer
of call 13, connection lookup by name and by ECR, the refusals in
[data-model.md](data-model.md#validation-and-refusal-rules-before-any-write), provenance through
targets, and the Principle I delete scope in each mode. `terraform test` passes the baseline's five
runs and the new ones in [contracts/terraform-module.md](contracts/terraform-module.md#tests).

## 2. Default mode still works (SC-004)

Run the baseline's live check unchanged, from `examples/sandbox/`:

```bash
./e2e.sh single
```

**Expected**: as in the baseline's [quickstart](../001-ecr-onboarding-baseline/quickstart.md): every
step passes, the mode check sees a default-mode org, and nothing is left behind.

## 3. Profiles mode, live (Constitution Principle VII)

**Needs**: everything `single` needs, plus `E2E_PROFILE_ORG_ID`: an org with Snyk's multiple profiles
feature on and no ECR connection. The harness never creates or deletes that org.

```bash
cd examples/sandbox
export E2E_PROFILE_ORG_ID=<flagged-org-uuid>
./e2e.sh profiles
```

**Expected**, step by step:

| Step | What it proves | Requirement |
|------|----------------|-------------|
| Preflight refuses a default-mode org, or one that already has an ECR connection | Safety of the run | R10 |
| `apply` without a name for region A creates a connection named after the registry URI | Default names | FR-005, US1/AC4 |
| `apply --connection e2e-b` for region B creates a second connection; the first is untouched | Several ECRs, one org | FR-004, FR-006, US1/AC2 |
| Re-running `apply` without a name for region A reaches the same connection | Same ECR, same connection | SC-007 |
| `apply --connection e2e-b` with region A is refused, and nothing changes | Name reuse refused | FR-006, US1/AC7 |
| `status` shows `snyk-e2e/app:v1.0.0` twice, once under each connection | Provenance | FR-010, SC-003, live check L4 |
| `teardown` without a name is refused | Teardown needs a name | FR-005, US3/AC1 |
| `teardown --connection e2e-b --yes` pauses it; its project stays | Pause | US3/AC2 |
| `teardown --connection <URI> --delete-connection`: the dry run names the project count; with `--yes` the connection and its project go, and `e2e-b` is unchanged | Disconnect | FR-014, SC-002, US3/AC3, US3/AC4 |
| A connection made through v1 by the harness is listed, synced, and deleted by the tool | Connection made before the flag | R6, live check L2 |
| `final`: the org holds no ECR connection; the role and the repositories are gone | Nothing left behind | SC-006 |

After a passing run, update the Verification Status in `spec.md` (Principle VII).
