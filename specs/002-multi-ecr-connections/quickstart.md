# Quickstart: prove profiles mode works

How to check the delivered feature against [spec.md](spec.md), offline first and then live. Usage for
real orgs goes into `docs/USAGE.md` during implementation; this guide only validates.

## 1. Offline (Constitution Principle V)

**Needs**: `uv`, Terraform 1.7 or later, `bash`.

```bash
make check
```

**Expected**: every unit test passes, including the profiles-mode ones: mode detection on each answer
of call 13, names parsed and built, lookup by full name, by label, and by the ECR a name carries, a
`Default profile` connection, the pacing and paging of closed-beta calls, the refusals in
[data-model.md](data-model.md#validation-and-refusal-rules-before-any-write), provenance through
targets, and the Principle I delete scope in each mode. `terraform test` passes the baseline's five
runs and the new ones in [contracts/terraform-module.md](contracts/terraform-module.md#tests).

## 2. Default mode still works (SC-004)

Run the baseline's live check unchanged, from `examples/sandbox/`:

```bash
./e2e.sh single
```

**Expected**: as in the baseline's [quickstart](../001-ecr-onboarding-baseline/quickstart.md): every
step passes, the mode check sees a default-mode org (`406`), and nothing is left behind.

## 3. Profiles mode, live (Constitution Principle VII)

**Needs**: everything `single` needs, plus `E2E_PROFILE_ORG_ID`: an org with Snyk's multiple profiles
feature on and no ECR connection. The harness never creates or deletes that org. Snyk advises a test
org for the beta; `antonio-org` is used by the owner's choice ([research R10](research.md#r10-where-the-profile-mode-live-test-runs)).

```bash
cd examples/sandbox
export E2E_PROFILE_ORG_ID=<flagged-org-uuid>
./e2e.sh profiles
```

**Expected**, step by step:

| Step | What it proves | Requirement |
|------|----------------|-------------|
| Preflight refuses a default-mode org (`406`), or one that already has an ECR connection; it requires `200` on this org | Safety of the run; the closed-beta address | R1, R10 |
| `apply` without a name for region A creates a connection named after its registry address | Default names | FR-005, US1/AC4 |
| `apply --connection e2e-b` for region B creates `e2e-b <region B's address>`; the first is untouched | Several ECRs, one org; labels | FR-004, FR-006, US1/AC2 |
| Re-running `apply` without a name for region A reaches the same connection | Same ECR, same connection | SC-007 |
| `apply --connection e2e-b` with region A is refused, and nothing changes | Name reuse refused | FR-006, US1/AC7 |
| `status` shows `snyk-e2e/app:v1.0.0` twice, once under each connection, each with its account and region | Provenance | FR-010, SC-003, live check L4 |
| `teardown` without a name is refused | Teardown needs a name | FR-005, US3/AC1 |
| `teardown --connection e2e-b --yes` pauses it; its project stays | Pause | US3/AC2 |
| `teardown --connection <region A's address> --delete-connection`: the dry run names the project count; with `--yes` the connection goes, its project is gone (or the run records it orphaned), and `e2e-b` is unchanged | Disconnect | FR-014, SC-002, US3/AC3, US3/AC4, live check L8 |
| `apply --connection e2e-b --update-credentials` with region A repoints it and renames it `e2e-b <region A's address>`; its connection test lists region A's repositories | Repoint | FR-006, live check L1 |
| `teardown --connection e2e-b --delete-connection --yes` | Disconnect the second | FR-014 |
| The step's closed-beta calls stay under 100 in the hour, with no `429` left unretried | Rate limits | R12, live check L7 |
| `final`: the org holds no ECR connection; the role and the repositories are gone | Nothing left behind | SC-006 |

A connection made before the flag (`Default profile`) is not created here: it needs a v1 create on a
flagged org, which Snyk advises against, and it could not be removed through the API (research R6,
live check L2). Unit tests cover how the tool treats one.

After a passing run, update the Verification Status in `spec.md` (Principle VII).
