# Quickstart: prove the tool works

How to check that the delivered tool meets [spec.md](spec.md): offline first, then live against
throwaway infrastructure. Usage for real registries is in [README.md](../../README.md) and
[docs/USAGE.md](../../docs/USAGE.md); this guide only validates.

## 1. Offline, no network or credentials (Constitution Principle V)

**Needs**: `uv`, Terraform 1.7 or later, `bash`.

```bash
make check
```

**Expected** (last run 2026-11-24 on `f035a43`, in under a minute):

| Part | Output to look for |
|------|--------------------|
| `make test` | `Ran 86 tests` … `OK` |
| `make tf-validate` | no `fmt` diff; `Success! The configuration is valid.`; `bash -n` silent |
| `make tf-test` | `5 passed, 0 failed.` |

This covers every requirement in the spec's "Offline tests" row
([spec.md, Verification Status](spec.md#verification-status)).

## 2. Live, from scratch, against a sandbox (Constitution Principle VII)

**Needs**: a sandbox AWS account with rights to create IAM roles, update their trust policy
(`iam:UpdateAssumeRolePolicy`), and create ECR repositories in two regions; a Snyk token that can
create and delete orgs in a group; `terraform`, `aws`, `docker`, `jq`, and `uv`. The full list is in
[docs/TESTING.md](../../docs/TESTING.md).

```bash
cd examples/sandbox
export AWS_PROFILE=<sandbox-profile> AWS_PAGER="" SNYK_GROUP_ID=<group-uuid> SNYK_AWS_PRINCIPAL=<principal-arn>
export SNYK_TOKEN=...
./e2e.sh single   # Story 1 and the whole-account teardown: org a, region A
./e2e.sh full     # every story: about 30 to 60 minutes, mostly waiting for Snyk's syncs
```

**Expected**: every step passes, and `final` reports the role, the repositories, and every throwaway
org gone. The steps map to the spec's stories:

| Spec story | e2e steps |
|------------|-----------|
| 1. Onboard one registry | `new` |
| 2. More regions of one account | `add-region` (the trust update), `multi` |
| 3. Pause, retire, remove | `retire-region`, `down` |
| 4. Check status | `status` |

**Not yet passed live**: the trust update in `add-region` and `retire-region`, which needs
`iam:UpdateAssumeRolePolicy` ([research O6](research.md#open-items)). Running `full` with an identity
that has it would close that gap; then update the Verification Status in the spec.
