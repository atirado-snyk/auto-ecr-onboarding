# ECR → Snyk onboarding

Connects an **existing** Amazon ECR registry (one AWS account, one region) to an **existing** Snyk org
so Snyk can scan it, sets up Snyk's automatic image sync, and tears both down again. The org and the
registry are the starting state; this tool never creates or deletes them.

Standard tooling only: **Terraform** for the IAM role, a dependency-free **Python script** (run with
`uv`) for the Snyk API calls, and Snyk's native **container registry sync** for ongoing imports.
No Lambda, no EventBridge, no custom Terraform provider.

```
terraform apply  ──►  IAM role "snyk-ecr-read"   (trust: the Snyk principal from your tenant's UI + ExternalId = Snyk org ID)
                              │ role ARN
scripts/onboard_ecr.py apply ◄┘
   1. connectivity  v1   find or create the ECR integration
                    REST dry run: Snyk lists the registry (imports nothing)
   2. sync          REST preview, then apply the registry sync policy
```

## Quick start
```bash
make check                                       # unit tests + terraform fmt/validate; no credentials needed

# 1. AWS: the role Snyk assumes
terraform -chdir=examples init
terraform -chdir=examples apply -var snyk_org_id=<uuid> \
    -var snyk_aws_principal=<Principal from the Snyk UI: Integrations → Amazon ECR>

# 2. Snyk: connectivity + sync. SNYK_TOKEN in the environment only (SNYK_API_BASE for non-US tenants)
export SNYK_TOKEN=...
uv run scripts/onboard_ecr.py apply --org-id <uuid> --region ap-southeast-2 \
    --role-arn "$(terraform -chdir=examples output -raw role_arn)" \
    --import-policy Regex --tag '^v[0-9]+\.[0-9]+\.[0-9]+$'
```

`plan` (same flags) writes nothing. The sync policy is stated in Snyk's own terms: `--import-policy`
with one of Snyk's types (`ImportAll`, `ImportAllNew`, `Regex`, `Recent`, `LastNObserved`) and its
fields, or `--policy-file` with Snyk's policy JSON. There is no default; `--no-sync` connects only.
Re-running is safe.

## Teardown
`onboard_ecr.py teardown` (dry run unless `--yes`) removes the sync policy and, with flags, the imported
projects (`--delete-projects --repo-prefix`) and the integration's stored credentials
(`--delete-credentials`, which disconnects Snyk); `terraform destroy` removes the role. The org and the
registry are never touched. The empty integration entry has no delete API and can only be removed in
the UI.

## Documentation
- [docs/USAGE.md](docs/USAGE.md): step by step, prerequisites, permissions, constraints, security notes,
  troubleshooting.
- [docs/TESTING.md](docs/TESTING.md): offline checks and the from-scratch end-to-end harness
  (`examples/sandbox/e2e.sh`), which creates and removes its own Snyk org and ECR repository.

## Constraints in one glance
- **One ECR registry per Snyk org** (one account + region); strictly one-to-one.
- The Snyk AWS principal is a **required input**, copied from your tenant's Snyk UI (it differs per tenant).
- Integration create/list/update exist only in the **v1** API (flagged deprecated); sync and projects are **REST**.
- `us-east-2` must be enabled for STS. Registry sync is generally available.

## Status
83 unit tests (fake Snyk API; request shapes from the published v1 OpenAPI spec and REST spec
`2026-03-25`). **Verified live end to end** on the US tenant with a PAT, by the from-scratch harness
(docs/TESTING.md): connectivity with the UI-prescribed principal, the connection test and its propagation
retry, Regex sync importing exactly the matching tag, and teardown of everything the product created.
Repeated with an org-level service account (access token, Org Admin). OAuth 2.0 service accounts (bearer tokens) are not supported yet.
