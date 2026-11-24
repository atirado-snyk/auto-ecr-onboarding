# Research: ECR → Snyk Onboarding (as-built baseline)

Phase 0 of an as-built plan. The Technical Context has no `NEEDS CLARIFICATION`, so instead of
resolving unknowns this file records three things: the design decisions as delivered, the Snyk
behavior the tool relies on that Snyk does not document, and the open items found while deriving
the spec.

Each rationale says where it comes from: **stated** means the repository's docs or code say it;
**inferred** means it was reasoned from the design and should be confirmed by the owner.

## Decisions as built

### D1. Terraform for AWS, a script for Snyk, kept apart

- **Decision**: the IAM role is a Terraform module, applied once per account; the Snyk calls are one
  script, run once per registry. They meet only at the role ARN.
- **Rationale**: stated. Terraform creates the AWS resources, and the script connects Snyk
  (`README.md`). Inferred: the AWS change then goes through the organization's normal plan and review
  (including Terraform Enterprise), while the Snyk side needs retries, previews, and polling that a
  declarative tool expresses poorly.
- **Alternatives considered**: a custom Terraform provider, ruled out by name in `README.md` and by
  Constitution Principle II.

### D2. Snyk's registry sync instead of push events

- **Decision**: ongoing imports come from Snyk's scheduled container registry sync; nothing of the tool
  runs between changes.
- **Rationale**: stated (`README.md`, `docs/USAGE.md` "Running it over time"). No Lambda, EventBridge
  rule, scheduled job, or daemon to operate.
- **Trade-off**: new images wait for the next sync, at least 2 hours apart. For large or fast-moving
  registries, the docs recommend adding `snyk container monitor` to CI (`docs/USAGE.md`, Constraints 7).

### D3. One role per account, trusting the tenant's principal with ExternalId = org ID

- **Decision**: the trust policy names the specific Snyk principal from the tenant's UI and requires
  `sts:ExternalId` to equal one of the listed org IDs.
- **Rationale**: stated. This is AWS's documented protection against the confused-deputy problem for
  third-party access, and a specific principal is narrower than trusting Snyk's whole account
  (`docs/USAGE.md`, Security notes; module `variables.tf`).
- **Alternatives considered**: trusting `arn:aws:iam::<snyk-account>:root`, as Snyk's AWS Partner
  Solution does. Rejected as broader, and flagged by Snyk IaC as SNYK-CC-TF-118.

### D4. The region-to-org map is the single source of the trust list

- **Decision**: `snyk_orgs` (region to org ID) is the only input for the trust list; with more than
  one region it lives in an `*.auto.tfvars` file in the operator's repository.
- **Rationale**: stated. Terraform writes the trust policy exactly as listed, so a list kept in one
  reviewed file prevents silently dropping an org (`docs/USAGE.md`, "Another region in the same
  account"; `examples/snyk-orgs.auto.tfvars.example`).
- **Alternatives considered**: `-var` switches, fine for one region but easy to get wrong later;
  Terraform Enterprise workspace variables, which would override the file, so only one place may
  hold the list.

### D5. v1 API for the integration, REST for everything else

- **Decision**: list, create, and update the ECR integration and delete its credentials with v1; dry
  runs, the sync policy, and projects with REST.
- **Rationale**: stated. The integration operations exist only in v1, which Snyk marks deprecated
  (`docs/USAGE.md`, Constraints 4).
- **Risk**: if Snyk removes v1 before offering a REST equivalent, connecting stops working. The
  calls are isolated in four `SnykClient` methods ([contracts/snyk-api.md](contracts/snyk-api.md)).

### D6. The connection test is an ImportAll dry run

- **Decision**: after connecting, prove read access with a dry run of an ImportAll policy, which lists
  repositories and tags and imports nothing.
- **Rationale**: stated. The v1 create does not validate the connection, which was found live
  (`docs/USAGE.md`, Constraints 10), so the create alone proves nothing.

### D7. Propagation retries only for credentials set in this run

- **Decision**: retry the create and the first dry run (10 times, 15 s apart) only when this run set
  the credentials; a reused integration is tested once, with a hint to update its credentials.
- **Rationale**: stated. AWS documents IAM changes as eventually consistent (`docs/USAGE.md`, step 3).
  Inferred: retrying a reused integration would hide a disconnected one behind 2.5 minutes of waiting.

### D8. No default policy, Snyk's vocabulary, a restricted policy file

- **Decision**: the engineer must state the policy with one of Snyk's types and its fields, or pass
  Snyk's policy JSON through unchanged; the file must be a small `.json` inside the working directory.
- **Rationale**: stated. Snyk's docs stay the reference for what a policy means (`docs/USAGE.md`, step
  4), and the file restriction keeps any other file from being read and sent to Snyk
  (`policy_file_path` docstring).

### D9. An image limit on what one apply may import

- **Decision**: refuse a preview above `--max-images` (1,000 by default) unless `--force`.
- **Rationale**: stated as a safeguard of the script, not a Snyk setting (`docs/USAGE.md`, step 3).
  Inferred: it bounds the first import, the one most likely to surprise.

### D10. Teardown order, literal prefix, dry run by default

- **Decision**: delete the policy, then the projects, then the credentials; select projects by a
  literal repository prefix; act only with `--yes`.
- **Rationale**: stated. Deleting the policy first keeps the next sync from re-importing deleted
  projects; user-supplied patterns never run locally (`docs/USAGE.md`, Teardown and Security notes).

### D11. Token handling

- **Decision**: read the token from `SNYK_TOKEN` only, send it as `Authorization: token …`, and only to
  `https://*.snyk.io`.
- **Rationale**: stated. The v1 API documents that scheme (`docs/USAGE.md`, Prerequisites). OAuth 2.0
  service accounts, which use `Authorization: bearer …`, are not supported yet (O9).

### D12. Offline tests at the transport boundary

- **Decision**: unit tests replace only the HTTP send and the sleep (`FakeClient`), so everything above
  them runs for real; `terraform test` mocks the AWS provider and covers the inputs only.
- **Rationale**: stated (`tests/test_onboard_ecr.py` docstring, `examples/snyk_orgs.tftest.hcl`
  header). Request shapes come from the published v1 OpenAPI spec and a REST spec (`README.md`,
  Status).

## Snyk behavior relied on but not documented

Verified live on the US tenant, 2026-10-01 unless noted (`docs/USAGE.md`, Constraints 1 and 10). If
Snyk changes any of these, the named part of the tool breaks first.

| Behavior | The tool depends on it for | How to re-check |
|----------|----------------------------|-----------------|
| A dry run on credentials Snyk cannot use fails with "Container registry authentication or configuration failed", and right after a new role this clears on retry | The connection test and its propagation retry (D6, D7) | e2e `new` step |
| The v1 create does not validate the connection | Running a separate connection test (D6) | e2e `add-region`: an untrusted org's create succeeds |
| After the credentials are deleted, the sync API answers "Integration not found" while the v1 list still returns the entry | Teardown's claim that Snyk can no longer read the registry | e2e `down` |
| ECR projects have the origin `ecr` and are named `repository:tag` | `status` filtering, teardown's prefix match (`ECR_ORIGIN`, `repository_of`) | `status --all-origins` |
| Omitting `schedule_frequency_hours` gives 24 hours | Reporting the schedule in effect | `status` after an `apply` without a schedule |
| In an org with Snyk's multi-integration beta, the v1 list names only one of its ECR integrations (November 2026, test org) | Nothing; the docs warn not to run the tool there (spec FR-016) | Manual |

## Open items

- **O1. Which REST version is the contract?** Requests default to `2025-09-17` (`DEFAULT_REST_VERSION`,
  also used by the tests), while `README.md` and `docs/USAGE.md` say request shapes and permissions
  were checked against the REST spec `2026-03-25`. Constitution Principle IV asks the docs to name the
  version they were checked against, so pick one. Moving the default needs an e2e run. Requests at
  `2025-09-17` passed live on 2026-11-24 (task T038).
- **O2. Documentation drift in the connection test output.** `docs/USAGE.md` step 3 shows
  `Snyk can read the registry: 12 repositories, 87 images visible`; the script prints
  `Snyk can read the registry: N repositories with tagged images (M tags) visible; nothing imported.`
  The script's form is the contract ([contracts/cli.md](contracts/cli.md#output-contract)); fix the
  doc.
- **O3. Minimum Python version is not declared.** There is no `requires-python` or inline script
  metadata. The highest requirement seen is `pathlib.Path.is_relative_to` (Python 3.9). The unit
  tests passed on 3.12 on 2026-11-24, and the script has run under 3.14 on the owner's machine (a
  `cpython-314` bytecode cache exists), but nothing below 3.12 has been tested. Inline script metadata
  (PEP 723) would let `uv` enforce a minimum.
- **O4. Terraform version for the offline tests.** The module requires 1.5 or later, and
  `docs/USAGE.md` lists 1.5 as the prerequisite, but `make tf-test` uses `mock_provider`, which
  `terraform test` gained in 1.7. Running needs 1.5; checking needs 1.7.
- **O5. Orgs in Snyk's multi-integration beta.** Decided on 2026-11-24 by the owner: support them.
  Specified as feature `002-multi-ecr-connections`. It redefines the "one registry per Snyk org"
  invariant, so it needs a constitution amendment before its plan.
- **O6. Not verified live.** Applying the in-place trust update (adding or retiring a region): the test
  identity lacked `iam:UpdateAssumeRolePolicy`. The EU and AU tenants: only the US tenant was tested.
- **O7. Paths with no offline test.** The missing-token exit (FR-030), the mapping of errors to exit
  code 1 (FR-034), the teardown's "not removed" report (FR-028), and the trust and permission
  documents (FR-005, FR-006), which the mocked provider computes, so `terraform test` cannot assert
  them as written.
- **O8. Which identity the scheduled sync uses.** Snyk's docs do not say whether the sync depends on the
  token that applied the policy. The docs recommend a service account so it keeps working when people
  leave (`docs/USAGE.md`, "Running it over time").
- **O9. OAuth 2.0 service accounts are not supported.** Their bearer tokens need a different
  `Authorization` scheme. This is the most likely next feature.
- **O10. Read access cannot be scoped to repositories without editing the module.** The inline policy
  grants read on all repositories; `docs/USAGE.md` suggests scoping `Resource` by hand, but the module
  has no input for it.
