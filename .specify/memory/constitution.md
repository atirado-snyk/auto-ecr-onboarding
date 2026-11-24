# ECR → Snyk Onboarding Constitution

## Core Principles

### I. The Starting State Is Never Touched

The tool connects an **existing** ECR registry to an **existing** Snyk org, and removes only what it
created. It MUST NOT create or delete a Snyk org, an ECR registry, or images. Every delete MUST be
limited to the sync policy, the credentials stored in the org's ECR integration, and ECR projects
under a caller-supplied literal repository prefix. A unit test MUST enforce that list of deletes.

Rationale: operators run the tool against production orgs and registries, so its blast radius has to
be provably bounded.

### II. Standard Tooling, No Custom Runtime

AWS resources MUST be Terraform. Snyk API calls MUST be one Python script that uses the standard
library only and runs with `uv run`. Ongoing work MUST be Snyk's own registry sync: no Lambda,
EventBridge rule, daemon, scheduled job, or custom Terraform provider.

Rationale: anyone with Terraform and uv can run, review, and audit the tool, and nothing of it runs
between the times someone changes something.

### III. Safe by Default

Every write path MUST have a read-only counterpart: `plan` for `apply`, and a dry run for `teardown`.
A destructive teardown MUST require `--yes`. Re-running any mode with the same inputs MUST be safe.
The sync MUST have no default policy, and `apply` MUST refuse a sync whose preview exceeds
`--max-images` unless `--force` is given.

Rationale: the cheapest mistake is the one shown in a preview before it happens.

### IV. Snyk's Own Terms and Published Contracts

Sync policies MUST be stated in Snyk's documented vocabulary (policy types and field names) and sent
as written, without a translation layer. Request shapes and token permissions MUST follow Snyk's
published v1 OpenAPI and REST specs, and the docs MUST name the spec version they were checked
against. Behavior Snyk does not document MAY be relied on only when the docs mark it as undocumented
and it has been verified live.

Rationale: Snyk's docs stay the reference for what a policy means, and every assumption about
undocumented behavior stays visible.

### V. Offline Verification First

`make check` (unit tests against a fake Snyk API, `terraform fmt` and `validate`, the e2e script's
syntax check, and `terraform test` with the AWS provider mocked) MUST pass with no network access and
no credentials before a change counts as done.

Rationale: every contributor and every CI runner can prove a change without access to Snyk or AWS.

### VI. Secrets Stay Out of the Repository, the Logs, and the Command Line

The Snyk token MUST come only from the `SNYK_TOKEN` environment variable, MUST be sent only to
`https://*.snyk.io`, and MUST NOT appear in output or error messages. Real org IDs and the Snyk
principal MUST live in gitignored `*.auto.tfvars` files or pipeline configuration, never in this
repository. The Snyk principal is a required input with no built-in value.

Rationale: this is a public repository whose users connect production accounts.

### VII. Claim Only What Was Verified

Docs and specs MUST distinguish what was verified offline, what was verified live (with the tenant
and the date), and what has not been verified. The status statements MUST be updated in the same
change that alters what is verified.

Rationale: engineers deciding whether to reuse or extend the tool need to know which claims carry
evidence.

### VIII. The Spec Is the Contract

`specs/` holds the living specification of the tool. A behavior change MUST update the affected
`spec.md`, its Mermaid diagrams, and the plan's contracts before or together with the code. Code that
contradicts the spec is a defect until the spec is amended.

Rationale: the description of the tool and the tool itself stay one change apart, never two.

## Product Invariants

These hold for every feature. Changing one requires a spec amendment and a MAJOR or MINOR
constitution amendment.

- **One registry per Snyk org.** One ECR registry (one AWS account and one region) maps to exactly one
  Snyk org, because Snyk allows one ECR integration per org.
- **One role per AWS account.** The orgs of one account share one IAM role whose trust policy lists
  every one of their org IDs. Retiring a region removes that org ID from the list; it MUST NOT destroy
  the shared role.
- **Least privilege for Snyk.** Snyk may assume the role only from the tenant's Snyk principal and
  only with its org ID as `sts:ExternalId`, and the role grants read-only ECR actions.
- **API split.** The v1 API (deprecated, with no REST equivalent) is used only for listing, creating
  and updating the ECR integration and deleting its credentials. Everything else uses the REST API.

## Development Workflow and Quality Gates

1. **Behavior changes go through Spec Kit**: amend the living spec or run `/speckit-specify`, then
   `/speckit-plan`, `/speckit-tasks`, `/speckit-implement`, and `/speckit-converge`. Changes with no
   observable effect (typos, refactors, docs that match the spec) need only the gates below.
2. **Gate**: `make check` is green.
3. **Snyk- or AWS-facing changes**: run the affected steps of `examples/sandbox/e2e.sh` against a
   sandbox account and throwaway orgs, then update the verification status; or mark the change as
   not yet verified live (Principle VII).
4. **Recommended, not a gate**: `make scan` (Snyk Code and Snyk IaC). It needs `snyk auth` and has no
   CI runner yet.
5. **Review** checks the diff against `spec.md` and the plan's contracts, not only against the code.

## Governance

This constitution governs how the tool is built and changed; `README.md` and `docs/` describe how it
is used. Where they conflict, this document wins until it is amended.

- **Amendments** are pull requests that change this file and state the version bump and its
  rationale in the commit message.
- **Versioning** follows semantic versioning: MAJOR for removing or redefining a principle or an
  invariant, MINOR for adding one or materially expanding guidance, PATCH for wording only.
- **Compliance**: every `plan.md` carries a Constitution Check against the current version. A
  violation MUST be justified in that plan's Complexity Tracking table or the plan does not proceed.

**Version**: 1.0.0 | **Ratified**: 2026-11-24 | **Last Amended**: 2026-11-24
