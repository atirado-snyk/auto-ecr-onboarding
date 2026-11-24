# Specification Quality Checklist: Several ECR registries in one Snyk org

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-11-24
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

- **Clarified 2026-11-24 by the owner**: region is orthogonal to the feature; two modes by Snyk's
  flag; provenance from Snyk's record instead of repository prefixes (former FR-011 question);
  disconnect deletes the connection and keeps scans as history (former FR-012 question, option A).
  Details in [research.md](../research.md#decisions-from-clarification-owner-2026-11-24).
- **Names (FR-005), owner 2026-11-24**: they default to the ECR registry URI for `plan` and `apply`;
  `teardown` needs the name. **Snyk's UI**: out of scope, since the tool onboards through the API.
- **Reopened and resolved 2026-11-24**: FR-014. Snyk's UI says deleting a profile deletes all of its
  projects, which conflicted with "delete and keep the scans as history". The owner chose to do what
  the product does: disconnect deletes the connection and its projects, and a pause keeps results.
- **Planning questions answered since, live on 2026-11-24**: Snyk exposes a project's connection
  (research item 1) and the org's mode (item 3). The refusal paths for a project without that record
  stay as a safeguard.
- **Implementation details**: the spec names Snyk and AWS concepts and the tool's operations; the API
  facts are kept in [research.md](../research.md).
- **Constitution**: amended to v2.0.0 in this branch before `/speckit-plan`.
- **Validation iterations**: 4. The first draft scoped connections by region and used an
  account-plus-region default name; the second required names; the third defaults them to the
  registry URI, which identifies the ECR rather than a region. The fourth (second clarification round,
  owner, 2026-11-24) adds the connection made before the flag (FR-004, FR-005) and refuses a name
  reused for another ECR (FR-006); all items still pass.
- **Validation iteration 5** (third clarification round, owner, 2026-11-24): Snyk's closed-beta
  documentation shows that no call returns a connection's region or role, so names carry the registry
  address by default, `[<label> ]<address>`, with an exact name on request (FR-005, FR-006); `status`
  points to Snyk's UI where a name carries none (FR-010); a connection made before the feature needs a
  name and cannot be disconnected by the tool (US1/AC6, FR-014); AWS's China and GovCloud partitions
  are refused (edge cases). All items still pass; the API facts stay in
  [research.md](../research.md#snyks-closed-beta-documentation-and-internal-sources-2026-11-24).
