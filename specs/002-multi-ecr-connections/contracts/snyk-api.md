# Contract: Snyk API calls in profiles mode

What 002 adds to the baseline's [list of calls](../../001-ecr-onboarding-baseline/contracts/snyk-api.md),
continuing its numbering. The transport rules there apply to every call here: the API host check, the
token header, the media types, timeouts, transient retries, refused redirects, and pagination.

## New calls

`{org}` is `--org-id`; `{id}` is a connection's integration ID. Calls 13 to 16 use Snyk's `closed-beta`
tier at version `2024-10-15`, as Snyk's Integrations API documentation for beta customers gives them:
the documentation is not public and promises no stability, so each call MUST be verified live before
release ([plan, Complexity Tracking](../plan.md#complexity-tracking)). The same paths were seen on
Snyk's `hidden` tier, which serves Snyk's UI, and are noted where that settles something.

| # | Call | Used by | Verified live | Notes |
|---|------|---------|---------------|-------|
| 13 | `GET /closed-beta/orgs/{org}/integrations?version=2024-10-15&limit=100` | every run, both modes | Not on `closed-beta` (live check L6); on `hidden`, 2026-11-24 (token) | Mode signal: `200` or `406` ([data-model.md](../data-model.md#mode-per-org-from-call-13)). In profiles mode, the connections: entries with `attributes.integration_type: "ecr"`, named by `attributes.profile_name`. Every integration type is listed, unfiltered; follows `links.next`. No region or role is returned |
| 14 | `POST /closed-beta/orgs/{org}/integrations?version=2024-10-15` | `apply` | Not on `closed-beta`; on `hidden`, 2026-11-24 (session in the UI) | Body `{"data": {"type": "integration", "attributes": {"integration_type": "ecr", "profile_name": …, "credentials": {"region": …, "role_arn": …}}}}`; `201` with `data.id`; `409` when the name is taken |
| 15 | `PATCH /closed-beta/orgs/{org}/integrations/{id}?version=2024-10-15` | `apply --update-credentials` | No (live check L1) | Body `{"data": {"id": …, "type": "integration", "attributes": {"profile_name": …, "credentials": {"region": …, "role_arn": …}}}}`, every attribute optional; the tool sends the new name when the old one carries the ECR (research R4); `409` when the name is taken |
| 16 | `DELETE /closed-beta/orgs/{org}/integrations/{id}?version=2024-10-15` | `teardown --delete-connection --yes` | Not on `closed-beta`; on `hidden`, 2026-11-24 (token) | `204`; Snyk deletes the connection's projects (seen live; the documentation says they are orphaned, live check L8); `404` means already gone. Refused by Snyk, and by the tool beforehand, for `Default profile` |
| 17 | `GET /rest/orgs/{org}/targets?limit=100` | profiles mode: `status`, `teardown` | 2026-11-24 (token) | `relationships.integration.data.id` names the target's connection; follows `links.next` |

**Rate limits**: Snyk quotes 1 request a second, 10 a minute, and 100 an hour for closed-beta APIs, on
an unknown basis. Calls 13 to 16 are spaced at least one second apart; a run lists once and writes at
most once; `429` is retried as for any call, then the run stops naming the limit
([research R12](../research.md#r12-rate-limits-and-paging-on-the-closed-beta-tier)).

**Not used**: the `hidden` tier's `…/integrations/{id}/credentials`, `…/status`, and `…/settings`
reads, seen from Snyk's UI. Snyk's documented API returns no region or role, so the tool reads a
connection's ECR from its name (research R3).

## Changed calls

| # | Change in profiles mode |
|---|-------------------------|
| 1 to 4 | Never called: v1 is for default mode only (product invariant "API split by mode"), and Snyk's beta documentation advises against v1 creates and lists on a flagged org |
| 5 to 10 | Unchanged, with `{id}` the named connection's integration ID (verified with a profile on 2026-11-24) |
| 11 | Also reads `relationships.target.data.id` of each project |
| 12 | Used for `teardown --delete-projects --yes` on projects whose target names the connection |

## Token permissions

Not documented for calls 13 to 16. The e2e uses the owner's token, an org admin; org service-account
tokens are not yet verified (live check L5).

## Never called

Unchanged from the baseline, plus: deleting a connection the run did not name, deleting
`Default profile`, and any v1 call on a profiles-mode org.
