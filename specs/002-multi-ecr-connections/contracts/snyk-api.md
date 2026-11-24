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
| 13 | `GET /closed-beta/orgs/{org}/integrations?version=2024-10-15&limit=100` | every run, both modes | 2026-11-24 (token; live check L6) | Mode signal: `200`, or `404` `Endpoint Not Found` ([data-model.md](../data-model.md#mode-per-org-from-call-13)); Snyk's docs say `406`, which was not seen. In profiles mode, the connections: entries with `attributes.integration_type: "ecr"`, named by `attributes.profile_name`. Entries carry `id`, `type`, and `attributes` only. Every integration type is listed, unfiltered; follows `links.next` (`{}` on a single page). No region or role is returned |
| 14 | `POST /closed-beta/orgs/{org}/integrations?version=2024-10-15` | `apply` | 2026-11-24 (token, `closed-beta`; names with a label and a space) | Body `{"data": {"type": "integration", "attributes": {"integration_type": "ecr", "profile_name": …, "credentials": {"region": …, "role_arn": …}}}}`; `201` with `data.id`; `409` when the name is taken |
| 15 | `PATCH /closed-beta/orgs/{org}/integrations/{id}?version=2024-10-15` | `apply --update-credentials` | No (live check L1, left out by the owner) | Body `{"data": {"id": …, "type": "integration", "attributes": {"profile_name": …, "credentials": {"region": …, "role_arn": …}}}}`, every attribute optional; the tool sends the new name when the old one carries the ECR (research R4); `409` when the name is taken |
| 16 | `DELETE /closed-beta/orgs/{org}/integrations/{id}?version=2024-10-15` | `teardown --delete-connection --yes` | 2026-11-24 (token, `closed-beta`) | `204`; the connection leaves the list, and its projects stay, orphaned (live check L8, 2026-11-24, as the documentation says; on `hidden` they had gone); `404` means already gone. Refused by Snyk, and by the tool beforehand, for `Default profile` |
| 17 | `GET /rest/orgs/{org}/targets?limit=100` | profiles mode: `status`, `teardown` | 2026-11-24 (token) | `relationships.integration.data.id` names the target's connection; follows `links.next` |

**Rate limits**: 1 request a second, 10 a minute, and 100 an hour, counted per principal across every
closed-beta API, as each answer's `X-RateLimit-Limit` states (2026-11-24). Calls 13 to 16 are spaced
at least one second apart, and wait `X-RateLimit-Reset` seconds after an answer with
`X-RateLimit-Remaining: 0`; a run lists once and writes at most once; `429` is retried as for any
call, then the run stops naming the limit
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
