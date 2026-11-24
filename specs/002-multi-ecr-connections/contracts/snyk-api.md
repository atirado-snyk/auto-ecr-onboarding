# Contract: Snyk API calls in profiles mode

What 002 adds to the baseline's [list of calls](../../001-ecr-onboarding-baseline/contracts/snyk-api.md),
continuing its numbering. The transport rules there apply to every call here: the API host check, the
token header, the media types, timeouts, transient retries, refused redirects, and pagination.

## New calls

`{org}` is `--org-id`; `{id}` is a connection's integration ID. Calls 13 to 17 use Snyk's unpublished
`hidden` tier at version `2024-10-15`: they are **undocumented by Snyk** and each MUST be verified live
before release ([plan, Complexity Tracking](../plan.md#complexity-tracking)).

| # | Call | Used by | Verified live | Notes |
|---|------|---------|---------------|-------|
| 13 | `GET /hidden/orgs/{org}/integrations?version=2024-10-15` | every run, both modes | 2026-11-24 | Mode signal ([data-model.md](../data-model.md#mode-per-org-from-call-13)). In profiles mode, the connections: entries with `attributes.integration_type: "ecr"`, named by `attributes.profile_name` |
| 14 | `GET /hidden/orgs/{org}/integrations/{id}/credentials?version=2024-10-15` | profiles mode, every mode of the tool | 2026-11-24 (session in the UI) | `attributes.region`, `attributes.role_arn`; no secret is returned |
| 15 | `POST /hidden/orgs/{org}/integrations?version=2024-10-15` | `apply` | 2026-11-24 (session in the UI) | Body `{"data": {"type": "integration", "attributes": {"integration_type": "ecr", "profile_name": …, "credentials": {"region": …, "role_arn": …}}}}`; `201` with `data.id` |
| 16 | `PATCH /hidden/orgs/{org}/integrations/{id}?version=2024-10-15` | `apply --update-credentials` | **No**: body unknown (live check L1) | Listed in Registry ADR 0096 |
| 17 | `DELETE /hidden/orgs/{org}/integrations/{id}?version=2024-10-15` | `teardown --delete-connection --yes` | 2026-11-24 (token) | `204`; Snyk deletes the connection's projects; `404` means already gone |
| 18 | `GET /rest/orgs/{org}/targets?limit=100` | profiles mode: `status`, `teardown` | 2026-11-24 (token) | `relationships.integration.data.id` names the target's connection; follows `links.next` |

Calls 14 and 15 were seen from Snyk's UI, which authenticates with a session; the token path for them
is verified by the first e2e run of the `profiles` step. Token authentication on the hidden tier was
verified with call 13 and call 17.

## Changed calls

| # | Change in profiles mode |
|---|-------------------------|
| 1 to 4 | Never called: v1 is for default mode only (product invariant "API split by mode") |
| 5 to 10 | Unchanged, with `{id}` the named connection's integration ID (verified with a profile on 2026-11-24) |
| 11 | Also reads `relationships.target.data.id` of each project |
| 12 | Used for `teardown --delete-projects --yes` on projects whose target names the connection |

## Token permissions

Not documented for calls 13 to 17. The e2e uses the owner's token, an org admin; org service-account
tokens are not yet verified (live check L5).

## Never called

Unchanged from the baseline, plus: deleting a connection the run did not name, and any v1 call on a
profiles-mode org.
