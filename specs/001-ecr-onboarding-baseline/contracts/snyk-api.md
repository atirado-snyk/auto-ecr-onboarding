# Contract: Snyk API calls made by `onboard_ecr.py`

Every call the script makes, as delivered at `f035a43`. This is the complete list: a call that is
not here is not made. Permissions are as `docs/USAGE.md` lists them from the published v1 OpenAPI
spec and the REST spec `2026-03-25`; requests are sent with REST version `2025-09-17` by default,
which passed live on 2026-11-24 ([research O1](../research.md#open-items)).

## Calls

Paths are relative to `--api-base`. `{org}` is `--org-id`; `{id}` is the org's ECR integration; every
REST path carries `?version=<--api-version>`.

| # | Call | API | Used by | Token permission | Notes |
|---|------|-----|---------|------------------|-------|
| 1 | `GET /v1/org/{org}/integrations` | v1 | every mode | View Organization, View Integrations | The answer maps `"ecr"` to the integration ID |
| 2 | `POST /v1/org/{org}/integrations` | v1 | `apply` | + Edit Integrations; admin on the org | Body `{"type": "ecr", "credentials": {"region": …, "roleArn": …}}`; does not validate the connection |
| 3 | `PUT /v1/org/{org}/integrations/{id}` | v1 | `apply --update-credentials` | Same as 2 | Same body as 2 |
| 4 | `DELETE /v1/org/{org}/integrations/{id}/authentication` | v1 | `teardown --delete-credentials --yes` | Same as 2 | 404 means already removed |
| 5 | `POST /rest/orgs/{org}/container_import/{id}/policy/dry_run` | REST | `plan`, `apply` | `integration.edit` | Starts a dry run; returns a job ID |
| 6 | `GET /rest/orgs/{org}/container_import/{id}/policy/dry_run/{job}` | REST | `plan`, `apply` | `integration.edit` | Polled until `completed` or `failed` |
| 7 | `GET /rest/orgs/{org}/container_import/{id}/policy` | REST | `status`, `teardown` | Not listed in `docs/USAGE.md` | 404 or an empty body means no policy |
| 8 | `POST /rest/orgs/{org}/container_import/{id}/policy` | REST | `apply` | `integration.edit` | Creates or replaces the policy; on 409, call 9 |
| 9 | `PATCH /rest/orgs/{org}/container_import/{id}/policy` | REST | `apply` | `integration.edit` | Same body as 8 |
| 10 | `DELETE /rest/orgs/{org}/container_import/{id}/policy` | REST | `teardown --yes` | `integration.edit` | 404 means there was none |
| 11 | `GET /rest/orgs/{org}/projects?limit=100&origins=ecr` | REST | `status`, `teardown --delete-projects` | View Projects (`org.project.read`) | `origins` is left out for `status --all-origins`; follows `links.next` |
| 12 | `DELETE /rest/orgs/{org}/projects/{project}` | REST | `teardown --delete-projects --yes` | Remove Projects (`org.project.delete`) | One call per matching project |

REST bodies for calls 5, 8, and 9 wrap the policy as
`{"data": {"type": "container_registry_import_policy", "attributes": {"policy": <policy>}}}`, where
`<policy>` is the object in [data-model.md](../data-model.md#sync-policy-snyk-rest-container_registry_import_policy).
The connection test is call 5 with `{"name": "connection test", "import_policy": {"name": "all",
"type": "ImportAll"}}`.

**Never called**: creating or deleting an org, deleting an integration entry, or anything that
changes a registry. Org creation and deletion exist only in the e2e harness
(`examples/sandbox/harness.py`), behind its own safety guards.

## Transport

| Aspect | Behavior |
|--------|----------|
| Host | `--api-base` must be `https://` on `snyk.io` or a subdomain; anything else is refused before the token is used |
| Authentication | `Authorization: token <SNYK_TOKEN>` on every call; OAuth bearer tokens are not supported |
| Media types | v1: `application/json`. REST: `application/vnd.api+json` for `Accept` and `Content-Type` |
| Timeout | 60 seconds per request |
| Transient retries | On 429, 500, 502, 503, and 504: up to 5 retries, waiting `Retry-After` seconds (any letter case; an HTTP date falls back to the default) or 1, 2, 4, 8, and 16 seconds, at most 60 seconds per wait |
| Propagation retries | Call 2 is retried `--connect-retries` times, `--connect-delay` apart, except on 401, 403, and 404; the connection test (calls 5 and 6) likewise, but only when the credentials were set in this run |
| Errors | A non-2xx answer raises an error naming the method, the URL, the status, and the first 500 characters of the body; a network failure or a non-JSON success body raises a clear error; none includes the token |
| Pagination | `links.next` may be relative to the REST base, with or without the `/rest` prefix, or absolute on the same host; a link to any other host is refused |
