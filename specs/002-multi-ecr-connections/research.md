# Research: Several ECR connections in one Snyk org

Seeded during `/speckit-specify` on 2026-11-24 so the findings are not lost; `/speckit-plan` completes
it (Phase 0). Sources are Snyk-internal unless marked public.

## What is known

- **The feature.** Snyk's "Multiple Container Registry Profiles" closed beta lets one org hold several
  integrations of one container registry type. It currently covers AWS ECR, for Enterprise customers,
  enabled per customer behind a feature flag. Each integration is labeled with a `profile_name`, for
  example `aws-prod-account`. (Highspot: "Snyk Container Q2 2026 Beta Features"; "TSM & IC Container
  Enablement: Demo and Q&A"; "Container Tech Enablement Session - April 2026".)
- **API only, at least at first.** Configuration, including container registry sync, is done through
  Snyk's REST ("V3") APIs. When the flag is on, the UI's registry configuration is removed; UI support
  was planned for June 2026. (Same sources.)
- **A new REST Integrations API.** Registry ADR 0096 adds `POST /integrations`, `GET /integrations`,
  `GET /integrations/{integration_id}`, `PATCH /integrations/{integration_id}`, and
  `DELETE /integrations/{integration_id}`, because the v1 API is modeled on one integration per org
  per type. `DELETE` is new: v1 cannot delete an integration. (`snyk/registry`,
  `docs/adrs/0096-adding-support-for-multiple-cr-integrations-per-org.md`.)
- **Uniqueness.** The ADR replaces the one-per-org-and-type constraint, for container registry types,
  with uniqueness on org, type, and `profile_name` (a `VARCHAR(255)` column).
- **Projects are tied to a connection internally.** Import tasks and org targets carry the integration's
  `orgSourcePublicId`, and deleting an integration stops recurring tests only for the projects imported
  through it. (Same ADR.)
- **The sync API is per integration already.** `/rest/orgs/{org}/container_import/{integration_id}/...`
  takes the integration ID (public docs: "Sync your container registry"), so it should serve each
  connection unchanged.
- **The baseline's blind spot.** In an org with the beta, the v1 integration listing names only one of
  its ECR integrations (verified in a test org, November 2026; `docs/USAGE.md`, Constraints 1).
- **Field experience.** One customer connected six AWS accounts to one org. The same image in several
  accounts showed as separate projects, with nothing on the project page saying which connection it
  came from, and saving an import policy in the UI failed with "Integration ID is required" (worked
  around through the API). (Slack, July 2026.)

## Observed in the Snyk UI (owner, 2026-11-24)

- **The UI has profile management.** "Create new ECR profile" asks for a profile name ("A unique name
  to identify this specific connection profile"), a region, and a role ARN: the same three fields the
  spec models for a named connection.
- **Creating a profile with a role that does not exist failed** with a generic "Failed to create
  profile." (role `arn:aws:iam::123456789012:role/snyk-ecr-read`, AWS's documentation placeholder
  account; region `us-west-2`). If the role is the cause, the profiles create checks access before it
  saves, unlike the v1 create, which does not (baseline research, D6). Then a create right after a new
  role is made can fail while IAM propagates, and the tool must retry it. Not yet confirmed: the
  message does not name the cause.
- **The name `this.is.a-test:1234567890/abc` drew no field error** in the form, so the UI does not
  restrict dots, hyphens, colons, or slashes before submitting. Whether Snyk's server accepts such a
  name is **unproven**: the request failed, possibly before the name was checked.
- **The baseline's view of a flagged org with no profiles** (`status --all-origins` on `antonio-org`,
  2026-11-24, read-only): `ECR integration: none`, no sync policy, no ECR projects, 60 projects of
  other origins. That is exactly what it reports for a default-mode org with no connection, so the v1
  listing alone cannot tell the modes apart, at least while the org has no profiles. The baseline's
  `apply` would therefore attempt a v1 create on this org (the FR-016 risk); 002 must find the mode
  elsewhere (question 3). Log: `examples/sandbox/.e2e/profiles-status-baseline.log` (gitignored).
- **Next observations**: the failed request's response body, from the browser's developer tools,
  would name the failing check and show the API call's path, version, and body (questions 2 and 8).
  A create with a real, trusted role and the default name format, followed by a delete, would prove
  the name.

## Observed API calls (Snyk UI, sanitized HAR, 2026-11-24)

The owner created profile `123456789012.dkr.ecr.us-east-1.amazonaws.com` in `antonio-org` (region
`us-east-1`, role `arn:aws:iam::123456789012:role/snyk-ecr-read`, which trusts only `antonio-org`). It
saved, and the UI shows it as connected with integration ID `<profile-id>`.
The UI calls `app.snyk.io/api/…`, its proxy to Snyk's API:

| Call | Request | Response |
|------|---------|----------|
| Create | `POST hidden/orgs/{org}/integrations?version=2024-10-15`, JSON:API body `{"data": {"type": "integration", "attributes": {"integration_type": "ecr", "profile_name": "…", "credentials": {"region": "…", "role_arn": "…"}}}}` | `201`: `data.id`, and `attributes` `integration_type`, `profile_name`, `has_broker`, `created_at`, `updated_at` |
| Read credentials | `GET hidden/orgs/{org}/integrations/{id}/credentials?version=2024-10-15` | `200`: `integration_type`, `region`, `role_arn` |
| Read status | `GET hidden/orgs/{org}/integrations/{id}/status?version=2024-10-15` | `200`: `connection_status: "valid"` |
| Read settings | `GET hidden/orgs/{org}/integrations/{id}/settings?version=2024-10-15` | `200`: `container_app_scan_enabled: true` |
| Read sync policy | `GET rest/orgs/{org}/container_import/{id}/policy?version=2023-10-11~experimental` | `404`: no policy yet |

What this settles:

- **Question 8 (names)**: answered. Snyk accepted the registry URI as `profile_name` unchanged, dots
  included.
- **Question 2 (API shape)**: create and three reads are known. Credentials use `role_arn`, where v1
  uses `roleArn`.
- **The sync API serves profiles**: `container_import/{id}` takes the profile's integration ID, so
  the per-connection sync needs no new API.
- **A cheap connection check exists**: `…/status` reports `connection_status`. The dry-run connection
  test stays more useful, since it also lists repositories and tags, but `status` could serve the
  `status` mode.

What it raises:

- **The integrations API is in Snyk's `hidden` tier**: unpublished, with no public spec or stability
  promise. Constitution Principle IV requires published contracts, so the plan must record this as a
  justified exception in its Complexity Tracking table, or wait for a published version.
- **Token access is unverified**: the UI authenticates with a session, while the tool sends
  `Authorization: token …` to `api.snyk.io`. The next check is a read-only list call with the token
  (`GET https://api.snyk.io/hidden/orgs/{org}/integrations?version=2024-10-15`).
- **Still open**: list, update, and delete shapes; the token permissions needed; the mode signal
  (question 3); provenance (question 1).

### Follow-up checks with the token (2026-11-24)

- **The baseline now sees the profile.** `status` on `antonio-org` reports
  `ECR integration: <profile-id>`, exactly as for a default-mode org with one connection. With one
  profile, the v1 view cannot tell the modes apart either.
- **Token authentication works on the hidden tier.** `GET
  https://api.snyk.io/hidden/orgs/{org}/integrations?version=2024-10-15` with `Authorization: token …`
  answered `200`. The same path under `/rest/` answered `404`: the API exists only in the hidden tier.
- **The list returns every integration type**, not only ECR: the profile, plus `cli`, `gitlab`, `gcr`,
  `azure-repos`, `github-cloud-app`, and `github`, each with `profile_name: "Default profile"`. The tool
  must filter on `integration_type: "ecr"`. The list carries no credentials, and `links` was empty for
  seven integrations.

### What the profile settings page's code says (from the HAR's JavaScript bundle)

- **Deleting a profile deletes its projects.** The page's text: "This will permanently delete your
  unique integration profile, disconnect from the registry, remove your credentials, and permanently
  delete all projects associated with this profile. This action cannot be undone." After a delete it
  reports: "associated projects have been scheduled for removal." This contradicts the assumption
  behind FR-014 (delete keeps the scans as history), which came from ADR 0096's note that deleting an
  integration stops the recurring tests of its projects. FR-014 is reopened.
- **Snyk tracks which projects belong to a profile**, since a delete removes exactly those. That
  supports question 1, though it does not show a public way to read the link.
- **Sync policy calls**: `GET`, `POST`, `PATCH`, and `DELETE` on
  `/orgs/{org_id}/container_import/{integration_id}/policy`, as the baseline already uses them.
- **Renaming a profile** sends `{profile_name: …}` to an update call whose path is in a bundle the HAR
  did not include.

## Decisions from clarification (owner, 2026-11-24)

- **Scope**: several ECRs per org; the region is an attribute of a connection and orthogonal to the
  feature. The first spec draft framed connections around regions; that framing was dropped.
- **Two modes**, decided by Snyk's flag on the org: default (baseline unchanged) and profiles.
- **Provenance instead of prefix matching**: overlapping repositories across environments are expected,
  so a project's connection must come from Snyk's record, and teardown selects projects by connection.
- **Disconnect means delete**: removing a connection deletes it; its scans stay as history.
- **Names default to the ECR registry URI** (owner, revising the no-default draft). The URI states
  exactly where an image came from, and a re-run for the same ECR reaches the same connection. The
  engineer may give another name, such as the environment. `teardown` still needs the name.
- **Snyk's UI is out of scope**: the tool onboards through the API, and Snyk's UI follows.

## What planning must find out

1. **Whether Snyk's public API exposes which connection imported a project.** This decides FR-011 and
   FR-013: without it, project removal is refused in profiles mode. Candidates: the project's target
   (the ADR ties org targets to the integration's `orgSourcePublicId`), or a relationship or attribute
   on the project itself. If neither is public, the fallback is a request to Snyk; the tool must not
   guess.
2. **The REST Integrations API's exact shape**: path prefix, API version and stability, request and
   response attributes for ECR (`profile_name`, region, role ARN), and required token permissions.
   The public API reference has no page for it (`docs.snyk.io/snyk-api/reference/integrations`
   returned 404 on 2026-11-24). Likely sources: the beta documentation given to enrolled customers,
   or Snyk's internal OpenAPI spec.
3. **How the tool tells an org's mode** (FR-002): for example whether the REST listing answers
   differently for orgs without the flag, or whether Snyk exposes the flag.
4. **Whether the external ID stays the org ID** for every connection.
5. **What `DELETE` does to the connection's projects**: Snyk's UI says it deletes them (see above),
   which reopens FR-014. Still to verify live through the API, and to check whether the hidden API
   can remove a profile's credentials without deleting it.
6. **What happens to extra connections if the flag is turned off.**
7. **How the Terraform input states account access without regions** (FR-016) while the baseline's
   region-to-org map keeps working for default mode (FR-017).
8. ~~Whether Snyk's `profile_name` accepts the registry URI as is.~~ Answered on 2026-11-24: it does
   (see "Observed API calls").
9. **Whether Snyk will publish the integrations API.** Token authentication at `api.snyk.io/hidden`
   works (verified 2026-11-24); the tier is still unpublished, which decides how the plan meets
   Principle IV.
