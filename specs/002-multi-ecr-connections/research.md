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

### Provenance through the public REST API (2026-11-24)

The owner pushed `alpine:3.18` as `snyk-profile-test/app:v1.0.0` to `us-east-1` and imported it
through the profile in the UI. The project page shows only "Source: ECR". The public REST API (version
`2025-09-17`, token authentication) links the project to the profile:

- `GET /rest/orgs/{org}/projects?origins=ecr&expand=target`: project
  `<project-id>`, named `snyk-profile-test/app:v1.0.0`, with
  `relationships.target.data.id` `<target-id>`. The project itself carries no
  integration ID.
- `GET /rest/orgs/{org}/targets`: target `<target-id>` (`display_name` `snyk-profile-test/app`) has
  `relationships.integration.data.id` `<profile-id>` (the profile) and
  `integration_type` `ecr`. Every other target names its own integration the same way.

**Question 1 is answered: yes.** A project's connection is project → target → integration, all in
the published API, so FR-011 and FR-013 need no hidden API. Not yet seen: two profiles holding the same
repository, which Registry ADR 0096 implies gives one target per profile; the Track 3 e2e should
assert it.

### Sync and delete against a profile, with the token (2026-11-24)

- **The published sync API serves profiles.** The baseline's `plan` on `antonio-org` (read-only; with
  one profile, the v1 listing names it) reused integration `<profile-id>`. Its connection test, an
  ImportAll dry run, listed 15 repositories with tagged images (22 tags), and a Regex preview for
  `^snyk-profile-test/` found `snyk-profile-test/app: v1.0.0` to import. Both are
  `container_import/{id}/policy/dry_run` calls at REST version `2025-09-17`.
- **The external ID is the org ID for profiles too** (question 4): the role trusts only `antonio-org`'s
  ID as `sts:ExternalId`, and the profile connected and read the registry.
- **A manual import does not count as imported for the sync**: the preview counted `v1.0.0` as "to
  import" although the UI had already imported it. Worth checking whether a sync then creates a second
  project or reuses the first.
- **Deleting the profile deletes its projects at once** (question 5): `DELETE
  https://api.snyk.io/hidden/orgs/{org}/integrations/{id}?version=2024-10-15` returned `204`, and the
  imported project was already `404` at the first check, seconds later. FR-014 holds through the API.

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
- **Disconnect means delete, as the product does**: removing a connection deletes it, and Snyk then
  deletes its projects. First answered as "delete and keep the scans as history"; revised by the owner
  ("we do what the product does") after the UI's code showed that a delete removes the projects.
  Pausing keeps a connection's results.
- **Names default to the ECR registry URI** (owner, revising the no-default draft). The URI states
  exactly where an image came from, and a re-run for the same ECR reaches the same connection. The
  engineer may give another name, such as the environment. `teardown` still needs the name.
- **Snyk's UI is out of scope**: the tool onboards through the API, and Snyk's UI follows.

## What planning must find out

1. ~~Whether Snyk's public API exposes which connection imported a project.~~ Answered on 2026-11-24:
   it does, through the project's target, whose `relationships.integration` names the profile (see
   "Provenance through the public REST API").
2. **The REST Integrations API's exact shape**: path prefix, API version and stability, request and
   response attributes for ECR (`profile_name`, region, role ARN), and required token permissions.
   The public API reference has no page for it (`docs.snyk.io/snyk-api/reference/integrations`
   returned 404 on 2026-11-24). Likely sources: the beta documentation given to enrolled customers,
   or Snyk's internal OpenAPI spec.
3. **How the tool tells an org's mode** (FR-002): for example whether the REST listing answers
   differently for orgs without the flag, or whether Snyk exposes the flag.
4. ~~Whether the external ID stays the org ID.~~ Answered on 2026-11-24: it does.
5. ~~What `DELETE` does to the connection's projects.~~ Answered on 2026-11-24: it deletes them at
   once (`204`, project `404` seconds later), matching the UI's text and FR-014.
6. **What happens to extra connections if the flag is turned off.**
7. **How the Terraform input states account access without regions** (FR-016) while the baseline's
   region-to-org map keeps working for default mode (FR-017).
8. ~~Whether Snyk's `profile_name` accepts the registry URI as is.~~ Answered on 2026-11-24: it does
   (see "Observed API calls").
9. **Whether Snyk will publish the integrations API.** Token authentication at `api.snyk.io/hidden`
   works (verified 2026-11-24); the tier is still unpublished, which decides how the plan meets
   Principle IV.
