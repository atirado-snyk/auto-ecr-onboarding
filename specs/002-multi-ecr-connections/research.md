# Research: Several ECR connections in one Snyk org

Seeded during `/speckit-specify` on 2026-11-24 so the findings are not lost; `/speckit-plan` completes
it (Phase 0). Sources are Snyk-internal unless marked public. Account and Snyk IDs from the sandbox
appear as placeholders: `123456789012`, `<profile-id>`, `<project-id>`, and `<target-id>`.

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

### Mode signal: the hidden list on an org without the flag (2026-11-24)

During the default-mode end-to-end run (`e2e.sh single` at `f035a43`, a throwaway org in the Snyk APJ
group, US tenant), while that org's ECR integration was connected through v1 and syncing, the same
token read the hidden list for both orgs within one minute:

| Org | Flag | ECR connections | `GET /hidden/orgs/{org}/integrations?version=2024-10-15` |
|-----|------|-----------------|---------------------------------------------------------|
| Throwaway org | off | one, connected through v1 | `404`, `errors[0].detail: "Endpoint Not Found"`, no `title` |
| `antonio-org` | on | none (the test profile was deleted) | `200`, six integrations, none of them ECR |

- **The flag gates the endpoint, not its contents.** The flagged org answers `200` with no ECR
  connection, and the unflagged org answers `404` while it has one. The answer tells the modes apart
  where the v1 view cannot.
- **This 404 is not the generic one.** A path Snyk does not route (the same list under `/rest/`)
  answered `404` with `title` and `detail` both `"Not Found"`.
- **Not yet seen**: the answer for an org ID that does not exist or that the token cannot read, for a
  token without the needed permissions, and on the EU and AU tenants.

**Question 3 is answered, with a caveat for planning.** `200` is the profiles-mode signal and `404`
with `Endpoint Not Found` the default-mode signal. Misreading a flagged org as default mode would send
it down the v1 path, which FR-002 forbids, so the plan should accept only those two answers and stop on
anything else.

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
- **A connection made before the flag is a named connection** (owner, second round): it keeps the
  name Snyk gives it, every operation works on it, and a run without a name for its ECR reaches it
  instead of creating a duplicate.
- **A name reused for another ECR is refused** (owner, second round): when `apply` names a connection
  with a different AWS account or region than it stores, nothing changes unless the engineer asks to
  repoint it.

## What planning must find out

1. ~~Whether Snyk's public API exposes which connection imported a project.~~ Answered on 2026-11-24:
   it does, through the project's target, whose `relationships.integration` names the profile (see
   "Provenance through the public REST API").
2. **The REST Integrations API's exact shape**: path prefix, API version and stability, request and
   response attributes for ECR (`profile_name`, region, role ARN), and required token permissions.
   The public API reference has no page for it (`docs.snyk.io/snyk-api/reference/integrations`
   returned 404 on 2026-11-24). Likely sources: the beta documentation given to enrolled customers,
   or Snyk's internal OpenAPI spec.
3. ~~How the tool tells an org's mode (FR-002).~~ Answered on 2026-11-24: the hidden list answers
   `200` when the flag is on and `404` `Endpoint Not Found` when it is off, whatever connections the
   org holds (see "Mode signal"). Still to see: the answers for an unknown org, a token without
   access, and the EU and AU tenants.
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
10. **How Snyk names and exposes an ECR connection made before the flag was enabled.** The hidden list
    shows older integrations of other types as `Default profile`; not yet seen for ECR. Also: whether
    the hidden API reads, pauses, and deletes it like any profile, and how the tool finds a connection
    by its ECR when the name differs (FR-005).

Status after Phase 0 (below): 2 is settled except the update call's body (live check L1); 6, 7, and 9
are decided (R7, R8, R2); 10 is decided pending live check L2.

## Phase 0: decisions (`/speckit-plan`, 2026-11-24)

Each decision resolves an open question or a design choice the plan depends on. Sources beyond this
file's earlier sections: Registry ADR 0096 ("Activities" item 5; "Operability", rollout steps 1.2 and
1.3 and the rollback plan), and Snyk-internal enablement and Slack material searched on 2026-11-24.

### R1. Mode detection (FR-002, question 3)

- **Decision**: every run starts with call 13 (`GET /hidden/orgs/{org}/integrations`). `200` means
  profiles mode; `404` whose error detail is exactly `Endpoint Not Found` means default mode; any
  other answer stops the run with exit 1 before any change. Default mode adds this one read and no
  output, so baseline output stays as it is (FR-001).
- **Rationale**: the two answers were seen live on one org of each kind, whatever connections the org
  held ("Mode signal"). Refusing everything else keeps a flagged org from ever taking the v1 path.
- **Alternatives**: asking the engineer for the mode (FR-002 says the org decides); inferring it from
  the v1 listing (it looks the same in both modes).
- **Residual risk**: if Snyk publishes the API and retires this path, a flagged org would answer
  `Endpoint Not Found` and look like default mode. The version is pinned and the e2e checks the
  signal; a published API is a deliberate change to this tool, not a silent one.

### R2. Snyk's unpublished integrations API (question 9, Principle IV)

- **Decision**: manage connections in profiles mode through the `hidden` tier at version
  `2024-10-15`, the only API that lists, creates, updates, and deletes profiles. Record this as the
  one Principle IV exception in the plan's Complexity Tracking, with the conditions of Principle IV's
  own clause for undocumented behavior: the calls are isolated in one section of `SnykClient`, the
  docs mark them as undocumented, each is verified live before release, and the version is pinned.
- **Rationale**: Snyk's material calls it the "V3 Integrations API" and says the beta is configured
  only through it; no publication date was found. Without it there is no profiles mode.
- **Alternatives**: waiting for publication (no date); Snyk's UI (out of scope, owner; not
  automatable). **Owner action**: ask the beta team whether and when the API will be published.
- **Approved** by the owner on 2026-11-24, with the conditions above.

### R3. Finding a connection (FR-004, FR-005, FR-006)

- **Decision**: list the org's ECR connections (call 13, `integration_type: "ecr"`), and read each
  one's region and role ARN (call 14); the account is the role ARN's account. With `--connection`,
  match the name exactly. Without it, match the ECR (account and region): none means create one
  named after the registry URI, one means use it whatever its name, several means change nothing and
  list them. A named connection whose stored account or region differs from the run's is refused
  unless `--update-credentials` is given.
- **Rationale**: it implements the second clarification round directly, and a re-run without a name
  always lands on the same connection (SC-007).
- **Alternatives**: matching by name only (a connection made before the flag would then be
  duplicated); comparing the full role ARN (a changed role name is a credentials update, not another
  ECR).

### R4. Repointing a connection (`--update-credentials`, question 2)

- **Decision**: `PATCH /hidden/orgs/{org}/integrations/{id}` (call 16), which ADR 0096 lists. Its
  body is not yet known; live check L1 settles it before the task that implements the call.
- **Alternatives**: delete and re-create the connection (it would delete the connection's projects,
  FR-014).

### R5. Provenance (FR-009 to FR-011, FR-013)

- **Decision**: a project's connection is the `relationships.integration` of its target (call 18,
  `GET /rest/orgs/{org}/targets`), and the project's target is its `relationships.target` (call 11).
  `status` groups projects by connection. A project whose target names no connection is reported as
  "connection unknown", and `teardown --delete-projects` refuses while any project of the org is in
  that state.
- **Rationale**: verified through the public REST API on 2026-11-24 ("Provenance through the public
  REST API"); no repository-name inference anywhere (SC-003).
- **Not yet seen**: two connections holding the same repository. Live check L4 asserts one target per
  connection.

### R6. A connection made before the flag (question 10)

- **Decision**: it is listed like any profile and used under the name the hidden list gives it. ADR
  0096 stores profile names as nullable and adds a unique index on org and type where the name is
  null, so v1 can create at most one unnamed ECR connection per org; the hidden list shows unnamed
  integrations of other types as `Default profile`. Live check L2 confirms the name and that reads,
  policy changes, and delete work on it.
- **Alternatives**: refusing such orgs, or managing that connection through v1 (it would break the
  API split by mode).

### R7. The flag turned off for an org with several connections (question 6)

- **Decision**: the tool follows the mode Snyk reports on every run. Once the flag is off, it is in
  default mode and sees only the one connection the v1 listing names; the others stay in Snyk,
  untouched by the tool. The docs tell engineers to disconnect extra connections while the org is
  still in profiles mode.
- **Rationale**: ADR 0096 gates the new code paths behind the flag; with it off, Snyk's legacy paths
  read one integration by type. Its rollback plan, for withdrawing the whole feature, removes extra
  integrations with their projects, which is Snyk's operation rather than the tool's.
- **Not testable here**: the owner cannot turn the flag off; recorded as a limitation.

### R8. Account access without regions (FR-016, FR-017, question 7)

- **Decision**: the example root gains an optional input, `snyk_profile_orgs`: org IDs that read the
  account's ECRs in any region. The role trusts the distinct union of `values(snyk_orgs)` and
  `snyk_profile_orgs`, and a new output lists that set. `snyk_orgs` keeps its validations and becomes
  optional, so an account read only by profiles-mode orgs needs no region keys. "At least one org
  overall" replaces "at least one map entry", checked without raising the example's Terraform minimum
  (a variable validation that reads another variable needs Terraform 1.9); the mechanism is settled
  in implementation with `terraform test`. The module is unchanged: `snyk_org_ids` is already
  independent of regions.
- **Rationale**: an org already in either input needs no AWS change to connect another ECR (FR-016,
  SC-005), and default-mode inputs behave as before (FR-017). Chosen by the owner on 2026-11-24.
- **Alternatives**: no change, listing a profiles-mode org under any one of its regions (misleading
  keys); replacing the map with a plain list (breaks the region-to-org pairs default mode passes to
  the script).

### R9. Command-line surface

- **Decision**: one new option, `--connection NAME`, for every mode, and one teardown flag,
  `--delete-connection`, which deletes the connection and with it its projects. In default mode both
  are refused before any change (FR-003). In profiles mode `--delete-credentials` is refused with a
  pointer to `--delete-connection` or a pause, `--delete-projects` selects by provenance with
  `--repo-prefix` optional, and `teardown` without `--connection` lists the connections and exits 1.
  Every line about a repository, an image, or a project starts with `[<connection>]` (FR-009).
- **Rationale**: a separate flag keeps the deletion of projects explicit (FR-014), and exit 1 lets CI
  catch a teardown that named nothing.

### R10. Where the profile-mode live test runs

- **Decision**: a new e2e step, `profiles`, against the org in `E2E_PROFILE_ORG_ID`, which the
  harness never creates or deletes. Preflight refuses unless that org is in profiles mode and holds
  no ECR connection. The step connects the fixture's two registries (the same image in two regions),
  names its connections, and deletes only the ones it created. Today only `antonio-org` has the flag,
  and it holds 60 other projects; a throwaway org with the flag is safer. **Owner action**: ask the
  beta team for one. The owner chose `antonio-org` for now, under these guards (2026-11-24).

### R11. Token permissions for the hidden calls

- **Decision**: record what the e2e uses (the owner's token, org admin) and mark service-account
  tokens as not verified (live check L5, optional).

### Live checks before or during implementation

| ID | What | How | Settles |
|----|------|-----|---------|
| L1 | The body of `PATCH /hidden/orgs/{org}/integrations/{id}` that changes region and role ARN | A probe against a connection the e2e created | R4, call 16 |
| L2 | How an ECR connection made through v1 on a flagged org appears in the hidden list, and whether reads, policy changes, and delete work on it | An e2e sub-step: the harness creates one through v1, the tool manages it | R6 |
| L3 | The hidden list's answer for an org ID that does not exist and for a token without access | Two read-only probes | R1's refusal messages |
| L4 | Two connections holding the same repository give one target each | The `profiles` e2e step | R5, SC-003 |
| L5 | The hidden calls with an org service account's token | Optional re-run of the `profiles` step | R11 |
