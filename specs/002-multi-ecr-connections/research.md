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

## Snyk's closed-beta documentation and internal sources (2026-11-24)

Found after the plan, through Snyk's internal search and Slack, including an engineer's post on
joining the beta. They change where the tool sends its profiles calls and what it can read back.

- **Snyk's API tiers.** Snyk's API guidelines (ADR 0084) separate `rest` (public), `hidden` (Snyk's own
  UI, CLI, and IDE plugins; undocumented), `closed-beta` (invited customers; documentation shared
  privately), and `internal`. The calls observed from the UI went to `hidden`; customers are given
  `closed-beta`. Closed-beta APIs carry "very low rate limits", quoted as 1 request a second, 10 a
  minute, and 100 an hour, with no stated basis for counting, and may be withdrawn or promoted.
- **The Integrations API's beta documentation** (Snyk's preview documentation site, shared with beta
  customers; read 2026-11-24) gives:
  - the address `https://api.snyk.io/closed-beta`, version `2024-10-15`, `Authorization: token`, and
    media type `application/vnd.api+json`;
  - list, create, get, update (`PATCH`), and delete on `/orgs/{org_id}/integrations[/{id}]`;
  - an integration object of `id`, `type`, `attributes` (`integration_type`, `profile_name`,
    `created_at`, `updated_at`, `has_broker`), and `relationships.org`. **No call returns a
    connection's region or role ARN**;
  - `PATCH` as a partial update: `data.id`, `data.type: "integration"`, and `profile_name`,
    `credentials` (`region`, `role_arn`), or both; `409` when the name is taken;
  - a list of every integration type, with no filter, paged by `starting_after` and `ending_before`,
    with `limit` from 10 to 100 in steps of 10 (default 10);
  - `profile_name`: 1 to 255 characters, starting with a letter or digit, of letters, digits, spaces,
    `_`, `-`, and `.`;
  - `role_arn` matching `arn:aws:iam::<12 digits>:role/…`, which leaves out AWS's China and GovCloud
    partitions;
  - "Only integrations created via the V3 API (with profile_name) can be deleted." An integration made
    through v1 appears as `Default profile` (the reference says `null`), keeps its v1 ID, and can be
    renamed and repointed with `PATCH`;
  - v1 stays the API for monitoring settings, credential deletion, cloning, and imports, and should not
    be used to create or list integrations on a flagged org;
  - `406` when the feature is off for the org or the address is wrong, and `409` for a duplicate name;
  - a delete is permanent, and the connection's projects "become orphaned";
  - brokered connections are not supported.
- **The feature's one-pager** (Snyk-internal): v3 for create, update, get, list, and delete; v1 for
  imports, settings, and cloning; registry sync through the API. "Brokered connections and access on
  existing (non-Test) Organizations are not supported": the beta belongs in a test org "to prevent
  credential or settings corruption that could impact existing Projects."
- **Registry ADR 0096**, read again: `profile_name` is nullable, and a unique index lets v1 create at
  most one unnamed integration per org and type, which Snyk lists as `Default profile`.
- **Joining the beta.** The flag, `enableMultipleAccountsPerIntegrationType`, is set per org, not per
  group. Customers ask their account team or TSM, giving the org IDs; Snyk staff ask in the container
  team's request channel.

What this changes:

- **Address**: the tool uses `closed-beta`, the tier documented for customers, rather than `hidden`,
  which Snyk keeps for its own apps (R2).
- **Mode signal**: the documentation says `406`; the live probe found `404` `Endpoint Not Found`, as on
  `hidden` (next section, R1).
- **Region and role**: the documented API returns neither, so the credentials read seen from the UI (a
  `hidden` call) is dropped, and the tool reads a connection's ECR from its name (third clarification
  round, R3).
- **Update**: the `PATCH` body is documented; live check L1 only confirms it (R4).
- **A connection made before the flag** cannot be deleted through the API (R6).
- **Projects on delete**: the documentation and the live check disagree (R14).
- **Rate limits and paging** (R12), and **AWS partitions** (R13).

## Live probe of the closed-beta tier (2026-11-24)

A read-only probe, run by the owner with his token at version `2024-10-15` (live checks L3, L6, L7):

| Org | Answer |
|-----|--------|
| Flagged (`antonio-org`) | `200`; version served `2024-10-15`; six integrations, none of them ECR |
| Not flagged (another of the owner's orgs) | `404` with detail `Endpoint Not Found` |
| An org ID that does not exist | `404` with detail `Endpoint Not Found` |

- **The documented `406` did not appear.** Snyk's gateway answers an org without the feature exactly as
  it answers an org that does not exist, on `closed-beta` as on `hidden`.
- **Entries** carry `id`, `type`, and `attributes` (`created_at`, `has_broker`, `integration_type`,
  `profile_name`, `updated_at`); no `relationships`, which the documentation lists. `links` was `{}`
  for a single page, so the form of a next-page link is still unseen: it needs an org with more
  integrations than one page holds.
- **Rate limits** are stated on every answer:
  `X-RateLimit-Limit: 1, 1;w=1;…per_second|principal_id, 10;w=60;…per_minute|principal_id,
  100;w=3600;…per_hour|principal_id`, with `X-RateLimit-Remaining` and `X-RateLimit-Reset` (seconds).
  The limits are counted per principal, the identity behind the token, across every closed-beta API
  (`api-gateway.api-closed-beta`), not per org or per call. Each answer showed `Remaining: 0` and
  `Reset: 1`: the one-a-second allowance was used.

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
  instead of creating a duplicate. Refined in the third round: its name, `Default profile`, carries no
  ECR, so a run without a name asks for one instead of reaching it, and Snyk does not let the API
  delete it.
- **A name reused for another ECR is refused** (owner, second round): when `apply` names a connection
  with a different AWS account or region than it stores, nothing changes unless the engineer asks to
  repoint it. Refined in the third round: this holds where the name carries the registry address; for
  any other name the tool uses the connection with a warning.
- **Names carry their ECR** (owner, third round, after the beta documentation showed that no call
  returns a connection's region or role): by default a connection the tool creates is named
  `[<label> ]<registry address>`, so its name says which ECR it reads; an exact name is possible on
  request. For a connection whose name carries no address, the tool says it cannot check its ECR and
  points to where Snyk's UI shows the region and role (Organization settings → Integrations → Amazon
  ECR → Profile Management). The owner judged the gap cosmetic: a customer who names profiles `dev`,
  `test`, and `prod` knows the rest of their context.

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

Status after the beta documentation (2026-11-24): 2 is answered by it, apart from token permissions
(R11), and L1 only confirms the update call; 9 is answered for now: the API is a documented closed
beta, which Snyk may promote (R2); 10 is answered by it (R6), and L2 leaves the e2e.

## Phase 0: decisions (`/speckit-plan`, 2026-11-24)

Each decision resolves an open question or a design choice the plan depends on. Sources beyond this
file's earlier sections: Registry ADR 0096 ("Activities" item 5; "Operability", rollout steps 1.2 and
1.3 and the rollback plan), and Snyk-internal enablement and Slack material searched on 2026-11-24.

### R1. Mode detection (FR-002, question 3)

- **Decision**: every run starts with call 13 (`GET /closed-beta/orgs/{org}/integrations`, version
  `2024-10-15`). `200` means profiles mode; `404` whose error detail is exactly `Endpoint Not Found`
  means default mode; any other answer stops the run with exit 1 before any change. Default mode adds
  this one read and no output, so baseline output stays as it is (FR-001).
- **Rationale**: seen live on both tiers ("Mode signal"; "Live probe of the closed-beta tier"), on orgs
  of each kind whatever connections they held. Snyk's documentation gives `406` instead; the API does
  not. Refusing everything else keeps a flagged org from ever taking the v1 path.
- **An org that does not exist** gets the same `404`, so the tool takes it for default mode; the run
  then fails on its first v1 read, before any change, as in the baseline. A token without access to
  the org is expected to behave the same way (L3, not yet tried).
- **Alternatives**: staying on `hidden` (same signal, but undocumented and kept for Snyk's own apps,
  R2); asking the engineer for the mode (FR-002 says the org decides); inferring it from the v1
  listing (it looks the same in both modes).
- **Residual risk**: a mistyped path or a retired version would most likely get the same
  `Endpoint Not Found`, so a flagged org would look like default mode. The path and version are one
  pinned constant that a unit test asserts, and the `profiles` e2e step requires `200` on its flagged
  org, so such a change fails the live test before release. If Snyk promotes the API, moving to it is
  a deliberate change through Spec Kit.
- **Owner action**: tell the beta team that their documentation says `406` where the API answers
  `404`.

### R2. Snyk's closed-beta Integrations API (question 9, Principle IV)

- **Decision**: manage connections in profiles mode through the `closed-beta` tier at version
  `2024-10-15`, the API Snyk documents for beta customers to list, create, update, and delete
  profiles. Record it as the one Principle IV exception in the plan's Complexity Tracking: its
  documentation is private to beta customers and carries no stability promise, and the tier may be
  withdrawn or promoted. Conditions, from Principle IV's own clause for undocumented behavior: the
  calls are isolated in one section of `SnykClient`; the docs mark them as closed beta; each is
  verified live before release; the version is pinned; the calls are paced (R12).
- **Rationale**: Snyk's material calls it the "V3 Integrations API" and says the beta is configured
  only through it. The `hidden` tier serves the same paths to Snyk's UI, but Snyk documents nothing
  there and keeps it for its own apps; `closed-beta` is what customers are given.
- **Alternatives**: `hidden` (undocumented, for Snyk's own apps); waiting for publication (no date);
  Snyk's UI (out of scope, owner; not automatable). **Owner action**: ask the beta team whether and
  when the API will be promoted to `rest`.
- **Approved** by the owner on 2026-11-24 for the `hidden` tier, with the conditions above. The move to
  `closed-beta` follows Snyk's beta documentation and narrows the exception, since its request shapes
  are documented.

### R3. Finding a connection (FR-004, FR-005, FR-006)

- **Decision**: list the org's ECR connections (call 13, every page, `integration_type: "ecr"`) and
  read each one's ECR from its name. A name carries an ECR when it is `<registry address>` or
  `<label> <registry address>`, where the address is `<12 digits>.dkr.ecr.<region>.amazonaws.com` and
  the label starts with a letter or digit and holds only letters, digits, `_`, `-`, and `.`. Any other
  name (`Default profile`, a name given in Snyk's UI, an exact name) carries no ECR. Then:
  - `--connection VALUE`: the connection whose full name is VALUE; failing that, those whose label is
    VALUE (several: change nothing, list them). Found, carrying an ECR other than the run's: refused
    unless `--update-credentials`. Found, carrying none: used, with a warning that its ECR cannot be
    checked. Not found: created as `VALUE <run's address>`; as VALUE itself when VALUE already carries
    the run's address; exactly as VALUE with `--exact-name`. A VALUE carrying another address than the
    run's is refused.
  - No name: the connections whose names carry the run's ECR. One: use it. Several: change nothing,
    list them. None: create `<run's address>`, unless a connection carrying no ECR exists; then change
    nothing and ask for a name, since that connection might read the same ECR.
- **Rationale**: it implements the third clarification round. A re-run without a name lands on the same
  connection (SC-007), and the list is the only read needed, which matters under the closed-beta rate
  limits (R12).
- **Alternatives**: reading region and role through `hidden`'s credentials call, as Snyk's UI does
  (undocumented, and Snyk's documented API leaves them out); matching by name only (a re-run without a
  name could not find its connection); comparing the full role ARN (not readable).

### R4. Repointing a connection (`--update-credentials`, question 2)

- **Decision**: `PATCH /closed-beta/orgs/{org}/integrations/{id}` (call 15) with `data.id`,
  `data.type: "integration"`, and `attributes.credentials` (`region`, `role_arn`), as Snyk's beta
  documentation gives it. When the connection's name carries its ECR, the same call renames it to carry
  the new address, keeping its label, so the name stays true; a `409` (name taken) refuses the change.
  Live check L1 confirms the call on a connection the e2e created.
- **Alternatives**: deleting and re-creating the connection (it would delete the connection's projects,
  FR-014); repointing without renaming (the name would then name the wrong ECR).

### R5. Provenance (FR-009 to FR-011, FR-013)

- **Decision**: a project's connection is the `relationships.integration` of its target (call 17,
  `GET /rest/orgs/{org}/targets`), and the project's target is its `relationships.target` (call 11).
  `status` groups projects by connection. A project whose target names no connection is reported as
  "connection unknown", and `teardown --delete-projects` refuses while any project of the org is in
  that state.
- **Rationale**: verified through the public REST API on 2026-11-24 ("Provenance through the public
  REST API"); no repository-name inference anywhere (SC-003).
- **Not yet seen**: two connections holding the same repository. Live check L4 asserts one target per
  connection.

### R6. A connection made before the flag (question 10)

- **Decision**: it is one of the org's connections, listed under the name Snyk gives it,
  `Default profile` (or no name, which the tool treats the same way). Its name carries no ECR, so the
  tool uses it only when named (`--connection "Default profile"`), with R3's warning, and while it
  exists a run without a name asks for one instead of creating a connection (R3). Snyk does not let
  the API delete it, so `--delete-connection` on it is refused before any change, pointing to Snyk's
  UI; the refusal also suggests renaming it there to its registry address, after which the tool
  recognizes it. Policy changes, pauses, and provenance use its ID and are expected to work as on any
  connection (not seen live).
- **Rationale**: Snyk's beta documentation ("Only integrations created via the V3 API (with
  profile_name) can be deleted"; v1 integrations appear as `Default profile` and can be renamed and
  repointed), and ADR 0096's nullable name with its index allowing one unnamed integration per org and
  type.
- **Live check L2 leaves the e2e**: making such a connection needs a v1 create on a flagged org, which
  Snyk's documentation advises against, and the result could not be removed through the API. Unit
  tests cover the tool's handling; an owner may run L2 once, by hand, on a throwaway org.
- **Alternatives**: refusing such orgs; managing that connection through v1 (it would break the API
  split by mode); renaming it through the tool (not asked for).

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

- **Decision**: two new options for every mode, `--connection VALUE` (a label or a full name, R3) and
  `--exact-name` (create VALUE as the whole name, with no address added), and one teardown flag,
  `--delete-connection`, which deletes the connection and with it its projects. In default mode all
  three are refused before any change (FR-003). In profiles mode `--delete-credentials` is refused
  with a pointer to `--delete-connection` or a pause, `--delete-projects` selects by provenance with
  `--repo-prefix` optional, and `teardown` without `--connection` lists the connections and exits 1.
  Every line about a repository, an image, or a project starts with `[<connection's full name>]`
  (FR-009). `status` gives each connection's account and region from its name, or, where its name
  carries none, where Snyk's UI shows them (FR-010).
- **Rationale**: a separate flag keeps the deletion of projects explicit (FR-014), and exit 1 lets CI
  catch a teardown that named nothing.

### R10. Where the profile-mode live test runs

- **Decision**: a new e2e step, `profiles`, against the org in `E2E_PROFILE_ORG_ID`, which the
  harness never creates or deletes. Preflight refuses unless that org is in profiles mode and holds
  no ECR connection. The step connects the fixture's two registries (the same image in two regions),
  names its connections, and deletes only the ones it created. Today only `antonio-org` has the flag,
  and it holds 60 other projects; a throwaway org with the flag is safer. **Owner action**: ask the
  beta team for one. The owner chose `antonio-org` for now, under these guards (2026-11-24), and kept
  it after reading the feature's one-pager, which says the beta is not supported on existing (non-test)
  orgs "to prevent credential or settings corruption that could impact existing Projects": a risk the
  owner accepted on 2026-11-24.

### R11. Token permissions for the closed-beta calls

- **Decision**: record what the e2e uses (the owner's token, org admin) and mark service-account
  tokens as not verified (live check L5, optional). Snyk's beta documentation states no permissions.

### R12. Rate limits and paging on the closed-beta tier

- **Decision**: a run makes as few closed-beta calls as it can: the list once (every page, `limit=100`),
  kept for the run, and at most one write (create, update, or delete). The transport paces closed-beta
  calls by Snyk's own headers: at least one second apart, and when an answer says
  `X-RateLimit-Remaining: 0`, the next closed-beta call waits `X-RateLimit-Reset` seconds. A wait over
  60 seconds (the hourly allowance is spent) stops the run before its next call, saying when the
  allowance resets; nothing is left half done, since the list comes before the one write. `429` is
  handled as for any call (`Retry-After`, at most 60 seconds, within its retries), then the run stops
  naming the limit. Pages follow `links.next` on the Snyk API host only, as the baseline's pagination
  does; the baseline adds `/rest` to a relative link, so the closed-beta list accepts a link relative
  to `/closed-beta`, one that already starts with it, or a full address on the API host, and unit tests
  cover each.
- **Rationale**: the limits are 1 a second, 10 a minute, and 100 an hour, counted per principal across
  every closed-beta API (live probe, L7). The tool, the e2e harness, and any probe run with the same
  token share them. A typical run makes two or three closed-beta calls; the `profiles` e2e step runs
  the tool about ten times in a few minutes, so it meets the per-minute limit and waits, and it counts
  its closed-beta calls to stay under 100 an hour.

### R13. AWS partitions

- **Decision**: in profiles mode a role ARN outside AWS's standard partition (`arn:aws-cn:`,
  `arn:aws-us-gov:`) or a region of those partitions (`cn-…`, `us-gov-…`) is refused before any
  change, naming the limitation. Default mode is unchanged.
- **Rationale**: Snyk's `role_arn` pattern accepts only `arn:aws:iam::`, so such a create would fail
  at Snyk after the run had begun. The default name's address therefore always ends in
  `.amazonaws.com`.

### R14. What a delete does to the connection's projects

- **Decision**: FR-014 stands: the tool follows what the product did when tested, which was to delete
  the projects at once ("Sync and delete against a profile"), as Snyk's UI also says. The `profiles`
  e2e step checks it again after its delete (live check L8). If the projects stay, orphaned, as Snyk's
  beta documentation says, the dry run's wording and FR-014 change through Spec Kit, by owner
  decision.
- **Owner action**: ask the beta team which behavior is intended.

### Live checks before or during implementation

| ID | What | How | Settles |
|----|------|-----|---------|
| L1 | The documented `PATCH` changes a connection's region and role ARN, and renames it, on a connection the e2e created | The `profiles` e2e step | R4, call 15 |
| L2 | How an ECR connection made through v1 on a flagged org appears, and what works on it. Left out of the e2e: it needs a v1 create on a flagged org and cannot be removed through the API | Optional, by hand, once, on a throwaway org | R6 |
| L3 | The closed-beta list's answer for an org ID that does not exist (**done**, 2026-11-24: `404` `Endpoint Not Found`) and for a token without access (not tried) | Read-only probes | R1 |
| L4 | Two connections holding the same repository give one target each | The `profiles` e2e step | R5, SC-003 |
| L5 | The closed-beta calls with an org service account's token, including the mode check on a default-mode org: a `401` or `403` there would stop default-mode runs made with such a token | Optional re-runs of the `single` and `profiles` steps | R1, R11 |
| L6 | The closed-beta list with a token at version `2024-10-15` (**done**, 2026-11-24: `200` on a flagged org, `404` `Endpoint Not Found` on an unflagged one); the form of `links.next` is still unseen | The owner's read-only probe | R1, R2, R12 |
| L7 | Rate-limit headers on closed-beta answers (**done**, 2026-11-24: per principal, across closed-beta APIs) | The same probe | R12 |
| L8 | The projects of a deleted connection: gone, or left orphaned | The `profiles` e2e step | R14 |
