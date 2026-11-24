# Contract: `scripts/onboard_ecr.py` command line

The script's interface, as delivered at `f035a43`. Anything listed here is relied on by operators,
by CI that drives the tool, or by the e2e harness; changing it is a behavior change (Constitution
Principle VIII).

## Synopsis

```text
uv run scripts/onboard_ecr.py {plan|apply|status|teardown} --org-id <uuid> [options]
```

| Environment | Required | Meaning |
|-------------|----------|---------|
| `SNYK_TOKEN` | Yes | Snyk service-account access token or personal access token. Never accepted as an argument. |
| `SNYK_API_BASE` | No | Tenant API host, for example `https://api.eu.snyk.io`. Default `https://api.snyk.io`. Same as `--api-base`. |

## Modes

| Mode | Needs | Reads | Writes | Notes |
|------|-------|-------|--------|-------|
| `plan` | `--org-id`, `--region`, `--role-arn`, a sync selection | Integration; with one, a connection test and a sync preview (dry runs, which import nothing) | Nothing | Stops after the integration lookup when none exists |
| `apply` | Same as `plan` | Same as `plan` | Integration (create, or update with `--update-credentials`); sync policy | Refuses with exit 2 above `--max-images` |
| `status` | `--org-id` | Integration, policy, ECR projects; with `--all-origins`, every project | Nothing | |
| `teardown` | `--org-id`; `--repo-prefix` with `--delete-projects` | Integration, policy, ECR projects | With `--yes`: policy, then prefixed projects, then credentials | A dry run without `--yes` |

Options that belong to another mode are accepted and ignored; for example, sync options do nothing in
`teardown`.

## Options

| Option | Modes | Default | Meaning |
|--------|-------|---------|---------|
| `--org-id UUID` | all | required | The Snyk org |
| `--region REGION` | plan, apply | — | The registry's AWS region |
| `--role-arn ARN` | plan, apply | — | The role Snyk assumes, from `terraform output -raw role_arn` |
| `--import-policy TYPE` | plan, apply | — | `ImportAll`, `ImportAllNew`, `Regex`, `Recent`, or `LastNObserved` |
| `--repo PATTERN` | plan, apply | — | `Regex`: RE2 pattern on repository names |
| `--tag PATTERN` | plan, apply | — | `Regex`: RE2 pattern on tags |
| `--max-age-days N` | plan, apply | — | `Recent`: Snyk field `maxAgeDays` |
| `--limit-newest-images N` | plan, apply | — | `LastNObserved`: Snyk field `limitNewestImages` |
| `--policy-file FILE` | plan, apply | — | Snyk's policy JSON, sent unchanged; for `And`, `Or`, and `RuntimeIntegrations` |
| `--schedule-frequency-hours H` | plan, apply | Snyk's 24 | Snyk field; at least 2 |
| `--delete-images` | plan, apply | off | Snyk field `delete_images`: remove projects whose images stop matching |
| `--policy-name NAME` | plan, apply | `ecr-onboarding` | Snyk field `name`, a label |
| `--no-sync` | plan, apply | off | Connect and test only; no policy |
| `--update-credentials` | apply (plan reports it) | off | Point an existing integration at this role and region; counts as new credentials for retries |
| `--max-images N` | apply | 1000 | Refuse a preview above N images |
| `--force` | apply | off | Apply above `--max-images` |
| `--delete-projects` | teardown | off | Also delete ECR projects under `--repo-prefix` |
| `--repo-prefix PREFIX` | teardown | — | Literal repository-name prefix, for example `team-a/` |
| `--delete-credentials` | teardown | off | Also delete the role and region stored in the integration |
| `--yes` | teardown | off | Execute; without it, teardown is a dry run |
| `--all-origins` | status | off | List every project in the org with its origin |
| `--connect-retries N` | plan, apply | 10 | Attempts at the create and the first dry run after new credentials |
| `--connect-delay S` | plan, apply | 15 | Seconds between those attempts |
| `--dry-run-timeout S` | plan, apply | 300 | Give up on a dry run job after S seconds |
| `--poll-seconds S` | plan, apply | 3 | Seconds between dry run polls |
| `--api-base URL` | all | `SNYK_API_BASE` or `https://api.snyk.io` | Must be `https://` on `snyk.io` or `*.snyk.io` |
| `--api-version DATE` | all | `2025-09-17` | REST API version ([research O1](../research.md#open-items)) |

## Sync selection rules

Checked in `plan` and `apply` before any network call:

1. `--no-sync` excludes every other sync option: `--import-policy`, `--policy-file`, `--repo`, `--tag`,
   `--max-age-days`, `--limit-newest-images`, `--schedule-frequency-hours`, `--delete-images`, and a
   non-default `--policy-name`.
2. Otherwise exactly one of `--import-policy` and `--policy-file` is required. Neither gives an error
   that lists Snyk's policy types.
3. `--policy-file` may be combined only with `--policy-name`, which names the policy when the file does
   not. The file must be a `.json` file inside the working directory, at most 64 KiB, holding an
   object with `import_policy.type`.
4. `--import-policy` accepts only that type's fields: `Regex` needs `--repo` or `--tag` or both,
   `Recent` needs `--max-age-days` of at least 1, and `LastNObserved` needs `--limit-newest-images` of
   at least 1. `--schedule-frequency-hours`, `--delete-images`, and `--policy-name` go with any type.
5. On the resulting policy: `schedule_frequency_hours` must be an integer of at least 2, and no
   `repo` or `tag` pattern anywhere in the tree may contain `(?=`, `(?!`, `(?<=`, or `(?<!`.
   Warnings, without refusing: a type outside Snyk's documented list, and `Recent` or
   `LastNObserved` without `delete_images`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, including a dry run, a plan, and a teardown with nothing to remove |
| 1 | Any error: invalid input, missing token, Snyk API error, failed dry run, unreachable host, unexpected response |
| 2 | `apply` refused because the preview exceeds `--max-images` |

Errors are printed to stderr as `error: <message>`. Error messages never contain the token.

## Output contract

The e2e harness (`examples/sandbox/e2e.sh`) matches these lines, so they are an interface even
though they look like plain output. Change one only together with the harness.

| Line (as printed; `…` marks variable parts) | Printed by | Matched in `e2e.sh` by |
|---------------------------------------------|------------|------------------------|
| `ECR integration missing: apply would create it (…, …)` | `plan` without an integration | `connect` ("apply would create it"), `disconnected` ("ECR integration missing") |
| `ECR integration created: …` | `apply` creating the integration | `connect`, `add_region` |
| `Snyk can read the registry: N repositories with tagged images (M tags) visible; nothing imported.` | the connection test | `connect`, `still_connected`; `disconnected` requires its absence |
| `  <repository> (K tags)` | the connection test, one per repository (up to 10) | `connect`, `still_connected` |
| `  + <repository>: <tag>, …` | the sync preview, one per repository (up to 10) | `connect` |
| `Sync policy applied for integration …; Snyk runs it now and then every … hours.` | `apply` | `connect` |
| `ECR integration: <id or none>` | `status`, `teardown` | `preflight` |
| `Sync policy    : <name> (…)` or `Sync policy    : none` | `status` | `verify_import`, `status`, `postcheck` |
| `  - <project name>` | `status`, one per ECR project (up to 20) | `has_project`, `preflight`, `postcheck` |
| `… after N attempts …` and `org <id> is missing from the role's sts:ExternalId list` | a failed connection test after its retries (stderr) | `add_region` |
| `… may still be propagating …` | each propagation retry (stderr) | `add_region` |

The e2e steps call these functions: `connect` and `verify_import` from `new`, `add-region`, and
`multi`; `still_connected` from `add-region`, `status`, and `retire-region`; `disconnected` from
`retire-region` and `down`; `has_project` from `status`.

Other stable lines, not matched by the harness: `Dry run: Snyk processed N images; I to import, D to
delete`, `Refusing to apply: N images would be imported, above --max-images M. …` (stderr), and
teardown's `Dry run only; re-run with --yes to execute.`
