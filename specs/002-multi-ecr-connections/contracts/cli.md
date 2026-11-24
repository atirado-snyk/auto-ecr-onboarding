# Contract: `scripts/onboard_ecr.py` in profiles mode

What 002 adds to the baseline's [command-line contract](../../001-ecr-onboarding-baseline/contracts/cli.md).
In default mode that contract applies unchanged: the same options, output, and exit codes (FR-001).
The mode comes from Snyk on every run ([data-model.md](../data-model.md#mode-per-org-from-call-13)).

## Synopsis

```text
uv run scripts/onboard_ecr.py {plan|apply|status|teardown} --org-id <uuid> [--connection VALUE [--exact-name]] [options]
```

## New options

| Option | Modes | Default | Meaning |
|--------|-------|---------|---------|
| `--connection VALUE` | all | `plan`, `apply`: the connection whose name carries this ECR, or a new one named after its registry address. `status`: every connection. `teardown`: none, so required | The connection to act on, by its full name or its label. A new connection is named `VALUE <registry address>`. Refused on a default-mode org |
| `--exact-name` | `plan`, `apply` | off | Create the connection as `VALUE` exactly, with no address added. Its ECR then cannot be checked on later runs. Needs `--connection`; refused on a default-mode org |
| `--delete-connection` | teardown | off | Delete the named connection; Snyk then deletes every project imported through it. Refused for `Default profile`, which Snyk's API cannot delete, and on a default-mode org |

## Changed meaning in profiles mode

| Option | Profiles mode |
|--------|---------------|
| `--update-credentials` | Repoints the named connection to the run's `--region` and `--role-arn` (call 15), renaming it to the new registry address, label kept, when its name carries the old one. Required when the run names another account or region than the connection's name carries |
| `--delete-projects` | Selects the projects imported through the named connection. `--repo-prefix` is optional and only narrows the selection |
| `--delete-credentials` | Refused: use `--delete-connection`, or a teardown without options to pause |
| `--all-origins` | Unchanged; each ECR project also names its connection |

## Lookup and refusals

The rules are in [data-model.md](../data-model.md#connection-snyk-profile-call-13) and
[its refusal table](../data-model.md#validation-and-refusal-rules-before-any-write). Every refusal
happens before any write, prints the org's connections where they help, and exits 1.

| Example, region `ap-southeast-2`, account `111111111111` | Name of a new connection |
|----------------------------------------------------------|--------------------------|
| no `--connection` | `111111111111.dkr.ecr.ap-southeast-2.amazonaws.com` |
| `--connection prod` | `prod 111111111111.dkr.ecr.ap-southeast-2.amazonaws.com` |
| `--connection "Payments prod" --exact-name` | `Payments prod` |

## Teardown in profiles mode

| Options | Effect, in this order, with `--yes` |
|---------|--------------------------------------|
| none | Delete the connection's policy (a pause); projects and connection stay |
| `--delete-projects [--repo-prefix P]` | Policy, then the connection's projects (narrowed by `P`) |
| `--delete-connection` | Policy, then the connection; Snyk deletes its projects |
| both | Policy, then the selected projects, then the connection |

Without `--yes` it is a dry run that lists exactly that. For `--delete-connection` the dry run says
that the connection's projects will be deleted and how many Snyk's record shows (FR-014).

## Exit codes

Unchanged: 0 success, 1 any error or refusal, 2 `apply` refused by `--max-images`.

## Output contract in profiles mode

Every line about a repository, an image, or a project starts with `[<connection's full name>] `
(FR-009). Lines the e2e step `profiles` matches, so they are an interface:

| Line (`…` marks variable parts) | Printed by |
|---------------------------------|------------|
| `Mode: profiles (Snyk's multiple profiles feature is on for this org)` | every mode, first line |
| `[…] ECR connection missing: apply would create it (…, …)` | `plan` |
| `[…] ECR connection created: …` | `apply` |
| `[…] ECR connection: … (account …, region …)` | `plan`, `apply`, `status`, `teardown`, for a name that carries its ECR |
| `[…] ECR connection: … (account and region not in its name; Snyk's UI shows them under Organization settings → Integrations → Amazon ECR → Profile Management)` | `status`, for any other name |
| `[…] Warning: this connection's name does not carry its registry, so its ECR cannot be checked against --region and --role-arn` | `plan`, `apply`, for any other name |
| `[…] Snyk can read the registry: N repositories with tagged images (M tags) visible; nothing imported.` | the connection test |
| `[…]   + <repository>: <tag>, …` | the sync preview |
| `[…] Sync policy applied for connection …; Snyk runs it now and then every … hours.` | `apply` |
| `[…] Sync policy    : <name> (…)` or `[…] Sync policy    : none` | `status` |
| `[…]   - <project name>` | `status`, one per project of that connection |
| `Connection unknown: N project(s) whose target names no listed connection` | `status`, when it applies |
| `[…] Connection: will be deleted, and with it N project(s) imported through it` | `teardown --delete-connection` dry run |
| `[…] Connection deleted; Snyk is deleting its projects.` | `teardown --delete-connection --yes` |
| `Refused: …` and `Connections in this org:` followed by `  <name> (account …, region …)` lines, or `  <name> (registry not in its name)` | every refusal (stderr) |

In default mode no `Mode:` line is printed and no line gets a prefix, so the baseline's output
contract and the harness's matches stay as they are.
