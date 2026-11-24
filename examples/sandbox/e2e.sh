#!/usr/bin/env bash
# From-scratch end-to-end test of the ECR -> Snyk onboarding, through the lifecycle the README describes.
#
# Bare-minimum prerequisites: an AWS account and a Snyk account, with credentials for both.
#   AWS : AWS_PROFILE (or any AWS credentials) for a SANDBOX account; AWS_REGION (region A, default
#         ap-southeast-2) and E2E_REGION_B (region B, default us-east-1) must differ
#   Snyk: SNYK_TOKEN allowed to create and delete orgs in SNYK_GROUP_ID (list: uv run harness.py groups);
#         SNYK_AWS_PRINCIPAL, the Principal from the trust policy your tenant shows under
#         Integrations > Amazon ECR; SNYK_API_BASE for non-US tenants
#   Tools: terraform, aws, jq, uv; docker (running) is optional: without it, infra-up copies the test image with
#          push_image.py over the registry API
#   Profiles mode (./e2e.sh profiles): E2E_PROFILE_ORG_ID, an existing org with Snyk's multiple profiles feature
#         on and no ECR connection. It is never created or deleted; only the connections the step makes go.
#
# Two layers, each removing exactly what it created:
#   test infrastructure (this harness): throwaway Snyk orgs (ecr-e2e-*) and an ECR repo with a test image in
#                                       each of the two regions
#   product under test (module + script): the IAM role, the ECR integrations (connectivity), the sync policies
#                                         and the projects the syncs import
#
# Scenarios (the README's lifecycle), one Snyk org per registry:
#   new            new account, one region: terraform apply with -var switches, then the script   (org a, region A)
#   add-region     another region in the same account: the hint for an org the role does not trust
#                  yet (org n), then org b listed with org a in snyk-orgs.auto.tfvars              (org b, region B)
#   status         what Terraform manages, what the role trusts, and each org's state in Snyk
#   retire-region  teardown of one region (org b) while region A keeps working
#   down           teardown of the whole account: every org, then terraform destroy
#   multi          new account, several regions in one go: the file lists both from the start       (orgs c, d)
#
#   ./e2e.sh full     infra-up, preflight, new, add-region, status, [pause], retire-region, down, multi, status,
#                     down, postcheck, infra-down, final
#   ./e2e.sh single   infra-up, preflight, new, status, [pause], down, postcheck, infra-down, final (org a only)
#   ./e2e.sh profiles infra-up, profiles-preflight, profiles-new, profiles-scenario, profiles-down, infra-down,
#                     profiles-final: several connections in one org (feature 002; quickstart.md section 3)
#   ./e2e.sh <step>   one step: infra-up | preflight | new | add-region | status | retire-region | down | multi |
#                     postcheck | infra-down | final | profiles-preflight | profiles-new | profiles-scenario |
#                     profiles-down | profiles-final
#
# Options: E2E_SLOTS which orgs infra-up creates (default "a b n c d"; single uses "a");
#   E2E_ORG_ID=<uuid> use an existing org as org a instead of creating one (single only; it is never deleted
#   and must have no ECR integration); E2E_PAUSE=0 skip the pause; E2E_ASSUME_YES=1 skip confirmations;
#   VERIFY_TIMEOUT seconds to wait for each sync (default 600); FINAL_TIMEOUT seconds to wait for the org
#   deletions to show (default 180); E2E_POLL_SECONDS seconds between status checks while waiting (default 60).
# Snyk's closed-beta APIs allow 1 call a second, 10 a minute, and 100 an hour per token, and every run of the tool
# makes at least one (its mode check). The steps keep count in .e2e/closed_beta.log, warn above 80 in the last
# hour, and stop above 100; the profiles steps space their runs at least 6 seconds apart.
set -euo pipefail
cd "$(dirname "$0")"

: "${SNYK_TOKEN:?export SNYK_TOKEN first}"
REGION_A="${AWS_REGION:-ap-southeast-2}"
REGION_B="${E2E_REGION_B:-us-east-1}"
STATE=.e2e
ROLE_NAME="snyk-ecr-e2e"
REPO_NAME="snyk-e2e/app"
REPO_PREFIX="snyk-e2e/"
ORGS_FILE="snyk-orgs.auto.tfvars" # what a user keeps in their repository once there is more than one region
ALL_SLOTS="a b n c d"
# The sync policy under test, in Snyk's terms: a Regex policy on repository and tag.
SYNC_POLICY=(--import-policy Regex --repo '^snyk-e2e/' --tag '^v[0-9]+\.[0-9]+\.[0-9]+$')
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-600}"
FINAL_TIMEOUT="${FINAL_TIMEOUT:-180}"
ONBOARD=(uv run ../../scripts/onboard_ecr.py)
HARNESS=(uv run harness.py)
PUSH_IMAGE=(uv run push_image.py)
POLL_SECONDS="${E2E_POLL_SECONDS:-60}"
CB_LOG="${STATE}/closed_beta.log"
PROFILE_ORG="${E2E_PROFILE_ORG_ID:-}"
LABEL_B="e2e-b" # the label of the profiles step's second connection
FIXTURE_VARS=(-var "region_a=${REGION_A}" -var "region_b=${REGION_B}" -var "repository_name=${REPO_NAME}")
PLACEHOLDER_ORG="00000000-0000-0000-0000-000000000000" # destroy only needs well-formed inputs
# What `terraform plan` may contain: a new role, or an in-place update of its trust policy and nothing else.
PLAN_CREATE="module.snyk_ecr.aws_iam_role.snyk_ecr_read:create module.snyk_ecr.aws_iam_role_policy.ecr_read:create"
PLAN_UPDATE="module.snyk_ecr.aws_iam_role.snyk_ecr_read:update"
TF_VARS=()

# Each org ("slot") is the Snyk org for one registry in one scenario.
slot_region() { case "$1" in a | c) echo "${REGION_A}" ;; *) echo "${REGION_B}" ;; esac }
org_of() {
  if [[ "$1" == "a" && -n "${E2E_ORG_ID:-}" ]]; then echo "${E2E_ORG_ID}"
  elif [[ -s "${STATE}/org_$1" ]]; then cat "${STATE}/org_$1"; fi
}
recorded_slots() {
  local slot
  for slot in ${ALL_SLOTS}; do if [[ -n "$(org_of "${slot}")" ]]; then echo "${slot}"; fi; done
}

# What still exists, read from the Terraform state files and the recorded orgs (no API calls).
leftovers() {
  local slot
  if grep -qs '"mode": "managed"' terraform.tfstate; then echo "the IAM role ${ROLE_NAME} (./e2e.sh down)"; fi
  if [[ -f "${ORGS_FILE}" ]]; then echo "${ORGS_FILE} (./e2e.sh down removes it)"; fi
  for slot in ${ALL_SLOTS}; do
    if [[ -s "${STATE}/org_${slot}" ]]; then
      echo "the throwaway Snyk org ${slot}: $(cat "${STATE}/org_${slot}") (./e2e.sh down, then ./e2e.sh infra-down)"
    fi
    if [[ -s "${STATE}/org_${slot}.deleted" ]]; then
      echo "confirmation that the throwaway org $(cat "${STATE}/org_${slot}.deleted") is gone (./e2e.sh final re-checks)"
    fi
  done
  if [[ -f "${STATE}/profiles_started" ]]; then
    echo "connections the profiles step made in org ${PROFILE_ORG:-<E2E_PROFILE_ORG_ID>} (./e2e.sh profiles-down)"
  fi
  if grep -qs '"mode": "managed"' fixture/terraform.tfstate; then
    echo "the test ECR repositories ${REPO_NAME} in ${REGION_A} and ${REGION_B} (./e2e.sh infra-down)"
  fi
  return 0
}
trap 'rc=$?; if [[ ${rc} -ne 0 && "${STARTED:-0}" == "1" ]]; then
  echo >&2
  left="$(leftovers)"
  if [[ -n "${left}" ]]; then
    echo "e2e stopped (exit ${rc}). Still outstanding:" >&2
    sed "s/^/  - /" <<<"${left}" >&2
  else
    echo "e2e stopped (exit ${rc}); nothing left to clean up." >&2
  fi
fi' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
step() { STARTED=1; cb_check; echo; echo "=== $* ==="; }
# Snyk's closed-beta allowance: one line per tool run, "<epoch seconds> <calls>"; a run without a count line
# (default mode) made one call, its mode check.
cb_add() { mkdir -p "${STATE}"; echo "$(date +%s) ${1:-1}" >>"${CB_LOG}"; }
cb_hour() { awk -v since=$(($(date +%s) - 3600)) '$1 >= since { n += $2 } END { print n + 0 }' "${CB_LOG}" 2>/dev/null || echo 0; }
cb_check() {
  local n
  n="$(cb_hour)"
  if ((n > 100)); then fail "${n} closed-beta calls in the last hour, above Snyk's 100: wait before the next step"; fi
  if ((n > 80)); then echo "warning: ${n} closed-beta calls in the last hour; Snyk allows 100" >&2; fi
}
cb_report() { echo "closed-beta calls by this e2e in the last hour: $(cb_hour) (Snyk allows 100)"; }
confirm() {
  if [[ "${E2E_ASSUME_YES:-0}" == "1" ]]; then return 0; fi
  read -r -p "$1 [y/N] " ok
  [[ "${ok}" == "y" ]] || { echo "Aborted."; exit 1; }
}
pause() {
  if [[ "${E2E_PAUSE:-1}" == "1" ]]; then
    read -r -p "$1 Press Enter to continue (Ctrl-C to stop here)... " _
  fi
}
# Fail fast, before changing anything, if the AWS session has expired (for example an SSO login during a pause).
aws_ok() {
  aws sts get-caller-identity --query Account --output text >/dev/null 2>&1 ||
    fail "AWS credentials not working: run aws sso login${AWS_PROFILE:+ --profile ${AWS_PROFILE}}, then re-run this step"
}
need_org() { [[ -n "$(org_of "$1")" ]] || fail "no org $1 recorded: run ./e2e.sh infra-up (E2E_SLOTS must include $1)"; }

# -- Terraform: the role, driven the way a user drives examples/main.tf -------------------------------------
role_arn() { terraform output -raw role_arn 2>/dev/null || echo "arn:aws:iam::000000000000:role/not-created"; }
# "region=org-id" pairs -> an HCL map literal, as a user would type it in a -var switch.
orgs_map() {
  local pair out=""
  for pair in "$@"; do out+="${out:+,}\"${pair%%=*}\"=\"${pair#*=}\""; done
  echo "{${out}}"
}
# "region=org-id" pairs -> snyk-orgs.auto.tfvars, in the shape of examples/snyk-orgs.auto.tfvars.example.
write_orgs_file() {
  local pair
  {
    echo "# Written by e2e.sh: the region => Snyk org ID list, kept in a file once there is more than one region."
    echo "snyk_orgs = {"
    for pair in "$@"; do printf '  "%s" = "%s"\n' "${pair%%=*}" "${pair#*=}"; done
    echo "}"
  } >"${ORGS_FILE}"
  terraform fmt "${ORGS_FILE}" >/dev/null # aligned as in a reviewed repository (and for make check)
  echo "${ORGS_FILE}:"
  sed 's/^/  /' "${ORGS_FILE}"
}
# TF_VARS for the role root. With a map argument, snyk_orgs comes from that -var switch; without one, from
# ORGS_FILE (a -var switch would override the file, so it is not passed at all).
tf_vars() {
  TF_VARS=(-var "role_name=${ROLE_NAME}" -var "region=${REGION_A}"
    -var "snyk_aws_principal=${SNYK_AWS_PRINCIPAL:-arn:aws:iam::000000000000:root}")
  if [[ -n "${1:-}" ]]; then TF_VARS+=(-var "snyk_orgs=$1"); fi
}
# terraform plan, check it contains exactly the expected managed-resource changes, then apply that plan.
plan_and_apply() {
  local expected=$1 got
  terraform init -input=false >/dev/null
  terraform plan -input=false -out="${STATE}/tfplan" "${TF_VARS[@]}" | tee "${STATE}/tfplan.log"
  got="$(terraform show -json "${STATE}/tfplan" | jq -r '[.resource_changes[]?
    | select(.mode == "managed" and .change.actions != ["no-op"])
    | "\(.address):\(.change.actions | join("+"))"] | sort | join(" ")')"
  [[ "${got}" == "${expected}" ]] || fail "terraform plan should contain exactly '${expected}', but has '${got:-no changes}'"
  pass "terraform plan: ${expected}"
  terraform apply -input=false "${STATE}/tfplan"
}
# The org IDs the role trusts (its sts:ExternalId list), as IAM reports them; read-only, as in docs/USAGE.md.
trusted_orgs() {
  aws iam get-role --role-name "${ROLE_NAME}" --query 'Role.AssumeRolePolicyDocument' --output json |
    jq -r '[.Statement[].Condition.StringEquals["sts:ExternalId"]] | flatten | map(ascii_downcase) | sort | join(" ")'
}
expect_trust() {
  local want got="" deadline=$((SECONDS + 60))
  want="$(printf '%s\n' "$@" | tr '[:upper:]' '[:lower:]' | LC_ALL=C sort | paste -sd' ' -)"
  while true; do
    got="$(trusted_orgs)"
    if [[ "${got}" == "${want}" ]]; then break; fi
    ((SECONDS < deadline)) || fail "the role should trust exactly '${want}', but IAM reports '${got}'"
    sleep 5
  done
  pass "the role's sts:ExternalId list is exactly: ${want}"
}
role_present() { aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; }

# -- Snyk: the script, one registry -> one org per run ------------------------------------------------------
onboard() { # mode slot [flags...]
  local mode=$1 slot=$2
  shift 2
  cb_add 1
  "${ONBOARD[@]}" "${mode}" --org-id "$(org_of "${slot}")" --region "$(slot_region "${slot}")" --role-arn "$(role_arn)" "$@"
}
snyk_status() { local slot=$1; shift; cb_add 1; "${ONBOARD[@]}" status --org-id "$(org_of "${slot}")" "$@"; }
teardown() { local slot=$1; shift; cb_add 1; "${ONBOARD[@]}" teardown --org-id "$(org_of "${slot}")" "$@"; }
org_exists_rc() { local rc=0; "${HARNESS[@]}" org-exists --org-id "$1" || rc=$?; echo "${rc}"; }
org_listed_rc() {
  if [[ -z "${SNYK_GROUP_ID:-}" ]]; then echo 2; return 0; fi
  local rc=0
  "${HARNESS[@]}" org-listed --group-id "${SNYK_GROUP_ID}" --org-id "$1" || rc=$?
  echo "${rc}"
}
repo_present() { aws ecr describe-repositories --region "$1" --repository-names "${REPO_NAME}" >/dev/null 2>&1; }
image_present() { aws ecr describe-images --region "$1" --repository-name "${REPO_NAME}" --image-ids imageTag=v1.0.0 >/dev/null 2>&1; }
# Project lines from `status` look like "  - <repository>:<tag>", possibly with the registry host in front.
has_project() { grep -Eq "^  - ([^ ]*/)?${1}\$" <<<"$2"; }
# The read proof lists at most 10 repositories. When it is cut short ("  ... and N more repositories"), the test
# repository may be among the rest; the sync preview's "+ snyk-e2e/app: v1.0.0" then shows Snyk reads it.
lists_repo() { grep -Eq "^  ([^ ]*/)?${REPO_NAME} \(" <<<"$1" || grep -Eq '^  \.\.\. and [0-9]+ more repositories$' <<<"$1"; }

# A first connection for one org: plan reports the integration as missing, apply creates it, the connection
# test lists the test repository, the preview selects exactly v1.0.0, and the policy is applied.
connect() {
  local slot=$1 region log
  region="$(slot_region "${slot}")"
  log="${STATE}/apply_${slot}.log"
  step "org ${slot} (${region}): onboard_ecr.py plan, then apply"
  onboard plan "${slot}" "${SYNC_POLICY[@]}" | tee "${STATE}/plan_${slot}.log"
  grep -q "apply would create it" "${STATE}/plan_${slot}.log" || fail "plan did not report the missing integration"
  onboard apply "${slot}" "${SYNC_POLICY[@]}" 2>&1 | tee "${log}"
  grep -q "^ECR integration created:" "${log}" || fail "the integration was not created"
  grep -q "^Snyk can read the registry:" "${log}" || fail "the connection test did not pass"
  lists_repo "$(cat "${log}")" || fail "the connection test did not list ${REPO_NAME}"
  grep -Eq "^  \+ ([^ ]*/)?${REPO_NAME}: v1\.0\.0\$" "${log}" || fail "the sync preview should select exactly v1.0.0"
  grep -q "^Sync policy applied" "${log}" || fail "the sync policy was not applied"
  pass "org ${slot} is connected to ${region}, and its sync is configured"
}
verify_import() {
  local slot=$1 deadline=$((SECONDS + VERIFY_TIMEOUT)) status=""
  step "org ${slot}: the sync imports ${REPO_NAME}:v1.0.0 from $(slot_region "${slot}") and not :latest"
  while ((SECONDS < deadline)); do
    status="$(snyk_status "${slot}")"
    if has_project "${REPO_NAME}:v1\.0\.0" "${status}"; then
      echo "${status}"
      if has_project "${REPO_NAME}:latest" "${status}"; then fail "latest was imported, but the tag regex excludes it"; fi
      grep -q '^Sync policy    : ecr-onboarding' <<<"${status}" || fail "the sync policy is not active"
      pass "org ${slot}: the sync imported v1.0.0 only"
      return 0
    fi
    echo "  not imported yet; checking again in ${POLL_SECONDS}s"
    sleep "${POLL_SECONDS}"
  done
  echo "${status}"
  echo "diagnostic: every project in the org with its origin"
  snyk_status "${slot}" --all-origins || true
  fail "org ${slot}: no ${REPO_NAME}:v1.0.0 project with origin ecr after ${VERIFY_TIMEOUT}s"
}
# An existing integration still works: the connection test (plan, no writes) lists the test repository.
still_connected() {
  local slot=$1 log="${STATE}/connected_$1.log" attempt
  for attempt in 1 2 3; do
    if onboard plan "${slot}" --no-sync >"${log}" 2>&1 && grep -q "^Snyk can read the registry:" "${log}" &&
      lists_repo "$(cat "${log}")"; then
      pass "org ${slot} ($(slot_region "${slot}")) still connects (attempt ${attempt} of 3)"
      return 0
    fi
    sleep 20
  done
  cat "${log}"
  fail "org ${slot} can no longer read its registry"
}
# Snyk can no longer read the registry for this org (credentials removed, or never set).
disconnected() {
  local slot=$1 log="${STATE}/disconnect_$1.log"
  if onboard plan "${slot}" --no-sync >"${log}" 2>&1 && grep -q "^Snyk can read the registry:" "${log}"; then
    cat "${log}"
    fail "org ${slot}: Snyk can still read the registry"
  fi
  sed 's/^/  /' "${log}"
  if grep -q "^ECR integration missing" "${log}"; then
    pass "org ${slot}: no ECR integration, so nothing to disconnect"
  else
    pass "org ${slot}: Snyk cannot read the registry"
  fi
}

# -- steps --------------------------------------------------------------------------------------------------
infra_up() {
  local slots="${E2E_SLOTS:-${ALL_SLOTS}}" slot name id region url
  if [[ "${slots}" == "none" ]]; then slots=""; fi # the profiles step: test repositories only, no throwaway org
  step "test infrastructure: throwaway Snyk orgs (${slots:-none}) + ${REPO_NAME} with a test image in ${REGION_A} and ${REGION_B}"
  [[ "${REGION_A}" != "${REGION_B}" ]] || fail "AWS_REGION and E2E_REGION_B must be two different regions"
  if [[ -n "${E2E_ORG_ID:-}" && "${slots}" != "a" ]]; then fail "E2E_ORG_ID works with ./e2e.sh single (E2E_SLOTS=a) only"; fi
  aws_ok
  mkdir -p "${STATE}"
  for slot in ${slots}; do
    if [[ "${slot}" == "a" && -n "${E2E_ORG_ID:-}" ]]; then
      echo "org a: existing Snyk org ${E2E_ORG_ID} (E2E_ORG_ID); it will not be deleted"
    elif [[ -s "${STATE}/org_${slot}" ]]; then
      echo "org ${slot}: reusing throwaway Snyk org $(cat "${STATE}/org_${slot}")"
    else
      : "${SNYK_GROUP_ID:?export SNYK_GROUP_ID (list yours with: uv run harness.py groups)}"
      name="ecr-e2e-$(date -u +%Y%m%d-%H%M%S)-${slot}"
      id="$("${HARNESS[@]}" create-org --group-id "${SNYK_GROUP_ID}" --name "${name}")"
      echo "${id}" >"${STATE}/org_${slot}"
      rm -f "${STATE}/org_${slot}.deleted"
      echo "org ${slot}: created throwaway Snyk org ${name}: ${id}"
    fi
  done
  terraform -chdir=fixture init -input=false >/dev/null
  terraform -chdir=fixture apply -input=false -auto-approve "${FIXTURE_VARS[@]}"
  if docker info >/dev/null 2>&1; then
    docker pull --platform linux/amd64 alpine:3.18
    for region in a b; do
      url="$(terraform -chdir=fixture output -raw "repository_url_${region}")"
      aws ecr get-login-password --region "$([[ "${region}" == "a" ]] && echo "${REGION_A}" || echo "${REGION_B}")" |
        docker login --username AWS --password-stdin "${url%%/*}"
      for tag in v1.0.0 latest; do
        docker tag alpine:3.18 "${url}:${tag}"
        docker push "${url}:${tag}"
      done
    done
  else
    echo "no Docker engine running: copying the test image with push_image.py over the registry API"
    # Signed in to AWS's public mirror, the fallback when Docker Hub refuses anonymous pulls (none if not allowed).
    PUBLIC_ECR_PASSWORD="$(aws ecr-public get-login-password --region us-east-1 2>/dev/null || true)"
    export PUBLIC_ECR_PASSWORD
    for region in a b; do
      url="$(terraform -chdir=fixture output -raw "repository_url_${region}")"
      aws ecr get-login-password --region "$([[ "${region}" == "a" ]] && echo "${REGION_A}" || echo "${REGION_B}")" |
        "${PUSH_IMAGE[@]}" "${url}" v1.0.0 latest
    done
    unset PUBLIC_ECR_PASSWORD
  fi
  pass "test infrastructure ready"
}

preflight() {
  local slot status org
  step "preflight: test infrastructure present, product artefacts absent"
  aws_ok
  [[ -n "$(recorded_slots)" ]] || fail "no orgs recorded: run ./e2e.sh infra-up"
  for slot in $(recorded_slots); do
    org="$(org_of "${slot}")"
    [[ "$(org_exists_rc "${org}")" == "0" ]] || fail "Snyk org ${slot} (${org}) is not reachable with this token"
    status="$(snyk_status "${slot}")"
    echo "org ${slot}:"
    sed 's/^/  /' <<<"${status}"
    grep -q '^ECR integration: none' <<<"${status}" || fail "org ${slot} already has an ECR integration; use a fresh org"
    if grep -Eq "^  - ([^ ]*/)?${REPO_PREFIX}" <<<"${status}"; then fail "org ${slot} already has ${REPO_PREFIX} projects"; fi
  done
  image_present "${REGION_A}" || fail "test image ${REPO_NAME}:v1.0.0 missing in ${REGION_A} (run ./e2e.sh infra-up)"
  image_present "${REGION_B}" || fail "test image ${REPO_NAME}:v1.0.0 missing in ${REGION_B} (run ./e2e.sh infra-up)"
  if role_present; then fail "IAM role ${ROLE_NAME} already exists (run ./e2e.sh down)"; fi
  if [[ -f "${ORGS_FILE}" ]]; then fail "${ORGS_FILE} exists from an earlier run (run ./e2e.sh down)"; fi
  pass "clean starting state"
}

# Scenario: new account, one region. No file: two -var switches, exactly as the README quick start.
new() {
  : "${SNYK_AWS_PRINCIPAL:?export SNYK_AWS_PRINCIPAL, the Principal shown by the Snyk UI under Integrations > Amazon ECR}"
  need_org a
  step "new account, one region: terraform apply -var 'snyk_orgs={\"${REGION_A}\"=\"<org a>\"}' -var snyk_aws_principal=..."
  aws_ok
  mkdir -p "${STATE}"
  if role_present; then fail "IAM role ${ROLE_NAME} already exists (run ./e2e.sh down)"; fi
  [[ ! -f "${ORGS_FILE}" ]] || fail "${ORGS_FILE} exists, but this scenario uses switches only (run ./e2e.sh down)"
  tf_vars "$(orgs_map "${REGION_A}=$(org_of a)")"
  plan_and_apply "${PLAN_CREATE}"
  expect_trust "$(org_of a)"
  connect a # a brand-new role, so IAM-propagation retries are expected here
  verify_import a
}

# Scenario: another region in the same account.
add_region() {
  local log="${STATE}/missing_trust.log" retries
  need_org a
  need_org b
  need_org n
  aws_ok
  role_present || fail "IAM role ${ROLE_NAME} missing: run ./e2e.sh new first"

  step "another region, first the mistake: connect org n before the role trusts it"
  if [[ "$(cat "${STATE}/hint_checked" 2>/dev/null)" == "$(org_of n)" ]]; then
    echo "already checked for org n in an earlier run of this step (its integration now exists): skipping"
  else
    if onboard apply n --no-sync --connect-retries 3 --connect-delay 10 >"${log}" 2>&1; then
      cat "${log}"
      fail "the connection test passed for an org the role does not trust"
    fi
    cat "${log}"
    grep -q "^ECR integration created:" "${log}" || fail "the integration for org n was not created"
    grep -qF "after 3 attempts" "${log}" || fail "the failure should come after the 3 attempts"
    grep -qF "org $(org_of n) is missing from the role's sts:ExternalId list" "${log}" ||
      fail "the failure should name org n as missing from the role's sts:ExternalId list"
    retries="$(grep -c "may still be propagating" "${log}" || true)"
    [[ "${retries}" == "2" ]] || fail "expected 2 retry notices before the hint, got ${retries}"
    teardown n --delete-credentials --yes # Snyk keeps no credentials for an org the role does not trust
    org_of n >"${STATE}/hint_checked"     # a re-run of this step resumes after this check
    pass "the connection test fails only after the retries, and the hint names the missing org ID"
  fi

  step "another region: list org b with org a in ${ORGS_FILE} (no -var for snyk_orgs from now on)"
  write_orgs_file "${REGION_A}=$(org_of a)" "${REGION_B}=$(org_of b)"
  tf_vars
  plan_and_apply "${PLAN_UPDATE}"
  expect_trust "$(org_of a)" "$(org_of b)"
  connect b
  verify_import b
  still_connected a
}

# Scenario: check status. Read-only; asserts only when given the slots that must be connected.
status() {
  local slot status
  step "status: what Terraform manages, what the role trusts, and each org's state in Snyk"
  aws_ok
  echo "terraform output snyk_orgs:"
  terraform output snyk_orgs 2>/dev/null | sed 's/^/  /' || echo "  (no role in this state)"
  if role_present; then echo "the role trusts (aws iam get-role): $(trusted_orgs)"; else echo "role ${ROLE_NAME}: absent"; fi
  for slot in $(recorded_slots); do
    status="$(snyk_status "${slot}")"
    echo "org ${slot} ($(slot_region "${slot}")):"
    sed 's/^/  /' <<<"${status}"
  done
  for slot in "$@"; do
    status="$(snyk_status "${slot}")"
    grep -q '^Sync policy    : ecr-onboarding' <<<"${status}" || fail "org ${slot}: the sync policy is not active"
    has_project "${REPO_NAME}:v1\.0\.0" "${status}" || fail "org ${slot}: ${REPO_NAME}:v1.0.0 is not a project"
    still_connected "${slot}"
  done
  if (($# > 0)); then pass "status: orgs $* are connected and syncing"; fi
}

# Scenario: teardown of one region while the others keep working.
retire_region() {
  need_org a
  need_org b
  aws_ok
  [[ -f "${ORGS_FILE}" ]] || fail "${ORGS_FILE} missing: run ./e2e.sh add-region first"
  step "retire one region: teardown org b (dry run, then --yes)"
  teardown b --delete-projects --delete-credentials --repo-prefix "${REPO_PREFIX}"
  confirm "Run the teardown above for org b?"
  teardown b --delete-projects --delete-credentials --repo-prefix "${REPO_PREFIX}" --yes

  step "retire one region: remove region B from ${ORGS_FILE}, then plan (trust policy update only) and apply"
  write_orgs_file "${REGION_A}=$(org_of a)"
  tf_vars
  plan_and_apply "${PLAN_UPDATE}"
  expect_trust "$(org_of a)"
  disconnected b
  still_connected a
}

# Scenario: teardown of the whole account. Safe to re-run; also the clean-up after a failed run.
down() {
  local slot
  step "teardown, whole account: every org (dry run first), then terraform destroy"
  aws_ok
  mkdir -p "${STATE}"
  for slot in $(recorded_slots); do
    echo "org ${slot}:"
    teardown "${slot}" --delete-projects --delete-credentials --repo-prefix "${REPO_PREFIX}" | sed 's/^/  /'
  done
  if [[ -n "$(recorded_slots)" ]]; then
    confirm "Run the teardowns above, then destroy the IAM role?"
    for slot in $(recorded_slots); do
      teardown "${slot}" --delete-projects --delete-credentials --repo-prefix "${REPO_PREFIX}" --yes
    done
    step "disconnect check: the role still exists, so failing connection tests prove the credentials are gone"
    for slot in $(recorded_slots); do disconnected "${slot}"; done
  else
    echo "no orgs recorded (infra-down already removed them): nothing to tear down on the Snyk side"
  fi

  # State-driven: destroys only what this Terraform root created (no-op if it holds nothing).
  if [[ -f "${ORGS_FILE}" ]]; then tf_vars; else tf_vars "$(orgs_map "${REGION_A}=${PLACEHOLDER_ORG}")"; fi
  terraform init -input=false >/dev/null
  terraform destroy -input=false -auto-approve "${TF_VARS[@]}"
  rm -f "${ORGS_FILE}" "${STATE}/tfplan"
  if role_present; then fail "IAM role ${ROLE_NAME} still exists after terraform destroy"; fi
  pass "the role is gone"
}

# Scenario: new account, several regions in one go. The file lists every org from the start.
multi() {
  : "${SNYK_AWS_PRINCIPAL:?export SNYK_AWS_PRINCIPAL, the Principal shown by the Snyk UI under Integrations > Amazon ECR}"
  need_org c
  need_org d
  aws_ok
  mkdir -p "${STATE}"
  step "new account, several regions in one go: ${ORGS_FILE} lists orgs c and d, one terraform apply"
  if role_present; then fail "IAM role ${ROLE_NAME} already exists (run ./e2e.sh down)"; fi
  write_orgs_file "${REGION_A}=$(org_of c)" "${REGION_B}=$(org_of d)"
  tf_vars
  plan_and_apply "${PLAN_CREATE}"
  expect_trust "$(org_of c)" "$(org_of d)"
  connect c
  connect d
  verify_import c
  verify_import d
}

postcheck() {
  local slot status org
  step "postcheck: product artefacts gone, test infrastructure untouched"
  aws_ok
  if role_present; then fail "IAM role ${ROLE_NAME} still exists"; fi
  [[ ! -f "${ORGS_FILE}" ]] || fail "${ORGS_FILE} still exists"
  for slot in $(recorded_slots); do
    org="$(org_of "${slot}")"
    status="$(snyk_status "${slot}")"
    echo "org ${slot}:"
    sed 's/^/  /' <<<"${status}"
    grep -q '^Sync policy    : none' <<<"${status}" || fail "org ${slot}: the sync policy is still present"
    if grep -Eq "^  - ([^ ]*/)?${REPO_PREFIX}" <<<"${status}"; then fail "org ${slot}: ${REPO_PREFIX} projects are still present"; fi
    [[ "$(org_exists_rc "${org}")" == "0" ]] || fail "org ${slot} is gone: the product teardown must not touch orgs"
  done
  image_present "${REGION_A}" || fail "the test image in ${REGION_A} is gone: the product teardown must not touch the registry"
  image_present "${REGION_B}" || fail "the test image in ${REGION_B} is gone: the product teardown must not touch the registry"
  pass "the product removed exactly what it created"
}

infra_down() {
  local slot id
  step "test infrastructure teardown"
  aws_ok
  terraform -chdir=fixture init -input=false >/dev/null
  terraform -chdir=fixture destroy -input=false -auto-approve "${FIXTURE_VARS[@]}"
  if [[ -n "${E2E_ORG_ID:-}" ]]; then echo "keeping Snyk org ${E2E_ORG_ID} (supplied via E2E_ORG_ID)"; fi
  for slot in ${ALL_SLOTS}; do
    if [[ "${slot}" == "a" && -n "${E2E_ORG_ID:-}" ]]; then continue; fi
    id=""
    if [[ -s "${STATE}/org_${slot}" ]]; then id="$(cat "${STATE}/org_${slot}")"
    elif [[ -s "${STATE}/org_${slot}.deleted" ]]; then id="$(cat "${STATE}/org_${slot}.deleted")"; fi
    if [[ -n "${id}" ]]; then
      echo "org ${slot}: $("${HARNESS[@]}" delete-org --org-id "${id}" --protect "${SNYK_ORG_ID:-}")"
      echo "${id}" >"${STATE}/org_${slot}.deleted"
      rm -f "${STATE}/org_${slot}"
      if [[ "${slot}" == "n" ]]; then rm -f "${STATE}/hint_checked"; fi
    fi
  done
}

final() {
  local slot id by_id listed deadline=$((SECONDS + FINAL_TIMEOUT))
  step "final: back to the bare minimum (AWS account + Snyk account)"
  aws_ok
  if role_present; then fail "IAM role ${ROLE_NAME} still exists"; fi
  if repo_present "${REGION_A}"; then fail "ECR repository ${REPO_NAME} still exists in ${REGION_A}"; fi
  if repo_present "${REGION_B}"; then fail "ECR repository ${REPO_NAME} still exists in ${REGION_B}"; fi
  for slot in ${ALL_SLOTS}; do
    [[ -s "${STATE}/org_${slot}.deleted" ]] || continue
    id="$(cat "${STATE}/org_${slot}.deleted")"
    while true; do
      by_id="$(org_exists_rc "${id}")"  # 0 found by ID, 1 not found, 2 error
      listed="$(org_listed_rc "${id}")" # 0 listed in the group, 1 not listed, 2 error or no SNYK_GROUP_ID
      if [[ "${by_id}" == "1" ]]; then
        echo "throwaway org ${slot} (${id}): not found by ID"
        break
      fi
      if [[ "${listed}" == "1" ]]; then
        echo "throwaway org ${slot} (${id}): no longer listed in group ${SNYK_GROUP_ID} (a lookup by ID still answers)"
        break
      fi
      if ((SECONDS >= deadline)); then
        fail "throwaway org ${id} still visible after ${FINAL_TIMEOUT}s (by ID rc=${by_id}, in group rc=${listed}); run ./e2e.sh infra-down again, or delete it in the Snyk UI"
      fi
      echo "  org deletion not visible yet (by ID rc=${by_id}, in group rc=${listed}); checking again in 15s"
      sleep 15
    done
    rm -f "${STATE}/org_${slot}.deleted"
  done
  pass "nothing left behind"
}

# -- profiles mode (feature 002): several connections in one org --------------------------------------------
need_profile_org() {
  local slot
  [[ "${PROFILE_ORG}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] ||
    fail "export E2E_PROFILE_ORG_ID: an org with Snyk's multiple profiles feature on and no ECR connection"
  for slot in ${ALL_SLOTS}; do
    [[ "$(org_of "${slot}")" != "${PROFILE_ORG}" ]] || fail "E2E_PROFILE_ORG_ID is the throwaway org ${slot}; use an org of your own"
  done
}
account_id() { role_arn | cut -d: -f5; }
address() { echo "$(account_id).dkr.ecr.$1.amazonaws.com"; }
P_LAST=-100
# One tool run against the profiles org, at least 6 s after the last (Snyk allows 10 closed-beta calls a minute):
# its output kept in .e2e/<log> and shown, its closed-beta calls added to the budget. Returns the tool's exit code.
pon() {
  local log="${STATE}/$1" rc=0 wait
  shift
  mkdir -p "${STATE}"
  wait=$((P_LAST + 6 - SECONDS))
  if ((wait > 0)); then sleep "${wait}"; fi
  "${ONBOARD[@]}" "$@" --org-id "${PROFILE_ORG}" >"${log}" 2>&1 </dev/null || rc=$?
  P_LAST=${SECONDS}
  cb_add "$(sed -n 's/^Closed-beta calls: \([0-9][0-9]*\)$/\1/p' "${log}" | tail -1)"
  sed 's/^/  | /' "${log}"
  return "${rc}"
}
# The lines a run printed for one connection, without their "[<name>] " prefix (names hold spaces and dots).
lines_of() { awk -v p="[$2] " 'index($0, p) == 1 { print substr($0, length(p) + 1) }' "${STATE}/$1"; }
connection_id() { lines_of "$1" "$2" | sed -n 's/^ECR connection\( created\)\{0,1\}: \([^ ]*\).*/\2/p' | head -1; }
has_conn_project() { lines_of "$1" "$2" | grep -Eq "^  - ([^ ]*/)?${REPO_NAME}:${3}\$"; }
profiles_onboard() { # log mode region [flags...]
  local log=$1 mode=$2 region=$3
  shift 3
  pon "${log}" "${mode}" --region "${region}" --role-arn "$(role_arn)" "$@"
}
# What a first apply of a connection must show: created (or reused), the read proof listing the test repository,
# a preview of exactly v1.0.0, and the policy applied.
expect_connected() { # log name created|reused
  local out
  out="$(lines_of "$1" "$2")"
  if [[ "$3" == "created" ]]; then
    grep -q '^ECR connection created:' <<<"${out}" || fail "[$2] the connection was not created"
  else
    grep -q '^ECR connection: ' <<<"${out}" || fail "[$2] the existing connection was not reused"
    ! grep -q '^ECR connection created:' <<<"${out}" || fail "[$2] a second connection was created"
  fi
  grep -q '^Snyk can read the registry:' <<<"${out}" || fail "[$2] the connection test did not pass"
  lists_repo "${out}" || fail "[$2] the connection test did not list ${REPO_NAME}"
  grep -Eq "^  \+ ([^ ]*/)?${REPO_NAME}: v1\.0\.0\$" <<<"${out}" || fail "[$2] the sync preview should select exactly v1.0.0"
  grep -qF "Sync policy applied for connection $2;" <<<"${out}" || fail "[$2] the sync policy was not applied"
}
profiles_tf_vars() { tf_vars "{}"; TF_VARS+=(-var "snyk_profile_orgs=[\"${PROFILE_ORG}\"]"); }

profiles_preflight() {
  local log="${STATE}/p_preflight.log"
  step "profiles preflight: org ${PROFILE_ORG} has the profiles feature and no ECR connection; test infrastructure present"
  need_profile_org
  aws_ok
  [[ "$(org_exists_rc "${PROFILE_ORG}")" == "0" ]] || fail "the profiles org ${PROFILE_ORG} is not reachable with this token"
  pon p_preflight.log status || fail "status failed on the profiles org"
  grep -q '^Mode: profiles' "${log}" || fail "org ${PROFILE_ORG} is not in profiles mode (the closed-beta list did not answer 200)"
  if grep -q '\] ECR connection: ' "${log}"; then fail "org ${PROFILE_ORG} already has an ECR connection; use an org with none"; fi
  if grep -Eq "^\[[^]]*\]   - ([^ ]*/)?${REPO_PREFIX}" "${log}"; then fail "org ${PROFILE_ORG} already has ${REPO_PREFIX} projects"; fi
  image_present "${REGION_A}" || fail "test image ${REPO_NAME}:v1.0.0 missing in ${REGION_A} (run ./e2e.sh infra-up)"
  image_present "${REGION_B}" || fail "test image ${REPO_NAME}:v1.0.0 missing in ${REGION_B} (run ./e2e.sh infra-up)"
  if role_present; then fail "IAM role ${ROLE_NAME} already exists (run ./e2e.sh profiles-down)"; fi
  if [[ -f "${ORGS_FILE}" ]]; then fail "${ORGS_FILE} exists from an earlier run (run ./e2e.sh down)"; fi
  pass "clean starting state for profiles mode"
}

profiles_new() {
  : "${SNYK_AWS_PRINCIPAL:?export SNYK_AWS_PRINCIPAL, the Principal shown by the Snyk UI under Integrations > Amazon ECR}"
  need_profile_org
  step "profiles: terraform apply with snyk_orgs={} and snyk_profile_orgs=[\"<org>\"]: the role trusts the org, no region"
  aws_ok
  if role_present; then fail "IAM role ${ROLE_NAME} already exists (run ./e2e.sh profiles-down)"; fi
  mkdir -p "${STATE}"
  touch "${STATE}/profiles_started"
  profiles_tf_vars
  plan_and_apply "${PLAN_CREATE}"
  expect_trust "${PROFILE_ORG}"
}

profiles_scenario() {
  local a b b_on_a id_a deadline found l8=""
  need_profile_org
  aws_ok
  a="$(address "${REGION_A}")"
  b="${LABEL_B} $(address "${REGION_B}")"
  b_on_a="${LABEL_B} ${a}"

  step "profiles: plan, then apply without a name for ${REGION_A}: a connection named after its registry, ${a}"
  profiles_onboard p_plan_a.log plan "${REGION_A}" "${SYNC_POLICY[@]}" || fail "plan failed"
  grep -qF "[${a}] ECR connection missing: apply would create it" "${STATE}/p_plan_a.log" || fail "plan did not report the missing connection"
  profiles_onboard p_apply_a.log apply "${REGION_A}" "${SYNC_POLICY[@]}" || fail "apply failed"
  expect_connected p_apply_a.log "${a}" created
  id_a="$(connection_id p_apply_a.log "${a}")"
  pass "default name: ${a} (${id_a})"

  step "profiles: apply --connection ${LABEL_B} for ${REGION_B}: a second connection, ${b}; the first untouched"
  profiles_onboard p_apply_b.log apply "${REGION_B}" --connection "${LABEL_B}" "${SYNC_POLICY[@]}" || fail "apply failed"
  expect_connected p_apply_b.log "${b}" created
  pass "two connections in one org (FR-004)"

  step "profiles: apply again without a name for ${REGION_A} reaches the same connection (SC-007)"
  profiles_onboard p_reapply_a.log apply "${REGION_A}" "${SYNC_POLICY[@]}" || fail "apply failed"
  expect_connected p_reapply_a.log "${a}" reused
  [[ "$(connection_id p_reapply_a.log "${a}")" == "${id_a}" ]] || fail "the re-run reached another connection"
  pass "same registry, same connection: ${id_a}"

  step "profiles: apply --connection ${LABEL_B} with ${REGION_A} is refused, and nothing changes (US1/AC7)"
  if profiles_onboard p_refuse_b.log apply "${REGION_A}" --connection "${LABEL_B}" "${SYNC_POLICY[@]}"; then
    fail "naming ${LABEL_B} with another region should be refused"
  fi
  grep -qF "Refused: connection '${b}' points at registry $(address "${REGION_B}"), not ${a}" "${STATE}/p_refuse_b.log" ||
    fail "the refusal did not name the registry ${b} reads"
  pass "name reuse for another registry refused"

  step "profiles: ${REPO_NAME}:v1.0.0 imported once through each connection (live check L4), not :latest"
  deadline=$((SECONDS + VERIFY_TIMEOUT))
  found=""
  while ((SECONDS < deadline)); do
    pon p_status.log status || fail "status failed"
    if has_conn_project p_status.log "${a}" 'v1\.0\.0' && has_conn_project p_status.log "${b}" 'v1\.0\.0'; then found=1; break; fi
    echo "  not imported through both connections yet; checking again in ${POLL_SECONDS}s"
    sleep "${POLL_SECONDS}"
  done
  [[ -n "${found}" ]] || fail "${REPO_NAME}:v1.0.0 is not under both connections after ${VERIFY_TIMEOUT}s"
  if has_conn_project p_status.log "${a}" latest || has_conn_project p_status.log "${b}" latest; then
    fail "latest was imported, but the tag regex excludes it"
  fi
  lines_of p_status.log "${a}" | grep -qF "ECR connection: ${id_a} (account $(account_id), region ${REGION_A})" ||
    fail "status did not give ${a}'s account and region"
  pass "L4: the same image appears twice, once under each connection, from Snyk's record"

  step "profiles: teardown without a name is refused (US3/AC1)"
  if pon p_td_none.log teardown --yes; then fail "teardown without --connection should be refused"; fi
  grep -q "^Refused: teardown needs --connection" "${STATE}/p_td_none.log" || fail "the refusal did not ask for a connection"
  pass "teardown needs a name"

  step "profiles: teardown --connection ${LABEL_B} --yes pauses it; its project stays (US3/AC2)"
  pon p_pause_b.log teardown --connection "${LABEL_B}" --yes || fail "teardown failed"
  lines_of p_pause_b.log "${b}" | grep -q '^Sync policy deleted\.' || fail "the policy of ${b} was not deleted"
  pon p_status_paused.log status || fail "status failed"
  lines_of p_status_paused.log "${b}" | grep -q '^Sync policy    : none' || fail "${b} still has a policy"
  has_conn_project p_status_paused.log "${b}" 'v1\.0\.0' || fail "pausing ${b} removed its project"
  lines_of p_status_paused.log "${a}" | grep -q '^Sync policy    : ecr-onboarding' || fail "pausing ${b} changed ${a}'s policy"
  pass "paused ${b}; ${a} untouched"

  step "profiles: teardown --connection ${a} --delete-connection: dry run, then --yes (US3/AC3, AC4; live check L8)"
  pon p_del_a_dry.log teardown --connection "${a}" --delete-connection || fail "the dry run failed"
  lines_of p_del_a_dry.log "${a}" | grep -q '^Connection: will be deleted, and with it [1-9][0-9]* project(s) imported through it' ||
    fail "the dry run did not count the connection's projects"
  [[ "$(cb_hour)" -lt 100 ]] || fail "closed-beta budget spent"
  pon p_del_a.log teardown --connection "${a}" --delete-connection --yes || fail "the disconnect failed"
  lines_of p_del_a.log "${a}" | grep -q '^Connection deleted; Snyk is deleting its projects\.' || fail "the connection was not deleted"
  for _ in 1 2 3; do
    sleep "${POLL_SECONDS}"
    pon p_status_after_del.log status || fail "status failed"
    if ! grep -qF "[${a}] ECR connection: " "${STATE}/p_status_after_del.log" &&
      ! grep -Eq "^  \? ([^ ]*/)?${REPO_NAME}:v1\.0\.0\$" "${STATE}/p_status_after_del.log"; then
      l8="deleted"
      break
    fi
  done
  if [[ -z "${l8}" ]]; then
    grep -qF "[${a}] ECR connection: " "${STATE}/p_status_after_del.log" && fail "${a} is still listed after the delete"
    l8="orphaned"
  fi
  echo "${l8}" >"${STATE}/L8"
  has_conn_project p_status_after_del.log "${b}" 'v1\.0\.0' || fail "disconnecting ${a} touched ${b}'s project"
  pass "L8: the deleted connection's project was ${l8} by Snyk; ${b} unchanged"

  step "profiles: apply --connection ${LABEL_B} --update-credentials for ${REGION_A}: repointed and renamed (live check L1)"
  profiles_onboard p_update_b.log apply "${REGION_A}" --connection "${LABEL_B}" --update-credentials "${SYNC_POLICY[@]}" ||
    fail "the repoint failed"
  lines_of p_update_b.log "${b}" | grep -q '^  credentials updated' || fail "the credentials were not updated"
  lines_of p_update_b.log "${b}" | grep -qF "  renamed to '${b_on_a}'" || fail "the connection was not renamed to ${b_on_a}"
  lines_of p_update_b.log "${b_on_a}" | grep -q '^Snyk can read the registry:' || fail "the repointed connection cannot read ${REGION_A}"
  pass "L1: Snyk's documented PATCH repointed and renamed the connection"

  step "profiles: teardown --connection ${LABEL_B} --delete-connection --yes"
  pon p_del_b.log teardown --connection "${LABEL_B}" --delete-connection --yes || fail "the disconnect failed"
  lines_of p_del_b.log "${b_on_a}" | grep -q '^Connection deleted;' || fail "${b_on_a} was not deleted"
  pass "both connections disconnected"
  cb_report
}

profiles_down() {
  local name keep
  step "profiles teardown: the connections this step made, then the role (safe to re-run)"
  need_profile_org
  aws_ok
  if [[ -f "${STATE}/profiles_started" ]] || role_present; then
    pon p_down_status.log status || fail "status failed on the profiles org"
    keep="$(address "${REGION_A}")"
    while IFS= read -r name; do
      case "${name}" in
        "${keep}" | "${LABEL_B} "*)
          pon p_down_del.log teardown --connection "${name}" --delete-connection --yes || fail "could not delete ${name}"
          ;;
        *) echo "  keeping ${name}: not made by this step" ;;
      esac
    done < <(sed -n 's/^\[\(.*\)\] ECR connection: .*/\1/p' "${STATE}/p_down_status.log")
  fi
  profiles_tf_vars
  terraform init -input=false >/dev/null
  terraform destroy -input=false -auto-approve "${TF_VARS[@]}"
  rm -f "${STATE}/tfplan" "${STATE}/profiles_started"
  if role_present; then fail "IAM role ${ROLE_NAME} still exists after terraform destroy"; fi
  pass "the profiles step's connections and the role are gone"
}

profiles_final() {
  step "profiles final: the org holds no ECR connection; the role and the repositories are gone"
  need_profile_org
  aws_ok
  if role_present; then fail "IAM role ${ROLE_NAME} still exists"; fi
  if repo_present "${REGION_A}"; then fail "ECR repository ${REPO_NAME} still exists in ${REGION_A}"; fi
  if repo_present "${REGION_B}"; then fail "ECR repository ${REPO_NAME} still exists in ${REGION_B}"; fi
  pon p_final.log status || fail "status failed on the profiles org"
  if grep -q '\] ECR connection: ' "${STATE}/p_final.log"; then fail "org ${PROFILE_ORG} still holds an ECR connection"; fi
  if grep -Eq "^  \? ([^ ]*/)?${REPO_PREFIX}" "${STATE}/p_final.log"; then
    fail "${REPO_PREFIX} projects are left without a connection in org ${PROFILE_ORG} (live check L8: Snyk orphaned them); remove them in Snyk's UI"
  fi
  cb_report
  pass "nothing left behind in the profiles org"
}

profiles() {
  need_profile_org
  export E2E_SLOTS=none E2E_ASSUME_YES=1
  infra_up
  profiles_preflight
  profiles_new
  profiles_scenario
  profiles_down
  infra_down
  profiles_final
  pass "profiles-mode end-to-end run complete: several connections in one org, each managed on its own"
}

full() {
  infra_up
  preflight
  new
  add_region
  status a b
  pause "Two regions of one account share role ${ROLE_NAME}: inspect AWS and orgs a and b now."
  export E2E_ASSUME_YES=1
  retire_region
  down
  multi
  status c d
  down
  postcheck
  infra_down
  final
  cb_report
  pass "full end-to-end run complete; only the AWS account and the Snyk account remain"
}

single() {
  export E2E_SLOTS=a
  infra_up
  preflight
  new
  status a
  pause "Inspect AWS and org a now."
  export E2E_ASSUME_YES=1
  down
  postcheck
  infra_down
  final
  cb_report
  pass "single-region end-to-end run complete; only the AWS account and the Snyk account remain"
}

case "${1:-}" in
  full) full ;;
  single) single ;;
  infra-up) infra_up ;;
  preflight) preflight ;;
  new) new ;;
  add-region) add_region ;;
  status) status "${@:2}" ;; # ./e2e.sh status a b: also assert that orgs a and b are connected and syncing
  retire-region) retire_region ;;
  down) down ;;
  multi) multi ;;
  postcheck) postcheck ;;
  infra-down) infra_down ;;
  final) final ;;
  profiles) profiles ;;
  profiles-preflight) profiles_preflight ;;
  profiles-new) profiles_new ;;
  profiles-scenario) profiles_scenario ;;
  profiles-down) profiles_down ;;
  profiles-final) profiles_final ;;
  *)
    echo "usage: $0 full|single|profiles|infra-up|preflight|new|add-region|status|retire-region|down|multi|postcheck|infra-down|final|profiles-preflight|profiles-new|profiles-scenario|profiles-down|profiles-final" >&2
    exit 1
    ;;
esac
