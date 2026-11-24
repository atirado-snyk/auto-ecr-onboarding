#!/usr/bin/env bash
# From-scratch end-to-end test of the ECR -> Snyk onboarding, through the lifecycle the README describes.
#
# Bare-minimum prerequisites: an AWS account and a Snyk account, with credentials for both.
#   AWS : AWS_PROFILE (or any AWS credentials) for a SANDBOX account; AWS_REGION (region A, default
#         ap-southeast-2) and E2E_REGION_B (region B, default us-east-1) must differ
#   Snyk: SNYK_TOKEN allowed to create and delete orgs in SNYK_GROUP_ID (list: uv run harness.py groups);
#         SNYK_AWS_PRINCIPAL, the Principal from the trust policy your tenant shows under
#         Integrations > Amazon ECR; SNYK_API_BASE for non-US tenants
#   Tools: terraform, aws, docker (running), jq, uv
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
#   ./e2e.sh <step>   one step: infra-up | preflight | new | add-region | status | retire-region | down | multi |
#                     postcheck | infra-down | final
#
# Options: E2E_SLOTS which orgs infra-up creates (default "a b n c d"; single uses "a");
#   E2E_ORG_ID=<uuid> use an existing org as org a instead of creating one (single only; it is never deleted
#   and must have no ECR integration); E2E_PAUSE=0 skip the pause; E2E_ASSUME_YES=1 skip confirmations;
#   VERIFY_TIMEOUT seconds to wait for each sync (default 600); FINAL_TIMEOUT seconds to wait for the org
#   deletions to show (default 180).
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
step() { STARTED=1; echo; echo "=== $* ==="; }
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
  "${ONBOARD[@]}" "${mode}" --org-id "$(org_of "${slot}")" --region "$(slot_region "${slot}")" --role-arn "$(role_arn)" "$@"
}
snyk_status() { local slot=$1; shift; "${ONBOARD[@]}" status --org-id "$(org_of "${slot}")" "$@"; }
teardown() { local slot=$1; shift; "${ONBOARD[@]}" teardown --org-id "$(org_of "${slot}")" "$@"; }
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
  grep -Eq "^  ([^ ]*/)?${REPO_NAME} \(" "${log}" || fail "the connection test did not list ${REPO_NAME}"
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
    echo "  not imported yet; checking again in 20s"
    sleep 20
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
      grep -Eq "^  ([^ ]*/)?${REPO_NAME} \(" "${log}"; then
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
  step "test infrastructure: throwaway Snyk orgs (${slots}) + ${REPO_NAME} with a test image in ${REGION_A} and ${REGION_B}"
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
  *)
    echo "usage: $0 full|single|infra-up|preflight|new|add-region|status|retire-region|down|multi|postcheck|infra-down|final" >&2
    exit 1
    ;;
esac
