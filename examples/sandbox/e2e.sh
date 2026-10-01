#!/usr/bin/env bash
# From-scratch end-to-end test of the ECR -> Snyk onboarding.
#
# Bare-minimum prerequisites: an AWS account and a Snyk account, with credentials for both.
#   AWS : AWS_PROFILE (or any AWS credentials) for a SANDBOX account; AWS_REGION (default ap-southeast-2)
#   Snyk: SNYK_TOKEN allowed to create and delete orgs in SNYK_GROUP_ID (list: uv run harness.py groups);
#         SNYK_AWS_PRINCIPAL, the Principal from the trust policy your tenant shows under
#         Integrations > Amazon ECR; SNYK_API_BASE for non-US tenants
#   Tools: terraform, aws, docker (running), uv
#
# Two layers, each removing exactly what it created:
#   test infrastructure (this harness): a throwaway Snyk org (ecr-e2e-*) and an ECR repo with a test image
#   product under test (module + script): the IAM role, the ECR integration (connectivity), the sync policy
#                                         and the projects the sync imports
#
#   ./e2e.sh full     infra-up, preflight, up, verify, [pause], down, postcheck, infra-down, final
#   ./e2e.sh <step>   one step: infra-up | preflight | up | verify | down | postcheck | infra-down | final | status
#
# Options: E2E_ORG_ID=<uuid> use an existing org instead of creating one (it is never deleted and must have no
#   ECR integration); E2E_PAUSE=0 skip the pause before teardown in `full`; E2E_ASSUME_YES=1 skip confirmations;
#   VERIFY_TIMEOUT seconds to wait for the sync (default 600); FINAL_TIMEOUT seconds to wait for the org
#   deletion to show (default 180).
set -euo pipefail
cd "$(dirname "$0")"

: "${SNYK_TOKEN:?export SNYK_TOKEN first}"
REGION="${AWS_REGION:-ap-southeast-2}"
STATE=.e2e
ROLE_NAME="snyk-ecr-e2e"
REPO_NAME="snyk-e2e/app"
REPO_PREFIX="snyk-e2e/"
# The sync policy under test, in Snyk's terms: a Regex policy on repository and tag.
SYNC_POLICY=(--import-policy Regex --repo '^snyk-e2e/' --tag '^v[0-9]+\.[0-9]+\.[0-9]+$')
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-600}"
FINAL_TIMEOUT="${FINAL_TIMEOUT:-180}"
ONBOARD=(uv run ../../scripts/onboard_ecr.py)
HARNESS=(uv run harness.py)
FIXTURE_VARS=(-var "region=${REGION}" -var "repository_name=${REPO_NAME}")
PLACEHOLDER_ORG="00000000-0000-0000-0000-000000000000" # destroy only needs well-formed inputs
ORG_ID=""

# What still exists, read from the Terraform state files and the recorded org (no API calls).
leftovers() {
  if grep -qs '"mode": "managed"' terraform.tfstate; then echo "the IAM role ${ROLE_NAME} (./e2e.sh down)"; fi
  if [[ -s "${STATE}/org_id" ]]; then
    echo "the throwaway Snyk org $(cat "${STATE}/org_id") (./e2e.sh down, then ./e2e.sh infra-down)"
  fi
  if grep -qs '"mode": "managed"' fixture/terraform.tfstate; then echo "the test ECR repository ${REPO_NAME} (./e2e.sh infra-down)"; fi
  if [[ -s "${STATE}/org_id.deleted" ]]; then
    echo "confirmation that the throwaway org $(cat "${STATE}/org_id.deleted") is gone (./e2e.sh final re-checks)"
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

# The org under test: E2E_ORG_ID, else the one this harness created. Resolved in the main shell, not in a
# command substitution, so a missing org stops the step cleanly.
resolve_org() {
  if [[ -n "${E2E_ORG_ID:-}" ]]; then ORG_ID="${E2E_ORG_ID}"
  elif [[ -s "${STATE}/org_id" ]]; then ORG_ID="$(cat "${STATE}/org_id")"
  else ORG_ID=""; fi
}
need_org() {
  resolve_org
  [[ -n "${ORG_ID}" ]] || fail "no test org recorded: run ./e2e.sh infra-up"
}
role_arn() { terraform output -raw role_arn 2>/dev/null || echo "arn:aws:iam::000000000000:role/not-created"; }
role_vars() {
  echo "-var=snyk_org_id=${ORG_ID:-${PLACEHOLDER_ORG}}" "-var=role_name=${ROLE_NAME}" "-var=region=${REGION}" \
    "-var=snyk_aws_principal=${SNYK_AWS_PRINCIPAL:-arn:aws:iam::000000000000:root}"
}
onboard() {
  local mode=$1
  shift
  "${ONBOARD[@]}" "${mode}" --org-id "${ORG_ID}" --region "${REGION}" --role-arn "$(role_arn)" "$@"
}
snyk_status() { "${ONBOARD[@]}" status --org-id "${ORG_ID}" "$@"; }
org_exists_rc() { local rc=0; "${HARNESS[@]}" org-exists --org-id "$1" || rc=$?; echo "${rc}"; }
org_listed_rc() {
  if [[ -z "${SNYK_GROUP_ID:-}" ]]; then echo 2; return 0; fi
  local rc=0
  "${HARNESS[@]}" org-listed --group-id "${SNYK_GROUP_ID}" --org-id "$1" || rc=$?
  echo "${rc}"
}
# Fail fast, before changing anything, if the AWS session has expired (for example an SSO login during a pause).
aws_ok() {
  aws sts get-caller-identity --query Account --output text >/dev/null 2>&1 ||
    fail "AWS credentials not working: run aws sso login${AWS_PROFILE:+ --profile ${AWS_PROFILE}}, then re-run this step"
}
role_present() { aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; }
repo_present() { aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_NAME}" >/dev/null 2>&1; }
image_present() { aws ecr describe-images --region "${REGION}" --repository-name "${REPO_NAME}" --image-ids imageTag=v1.0.0 >/dev/null 2>&1; }
# Project lines from `status` look like "  - <repository>:<tag>", possibly with the registry host in front.
has_project() { grep -Eq "^  - ([^ ]*/)?${1}\$" <<<"$2"; }

infra_up() {
  step "test infrastructure: throwaway Snyk org + ECR repository with a test image"
  aws_ok
  mkdir -p "${STATE}"
  if [[ -n "${E2E_ORG_ID:-}" ]]; then
    echo "using existing Snyk org ${E2E_ORG_ID} (E2E_ORG_ID); it will not be deleted"
  elif [[ -s "${STATE}/org_id" ]]; then
    echo "reusing throwaway Snyk org $(cat "${STATE}/org_id")"
  else
    : "${SNYK_GROUP_ID:?export SNYK_GROUP_ID (list yours with: uv run harness.py groups)}"
    local name id
    name="ecr-e2e-$(date -u +%Y%m%d-%H%M%S)"
    id="$("${HARNESS[@]}" create-org --group-id "${SNYK_GROUP_ID}" --name "${name}")"
    echo "${id}" >"${STATE}/org_id"
    rm -f "${STATE}/org_id.deleted"
    echo "created throwaway Snyk org ${name}: ${id}"
  fi
  terraform -chdir=fixture init -input=false >/dev/null
  terraform -chdir=fixture apply -input=false -auto-approve "${FIXTURE_VARS[@]}"
  local url
  url="$(terraform -chdir=fixture output -raw repository_url)"
  aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${url%%/*}"
  docker pull --platform linux/amd64 alpine:3.18
  for tag in v1.0.0 latest; do
    docker tag alpine:3.18 "${url}:${tag}"
    docker push "${url}:${tag}"
  done
  pass "test infrastructure ready"
}

preflight() {
  step "preflight: test infrastructure present, product artefacts absent"
  need_org
  aws_ok
  [[ "$(org_exists_rc "${ORG_ID}")" == "0" ]] || fail "Snyk org ${ORG_ID} is not reachable with this token"
  image_present || fail "test image ${REPO_NAME}:v1.0.0 missing (run ./e2e.sh infra-up)"
  if role_present; then fail "IAM role ${ROLE_NAME} already exists (run ./e2e.sh down)"; fi
  local status
  status="$(snyk_status)"
  echo "${status}"
  grep -q '^ECR integration: none' <<<"${status}" || fail "the org already has an ECR integration; use a fresh org"
  if grep -Eq "^  - ([^ ]*/)?${REPO_PREFIX}" <<<"${status}"; then fail "the org already has ${REPO_PREFIX} projects"; fi
  pass "clean starting state"
}

up() {
  : "${SNYK_AWS_PRINCIPAL:?export SNYK_AWS_PRINCIPAL, the Principal shown by the Snyk UI under Integrations > Amazon ECR}"
  step "product: IAM role (Terraform module)"
  aws_ok
  need_org
  mkdir -p "${STATE}"
  terraform init -input=false >/dev/null
  # shellcheck disable=SC2046  # role_vars returns separate -var flags
  terraform apply -input=false -auto-approve $(role_vars)

  step "product: plan (writes nothing)"
  onboard plan "${SYNC_POLICY[@]}" | tee "${STATE}/plan.log"
  grep -q "apply would create it" "${STATE}/plan.log" || fail "plan did not report the missing integration"

  step "product: apply = connectivity + sync (a brand-new role, so IAM-propagation retries are expected)"
  onboard apply "${SYNC_POLICY[@]}" 2>&1 | tee "${STATE}/apply.log"
  grep -q "^ECR integration created:" "${STATE}/apply.log" || fail "the integration was not created"
  grep -q "^Snyk can read the registry:" "${STATE}/apply.log" || fail "the connection test did not pass"
  grep -Eq "^  ([^ ]*/)?${REPO_NAME} \(" "${STATE}/apply.log" || fail "the connection test did not list ${REPO_NAME}"
  grep -Eq "^  \+ ([^ ]*/)?${REPO_NAME}: v1\.0\.0\$" "${STATE}/apply.log" || fail "the sync preview should select exactly v1.0.0"
  grep -q "^Sync policy applied" "${STATE}/apply.log" || fail "the sync policy was not applied"
  pass "connected, and the sync is configured"
}

verify() {
  step "verify: the sync imports ${REPO_NAME}:v1.0.0 and not :latest"
  need_org
  local deadline=$((SECONDS + VERIFY_TIMEOUT)) status=""
  while ((SECONDS < deadline)); do
    status="$(snyk_status)"
    if has_project "${REPO_NAME}:v1\.0\.0" "${status}"; then
      echo "${status}"
      if has_project "${REPO_NAME}:latest" "${status}"; then fail "latest was imported, but the tag regex excludes it"; fi
      grep -q '^Sync policy    : ecr-onboarding' <<<"${status}" || fail "the sync policy is not active"
      pass "the sync imported v1.0.0 only"
      return 0
    fi
    echo "  not imported yet; checking again in 20s"
    sleep 20
  done
  echo "${status}"
  echo "diagnostic: every project in the org with its origin"
  snyk_status --all-origins || true
  fail "no ${REPO_NAME}:v1.0.0 project with origin ecr after ${VERIFY_TIMEOUT}s"
}

down() {
  step "product teardown: remove what apply created"
  aws_ok
  mkdir -p "${STATE}"
  resolve_org
  if [[ -n "${ORG_ID}" ]]; then
    onboard teardown --delete-projects --delete-credentials --repo-prefix "${REPO_PREFIX}" # dry run
    confirm "Run the product teardown above, then destroy the IAM role?"
    onboard teardown --delete-projects --delete-credentials --repo-prefix "${REPO_PREFIX}" --yes

    step "disconnect check: the role still exists, so a failing connection test proves the credentials are gone"
    if onboard plan --no-sync >"${STATE}/disconnect.log" 2>&1 && grep -q "^Snyk can read the registry:" "${STATE}/disconnect.log"; then
      cat "${STATE}/disconnect.log"
      fail "Snyk can still read the registry after --delete-credentials"
    fi
    cat "${STATE}/disconnect.log"
    pass "Snyk is disconnected from the registry"
  else
    echo "no test org recorded (infra-down already removed it): nothing to tear down on the Snyk side"
  fi

  # State-driven: destroys only what this Terraform root created (no-op if it holds nothing).
  terraform init -input=false >/dev/null
  # shellcheck disable=SC2046
  terraform destroy -input=false -auto-approve $(role_vars)
}

postcheck() {
  step "postcheck: product artefacts gone, test infrastructure untouched"
  aws_ok
  need_org
  if role_present; then fail "IAM role ${ROLE_NAME} still exists"; fi
  local status
  status="$(snyk_status)"
  echo "${status}"
  grep -q '^Sync policy    : none' <<<"${status}" || fail "the sync policy is still present"
  if grep -Eq "^  - ([^ ]*/)?${REPO_PREFIX}" <<<"${status}"; then fail "${REPO_PREFIX} projects are still present"; fi
  image_present || fail "the test image is gone: the product teardown must not touch the registry"
  [[ "$(org_exists_rc "${ORG_ID}")" == "0" ]] || fail "the Snyk org is gone: the product teardown must not touch the org"
  pass "the product removed exactly what it created"
}

infra_down() {
  step "test infrastructure teardown"
  aws_ok
  terraform -chdir=fixture init -input=false >/dev/null
  terraform -chdir=fixture destroy -input=false -auto-approve "${FIXTURE_VARS[@]}"
  if [[ -n "${E2E_ORG_ID:-}" ]]; then
    echo "keeping Snyk org ${E2E_ORG_ID} (supplied via E2E_ORG_ID)"
    return 0
  fi
  local id=""
  if [[ -s "${STATE}/org_id" ]]; then id="$(cat "${STATE}/org_id")"
  elif [[ -s "${STATE}/org_id.deleted" ]]; then id="$(cat "${STATE}/org_id.deleted")"; fi
  if [[ -n "${id}" ]]; then
    "${HARNESS[@]}" delete-org --org-id "${id}" --protect "${SNYK_ORG_ID:-}"
    echo "${id}" >"${STATE}/org_id.deleted"
    rm -f "${STATE}/org_id"
  fi
}

final() {
  step "final: back to the bare minimum (AWS account + Snyk account)"
  aws_ok
  if role_present; then fail "IAM role ${ROLE_NAME} still exists"; fi
  if repo_present; then fail "ECR repository ${REPO_NAME} still exists"; fi
  if [[ -z "${E2E_ORG_ID:-}" && -s "${STATE}/org_id.deleted" ]]; then
    local id by_id listed deadline=$((SECONDS + FINAL_TIMEOUT))
    id="$(cat "${STATE}/org_id.deleted")"
    while true; do
      by_id="$(org_exists_rc "${id}")"  # 0 found by ID, 1 not found, 2 error
      listed="$(org_listed_rc "${id}")" # 0 listed in the group, 1 not listed, 2 error or no SNYK_GROUP_ID
      if [[ "${by_id}" == "1" ]]; then
        echo "throwaway org ${id}: not found by ID"
        break
      fi
      if [[ "${listed}" == "1" ]]; then
        echo "throwaway org ${id}: no longer listed in group ${SNYK_GROUP_ID} (a lookup by ID still answers)"
        break
      fi
      if ((SECONDS >= deadline)); then
        fail "throwaway org ${id} still visible after ${FINAL_TIMEOUT}s (by ID rc=${by_id}, in group rc=${listed}); run ./e2e.sh infra-down again, or delete it in the Snyk UI"
      fi
      echo "  org deletion not visible yet (by ID rc=${by_id}, in group rc=${listed}); checking again in 15s"
      sleep 15
    done
    rm -f "${STATE}/org_id.deleted"
  fi
  pass "nothing left behind"
}

full() {
  infra_up
  preflight
  up
  verify
  if [[ "${E2E_PAUSE:-1}" == "1" ]]; then
    read -r -p "Inspect AWS and the Snyk org now. Press Enter to tear everything down (Ctrl-C to stop here)... " _
  fi
  export E2E_ASSUME_YES=1
  down
  postcheck
  infra_down
  final
  pass "full end-to-end run complete; only the AWS account and the Snyk account remain"
}

case "${1:-}" in
  full) full ;;
  infra-up) infra_up ;;
  preflight) preflight ;;
  up) up ;;
  verify) verify ;;
  down) down ;;
  postcheck) postcheck ;;
  infra-down) infra_down ;;
  final) final ;;
  status)
    need_org
    snyk_status
    ;;
  *)
    echo "usage: $0 full|infra-up|preflight|up|verify|down|postcheck|infra-down|final|status" >&2
    exit 1
    ;;
esac
