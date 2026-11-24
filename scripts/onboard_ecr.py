#!/usr/bin/env python3
"""Connect one Amazon ECR registry (one account, one region) to one Snyk org, set up the automatic
image sync, and tear both down again.

Starting state: the Snyk org and the ECR registry exist, and the IAM role Snyk assumes exists
(terraform/modules/snyk-ecr-role). This script never creates or deletes the org or the registry.

Modes (all idempotent, safe to re-run):
  plan      Never writes. Shows what apply would do; if the integration exists, runs the
            connection test and the sync preview.
  apply     1. Connectivity: creates the ECR integration if missing (v1 API) and proves Snyk can
               read the registry with a dry run that imports nothing (REST API).
            2. Sync: previews and applies Snyk's container registry sync policy (REST API). The policy
               is stated in Snyk's own terms: --import-policy with one of Snyk's policy types and its
               fields (--repo/--tag, --max-age-days, --limit-newest-images), or --policy-file with a
               policy object in Snyk's JSON format (And/Or, RuntimeIntegrations, ...). There is no
               default. --no-sync stops after step 1.
  status    Read-only: the integration, the sync policy and the ECR projects in the org.
  teardown  Removes what apply created: the sync policy (stops auto-import); with --delete-projects
            the ECR projects whose repository starts with --repo-prefix; with --delete-credentials
            the role/region stored in the integration (disconnecting Snyk). Dry run unless --yes.
            The empty integration entry cannot be deleted through the API.

Exit codes: 0 success, 1 error, 2 apply refused by --max-images.
The Snyk token is read from the SNYK_TOKEN environment variable only.
Standard library only, so it runs unchanged with `uv run` or in any CI runner.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_API_BASE = "https://api.snyk.io"
DEFAULT_REST_VERSION = "2025-09-17"
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
ROLE_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/.+$")
ECR_HOST_RE = re.compile(r"^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$")
# Statuses worth retrying on any call.
RETRYABLE = {429, 500, 502, 503, 504}
# Statuses that retrying will never fix (bad token, no permission, wrong org).
FATAL = {401, 403, 404}
# Not stated in Snyk's docs, which only say a project's origin is "the name of the originating SCM,
# Container registry, and so on". "ecr" matches the v1 integration type; `status --all-origins` shows the
# real values, and the e2e run verifies it.
ECR_ORIGIN = "ecr"
CONNECTION_TEST_POLICY = {"name": "connection test", "import_policy": {"name": "all", "type": "ImportAll"}}
# Snyk's container registry sync policy vocabulary, as documented ("Sync your container registry").
# Single policy types selectable with --import-policy, and their fields (Snyk's names):
SINGLE_POLICY_TYPES = ("ImportAll", "ImportAllNew", "Regex", "Recent", "LastNObserved")
# Also documented, available through --policy-file:
FILE_ONLY_POLICY_TYPES = ("And", "Or", "RuntimeIntegrations")
# Snyk docs: "LastNObserved and Recent require delete_images set to true to rotate".
ROTATING_POLICY_TYPES = ("Recent", "LastNObserved")
SNYK_DEFAULT_SCHEDULE_HOURS = 24  # Snyk docs: minimum 2, default 24 (used when the field is omitted)
RE2_UNSUPPORTED = ("(?=", "(?!", "(?<=", "(?<!")  # Snyk docs: RE2, no lookahead/lookbehind
DEFAULT_POLICY_NAME = "ecr-onboarding"  # a label only; Snyk requires a policy name


class ApiError(Exception):
    def __init__(self, status: int, body: str, method: str, url: str):
        super().__init__(f"{method} {url} -> HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


class UsageError(Exception):
    pass


class DryRunFailed(RuntimeError):
    """Snyk reported the dry-run job as failed (for example it could not read the registry)."""


def validate_api_base(api_base: str) -> str:
    """Refuse to send the token anywhere but a Snyk API host over HTTPS."""
    parsed = urllib.parse.urlparse(api_base)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not (host == "snyk.io" or host.endswith(".snyk.io")):
        raise UsageError(f"--api-base must be an https://*.snyk.io URL, got {api_base!r}")
    return api_base.rstrip("/")


def retry_after_seconds(headers: dict[str, str], default: float) -> float:
    """Retry-After may arrive in any case and as seconds or an HTTP date; fall back to the default."""
    for name, value in headers.items():
        if name.lower() == "retry-after":
            try:
                return float(value)
            except ValueError:
                return default
    return default


class SnykClient:
    def __init__(self, token: str, api_base: str, rest_version: str, max_retries: int = 5):
        self._token = token
        self.api_base = validate_api_base(api_base)
        self.rest_version = rest_version
        self.max_retries = max_retries

    # -- transport (overridden in tests) ---------------------------------------------
    def _send(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, dict[str, str], str]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (https enforced)
                return resp.status, dict(resp.headers), resp.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers or {}), err.read().decode("utf-8", "replace")

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def request(self, method: str, url: str, payload: Any = None, rest: bool = False) -> Any:
        headers = {"Authorization": f"token {self._token}", "Accept": "application/json"}
        if rest:
            headers["Content-Type"] = "application/vnd.api+json"
            headers["Accept"] = "application/vnd.api+json"
        elif payload is not None:
            headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None

        for attempt in range(self.max_retries + 1):
            try:
                status, resp_headers, text = self._send(method, url, headers, body)
            except urllib.error.URLError as err:  # DNS, TLS, proxy, connection refused, timeouts
                raise RuntimeError(f"cannot reach {method} {url.split('?')[0]}: {err.reason}") from err
            if 200 <= status < 300:
                try:
                    return json.loads(text) if text.strip() else {}
                except json.JSONDecodeError as err:
                    raise RuntimeError(f"{method} {url.split('?')[0]} returned a non-JSON body: {text[:200]!r}") from err
            if status in RETRYABLE and attempt < self.max_retries:
                self._sleep(min(retry_after_seconds(resp_headers, 2 ** attempt), 60))
                continue
            raise ApiError(status, text, method, url)
        raise AssertionError("unreachable")

    # -- v1 API: integrations --------------------------------------------------------
    def list_integrations(self, org_id: str) -> dict[str, str]:
        return self.request("GET", f"{self.api_base}/v1/org/{org_id}/integrations")

    def create_ecr_integration(self, org_id: str, region: str, role_arn: str) -> str:
        payload = {"type": "ecr", "credentials": {"region": region, "roleArn": role_arn}}
        return self.request("POST", f"{self.api_base}/v1/org/{org_id}/integrations", payload)["id"]

    def update_ecr_integration(self, org_id: str, integration_id: str, region: str, role_arn: str) -> None:
        payload = {"type": "ecr", "credentials": {"region": region, "roleArn": role_arn}}
        self.request("PUT", f"{self.api_base}/v1/org/{org_id}/integrations/{integration_id}", payload)

    def delete_integration_credentials(self, org_id: str, integration_id: str) -> bool:
        """Remove the role ARN / region Snyk holds (v1 'Delete credentials'). The integration entry stays."""
        try:
            self.request("DELETE", f"{self.api_base}/v1/org/{org_id}/integrations/{integration_id}/authentication")
            return True
        except ApiError as err:
            if err.status == 404:
                return False
            raise

    # -- REST API: container registry sync ---------------------------------------------
    def _policy_url(self, org_id: str, integration_id: str, suffix: str = "") -> str:
        query = urllib.parse.urlencode({"version": self.rest_version})
        return f"{self.api_base}/rest/orgs/{org_id}/container_import/{integration_id}/policy{suffix}?{query}"

    @staticmethod
    def _policy_body(policy: dict[str, Any]) -> dict[str, Any]:
        return {"data": {"type": "container_registry_import_policy", "attributes": {"policy": policy}}}

    def start_dry_run(self, org_id: str, integration_id: str, policy: dict[str, Any]) -> str:
        url = self._policy_url(org_id, integration_id, "/dry_run")
        return self.request("POST", url, self._policy_body(policy), rest=True)["data"]["id"]

    def get_dry_run(self, org_id: str, integration_id: str, job_id: str) -> dict[str, Any]:
        url = self._policy_url(org_id, integration_id, f"/dry_run/{job_id}")
        return self.request("GET", url, rest=True)["data"]["attributes"]

    def get_policy(self, org_id: str, integration_id: str) -> dict[str, Any] | None:
        try:
            page = self.request("GET", self._policy_url(org_id, integration_id), rest=True)
        except ApiError as err:
            if err.status == 404:
                return None
            raise
        return ((page.get("data") or {}).get("attributes") or {}).get("policy") or None

    def apply_policy(self, org_id: str, integration_id: str, policy: dict[str, Any]) -> None:
        """POST creates or replaces the whole policy; fall back to PATCH on conflict."""
        url = self._policy_url(org_id, integration_id)
        body = self._policy_body(policy)
        try:
            self.request("POST", url, body, rest=True)
        except ApiError as err:
            if err.status != 409:
                raise
            self.request("PATCH", url, body, rest=True)

    def delete_policy(self, org_id: str, integration_id: str) -> bool:
        """Remove the sync policy (stops auto-import). Returns False if there was none."""
        try:
            self.request("DELETE", self._policy_url(org_id, integration_id), rest=True)
            return True
        except ApiError as err:
            if err.status == 404:
                return False
            raise

    # -- REST API: projects ----------------------------------------------------------
    def _follow(self, link: Any) -> str | None:
        """Turn a JSON:API pagination link into an absolute URL on the Snyk API host, or None.

        Snyk returns links relative to the REST base and without the /rest prefix
        (e.g. "/orgs/<id>/projects?...&starting_after=..."); accept the prefixed form too.
        """
        if isinstance(link, dict):
            link = link.get("href")
        if not link:
            return None
        if link.startswith("/"):
            link = self.api_base + (link if link.startswith("/rest/") else "/rest" + link)
        if not link.startswith(self.api_base + "/"):
            raise RuntimeError(f"refusing to follow pagination link off the Snyk API host: {link}")
        return link

    def list_projects(self, org_id: str, origin: str | None = ECR_ORIGIN) -> list[dict[str, str]]:
        """Projects in the org, filtered by origin (None = all), following pagination."""
        params = {"version": self.rest_version, "limit": 100}
        if origin:
            params["origins"] = origin
        url: str | None = f"{self.api_base}/rest/orgs/{org_id}/projects?{urllib.parse.urlencode(params)}"
        projects: list[dict[str, str]] = []
        while url:
            page = self.request("GET", url, rest=True)
            projects += [{"id": p["id"], "name": p["attributes"]["name"], "origin": p["attributes"].get("origin", "")}
                         for p in page.get("data", [])]
            url = self._follow((page.get("links") or {}).get("next"))
        return projects

    def list_ecr_projects(self, org_id: str) -> list[dict[str, str]]:
        return self.list_projects(org_id, ECR_ORIGIN)

    def delete_project(self, org_id: str, project_id: str) -> None:
        query = urllib.parse.urlencode({"version": self.rest_version})
        self.request("DELETE", f"{self.api_base}/rest/orgs/{org_id}/projects/{project_id}?{query}", rest=True)


# -- policy construction -------------------------------------------------------------------
def policy_from_flags(args: argparse.Namespace) -> dict[str, Any]:
    """Snyk's policy object for one --import-policy type, with only the fields Snyk documents for it."""
    kind = args.import_policy
    import_policy: dict[str, Any] = {"name": f"{args.policy_name} ({kind})", "type": kind}
    if kind == "Regex":
        import_policy["policy"] = {field: value for field, value in (("repo", args.repo), ("tag", args.tag)) if value}
    elif kind == "Recent":
        import_policy["policy"] = {"maxAgeDays": args.max_age_days}
    elif kind == "LastNObserved":
        import_policy["policy"] = {"limitNewestImages": args.limit_newest_images}
    policy: dict[str, Any] = {"name": args.policy_name, "delete_images": args.delete_images, "import_policy": import_policy}
    if args.schedule_frequency_hours is not None:
        policy["schedule_frequency_hours"] = args.schedule_frequency_hours
    return policy


POLICY_FILE_MAX_BYTES = 64 * 1024


def policy_file_path(path: str) -> pathlib.Path:
    """Only a .json file inside the working directory (policies are meant to live in the repository,
    reviewed like the Terraform), and small, so nothing else can be read and sent to Snyk."""
    base = pathlib.Path.cwd().resolve()
    candidate = (base / path).resolve()
    if not candidate.is_relative_to(base):
        raise UsageError(f"--policy-file {path}: must be inside the current directory ({base})")
    if candidate.suffix.lower() != ".json":
        raise UsageError(f"--policy-file {path}: must be a .json file")
    if not candidate.is_file():
        raise UsageError(f"--policy-file {path}: no such file")
    if candidate.stat().st_size > POLICY_FILE_MAX_BYTES:
        raise UsageError(f"--policy-file {path}: larger than {POLICY_FILE_MAX_BYTES // 1024} KiB")
    return candidate


def policy_from_file(path: str, default_name: str) -> dict[str, Any]:
    """A policy object in Snyk's documented JSON format, passed through as written."""
    try:
        policy = json.loads(policy_file_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise UsageError(f"--policy-file {path}: {err}") from err
    import_policy = policy.get("import_policy") if isinstance(policy, dict) else None
    if not isinstance(import_policy, dict) or "type" not in import_policy:
        raise UsageError(f"--policy-file {path}: expected Snyk's policy object, "
                         '{"name": ..., "import_policy": {"type": ..., ...}, "delete_images": ..., "schedule_frequency_hours": ...}')
    # Snyk's REST schema requires a name on the policy and on import_policy; fill them in only if missing.
    policy.setdefault("name", default_name)
    import_policy.setdefault("name", policy["name"])
    return policy


def policy_types(node: Any) -> list[str]:
    """Every policy type used in an import_policy tree (sub_policies included)."""
    if not isinstance(node, dict):
        return []
    found = [node["type"]] if isinstance(node.get("type"), str) else []
    for sub in node.get("sub_policies") or []:
        found += policy_types(sub)
    return found


def regex_fields(node: Any) -> list[tuple[str, str]]:
    """Every (field, pattern) of the Regex policies in an import_policy tree."""
    if not isinstance(node, dict):
        return []
    found = []
    if node.get("type") == "Regex":
        found += [(k, v) for k, v in (node.get("policy") or {}).items() if k in ("repo", "tag") and isinstance(v, str)]
    for sub in node.get("sub_policies") or []:
        found += regex_fields(sub)
    return found


def check_policy(policy: dict[str, Any]) -> list[str]:
    """Enforce what Snyk documents about policies; return the types used."""
    hours = policy.get("schedule_frequency_hours")
    if hours is not None and (not isinstance(hours, int) or hours < 2):
        raise UsageError("schedule_frequency_hours must be an integer of at least 2 (Snyk's minimum)")
    for field, pattern in regex_fields(policy["import_policy"]):
        if any(token in pattern for token in RE2_UNSUPPORTED):
            raise UsageError(f"Regex {field} {pattern!r}: Snyk uses RE2, which does not support lookahead or "
                             "lookbehind; write an allow-list pattern instead")
    types = policy_types(policy["import_policy"])
    unknown = sorted(set(types) - set(SINGLE_POLICY_TYPES) - set(FILE_ONLY_POLICY_TYPES))
    if unknown:
        print(f"warning: policy type(s) {', '.join(unknown)} are not in Snyk's documented list; "
              "the preview will show whether Snyk accepts them.", file=sys.stderr)
    rotating = sorted(set(types) & set(ROTATING_POLICY_TYPES))
    if rotating and not policy.get("delete_images"):
        print(f"warning: Snyk documents that {' and '.join(rotating)} only add images unless delete_images is true; "
              "older projects then remain indefinitely (add --delete-images to rotate).", file=sys.stderr)
    return types


def validate_inputs(args: argparse.Namespace) -> None:
    if not UUID_RE.match(args.org_id):
        raise UsageError("--org-id must be a Snyk org UUID")
    if args.mode in ("plan", "apply"):
        if not args.region or not REGION_RE.match(args.region):
            raise UsageError("--region is required and must look like eu-west-3")
        if not args.role_arn or not ROLE_ARN_RE.match(args.role_arn):
            raise UsageError("--role-arn is required and must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)")
        validate_sync_selection(args)
    if args.mode == "teardown" and args.delete_projects and not args.repo_prefix:
        raise UsageError("--repo-prefix is required with --delete-projects (it scopes what is deleted)")


def validate_sync_selection(args: argparse.Namespace) -> None:
    """The sync is stated in Snyk's terms, with no default: one --import-policy (and its fields),
    or --policy-file, or --no-sync. Fields that do not belong to the chosen type are refused."""
    fields = {"--repo": args.repo, "--tag": args.tag, "--max-age-days": args.max_age_days,
              "--limit-newest-images": args.limit_newest_images}
    settings = {"--schedule-frequency-hours": args.schedule_frequency_hours, "--delete-images": args.delete_images or None,
                "--policy-name": args.policy_name if args.policy_name != DEFAULT_POLICY_NAME else None}
    given = [flag for flag, value in {**fields, **settings}.items() if value is not None]
    if args.no_sync:
        chosen = [f for f, v in (("--import-policy", args.import_policy), ("--policy-file", args.policy_file)) if v]
        if chosen or given:
            raise UsageError(f"{', '.join(chosen + given)} configure the sync, which --no-sync turns off")
        return
    if args.import_policy and args.policy_file:
        raise UsageError("use either --import-policy or --policy-file, not both")
    if not args.import_policy and not args.policy_file:
        raise UsageError(
            "say what the sync should import, using Snyk's policy types: --import-policy "
            f"{{{','.join(SINGLE_POLICY_TYPES)}}} (with --repo/--tag for Regex, --max-age-days for Recent, "
            f"--limit-newest-images for LastNObserved), or --policy-file with Snyk's policy JSON "
            f"({'/'.join(FILE_ONLY_POLICY_TYPES)} and combinations); or --no-sync to only connect")
    if args.policy_file:
        extra = [flag for flag in given if flag != "--policy-name"]
        if extra:
            raise UsageError(f"{', '.join(extra)} cannot be combined with --policy-file; set them in the file")
        return
    kind = args.import_policy
    allowed = {"Regex": {"--repo", "--tag"}, "Recent": {"--max-age-days"},
               "LastNObserved": {"--limit-newest-images"}}.get(kind, set())
    misplaced = [flag for flag, value in fields.items() if value is not None and flag not in allowed]
    if misplaced:
        raise UsageError(f"{', '.join(misplaced)} {'is' if len(misplaced) == 1 else 'are'} not a field of the {kind} policy")
    if kind == "Regex" and not (args.repo or args.tag):
        raise UsageError("the Regex policy needs --repo and/or --tag")
    if kind == "Recent" and not (args.max_age_days and args.max_age_days > 0):
        raise UsageError("the Recent policy needs --max-age-days N (N >= 1)")
    if kind == "LastNObserved" and not (args.limit_newest_images and args.limit_newest_images > 0):
        raise UsageError("the LastNObserved policy needs --limit-newest-images N (N >= 1)")


# -- workflow ----------------------------------------------------------------------------
def ensure_integration(client: SnykClient, args: argparse.Namespace, create: bool) -> tuple[str | None, bool]:
    """Return (integration id or None, fresh). fresh means credentials were set in this run, so
    Snyk may not be able to assume the role yet (IAM propagation) and the first checks are retried."""
    existing = client.list_integrations(args.org_id).get("ecr")
    if existing:
        print(f"ECR integration already exists: {existing}")
        if args.update_credentials and create:
            client.update_ecr_integration(args.org_id, existing, args.region, args.role_arn)
            print("  credentials updated (--update-credentials)")
            return existing, True
        if args.update_credentials:
            print("  would update credentials (--update-credentials)")
        else:
            print("  reusing as-is; pass --update-credentials to point it at this role/region")
        return existing, False
    if not create:
        print(f"ECR integration missing: apply would create it ({args.region}, {args.role_arn})")
        return None, False

    for attempt in range(1, args.connect_retries + 1):
        try:
            integration_id = client.create_ecr_integration(args.org_id, args.region, args.role_arn)
            print(f"ECR integration created: {integration_id}")
            return integration_id, True
        except ApiError as err:
            # A fresh IAM trust policy can take minutes to propagate; anything else is not retryable.
            if err.status in FATAL or attempt == args.connect_retries:
                raise
            print(
                f"  integration create failed (HTTP {err.status}); IAM may still be propagating. "
                f"Retry {attempt}/{args.connect_retries - 1} in {args.connect_delay}s",
                file=sys.stderr,
            )
            client._sleep(args.connect_delay)
    raise AssertionError("unreachable")


def run_dry_run(client: SnykClient, args: argparse.Namespace, integration_id: str, policy: dict[str, Any]) -> dict[str, Any]:
    job_id = client.start_dry_run(args.org_id, integration_id, policy)
    deadline = time.monotonic() + args.dry_run_timeout
    while True:
        result = client.get_dry_run(args.org_id, integration_id, job_id)
        status = result.get("status")
        if status == "completed":
            return result["result"]
        if status == "failed":
            raise DryRunFailed(f"dry run failed: {result.get('error_message', 'no message')}")
        if time.monotonic() > deadline:
            raise RuntimeError(f"dry run still {status!r} after {args.dry_run_timeout}s")
        client._sleep(args.poll_seconds)


def checked_dry_run(client: SnykClient, args: argparse.Namespace, integration_id: str,
                    policy: dict[str, Any], fresh: bool) -> dict[str, Any]:
    """Dry run that tolerates IAM propagation right after credentials were set, and explains failures."""
    attempts = args.connect_retries if fresh else 1
    for attempt in range(1, attempts + 1):
        try:
            return run_dry_run(client, args, integration_id, policy)
        except DryRunFailed as err:
            if attempt < attempts:
                print(f"  {err}; the new credentials may still be propagating. "
                      f"Retry {attempt}/{attempts - 1} in {args.connect_delay}s", file=sys.stderr)
                client._sleep(args.connect_delay)
                continue
            if fresh:
                raise DryRunFailed(
                    f"{err}. Snyk still cannot use the role after {attempts} attempts. Likely causes "
                    "(this script cannot read the role's trust policy, so check them in AWS):\n"
                    f"  - org {args.org_id} is missing from the role's sts:ExternalId list: add it to the org IDs "
                    "the role trusts (snyk_orgs in examples/main.tf, snyk_org_ids on the module), keep every "
                    "existing ID, and run terraform apply\n"
                    "  - the Snyk principal in the role's trust policy is not the one your Snyk tenant's UI shows\n"
                    f"  - --region {args.region} is not the region of the ECR registry\n"
                    "  - us-east-2 is not enabled for STS in the AWS account\n"
                    "The integration now exists, so after the fix re-run 'apply' with --update-credentials: it stores "
                    "the role and region again and retries while the change propagates.") from err
            raise DryRunFailed(f"{err}. If this integration was disconnected (teardown --delete-credentials) or "
                               "points at another role/region, re-run 'apply' with --update-credentials.") from err
    raise AssertionError("unreachable")


def repository_of(project_name: str) -> str:
    """'<repository>:<tag>' -> '<repository>'. Drops a leading ECR registry host if Snyk includes one;
    only an exact ECR host pattern is stripped, so the match can never widen to other repositories."""
    repo = project_name.rsplit(":", 1)[0] if ":" in project_name.rsplit("/", 1)[-1] else project_name
    first, _, rest = repo.partition("/")
    return rest if rest and ECR_HOST_RE.match(first) else repo


def count_tags(entries: list[dict[str, Any]]) -> int:
    return sum(len(e.get("tags", [])) for e in entries)


def summarise(result: dict[str, Any]) -> tuple[int, int]:
    to_import = count_tags(result["images_to_import"])
    to_delete = count_tags(result["images_to_delete"])
    print(f"Dry run: Snyk processed {result['total_images_processed']} images; {to_import} to import, {to_delete} to delete")
    for entry in result["images_to_import"][:10]:
        tags = ", ".join(t["tag"] for t in entry["tags"][:5])
        print(f"  + {entry['repository']}: {tags}{' ...' if len(entry['tags']) > 5 else ''}")
    if len(result["images_to_import"]) > 10:
        print(f"  ... and {len(result['images_to_import']) - 10} more repositories")
    return to_import, to_delete


def connection_test(client: SnykClient, args: argparse.Namespace, integration_id: str, fresh: bool) -> None:
    """Prove Snyk can read the registry: an ImportAll dry run lists repositories and tags, imports nothing."""
    result = checked_dry_run(client, args, integration_id, CONNECTION_TEST_POLICY, fresh)
    repos = result["images_to_import"]
    print(f"Snyk can read the registry: {len(repos)} repositories with tagged images ({count_tags(repos)} tags) "
          "visible; nothing imported.")
    for entry in repos[:10]:
        print(f"  {entry['repository']} ({len(entry.get('tags', []))} tags)")
    if len(repos) > 10:
        print(f"  ... and {len(repos) - 10} more repositories")


def run_teardown(args: argparse.Namespace, client: SnykClient) -> int:
    """Stop the sync and optionally remove the synced projects and the stored credentials. Dry run unless --yes."""
    existing = client.list_integrations(args.org_id).get("ecr")
    has_policy = bool(existing and client.get_policy(args.org_id, existing))
    doomed = []
    if args.delete_projects:
        # Scope deletion to repositories under a literal prefix (project names are "<repository>:<tag>").
        doomed = [p for p in client.list_ecr_projects(args.org_id) if repository_of(p["name"]).startswith(args.repo_prefix)]

    print(f"ECR integration: {existing or 'none'}")
    print(f"Sync policy    : {'present, will be deleted (stops auto-import)' if has_policy else 'none'}")
    if args.delete_projects:
        print(f"Projects       : {len(doomed)} ECR project(s) under prefix {args.repo_prefix!r} will be deleted")
        for p in doomed[:10]:
            print(f"  - {p['name']}")
        if len(doomed) > 10:
            print(f"  ... and {len(doomed) - 10} more")
    else:
        print("Projects       : left in place (pass --delete-projects to remove them)")
    if not existing:
        print("Credentials    : none (no ECR integration)")
    elif args.delete_credentials:
        print("Credentials    : will be removed (Snyk can no longer read the registry; the empty integration entry remains)")
    else:
        print("Credentials    : left in place (pass --delete-credentials to disconnect Snyk from the registry)")

    if not args.yes:
        print("Dry run only; re-run with --yes to execute.")
        return 0

    if existing and client.delete_policy(args.org_id, existing):
        print("Sync policy deleted.")
    for p in doomed:
        client.delete_project(args.org_id, p["id"])
    if doomed:
        print(f"Deleted {len(doomed)} project(s).")
    if args.delete_credentials and existing:
        if client.delete_integration_credentials(args.org_id, existing):
            print("Integration credentials deleted: Snyk can no longer assume the AWS role.")
        else:
            print("Integration credentials: already removed.")
    print(
        "Not removed: the empty ECR integration entry (no API deletes it; remove it in the Snyk UI under "
        "Integrations if you want it gone) and the AWS role (terraform destroy). The Snyk org is never touched."
    )
    return 0


def run_status(args: argparse.Namespace, client: SnykClient) -> int:
    """Read-only report: integration, sync policy, and the ECR projects in the org."""
    existing = client.list_integrations(args.org_id).get("ecr")
    print(f"ECR integration: {existing or 'none'}")
    policy = client.get_policy(args.org_id, existing) if existing else None
    if policy:
        print(f"Sync policy    : {policy.get('name')} "
              f"(import_policy {', '.join(policy_types(policy.get('import_policy'))) or '?'}; "
              f"schedule_frequency_hours {policy.get('schedule_frequency_hours', f'{SNYK_DEFAULT_SCHEDULE_HOURS} (Snyk default)')}; "
              f"delete_images {str(policy.get('delete_images', False)).lower()})")
    else:
        print("Sync policy    : none")
    projects = client.list_ecr_projects(args.org_id)
    print(f"ECR projects   : {len(projects)}")
    for p in projects[:20]:
        print(f"  - {p['name']}")
    if len(projects) > 20:
        print(f"  ... and {len(projects) - 20} more")
    if args.all_origins:
        everything = client.list_projects(args.org_id, origin=None)
        print(f"All projects   : {len(everything)} (any origin)")
        for p in everything[:50]:
            print(f"  * {p['name']}  [origin: {p['origin'] or '?'}]")
        if len(everything) > 50:
            print(f"  ... and {len(everything) - 50} more")
    return 0


def run(args: argparse.Namespace, client: SnykClient) -> int:
    validate_inputs(args)
    if args.mode == "status":
        return run_status(args, client)
    if args.mode == "teardown":
        return run_teardown(args, client)
    apply_mode = args.mode == "apply"
    policy = None
    types: list[str] = []
    if not args.no_sync:
        policy = policy_from_file(args.policy_file, args.policy_name) if args.policy_file else policy_from_flags(args)
        types = check_policy(policy)

    # 1. Connectivity
    integration_id, fresh = ensure_integration(client, args, create=apply_mode)
    if integration_id is None:
        print("Nothing more to check in plan mode: the connection test needs an existing integration.")
        if policy:
            print("Sync policy apply would set:\n" + json.dumps(policy, indent=2))
        else:
            print("--no-sync: apply would only connect.")
        return 0
    connection_test(client, args, integration_id, fresh)
    if policy is None:
        print("Connected (--no-sync): import images from the Snyk UI, or re-run without --no-sync to set up the sync."
              if apply_mode else "Plan only; apply would connect without setting up the sync.")
        return 0

    # 2. Sync
    to_import, _ = summarise(checked_dry_run(client, args, integration_id, policy, fresh=False))
    if "ImportAllNew" in types:
        print("note: Snyk records the images that exist when the policy is created as a baseline; ImportAllNew "
              "imports only images pushed after that, so the preview of existing images can be empty.")
    if not apply_mode:
        print("Plan only; re-run with 'apply' to connect and set up the sync.")
        return 0

    if to_import > args.max_images and not args.force:
        print(
            f"Refusing to apply: {to_import} images would be imported, above --max-images {args.max_images}. "
            "Narrow the policy, raise --max-images, or pass --force.",
            file=sys.stderr,
        )
        return 2

    client.apply_policy(args.org_id, integration_id, policy)
    hours = policy.get("schedule_frequency_hours", f"{SNYK_DEFAULT_SCHEDULE_HOURS} (Snyk default)")
    print(f"Sync policy applied for integration {integration_id}; Snyk runs it now and then every {hours} hours.")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=["plan", "apply", "teardown", "status"])
    p.add_argument("--org-id", required=True, help="Snyk org UUID")
    p.add_argument("--region", help="AWS region of the ECR registry, e.g. ap-southeast-2 (plan/apply)")
    p.add_argument("--role-arn", help="ARN of the IAM role Snyk assumes, a Terraform output (plan/apply)")
    sync = p.add_argument_group("sync policy (Snyk's container registry sync, in Snyk's own terms)")
    sync.add_argument("--import-policy", choices=SINGLE_POLICY_TYPES,
                      help="Snyk policy type: ImportAll, ImportAllNew, Regex, Recent or LastNObserved")
    sync.add_argument("--repo", help="Regex: RE2 pattern for repository names (Snyk field 'repo')")
    sync.add_argument("--tag", help="Regex: RE2 pattern for tags (Snyk field 'tag')")
    sync.add_argument("--max-age-days", type=int, help="Recent: Snyk field 'maxAgeDays'")
    sync.add_argument("--limit-newest-images", type=int, help="LastNObserved: Snyk field 'limitNewestImages'")
    sync.add_argument("--policy-file", help="Snyk policy object as JSON (for And/Or, RuntimeIntegrations, combinations)")
    sync.add_argument("--schedule-frequency-hours", type=int,
                      help=f"Snyk field 'schedule_frequency_hours' (minimum 2; omitted = Snyk default {SNYK_DEFAULT_SCHEDULE_HOURS})")
    sync.add_argument("--delete-images", action="store_true",
                      help="Snyk field 'delete_images': delete projects whose images no longer match the policy")
    sync.add_argument("--policy-name", default=DEFAULT_POLICY_NAME, help="Snyk field 'name' (a label)")
    sync.add_argument("--no-sync", action="store_true", help="Only set up connectivity; no sync policy")
    p.add_argument("--update-credentials", action="store_true", help="Point an existing ECR integration at this role/region")
    p.add_argument("--max-images", type=int, default=1000, help="Sync: refuse to apply above this many images")
    p.add_argument("--force", action="store_true", help="Sync: apply even above --max-images")
    p.add_argument("--delete-projects", action="store_true",
                   help="teardown: also delete ECR projects whose repository starts with --repo-prefix")
    p.add_argument("--repo-prefix", help="teardown: literal repository-name prefix scoping --delete-projects, e.g. 'team-a/'")
    p.add_argument("--delete-credentials", action="store_true",
                   help="teardown: also delete the role ARN/region stored in the ECR integration (disconnects Snyk)")
    p.add_argument("--yes", action="store_true", help="teardown: actually delete; without it teardown is a dry run")
    p.add_argument("--all-origins", action="store_true", help="status: also list every project with its origin (diagnostic)")
    p.add_argument("--connect-retries", type=int, default=10,
                   help="Attempts at the integration create and the first dry run after credentials are set (IAM propagation)")
    p.add_argument("--connect-delay", type=int, default=15, help="Seconds between those attempts")
    p.add_argument("--dry-run-timeout", type=int, default=300)
    p.add_argument("--poll-seconds", type=int, default=3)
    p.add_argument("--api-base", default=os.environ.get("SNYK_API_BASE", DEFAULT_API_BASE),
                   help="Snyk API host for your tenant, e.g. https://api.eu.snyk.io (env SNYK_API_BASE)")
    p.add_argument("--api-version", default=DEFAULT_REST_VERSION, help="REST API version date")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # keep stdout and stderr in order when piped (CI, tee)
    args = parse_args(argv)
    token = os.environ.get("SNYK_TOKEN")
    if not token:
        print("error: set SNYK_TOKEN in the environment (service-account token)", file=sys.stderr)
        return 1
    try:
        return run(args, SnykClient(token, args.api_base, args.api_version))
    except (UsageError, ApiError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyError as err:
        print(f"error: unexpected Snyk API response (missing field {err})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
