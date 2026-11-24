#!/usr/bin/env python3
"""Connect Amazon ECR registries to a Snyk org, set up the automatic image sync, and tear both down
again.

Two modes, decided by the org and never by the caller: every run first asks Snyk's closed-beta
Integrations API whether the org has Snyk's multiple profiles feature.
  default mode   (feature off) one ECR connection per org, one registry (one account, one region); the
                 behavior below, unchanged from the baseline.
  profiles mode  (feature on) any number of named connections, each to one registry; every change acts
                 on one of them, named by --connection (a label or a full name) or found by the
                 registry address its name carries. Names default to "[<label> ]<registry address>".

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
import dataclasses
import http.client
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

# -- profiles mode (feature 002) -----------------------------------------------------------
# Snyk's Integrations API is documented only to beta customers, on its closed-beta tier; the version is
# pinned (Principle IV exception, specs/002-multi-ecr-connections/plan.md, Complexity Tracking).
CLOSED_BETA_VERSION = "2024-10-15"
CLOSED_BETA_PREFIX = "/closed-beta"
# Rate limits, per token, shared by every closed-beta API: 1 a second, 10 a minute, 100 an hour (seen in
# X-RateLimit-Limit, 2026-11-24). Calls are spaced at least a second apart, and a wait longer than this
# stops the run instead (research R12).
CLOSED_BETA_MIN_SPACING = 1.0
CLOSED_BETA_MAX_WAIT = 60.0
DEFAULT_PROFILE_NAME = "Default profile"  # how Snyk lists a connection made before the feature
PROFILE_UI_PATH = "Organization settings → Integrations → Amazon ECR → Profile Management"
MODE_LINE = "Mode: profiles (Snyk's multiple profiles feature is on for this org)"
# Snyk's profiles accept only roles in AWS's standard partition (role_arn pattern, research R13).
STANDARD_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/.+$")
OTHER_PARTITION_REGIONS = ("cn-", "us-gov-")
# A label: a letter or digit, then letters, digits, "_", "-", or "." (no spaces, so names parse back).
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# Snyk's rule for profile names: 1 to 255 characters, starting with a letter or digit, of letters,
# digits, spaces, underscores, hyphens, and dots.
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,254}$")
# A name that carries its registry: "[<label> ]<12 digits>.dkr.ecr.<region>.amazonaws.com".
CONNECTION_NAME_RE = re.compile(
    r"^(?:(?P<label>[A-Za-z0-9][A-Za-z0-9_.-]*) )?(?P<account>\d{12})\.dkr\.ecr\."
    r"(?P<region>[a-z]{2}(?:-[a-z]+)+-\d)\.amazonaws\.com$")


class ApiError(Exception):
    def __init__(self, status: int, body: str, method: str, url: str):
        super().__init__(f"{method} {url} -> HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


class UsageError(Exception):
    pass


class Refusal(Exception):
    """A profiles-mode run that must change nothing: the message, and the org's connections to choose from."""

    def __init__(self, message: str, connections: list[Connection] | None = None):
        super().__init__(message)
        self.connections = connections or []


class RateLimited(RuntimeError):
    """Snyk's closed-beta allowance for this token is spent for longer than a run should wait."""


class DryRunFailed(RuntimeError):
    """Snyk reported the dry-run job as failed (for example it could not read the registry)."""


class RedirectRefused(RuntimeError):
    """The API answered with a redirect, which is never followed (see _RefuseRedirects)."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """urllib follows redirects by itself and resends the request's headers, Authorization included, to
    whatever host the Location names, from https to http too. The token must reach only the validated
    Snyk API host, so no redirect is followed: the call fails instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise RedirectRefused(f"{req.get_method()} {req.full_url.split('?')[0]} answered HTTP {code}, a redirect to "
                              f"{newurl.split('?')[0]}; not followed, so the token goes only to the Snyk API host")


_OPENER = urllib.request.build_opener(_RefuseRedirects)


def validate_api_base(api_base: str) -> str:
    """Refuse to send the token anywhere but a Snyk API host over HTTPS."""
    parsed = urllib.parse.urlparse(api_base)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not (host == "snyk.io" or host.endswith(".snyk.io")):
        raise UsageError(f"--api-base must be an https://*.snyk.io URL, got {api_base!r}")
    return api_base.rstrip("/")


def retry_after_seconds(headers: dict[str, str], default: float) -> float:
    """Retry-After may arrive in any case and as seconds or an HTTP date; fall back to the default."""
    return header_seconds(headers, "retry-after", default)


def header_seconds(headers: dict[str, str], wanted: str, default: float) -> float:
    """A header holding seconds, in any case; the default when absent or not a number."""
    for name, value in headers.items():
        if name.lower() == wanted:
            try:
                return float(value)
            except ValueError:
                return default
    return default


def rate_limit_message(wait: float) -> str:
    return (f"Snyk's closed-beta rate limit for this token is spent (1 call a second, 10 a minute, 100 an hour, "
            f"shared by every closed-beta API); it resets in about {int(wait) + 1} s. Nothing more was sent; "
            "re-run after that.")


class SnykClient:
    def __init__(self, token: str, api_base: str, rest_version: str, max_retries: int = 5):
        self._token = token
        self.api_base = validate_api_base(api_base)
        self.rest_version = rest_version
        self.max_retries = max_retries
        self.closed_beta_calls = 0
        self._cb_last: float | None = None  # when the last closed-beta call was answered
        self._cb_ready_at: float | None = None  # earliest next call after X-RateLimit-Remaining: 0

    # -- transport (overridden in tests) ---------------------------------------------
    def _send(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, dict[str, str], str]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with _OPENER.open(req, timeout=60) as resp:  # noqa: S310 (https enforced; redirects refused)
                return resp.status, dict(resp.headers), resp.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers or {}), err.read().decode("utf-8", "replace")

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def _clock(self) -> float:
        return time.monotonic()

    def request(self, method: str, url: str, payload: Any = None, rest: bool = False, closed_beta: bool = False) -> Any:
        headers = {"Authorization": f"token {self._token}", "Accept": "application/json"}
        if rest or closed_beta:
            headers["Content-Type"] = "application/vnd.api+json"
            headers["Accept"] = "application/vnd.api+json"
        elif payload is not None:
            headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None

        for attempt in range(self.max_retries + 1):
            if closed_beta:
                self._pace_closed_beta()
            try:
                status, resp_headers, text = self._send(method, url, headers, body)
            except urllib.error.URLError as err:  # DNS, TLS, proxy, connection refused, timeouts
                raise RuntimeError(f"cannot reach {method} {url.split('?')[0]}: {err.reason}") from err
            except (OSError, http.client.HTTPException) as err:  # timeout, reset, or a body cut short
                raise RuntimeError(f"connection lost while reading {method} {url.split('?')[0]}: "
                                   f"{str(err) or type(err).__name__}") from err
            if closed_beta:
                self._note_closed_beta(resp_headers)
            if 200 <= status < 300:
                try:
                    return json.loads(text) if text.strip() else {}
                except json.JSONDecodeError as err:
                    raise RuntimeError(f"{method} {url.split('?')[0]} returned a non-JSON body: {text[:200]!r}") from err
            if status in RETRYABLE and attempt < self.max_retries:
                wait = retry_after_seconds(resp_headers, 2 ** attempt)
                if closed_beta and status == 429:
                    wait = retry_after_seconds(resp_headers, header_seconds(resp_headers, "x-ratelimit-reset", 2 ** attempt))
                    if wait > CLOSED_BETA_MAX_WAIT:
                        raise RateLimited(rate_limit_message(wait))
                self._sleep(min(wait, 60))
                continue
            if closed_beta and status == 429:
                raise RateLimited(rate_limit_message(header_seconds(resp_headers, "x-ratelimit-reset", 60)))
            raise ApiError(status, text, method, url)
        raise AssertionError("unreachable")

    # -- closed-beta pacing ------------------------------------------------------------
    def closed_beta_wait(self) -> float:
        """Seconds the next closed-beta call must wait: one second after the last, and until the reset
        Snyk announced when an answer said X-RateLimit-Remaining: 0."""
        now = self._clock()
        wait = 0.0
        if self._cb_last is not None:
            wait = max(wait, self._cb_last + CLOSED_BETA_MIN_SPACING - now)
        if self._cb_ready_at is not None:
            wait = max(wait, self._cb_ready_at - now)
        return wait

    def ensure_closed_beta_budget(self) -> None:
        """Stop before a change when the next closed-beta call could not be made within the run's wait."""
        wait = self.closed_beta_wait()
        if wait > CLOSED_BETA_MAX_WAIT:
            raise RateLimited(rate_limit_message(wait))

    def _pace_closed_beta(self) -> None:
        wait = self.closed_beta_wait()
        if wait > CLOSED_BETA_MAX_WAIT:
            raise RateLimited(rate_limit_message(wait))
        if wait > 0:
            self._sleep(wait)
        self.closed_beta_calls += 1

    def _note_closed_beta(self, headers: dict[str, str]) -> None:
        now = self._clock()
        self._cb_last = now
        remaining = next((v.strip() for k, v in headers.items() if k.lower() == "x-ratelimit-remaining"), None)
        reset = header_seconds(headers, "x-ratelimit-reset", -1)
        self._cb_ready_at = now + reset if remaining == "0" and reset >= 0 else None

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
    def _follow(self, link: Any, prefix: str = "/rest") -> str | None:
        """Turn a JSON:API pagination link into an absolute URL on the Snyk API host, or None.

        Snyk returns links relative to the tier's base and without its prefix (e.g.
        "/orgs/<id>/projects?...&starting_after=..." for /rest); accept the prefixed form too.
        """
        if isinstance(link, dict):
            link = link.get("href")
        if not link:
            return None
        if link.startswith("/"):
            link = self.api_base + (link if link.startswith(prefix + "/") else prefix + link)
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
            projects += [{"id": p["id"], "name": p["attributes"]["name"], "origin": p["attributes"].get("origin", ""),
                          "target_id": (((p.get("relationships") or {}).get("target") or {}).get("data") or {}).get("id")}
                         for p in page.get("data", [])]
            url = self._follow((page.get("links") or {}).get("next"))
        return projects

    def list_ecr_projects(self, org_id: str) -> list[dict[str, str]]:
        return self.list_projects(org_id, ECR_ORIGIN)

    def delete_project(self, org_id: str, project_id: str) -> None:
        query = urllib.parse.urlencode({"version": self.rest_version})
        self.request("DELETE", f"{self.api_base}/rest/orgs/{org_id}/projects/{project_id}?{query}", rest=True)

    # -- REST API: targets (provenance in profiles mode; call 17) -----------------------------
    def list_targets(self, org_id: str) -> dict[str, str | None]:
        """Target ID -> the integration (connection) that imported it, following pagination."""
        params = {"version": self.rest_version, "limit": 100}
        url: str | None = f"{self.api_base}/rest/orgs/{org_id}/targets?{urllib.parse.urlencode(params)}"
        targets: dict[str, str | None] = {}
        while url:
            page = self.request("GET", url, rest=True)
            for t in page.get("data", []):
                targets[t["id"]] = (((t.get("relationships") or {}).get("integration") or {}).get("data") or {}).get("id")
            url = self._follow((page.get("links") or {}).get("next"))
        return targets

    # -- closed-beta Integrations API: documented only to beta customers (Principle IV exception,
    # -- specs/002-multi-ecr-connections/plan.md, Complexity Tracking; calls 13 to 16) ------------
    def _cb_url(self, path: str, **params: Any) -> str:
        query = urllib.parse.urlencode({"version": CLOSED_BETA_VERSION, **params})
        return f"{self.api_base}{CLOSED_BETA_PREFIX}{path}?{query}"

    def list_closed_beta_integrations(self, org_id: str) -> list[dict[str, Any]]:
        """Call 13: every integration of the org (all types), following pagination. The first page's
        answer is the mode signal, so only its errors reach the caller as ApiError."""
        page = self.request("GET", self._cb_url(f"/orgs/{org_id}/integrations", limit=100), closed_beta=True)
        entries = list(page.get("data") or [])
        url = self._follow((page.get("links") or {}).get("next"), CLOSED_BETA_PREFIX)
        while url:
            try:
                page = self.request("GET", url, closed_beta=True)
            except ApiError as err:
                raise RuntimeError(f"the closed-beta integrations list failed on a later page: HTTP {err.status}") from err
            entries += page.get("data") or []
            url = self._follow((page.get("links") or {}).get("next"), CLOSED_BETA_PREFIX)
        return entries

    def create_profile(self, org_id: str, name: str, region: str, role_arn: str) -> str:
        """Call 14: a new ECR connection (Snyk: profile)."""
        body = {"data": {"type": "integration", "attributes": {
            "integration_type": "ecr", "profile_name": name, "credentials": {"region": region, "role_arn": role_arn}}}}
        try:
            return self.request("POST", self._cb_url(f"/orgs/{org_id}/integrations"), body, closed_beta=True)["data"]["id"]
        except ApiError as err:
            if err.status == 409:
                raise Refusal(f"Snyk already has a connection named {name!r} in this org") from err
            raise

    def update_profile(self, org_id: str, integration_id: str, region: str, role_arn: str, name: str | None = None) -> None:
        """Call 15: repoint a connection (and rename it, when given a name), a partial update."""
        attributes: dict[str, Any] = {"credentials": {"region": region, "role_arn": role_arn}}
        if name:
            attributes["profile_name"] = name
        body = {"data": {"id": integration_id, "type": "integration", "attributes": attributes}}
        try:
            self.request("PATCH", self._cb_url(f"/orgs/{org_id}/integrations/{integration_id}"), body, closed_beta=True)
        except ApiError as err:
            if err.status == 409:
                raise Refusal(f"Snyk already has a connection named {name!r} in this org, so this one cannot take "
                              "that name; nothing was changed") from err
            raise

    def delete_profile(self, org_id: str, integration_id: str) -> bool:
        """Call 16: delete a connection; Snyk then deletes its projects. False if it was already gone."""
        try:
            self.request("DELETE", self._cb_url(f"/orgs/{org_id}/integrations/{integration_id}"), closed_beta=True)
            return True
        except ApiError as err:
            if err.status == 404:
                return False
            raise


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
    if args.exact_name:
        if not args.connection:
            raise UsageError("--exact-name needs --connection: the name to create")
        if args.mode not in ("plan", "apply"):
            raise UsageError("--exact-name applies to plan and apply only: it says how a new connection is named")
        if args.connection == DEFAULT_PROFILE_NAME:
            raise UsageError(f"{DEFAULT_PROFILE_NAME!r} is the name Snyk gives a connection made before the feature; "
                             "choose another name")


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


# -- connections (profiles mode) -----------------------------------------------------------
def registry_address(account: str, region: str) -> str:
    return f"{account}.dkr.ecr.{region}.amazonaws.com"


def account_of(role_arn: str) -> str:
    match = re.match(r"^arn:aws[a-z-]*:iam::(\d{12}):role/", role_arn)
    if not match:
        raise UsageError("--role-arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)")
    return match.group(1)


def connection_name(label: str | None, account: str, region: str) -> str:
    """The default name of a new connection: its registry address, with the engineer's label in front."""
    address = registry_address(account, region)
    return f"{label} {address}" if label else address


def parse_connection_name(name: str | None) -> tuple[str | None, str, str] | None:
    """(label, account, region) when the name carries its registry, else None."""
    match = CONNECTION_NAME_RE.match(name or "")
    return (match.group("label"), match.group("account"), match.group("region")) if match else None


def validate_label(label: str) -> None:
    if not LABEL_RE.match(label):
        raise UsageError(f"--connection {label!r} is not a label: a label starts with a letter or digit and holds only "
                         "letters, digits, '_', '-', and '.' (no spaces). Pass --exact-name to use it as the whole name.")


def validate_exact_name(name: str) -> None:
    if not PROFILE_NAME_RE.match(name):
        raise UsageError(f"{name!r} is not a name Snyk accepts: 1 to 255 characters, starting with a letter or digit, of "
                         "letters, digits, spaces, underscores, hyphens, and dots")


@dataclasses.dataclass(frozen=True)
class Connection:
    """One ECR connection of a profiles-mode org (Snyk: a profile). Snyk returns no region or role, so
    the registry is known only when the name carries it."""

    id: str
    name: str
    label: str | None = None
    account: str | None = None
    region: str | None = None

    @classmethod
    def from_entry(cls, entry: dict[str, Any]) -> Connection:
        name = (entry.get("attributes") or {}).get("profile_name") or DEFAULT_PROFILE_NAME
        label, account, region = parse_connection_name(name) or (None, None, None)
        return cls(entry["id"], name, label, account, region)

    @property
    def carries_ecr(self) -> bool:
        return self.account is not None

    @property
    def registry(self) -> str | None:
        return registry_address(self.account, self.region) if self.account and self.region else None

    @property
    def api_deletable(self) -> bool:
        return self.name != DEFAULT_PROFILE_NAME

    def where(self) -> str:
        return f"(account {self.account}, region {self.region})" if self.carries_ecr else "(registry not in its name)"

    def where_long(self) -> str:
        if self.carries_ecr:
            return self.where()
        return f"(account and region not in its name; Snyk's UI shows them under {PROFILE_UI_PATH})"


def connections_from(entries: list[dict[str, Any]]) -> list[Connection]:
    return sorted((Connection.from_entry(e) for e in entries
                   if (e.get("attributes") or {}).get("integration_type") == "ecr"), key=lambda c: c.name)


def endpoint_not_found(body: str) -> bool:
    try:
        errors = json.loads(body).get("errors") or []
    except (ValueError, AttributeError):
        return False
    return any(isinstance(e, dict) and e.get("detail") == "Endpoint Not Found" for e in errors)


def org_mode(client: SnykClient, org_id: str) -> tuple[str, list[Connection]]:
    """Call 13 decides the mode (research R1): 200 is profiles mode; 404 'Endpoint Not Found' is default
    mode; anything else stops the run before any change."""
    try:
        return "profiles", connections_from(client.list_closed_beta_integrations(org_id))
    except ApiError as err:
        if err.status == 404 and endpoint_not_found(err.body):
            return "default", []
        raise RuntimeError(
            f"cannot tell whether Snyk's multiple profiles feature is on for org {org_id}: its closed-beta Integrations "
            f"API answered HTTP {err.status}, neither 200 (on) nor 404 Endpoint Not Found (off). Nothing was changed."
        ) from err


@dataclasses.dataclass
class Resolution:
    connection: Connection | None  # the connection to use, or None to create one
    name: str  # its name, or the name to create
    warnings: list[str]


def find_named_connection(connections: list[Connection], value: str, exact: bool = False) -> Connection | None:
    """By full name first, then by label (data-model.md, Lookup). Several with one label is a refusal."""
    for conn in connections:
        if conn.name == value:
            return conn
    if exact:
        return None
    labeled = [c for c in connections if c.label == value]
    if len(labeled) > 1:
        raise Refusal(f"{len(labeled)} connections are labeled {value!r}; name one in full with --connection", connections)
    return labeled[0] if labeled else None


def resolve_connection(connections: list[Connection], args: argparse.Namespace, account: str, region: str) -> Resolution:
    """The lookup of research R3 for plan and apply: the connection to use, or the name to create."""
    address = registry_address(account, region)
    value = args.connection
    if value:
        conn = find_named_connection(connections, value, exact=args.exact_name)
        if conn:
            if conn.carries_ecr and conn.registry != address and not args.update_credentials:
                raise Refusal(f"connection {conn.name!r} points at registry {conn.registry}, not {address}. Nothing was "
                              "changed; pass --update-credentials to repoint it, or name another connection", connections)
            warnings = [] if conn.carries_ecr else [
                "Warning: this connection's name does not carry its registry, so its ECR cannot be checked "
                "against --region and --role-arn"]
            return Resolution(conn, conn.name, warnings)
        if args.exact_name:
            validate_exact_name(value)
            name = value
        elif parse_connection_name(value):
            _, named_account, named_region = parse_connection_name(value)
            if registry_address(named_account, named_region) != address:
                raise Refusal(f"--connection {value!r} names registry {registry_address(named_account, named_region)}, "
                              f"but --role-arn and --region give {address}", connections)
            name = value
        else:
            validate_label(value)
            name = connection_name(value, account, region)
        validate_exact_name(name)
        twins = [c.name for c in connections if c.registry == address]
        warnings = [f"Warning: {', '.join(twins)} already read{'s' if len(twins) == 1 else ''} registry {address}; "
                    "its images will be imported twice"] if twins else []
        if args.exact_name:
            warnings.append("Warning: this name does not carry the registry, so later runs cannot check its ECR")
        return Resolution(None, name, warnings)
    carrying = [c for c in connections if c.registry == address]
    if len(carrying) == 1:
        return Resolution(carrying[0], carrying[0].name, [])
    if len(carrying) > 1:
        raise Refusal(f"{len(carrying)} connections read registry {address}; name one with --connection", connections)
    unknown = [c for c in connections if not c.carries_ecr]
    if unknown:
        raise Refusal(f"no connection's name carries registry {address}, but {', '.join(repr(c.name) for c in unknown)} "
                      "carr" + ("ies" if len(unknown) == 1 else "y") + " no registry in "
                      + ("its name" if len(unknown) == 1 else "their names") + " and may read it. Nothing was changed; "
                      "name the connection to use, or a label for a new one, with --connection", connections)
    return Resolution(None, address, [])


def prefixed(args: argparse.Namespace, line: str) -> str:
    return f"{getattr(args, 'out_prefix', '')}{line}"


def use_connection(args: argparse.Namespace, name: str) -> None:
    """Every later line of the run names this connection (FR-009), and failure hints do too (FR-008)."""
    args.active_connection = name
    args.out_prefix = f"[{name}] "


def ensure_connection(client: SnykClient, args: argparse.Namespace, connections: list[Connection],
                      create: bool) -> tuple[str | None, bool]:
    """Profiles mode's ensure_integration: (connection id or None, fresh). Sets args.out_prefix."""
    account = account_of(args.role_arn)
    found = resolve_connection(connections, args, account, args.region)
    conn, name = found.connection, found.name
    use_connection(args, name)
    for warning in found.warnings:
        print(prefixed(args, warning))
    if conn is None:
        if not create:
            print(prefixed(args, f"ECR connection missing: apply would create it ({args.region}, {args.role_arn})"))
            return None, False
        client.ensure_closed_beta_budget()
        for attempt in range(1, args.connect_retries + 1):
            try:
                integration_id = client.create_profile(args.org_id, name, args.region, args.role_arn)
                print(prefixed(args, f"ECR connection created: {integration_id}"))
                return integration_id, True
            except ApiError as err:
                if err.status in FATAL or attempt == args.connect_retries:
                    raise
                print(prefixed(args, f"  connection create failed (HTTP {err.status}); IAM may still be propagating. "
                                     f"Retry {attempt}/{args.connect_retries - 1} in {args.connect_delay}s"), file=sys.stderr)
                client._sleep(args.connect_delay)
        raise AssertionError("unreachable")

    print(prefixed(args, f"ECR connection: {conn.id} {conn.where()}"))
    if not args.update_credentials:
        print(prefixed(args, "  reusing as-is; pass --update-credentials to point it at this role/region"))
        return conn.id, False
    new_name = connection_name(conn.label, account, args.region) if conn.carries_ecr else None
    if new_name == conn.name:
        new_name = None
    if not create:
        print(prefixed(args, "  would update credentials (--update-credentials)"
                       + (f" and rename it to {new_name!r}" if new_name else "")))
        return conn.id, False
    client.ensure_closed_beta_budget()
    client.update_profile(args.org_id, conn.id, args.region, args.role_arn, name=new_name)
    print(prefixed(args, "  credentials updated (--update-credentials)"))
    if new_name:
        print(prefixed(args, f"  renamed to {new_name!r}, so its name still carries its registry"))
        use_connection(args, new_name)
    return conn.id, True


def projects_by_connection(client: SnykClient, org_id: str, connections: list[Connection],
                           projects: list[dict[str, Any]] | None = None) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """ECR projects grouped by the connection that imported them, from Snyk's record (project -> target ->
    integration), never from names; plus the projects whose target names no listed connection."""
    projects = client.list_ecr_projects(org_id) if projects is None else projects
    targets = client.list_targets(org_id)
    known = {c.id for c in connections}
    grouped: dict[str, list[dict[str, Any]]] = {c.id: [] for c in connections}
    unknown: list[dict[str, Any]] = []
    for project in projects:
        integration = targets.get(project.get("target_id") or "")
        if integration in known:
            grouped[integration].append(project)
        else:
            unknown.append(project)
    return grouped, unknown


def policy_summary(policy: dict[str, Any] | None) -> str:
    if not policy:
        return "none"
    return (f"{policy.get('name')} "
            f"(import_policy {', '.join(policy_types(policy.get('import_policy'))) or '?'}; "
            f"schedule_frequency_hours {policy.get('schedule_frequency_hours', f'{SNYK_DEFAULT_SCHEDULE_HOURS} (Snyk default)')}; "
            f"delete_images {str(policy.get('delete_images', False)).lower()})")


def run_status_profiles(args: argparse.Namespace, client: SnykClient, connections: list[Connection]) -> int:
    """Read-only: every connection (or the named one), its policy, and the ECR projects it imported."""
    shown = connections
    if args.connection:
        conn = find_named_connection(connections, args.connection)
        if conn is None:
            raise Refusal(f"no connection named or labeled {args.connection!r}", connections)
        shown = [conn]
    projects = client.list_ecr_projects(args.org_id)
    grouped, unknown = projects_by_connection(client, args.org_id, connections, projects)
    if not connections:
        print("ECR connections: none")
    for conn in shown:
        args.out_prefix = f"[{conn.name}] "
        print(prefixed(args, f"ECR connection: {conn.id} {conn.where_long()}"))
        print(prefixed(args, f"Sync policy    : {policy_summary(client.get_policy(args.org_id, conn.id))}"))
        mine = grouped.get(conn.id, [])
        print(prefixed(args, f"ECR projects   : {len(mine)}"))
        for project in mine[:20]:
            print(prefixed(args, f"  - {project['name']}"))
        if len(mine) > 20:
            print(prefixed(args, f"  ... and {len(mine) - 20} more"))
    args.out_prefix = ""
    if unknown and not args.connection:
        print(f"Connection unknown: {len(unknown)} project(s) whose target names no listed connection "
              "(a connection disconnected moments ago can still show projects Snyk is deleting)")
        for project in unknown[:20]:
            print(f"  ? {project['name']}")
    if args.all_origins:
        names = {c.id: c.name for c in connections}
        targets = client.list_targets(args.org_id)
        everything = client.list_projects(args.org_id, origin=None)
        print(f"All projects   : {len(everything)} (any origin)")
        for project in everything[:50]:
            via = names.get(targets.get(project.get("target_id") or ""), "unknown") if project["origin"] == ECR_ORIGIN else None
            print(f"  * {project['name']}  [origin: {project['origin'] or '?'}"
                  + (f", connection: {via}" if via else "") + "]")
        if len(everything) > 50:
            print(f"  ... and {len(everything) - 50} more")
    return 0


def run_teardown_profiles(args: argparse.Namespace, client: SnykClient, connections: list[Connection]) -> int:
    """Pause or disconnect one named connection (FR-012 to FR-015). Dry run unless --yes."""
    if not args.connection:
        raise Refusal("teardown needs --connection in profiles mode: name the connection to pause or disconnect", connections)
    conn = find_named_connection(connections, args.connection)
    if conn is None:
        raise Refusal(f"no connection named or labeled {args.connection!r}", connections)
    if args.delete_credentials:
        raise Refusal("--delete-credentials applies to default mode only; use --delete-connection to disconnect, or "
                      "a teardown without options to pause", connections)
    if args.delete_connection and not conn.api_deletable:
        raise Refusal(f"Snyk does not let its API delete {conn.name!r}, a connection made before the feature. Remove it "
                      f"in Snyk's UI under {PROFILE_UI_PATH}, or rename it there to its registry address so this tool "
                      "can recognize it. Nothing was changed.", connections)
    args.out_prefix = f"[{conn.name}] "
    has_policy = bool(client.get_policy(args.org_id, conn.id))
    mine: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    if args.delete_projects or args.delete_connection:
        grouped, unknown = projects_by_connection(client, args.org_id, connections)
        mine = grouped.get(conn.id, [])
    prefix = args.repo_prefix or ""
    doomed = [p for p in mine if repository_of(p["name"]).startswith(prefix)] if args.delete_projects else []
    if args.delete_projects:
        unattributed = [p for p in unknown if repository_of(p["name"]).startswith(prefix)]
        if unattributed:
            raise Refusal(f"{len(unattributed)} ECR project(s){f' under prefix {prefix!r}' if prefix else ''} have no "
                          f"recorded connection, so this tool cannot tell whether they belong to {conn.name!r}. "
                          "Nothing was deleted.", connections)

    print(prefixed(args, f"ECR connection: {conn.id} {conn.where()}"))
    print(prefixed(args, f"Sync policy    : {'present, will be deleted (stops auto-import)' if has_policy else 'none'}"))
    if args.delete_projects:
        scope = f" under prefix {prefix!r}" if prefix else ""
        print(prefixed(args, f"Projects       : {len(doomed)} project(s) imported through it{scope} will be deleted"))
        for project in doomed[:10]:
            print(prefixed(args, f"  - {project['name']}"))
        if len(doomed) > 10:
            print(prefixed(args, f"  ... and {len(doomed) - 10} more"))
    else:
        print(prefixed(args, "Projects       : left in place (pass --delete-projects to remove them)"))
    if args.delete_connection:
        print(prefixed(args, f"Connection: will be deleted, and with it {len(mine)} project(s) imported through it"))
        if unknown:
            print(prefixed(args, f"  ({len(unknown)} other ECR project(s) have no recorded connection and are not counted)"))
    else:
        print(prefixed(args, "Connection     : left in place (pass --delete-connection to disconnect; Snyk then deletes "
                             "its projects)"))
    if not args.yes:
        print("Dry run only; re-run with --yes to execute.")
        return 0

    if args.delete_connection:
        client.ensure_closed_beta_budget()  # stop now rather than after the policy and projects are gone
    if client.delete_policy(args.org_id, conn.id):
        print(prefixed(args, "Sync policy deleted."))
    for project in doomed:
        client.delete_project(args.org_id, project["id"])
    if doomed:
        print(prefixed(args, f"Deleted {len(doomed)} project(s)."))
    if args.delete_connection:
        if client.delete_profile(args.org_id, conn.id):
            print(prefixed(args, "Connection deleted; Snyk is deleting its projects."))
        else:
            print(prefixed(args, "Connection: already gone."))
    print("Not removed: the org's other connections, and the AWS role (terraform destroy). The Snyk org is never touched.")
    return 0


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
                print(prefixed(args, f"  {err}; the new credentials may still be propagating. "
                               f"Retry {attempt}/{attempts - 1} in {args.connect_delay}s"), file=sys.stderr)
                client._sleep(args.connect_delay)
                continue
            name = getattr(args, "active_connection", None)
            if name and fresh:
                raise DryRunFailed(
                    f"{err}. Snyk still cannot use the role for connection {name!r} of org {args.org_id} after {attempts} "
                    "attempts. Likely causes (this script cannot read the role's trust policy, so check them in AWS):\n"
                    f"  - org {args.org_id} is missing from the role's sts:ExternalId list: add it to the org IDs the role "
                    "trusts (snyk_profile_orgs or snyk_orgs in examples/main.tf, snyk_org_ids on the module), keep every "
                    "existing ID, and run terraform apply\n"
                    "  - the Snyk principal in the role's trust policy is not the one your Snyk tenant's UI shows\n"
                    f"  - --region {args.region} is not the region of the ECR registry\n"
                    "  - us-east-2 is not enabled for STS in the AWS account\n"
                    f"The connection now exists, so after the fix re-run 'apply' with --connection {name!r} "
                    "--update-credentials: it stores the role and region again and retries while the change "
                    "propagates.") from err
            if name:
                raise DryRunFailed(f"{err}. If connection {name!r} of org {args.org_id} points at another role/region, "
                                   f"re-run 'apply' with --connection {name!r} --update-credentials.") from err
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


def summarise(result: dict[str, Any], prefix: str = "") -> tuple[int, int]:
    to_import = count_tags(result["images_to_import"])
    to_delete = count_tags(result["images_to_delete"])
    print(f"{prefix}Dry run: Snyk processed {result['total_images_processed']} images; {to_import} to import, {to_delete} to delete")
    for entry in result["images_to_import"][:10]:
        tags = ", ".join(t["tag"] for t in entry["tags"][:5])
        print(f"{prefix}  + {entry['repository']}: {tags}{' ...' if len(entry['tags']) > 5 else ''}")
    if len(result["images_to_import"]) > 10:
        print(f"{prefix}  ... and {len(result['images_to_import']) - 10} more repositories")
    return to_import, to_delete


def connection_test(client: SnykClient, args: argparse.Namespace, integration_id: str, fresh: bool) -> None:
    """Prove Snyk can read the registry: an ImportAll dry run lists repositories and tags, imports nothing."""
    result = checked_dry_run(client, args, integration_id, CONNECTION_TEST_POLICY, fresh)
    repos = result["images_to_import"]
    print(prefixed(args, f"Snyk can read the registry: {len(repos)} repositories with tagged images ({count_tags(repos)} tags) "
                   "visible; nothing imported."))
    for entry in repos[:10]:
        print(prefixed(args, f"  {entry['repository']} ({len(entry.get('tags', []))} tags)"))
    if len(repos) > 10:
        print(prefixed(args, f"  ... and {len(repos) - 10} more repositories"))


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
    mode, connections = org_mode(client, args.org_id)  # before anything else (FR-002)
    args.org_mode = mode
    if mode == "default":
        given = [flag for flag, on in (("--connection", args.connection), ("--exact-name", args.exact_name),
                                       ("--delete-connection", args.delete_connection)) if on]
        if given:
            raise UsageError(f"this org is in default mode (Snyk's multiple profiles feature is off for it), so it holds "
                             f"at most one ECR integration and {', '.join(given)} do{'es' if len(given) == 1 else ''} not "
                             "apply. Nothing was changed.")
        return run_default(args, client)
    print(MODE_LINE)
    try:
        return run_profiles(args, client, connections)
    finally:
        print(f"Closed-beta calls: {client.closed_beta_calls}", file=sys.stderr)


def run_profiles(args: argparse.Namespace, client: SnykClient, connections: list[Connection]) -> int:
    if args.mode == "status":
        return run_status_profiles(args, client, connections)
    if args.mode == "teardown":
        return run_teardown_profiles(args, client, connections)
    if not STANDARD_ROLE_ARN_RE.match(args.role_arn) or args.region.startswith(OTHER_PARTITION_REGIONS):
        raise UsageError("Snyk's profiles accept only IAM roles in AWS's standard partition (arn:aws:iam::...); a registry "
                         "in AWS China or GovCloud can be connected only to an org in default mode. Nothing was changed.")
    return run_sync(args, client, lambda create: ensure_connection(client, args, connections, create))


def run_default(args: argparse.Namespace, client: SnykClient) -> int:
    if args.mode == "status":
        return run_status(args, client)
    if args.mode == "teardown":
        if args.delete_projects and not args.repo_prefix:
            raise UsageError("--repo-prefix is required with --delete-projects (it scopes what is deleted)")
        return run_teardown(args, client)
    return run_sync(args, client, lambda create: ensure_integration(client, args, create))


def run_sync(args: argparse.Namespace, client: SnykClient, ensure: Any) -> int:
    """plan and apply, in either mode: connectivity through `ensure`, then the sync."""
    apply_mode = args.mode == "apply"
    policy = None
    types: list[str] = []
    if not args.no_sync:
        policy = policy_from_file(args.policy_file, args.policy_name) if args.policy_file else policy_from_flags(args)
        types = check_policy(policy)

    # 1. Connectivity
    integration_id, fresh = ensure(apply_mode)
    if integration_id is None:
        print(prefixed(args, "Nothing more to check in plan mode: the connection test needs an existing integration."))
        if policy:
            print(prefixed(args, "Sync policy apply would set:\n") + json.dumps(policy, indent=2))
        else:
            print(prefixed(args, "--no-sync: apply would only connect."))
        return 0
    connection_test(client, args, integration_id, fresh)
    if policy is None:
        print(prefixed(args, "Connected (--no-sync): import images from the Snyk UI, or re-run without --no-sync to set up "
                             "the sync." if apply_mode else "Plan only; apply would connect without setting up the sync."))
        return 0

    # 2. Sync
    to_import, _ = summarise(checked_dry_run(client, args, integration_id, policy, fresh=False), getattr(args, "out_prefix", ""))
    if "ImportAllNew" in types:
        print(prefixed(args, "note: Snyk records the images that exist when the policy is created as a baseline; "
                             "ImportAllNew imports only images pushed after that, so the preview of existing images can be "
                             "empty."))
    if not apply_mode:
        print(prefixed(args, "Plan only; re-run with 'apply' to connect and set up the sync."))
        return 0

    if to_import > args.max_images and not args.force:
        print(
            prefixed(args, f"Refusing to apply: {to_import} images would be imported, above --max-images {args.max_images}. "
                     "Narrow the policy, raise --max-images, or pass --force."),
            file=sys.stderr,
        )
        return 2

    client.apply_policy(args.org_id, integration_id, policy)
    hours = policy.get("schedule_frequency_hours", f"{SNYK_DEFAULT_SCHEDULE_HOURS} (Snyk default)")
    name = getattr(args, "active_connection", None)
    target = f"connection {name}" if name else f"integration {integration_id}"
    print(prefixed(args, f"Sync policy applied for {target}; Snyk runs it now and then every {hours} hours."))
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
    prof = p.add_argument_group("profiles mode (orgs where Snyk has turned on its multiple profiles feature)")
    prof.add_argument("--connection", help="The connection to act on, by label or full name; a new one is named "
                                           "'<label> <registry address>'. Refused on an org in default mode")
    prof.add_argument("--exact-name", action="store_true",
                      help="plan/apply: name a new connection exactly --connection, with no registry address added")
    prof.add_argument("--delete-connection", action="store_true",
                      help="teardown: delete the named connection; Snyk then deletes every project imported through it")
    p.add_argument("--update-credentials", action="store_true", help="Point an existing ECR integration at this role/region")
    p.add_argument("--max-images", type=int, default=1000, help="Sync: refuse to apply above this many images")
    p.add_argument("--force", action="store_true", help="Sync: apply even above --max-images")
    p.add_argument("--delete-projects", action="store_true",
                   help="teardown: also delete ECR projects whose repository starts with --repo-prefix (profiles mode: "
                        "the projects imported through the named connection, optionally narrowed by --repo-prefix)")
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
    if hasattr(sys.stdout, "reconfigure"):  # a real stream, not a test's capture
        sys.stdout.reconfigure(line_buffering=True)  # keep stdout and stderr in order when piped (CI, tee)
    args = parse_args(argv)
    token = os.environ.get("SNYK_TOKEN")
    if not token:
        print("error: set SNYK_TOKEN in the environment (service-account token)", file=sys.stderr)
        return 1
    try:
        return run(args, SnykClient(token, args.api_base, args.api_version))
    except Refusal as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        if refusal.connections:
            print("Connections in this org:", file=sys.stderr)
            for conn in refusal.connections:
                print(f"  {conn.name} {conn.where()}", file=sys.stderr)
        return 1
    except (UsageError, ApiError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyError as err:
        print(f"error: unexpected Snyk API response (missing field {err})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
