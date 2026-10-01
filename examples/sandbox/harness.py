#!/usr/bin/env python3
"""Snyk side of the e2e test infrastructure: a THROWAWAY org. Test harness only, not the product.

  uv run harness.py groups                                   list the groups your token can see
  uv run harness.py create-org --group-id G --name ecr-e2e-X  create an org, print its ID
  uv run harness.py org-exists --org-id O                     exit 0 exists, 1 missing/no access, 2 error
  uv run harness.py org-listed --group-id G --org-id O        exit 0 listed in the group, 1 not listed, 2 error
  uv run harness.py delete-org --org-id O [--protect ID ...]  delete an org the harness created

Deletion is guarded three ways: the org's name must start with ORG_PREFIX (only this harness creates
such orgs), IDs passed with --protect are refused, and Snyk itself only deletes orgs with no projects.
The org is created without sourceOrgId, so no integrations or settings are copied into it.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
from onboard_ecr import DEFAULT_API_BASE, DEFAULT_REST_VERSION, UUID_RE, ApiError, SnykClient, UsageError  # noqa: E402

ORG_PREFIX = "ecr-e2e-"


def org_name(client: SnykClient, org_id: str) -> str | None:
    """The org's name, or None if it does not exist or the token cannot see it."""
    query = urllib.parse.urlencode({"version": client.rest_version})
    try:
        page = client.request("GET", f"{client.api_base}/rest/orgs/{org_id}?{query}", rest=True)
    except ApiError as err:
        if err.status in (403, 404):
            return None
        raise
    return page["data"]["attributes"]["name"]


def create_org(client: SnykClient, group_id: str, name: str) -> str:
    if not name.startswith(ORG_PREFIX):
        raise UsageError(f"--name must start with {ORG_PREFIX!r}, so that delete-org can recognise it later")
    if not UUID_RE.match(group_id):
        raise UsageError("--group-id must be a Snyk group UUID (see: harness.py groups)")
    try:
        return client.request("POST", f"{client.api_base}/v1/org", {"name": name, "groupId": group_id})["id"]
    except ApiError as err:
        if err.status == 404:
            raise UsageError(f"Snyk found no group {group_id}. SNYK_GROUP_ID must be a group ID, not an org ID; "
                             "list the groups your token can see with: uv run harness.py groups") from err
        raise


def delete_org(client: SnykClient, org_id: str, protected: list[str]) -> bool:
    """Delete an org this harness created. Returns False if it was already gone."""
    if not UUID_RE.match(org_id):
        raise UsageError("--org-id must be a Snyk org UUID")
    if org_id.lower() in {p.lower() for p in protected if p}:
        raise UsageError(f"refusing to delete protected org {org_id}")
    name = org_name(client, org_id)
    if name is None:
        return False
    if not name.startswith(ORG_PREFIX):
        raise UsageError(f"refusing to delete org {org_id} named {name!r}: only orgs named {ORG_PREFIX}* "
                         "(created by this harness) can be deleted")
    try:
        client.request("DELETE", f"{client.api_base}/v1/org/{org_id}")
    except ApiError as err:
        if err.status == 404:
            return False
        raise
    return True


def org_listed(client: SnykClient, group_id: str, org_id: str) -> bool:
    """Whether the group's org list (REST GET /groups/{group_id}/orgs) still includes the org."""
    query = urllib.parse.urlencode({"version": client.rest_version, "name": ORG_PREFIX, "limit": 100})
    url: str | None = f"{client.api_base}/rest/groups/{group_id}/orgs?{query}"
    while url:
        page = client.request("GET", url, rest=True)
        if any(o.get("id") == org_id for o in page.get("data", [])):
            return True
        url = client._follow((page.get("links") or {}).get("next"))
    return False


def list_groups(client: SnykClient) -> list[tuple[str, str]]:
    groups: dict[str, str] = {}
    for org in client.request("GET", f"{client.api_base}/v1/orgs").get("orgs", []):
        group = org.get("group") or {}
        if group.get("id"):
            groups[group["id"]] = group.get("name", "")
    return sorted(groups.items(), key=lambda item: item[1].lower())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api-base", default=os.environ.get("SNYK_API_BASE", DEFAULT_API_BASE))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("groups")
    c = sub.add_parser("create-org")
    c.add_argument("--group-id", required=True)
    c.add_argument("--name", required=True)
    e = sub.add_parser("org-exists")
    e.add_argument("--org-id", required=True)
    li = sub.add_parser("org-listed")
    li.add_argument("--group-id", required=True)
    li.add_argument("--org-id", required=True)
    d = sub.add_parser("delete-org")
    d.add_argument("--org-id", required=True)
    d.add_argument("--protect", action="append", default=[], help="an org ID that must never be deleted (repeatable)")
    args = p.parse_args(argv)

    token = os.environ.get("SNYK_TOKEN")
    if not token:
        print("error: set SNYK_TOKEN in the environment", file=sys.stderr)
        return 2
    try:
        client = SnykClient(token, args.api_base, DEFAULT_REST_VERSION)
        if args.cmd == "groups":
            for group_id, name in list_groups(client):
                print(f"{group_id}  {name}")
        elif args.cmd == "create-org":
            print(create_org(client, args.group_id, args.name))
        elif args.cmd == "org-exists":
            return 0 if org_name(client, args.org_id) is not None else 1
        elif args.cmd == "org-listed":
            return 0 if org_listed(client, args.group_id, args.org_id) else 1
        elif args.cmd == "delete-org":
            print("deleted" if delete_org(client, args.org_id, args.protect) else "already gone")
        return 0
    except (UsageError, ApiError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
