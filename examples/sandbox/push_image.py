#!/usr/bin/env python3
"""Copy the e2e test image into an ECR repository over the registry HTTP API, without Docker.

    aws ecr get-login-password --region <region> | \
        uv run push_image.py [--source-tag 3.18] <account>.dkr.ecr.<region>.amazonaws.com/<repository> v1.0.0 latest

The image is the one e2e.sh pushes with Docker when a Docker engine is running: alpine 3.18 for
linux/amd64 from Docker Hub. When Docker Hub refuses with HTTP 429 (its anonymous pulls are counted
per address), AWS's public mirror of Docker's official images (public.ecr.aws) is used instead,
signed in when PUBLIC_ECR_PASSWORD holds `aws ecr-public get-login-password --region us-east-1`.
The ECR password is read from stdin, never from the command line, and no credential follows a
redirect to another host. Standard library only (Principle II), like the rest of the harness.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

# (name, token URL, registry base, repository), tried in order; the next one only after an HTTP 429.
SOURCES = (
    ("Docker Hub", "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull",
     "https://registry-1.docker.io", "library/alpine"),
    ("AWS's public mirror", "https://public.ecr.aws/token/?service=public.ecr.aws&scope=repository:docker/library/alpine:pull",
     "https://public.ecr.aws", "docker/library/alpine"),
)
SOURCE_TAG = "3.18"
PLATFORM = {"os": "linux", "architecture": "amd64"}
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
DEST_RE = re.compile(r"^(\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com)/([a-z0-9][a-z0-9._/-]*)$")

Send = Callable[[str, str, dict, "bytes | None"], "tuple[int, dict, bytes]"]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # copy_image follows redirects itself, dropping credentials when the host changes


_OPENER = urllib.request.build_opener(_NoRedirects)


def http_send(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=120) as resp:  # noqa: S310 (https URLs only, see parse_destination)
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers or {}), err.read()


def parse_destination(dest: str) -> tuple[str, str]:
    """'<account>.dkr.ecr.<region>.amazonaws.com/<repository>' -> (registry base URL, repository)."""
    match = DEST_RE.match(dest)
    if not match:
        raise ValueError(f"not an ECR repository: {dest!r} (expected <account>.dkr.ecr.<region>.amazonaws.com/<repository>)")
    return f"https://{match.group(1)}", match.group(2)


def _header(headers: dict, name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), None)


def _host(url: str) -> str:
    return urllib.parse.urlparse(url).netloc


def _request(send: Send, method: str, url: str, auth: str | None, headers: dict | None = None,
             body: bytes | None = None, expect: tuple[int, ...] = (200,)) -> tuple[dict, bytes, str]:
    """One registry call, following up to five redirects. Authorization goes only to the host it was
    meant for. Returns (headers, body, final URL); any other status is a RuntimeError without secrets."""
    origin = _host(url)
    for _ in range(6):
        sent = dict(headers or {})
        if auth and _host(url) == origin:
            sent["Authorization"] = auth
        status, resp_headers, data = send(method, url, sent, body)
        location = _header(resp_headers, "Location")
        if status in (301, 302, 303, 307, 308) and location and method in ("GET", "HEAD"):
            url = urllib.parse.urljoin(url, location)
            if not url.startswith("https://"):
                raise RuntimeError(f"{method} redirected to a non-HTTPS URL; refused")
            continue
        if status not in expect:
            raise RuntimeError(f"{method} {url.split('?')[0]} answered HTTP {status}: {data[:200]!r}")
        return resp_headers, data, url
    raise RuntimeError(f"{method} {url.split('?')[0]}: too many redirects")


def _checked(data: bytes, digest: str) -> bytes:
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f"downloaded content does not match its digest {digest}; refused")
    return data


def _pull_manifest(send: Send, source: tuple[str, str, str, str], public_ecr_password: str | None,
                   source_tag: str = SOURCE_TAG) -> tuple[str, str, str, bytes]:
    """(pull authorization, source repository URL, manifest media type, manifest bytes) for linux/amd64."""
    _, token_url, base, repository = source
    auth = None
    if public_ecr_password and _host(token_url) == "public.ecr.aws":
        auth = "Basic " + base64.b64encode(f"AWS:{public_ecr_password}".encode()).decode()
    _, token_body, _ = _request(send, "GET", token_url, auth)
    answer = json.loads(token_body)
    pull = f"Bearer {answer.get('token') or answer['access_token']}"
    src = f"{base}/v2/{repository}"
    accept = {"Accept": ", ".join(INDEX_TYPES + MANIFEST_TYPES)}
    headers, body, _ = _request(send, "GET", f"{src}/manifests/{source_tag}", pull, accept)
    media_type = (_header(headers, "Content-Type") or json.loads(body).get("mediaType") or "").split(";")[0]
    if media_type in INDEX_TYPES:
        entry = next((m for m in json.loads(body)["manifests"]
                      if all(m.get("platform", {}).get(k) == v for k, v in PLATFORM.items())), None)
        if entry is None:
            raise RuntimeError(f"{repository}:{source_tag} has no {PLATFORM['os']}/{PLATFORM['architecture']} image")
        headers, body, _ = _request(send, "GET", f"{src}/manifests/{entry['digest']}", pull,
                                    {"Accept": ", ".join(MANIFEST_TYPES)})
        body = _checked(body, entry["digest"])
        media_type = (_header(headers, "Content-Type") or entry.get("mediaType") or "").split(";")[0]
    if media_type not in MANIFEST_TYPES:
        raise RuntimeError(f"unexpected manifest type {media_type!r}")
    return pull, src, media_type, body


def copy_image(dest: str, tags: list[str], password: str, send: Send = http_send,
               public_ecr_password: str | None = None, source_tag: str = SOURCE_TAG) -> str:
    """Copy the source image's linux/amd64 manifest and blobs to dest under every tag; returns its digest."""
    ecr, repository = parse_destination(dest)
    push = "Basic " + base64.b64encode(f"AWS:{password}".encode()).decode()
    for i, source in enumerate(SOURCES):
        try:
            pull, src, media_type, body = _pull_manifest(send, source, public_ecr_password, source_tag)
            break
        except RuntimeError as err:
            if "HTTP 429" not in str(err) or i == len(SOURCES) - 1:
                raise
            print(f"note: {source[0]} refused the pull (HTTP 429); trying {SOURCES[i + 1][0]}", file=sys.stderr)
    manifest = json.loads(body)

    dst = f"{ecr}/v2/{repository}"
    for blob in [manifest["config"], *manifest["layers"]]:
        digest = blob["digest"]
        status = send("HEAD", f"{dst}/blobs/{digest}", {"Authorization": push}, None)[0]
        if status == 200:
            continue
        if status != 404:
            raise RuntimeError(f"HEAD {dst}/blobs/{digest} answered HTTP {status}")
        _, data, _ = _request(send, "GET", f"{src}/blobs/{digest}", pull)
        data = _checked(data, digest)
        start, _, _ = _request(send, "POST", f"{dst}/blobs/uploads/", push, expect=(202,))
        location = urllib.parse.urljoin(ecr + "/", _header(start, "Location") or "")
        chunk, _, _ = _request(send, "PATCH", location, push, {
            "Content-Type": "application/octet-stream", "Content-Length": str(len(data)),
            "Content-Range": f"0-{len(data) - 1}"}, data, expect=(201, 202))  # ECR answers 201, the spec says 202
        location = urllib.parse.urljoin(ecr + "/", _header(chunk, "Location") or location)
        joiner = "&" if "?" in location else "?"
        _request(send, "PUT", f"{location}{joiner}{urllib.parse.urlencode({'digest': digest})}", push,
                 {"Content-Length": "0"}, b"", expect=(201,))
    for tag in tags:
        _request(send, "PUT", f"{dst}/manifests/{tag}", push, {"Content-Type": media_type}, body, expect=(201,))
    return "sha256:" + hashlib.sha256(body).hexdigest()


def main(argv: list[str] | None = None, stdin_text: str | None = None, send: Send = http_send) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    source_tag = SOURCE_TAG
    if args[:1] == ["--source-tag"] and len(args) > 1:
        source_tag, args = args[1], args[2:]
    if len(args) < 2 or not re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", source_tag):
        print(__doc__, file=sys.stderr)
        return 1
    password = (sys.stdin.read() if stdin_text is None else stdin_text).strip()
    if not password:
        print("error: pipe the ECR password in: aws ecr get-login-password --region <region> | uv run push_image.py ...",
              file=sys.stderr)
        return 1
    try:
        digest = copy_image(args[0], args[1:], password, send=send,
                            public_ecr_password=os.environ.get("PUBLIC_ECR_PASSWORD") or None, source_tag=source_tag)
    except (ValueError, RuntimeError, KeyError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    for tag in args[1:]:
        print(f"pushed {args[0]}:{tag} ({digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
