"""Offline tests for the e2e harness's Docker-free image copy (examples/sandbox/push_image.py)."""

import hashlib
import json
import pathlib
import sys
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "examples" / "sandbox"))
import push_image as pi  # noqa: E402

DEST = "123456789012.dkr.ecr.ap-southeast-2.amazonaws.com/snyk-e2e/app"
ECR = "https://123456789012.dkr.ecr.ap-southeast-2.amazonaws.com"
SRC = "https://registry-1.docker.io"
MIRROR = "https://public.ecr.aws"
PASSWORD = "ecr-password-do-not-print"
LAYER = b"layer bytes" * 100
CONFIG = b'{"architecture":"amd64","os":"linux"}'


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


MANIFEST = json.dumps({
    "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(CONFIG), "size": len(CONFIG)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(LAYER), "size": len(LAYER)}],
}, separators=(",", ":")).encode()
INDEX = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
    {"digest": "sha256:" + "a" * 64, "mediaType": "application/vnd.oci.image.manifest.v1+json",
     "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
    {"digest": digest(MANIFEST), "mediaType": "application/vnd.oci.image.manifest.v1+json",
     "platform": {"os": "linux", "architecture": "amd64"}},
]}).encode()


class FakeRegistries:
    """public.ecr.aws (source, with a CDN redirect for the layer) and one ECR registry (destination)."""

    def __init__(self, config_present=True, ecr_status=None, hub_status=None, patch_status=202):
        self.calls = []
        self.patch_status = patch_status
        self.hub_status = hub_status
        self.config_present = config_present
        self.ecr_status = ecr_status
        self.uploaded = {}
        self.manifests = {}

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        path = url.split("?")[0]
        if url.startswith("https://auth.docker.io/token") or url.startswith(f"{MIRROR}/token/"):
            return 200, {}, json.dumps({"token": "pull-token"}).encode()
        if url.startswith(SRC) and self.hub_status:
            return self.hub_status, {}, b'{"errors":[{"code":"TOOMANYREQUESTS"}]}'
        if url.startswith(SRC) or url.startswith(MIRROR):
            assert headers.get("Authorization") == "Bearer pull-token", "the source needs the pull token"
            if path.endswith("/manifests/3.18"):
                return 200, {"Content-Type": "application/vnd.oci.image.index.v1+json"}, INDEX
            if path.endswith(f"/manifests/{digest(MANIFEST)}"):
                return 200, {"Content-Type": "application/vnd.oci.image.manifest.v1+json"}, MANIFEST
            if path.endswith(f"/blobs/{digest(CONFIG)}"):
                return 200, {}, CONFIG
            if path.endswith(f"/blobs/{digest(LAYER)}"):
                return 307, {"Location": "https://cdn.example.net/layer?signature=x"}, b""
        if url.startswith("https://cdn.example.net/"):
            return 200, {}, LAYER
        if url.startswith(ECR):
            if self.ecr_status:
                return self.ecr_status, {}, b'{"errors":[{"code":"DENIED"}]}'
            if method == "HEAD" and "/blobs/sha256:" in path:
                present = path.endswith(digest(CONFIG)) and self.config_present
                return (200 if present else 404), {}, b""
            if method == "POST" and path.endswith("/blobs/uploads/"):
                return 202, {"Location": "/v2/snyk-e2e/app/blobs/uploads/u1?_state=s1"}, b""
            if method == "PATCH" and "/blobs/uploads/u1" in path:
                self.uploaded["u1"] = body
                return self.patch_status, {"Location": f"{ECR}/v2/snyk-e2e/app/blobs/uploads/u1?_state=s2"}, b""
            if method == "PUT" and "/blobs/uploads/u1" in path:
                return 201, {}, b""
            if method == "PUT" and "/manifests/" in path:
                self.manifests[path.rsplit("/", 1)[-1]] = (headers.get("Content-Type"), body)
                return 201, {}, b""
        raise AssertionError(f"unexpected call {method} {url}")


class PushImageTests(unittest.TestCase):
    def test_copies_the_amd64_image_under_each_tag_with_the_manifest_unchanged(self):
        fake = FakeRegistries(config_present=False)
        self.assertEqual(pi.copy_image(DEST, ["v1.0.0", "latest"], PASSWORD, send=fake), digest(MANIFEST))
        self.assertEqual(set(fake.manifests), {"v1.0.0", "latest"})
        for content_type, body in fake.manifests.values():
            self.assertEqual((content_type, body), ("application/vnd.oci.image.manifest.v1+json", MANIFEST))
        self.assertFalse([u for _, u, _, _ in fake.calls if "a" * 64 in u], "the arm64 manifest is never fetched")

    def test_the_source_is_docker_hub_pulled_with_an_anonymous_token(self):
        fake = FakeRegistries()
        pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=fake)
        self.assertIn("scope=repository:library/alpine:pull", fake.calls[0][1])
        self.assertNotIn("Authorization", fake.calls[0][2])
        self.assertTrue(fake.calls[1][1].startswith(f"{SRC}/v2/library/alpine/manifests/3.18"))

    def test_a_refused_docker_hub_falls_back_to_the_mirror_signed_in_with_aws(self):
        fake = FakeRegistries(hub_status=429)
        with unittest.mock.patch("sys.stderr"):
            pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=fake, public_ecr_password="public-ecr-pw")
        mirror_token = next(h for _, u, h, _ in fake.calls if u.startswith(f"{MIRROR}/token/"))
        self.assertTrue(mirror_token["Authorization"].startswith("Basic "))
        self.assertTrue(any(u.startswith(f"{MIRROR}/v2/docker/library/alpine/manifests/") for _, u, _, _ in fake.calls))
        self.assertEqual(set(fake.manifests), {"v1.0.0"})

    def test_any_other_refusal_from_docker_hub_stops_the_copy(self):
        with self.assertRaisesRegex(RuntimeError, "HTTP 500"):
            pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=FakeRegistries(hub_status=500))

    def test_a_blob_already_in_ecr_is_skipped_and_a_missing_one_uploaded_in_one_chunk(self):
        fake = FakeRegistries(config_present=True)
        pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=fake)
        ecr = [(m, u.split("?")[0].replace(ECR, ""), u) for m, u, _, _ in fake.calls if u.startswith(ECR)]
        uploads = [(m, p) for m, p, _ in ecr if "/uploads/" in p]
        self.assertEqual(uploads, [("POST", "/v2/snyk-e2e/app/blobs/uploads/"), ("PATCH", "/v2/snyk-e2e/app/blobs/uploads/u1"),
                                   ("PUT", "/v2/snyk-e2e/app/blobs/uploads/u1")])
        self.assertEqual(fake.uploaded["u1"], LAYER)
        put = next(u for m, p, u in ecr if m == "PUT" and "/uploads/" in p)
        self.assertIn("_state=s2", put)
        self.assertIn("digest=sha256%3A" + hashlib.sha256(LAYER).hexdigest(), put)
        patch = next(h for m, u, h, _ in fake.calls if m == "PATCH")
        self.assertEqual(patch["Content-Range"], f"0-{len(LAYER) - 1}")

    def test_ecr_answering_the_chunk_with_201_is_accepted(self):
        # Seen live on 2026-11-24: ECR answers the PATCH with 201 Created, where the spec says 202.
        fake = FakeRegistries(config_present=False, patch_status=201)
        pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=fake)
        self.assertEqual(set(fake.manifests), {"v1.0.0"})

    def test_credentials_never_follow_a_redirect_to_another_host(self):
        fake = FakeRegistries()
        pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=fake)
        cdn = [h for _, u, h, _ in fake.calls if u.startswith("https://cdn.example.net/")]
        self.assertEqual(len(cdn), 1)
        self.assertNotIn("Authorization", cdn[0])

    def test_ecr_is_sent_basic_auth_for_the_aws_user(self):
        fake = FakeRegistries()
        pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=fake)
        auth = {h.get("Authorization") for _, u, h, _ in fake.calls if u.startswith(ECR)}
        self.assertEqual(len(auth), 1)
        self.assertTrue(auth.pop().startswith("Basic "))

    def test_a_tampered_blob_is_refused(self):
        fake = FakeRegistries(config_present=False)
        original = fake.__call__

        def tamper(method, url, headers, body):
            status, h, data = original(method, url, headers, body)
            return (status, h, b"evil") if url.startswith("https://cdn.example.net/") else (status, h, data)

        with self.assertRaisesRegex(RuntimeError, "digest"):
            pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=tamper)

    def test_only_an_ecr_repository_is_a_destination(self):
        for dest in ("docker.io/library/alpine", "123456789012.dkr.ecr.ap-southeast-2.amazonaws.com",
                     "evil.example.com/123456789012.dkr.ecr.ap-southeast-2.amazonaws.com/x",
                     "123456789012.dkr.ecr.ap-southeast-2.amazonaws.com.evil.com/x"):
            with self.assertRaises(ValueError, msg=dest):
                pi.parse_destination(dest)
        self.assertEqual(pi.parse_destination(DEST), (ECR, "snyk-e2e/app"))

    def test_no_message_contains_the_password(self):
        with self.assertRaises(RuntimeError) as cm:
            pi.copy_image(DEST, ["v1.0.0"], PASSWORD, send=FakeRegistries(ecr_status=401))
        self.assertNotIn(PASSWORD, str(cm.exception))
        self.assertIn("HTTP 401", str(cm.exception))

    def test_main_reads_the_password_from_stdin_only(self):
        self.assertEqual(pi.main([DEST, "v1.0.0"], stdin_text="", send=FakeRegistries()), 1)
        self.assertEqual(pi.main([DEST, "v1.0.0"], stdin_text=PASSWORD + "\n", send=FakeRegistries()), 0)


if __name__ == "__main__":
    unittest.main()
