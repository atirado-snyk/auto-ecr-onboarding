import argparse
import contextlib
import http.client
import http.server
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import onboard_ecr as o  # noqa: E402

ORG = "11111111-1111-1111-1111-111111111111"
ROLE = "arn:aws:iam::123456789012:role/snyk-ecr-read"
INTEGRATION = "22222222-2222-2222-2222-222222222222"


class FakeClient(o.SnykClient):
    """Replays scripted responses and records every call; never touches the network.

    routes: {(method, url-substring): [response, ...]} where a response is (status, body) or
    (status, body, headers); a str body is returned verbatim, anything else as JSON. Each call pops
    the next response, and the last one repeats.
    """

    def __init__(self, routes):
        super().__init__("test-token", "https://api.snyk.io", "2025-09-17", max_retries=2)
        self.routes = routes
        self.calls = []
        self.sleeps = []

    def _sleep(self, seconds):
        self.sleeps.append(seconds)

    def _send(self, method, url, headers, body):
        self.calls.append((method, url, headers, json.loads(body) if body else None))
        for (m, frag), queue in self.routes.items():
            if m == method and frag in url:
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                status, payload = item[0], item[1]
                resp_headers = item[2] if len(item) > 2 else {}
                return status, resp_headers, payload if isinstance(payload, str) else json.dumps(payload)
        raise AssertionError(f"unexpected call {method} {url}")

    def methods(self):
        return [(m, u.split("?")[0].split("snyk.io")[1]) for m, u, _, _ in self.calls]

    def posts_to(self, suffix):
        return [p for m, p in self.methods() if m == "POST" and p.endswith(suffix)]


def make_args(mode="apply", **over):
    base = dict(
        mode=mode, org_id=ORG, region="ap-southeast-2", role_arn=ROLE,
        import_policy="Regex", repo="^team-a/.*", tag=None, max_age_days=None, limit_newest_images=None,
        policy_file=None, schedule_frequency_hours=None, delete_images=False, policy_name="ecr-onboarding",
        no_sync=False, update_credentials=False, max_images=1000, force=False, connect_retries=3, connect_delay=1,
        dry_run_timeout=30, poll_seconds=0, delete_projects=False, delete_credentials=False, yes=False,
        repo_prefix=None, all_origins=False, api_base="https://api.snyk.io", api_version="2025-09-17",
    )
    base.update(over)
    return argparse.Namespace(**base)


def dry_run_done(n_tags, repo="team-a/app"):
    return (200, {"data": {"attributes": {"status": "completed", "result": {
        "images_to_import": [{"repository": repo, "tags": [{"tag": f"v1.0.{i}"} for i in range(n_tags)]}],
        "images_to_delete": [], "total_images_processed": n_tags}}}})


def dry_run_failed(message):
    return (200, {"data": {"attributes": {"status": "failed", "error_message": message}}})


def happy_routes(existing=None, tags=3):
    return {
        ("GET", "/v1/org/"): [(200, {"ecr": existing} if existing else {})],
        ("POST", "/v1/org/"): [(200, {"id": INTEGRATION})],
        ("POST", "/dry_run"): [(202, {"data": {"id": "job-1", "type": "dry_run_job", "attributes": {"status": "pending"}}})],
        ("GET", "/dry_run/job-1"): [dry_run_done(tags)],
        ("POST", "/policy?"): [(201, {"data": {"type": "container_registry_import_policy"}})],
    }


class Quiet(unittest.TestCase):
    """Captures stdout/stderr so the run's own output does not clutter the test report."""

    def setUp(self):
        self.out, self.err = io.StringIO(), io.StringIO()
        for cm in (contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err)):
            cm.__enter__()
            self.addCleanup(cm.__exit__, None, None, None)

    def write_policy(self, content, name="policy.json"):
        """Write a policy file inside a temporary working directory (policy files must be under the cwd)."""
        if not getattr(self, "_workdir", None):
            self._workdir = tempfile.TemporaryDirectory()
            self.addCleanup(self._workdir.cleanup)
            self.addCleanup(os.chdir, os.getcwd())
            os.chdir(self._workdir.name)
        pathlib.Path(name).write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return name


class PolicyTests(Quiet):
    """The policy is Snyk's own object, built from Snyk's type and field names, nothing invented."""

    def test_each_snyk_type_maps_to_its_documented_fields(self):
        cases = {
            ("ImportAll", ()): None,
            ("ImportAllNew", ()): None,
            ("Regex", (("repo", "^a/"), ("tag", "^v"))): {"repo": "^a/", "tag": "^v"},
            ("Recent", (("max_age_days", 30),)): {"maxAgeDays": 30},
            ("LastNObserved", (("limit_newest_images", 5),)): {"limitNewestImages": 5},
        }
        for (kind, fields), expected in cases.items():
            over = {"import_policy": kind, "repo": None, **dict(fields)}
            ip = o.policy_from_flags(make_args(**over))["import_policy"]
            self.assertEqual(ip["type"], kind)
            self.assertEqual(ip.get("policy"), expected, kind)

    def test_regex_with_only_a_tag_sends_only_the_tag(self):
        p = o.policy_from_flags(make_args(repo=None, tag="^v"))
        self.assertEqual(p["import_policy"]["policy"], {"tag": "^v"})

    def test_schedule_is_omitted_unless_given_so_snyk_applies_its_default(self):
        self.assertNotIn("schedule_frequency_hours", o.policy_from_flags(make_args()))
        self.assertEqual(o.policy_from_flags(make_args(schedule_frequency_hours=12))["schedule_frequency_hours"], 12)

    def test_delete_images_is_snyks_field(self):
        self.assertIs(o.policy_from_flags(make_args(delete_images=True))["delete_images"], True)
        self.assertIs(o.policy_from_flags(make_args())["delete_images"], False)

    def test_policy_file_is_passed_through_as_written(self):
        doc = {"name": "semver, newest 5", "schedule_frequency_hours": 12, "delete_images": True,
               "import_policy": {"name": "x", "type": "And", "sub_policies": [
                   {"type": "Regex", "policy": {"repo": ".*", "tag": "^v?[0-9]+\\.[0-9]+\\.[0-9]+$"}},
                   {"type": "LastNObserved", "policy": {"limitNewestImages": 5}}]}}
        self.assertEqual(o.policy_from_file(self.write_policy(doc), "default"), doc)

    def test_policy_file_gets_only_the_names_snyk_requires(self):
        p = o.policy_from_file(self.write_policy({"import_policy": {"type": "ImportAllNew"}}), "ecr-onboarding")
        self.assertEqual(p, {"name": "ecr-onboarding", "import_policy": {"type": "ImportAllNew", "name": "ecr-onboarding"}})

    def test_policy_file_must_be_a_snyk_policy_object(self):
        for content in ("not json", "[]", '{"name": "x"}', '{"import_policy": {}}'):
            with self.assertRaises(o.UsageError, msg=content):
                o.policy_from_file(self.write_policy(content), "n")

    def test_policy_file_must_be_a_json_file_inside_the_working_directory(self):
        self.write_policy({"import_policy": {"type": "ImportAll"}})
        outside = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        outside.write('{"import_policy": {"type": "ImportAll"}}')
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        for path in (outside.name, "../" + pathlib.Path(outside.name).name, "/etc/passwd"):
            with self.assertRaisesRegex(o.UsageError, "inside the current directory|\\.json", msg=path):
                o.policy_from_file(path, "n")
        self.write_policy("{}", name="policy.txt")
        with self.assertRaisesRegex(o.UsageError, "\\.json"):
            o.policy_from_file("policy.txt", "n")
        with self.assertRaisesRegex(o.UsageError, "no such file"):
            o.policy_from_file("missing.json", "n")

    def test_policy_file_size_is_capped(self):
        big = self.write_policy('{"import_policy": {"type": "ImportAll"}, "pad": "' + "x" * (64 * 1024) + '"}')
        with self.assertRaisesRegex(o.UsageError, "larger than"):
            o.policy_from_file(big, "n")

    def test_check_rejects_re2_unsupported_lookarounds_anywhere_in_the_tree(self):
        for pattern in ("^(?!cache/)", "^v(?=1)", "(?<=x)y", "(?<!x)y"):
            nested = {"name": "n", "import_policy": {"type": "Or", "sub_policies": [
                {"type": "ImportAllNew"}, {"type": "Regex", "policy": {"tag": pattern}}]}}
            with self.assertRaisesRegex(o.UsageError, "RE2", msg=pattern):
                o.check_policy(nested)
        o.check_policy(o.policy_from_flags(make_args(repo="^(?:team-a|team-b)/", tag="(?i)^v")))  # valid RE2

    def test_check_enforces_snyks_minimum_schedule(self):
        with self.assertRaises(o.UsageError):
            o.check_policy({"name": "n", "schedule_frequency_hours": 1, "import_policy": {"type": "ImportAll"}})

    def test_check_warns_when_rotating_types_lack_delete_images(self):
        o.check_policy(o.policy_from_flags(make_args(import_policy="LastNObserved", repo=None, limit_newest_images=3)))
        self.assertIn("delete_images", self.err.getvalue())
        before = len(self.err.getvalue())
        o.check_policy(o.policy_from_flags(make_args(import_policy="LastNObserved", repo=None,
                                                     limit_newest_images=3, delete_images=True)))
        self.assertEqual(self.err.getvalue()[before:], "")

    def test_check_flags_types_outside_snyks_documented_list(self):
        self.assertEqual(o.check_policy({"name": "n", "import_policy": {"type": "Newest"}}), ["Newest"])
        self.assertIn("not in Snyk's documented list", self.err.getvalue())

    def test_lists_types_of_nested_policies(self):
        tree = {"type": "Or", "sub_policies": [{"type": "Regex"}, {"type": "And", "sub_policies": [{"type": "Recent"}]}]}
        self.assertEqual(o.policy_types(tree), ["Or", "Regex", "And", "Recent"])


class RepositoryNameTests(unittest.TestCase):
    def test_strips_the_tag(self):
        self.assertEqual(o.repository_of("snyk-e2e/app:v1.0.0"), "snyk-e2e/app")

    def test_strips_an_ecr_registry_host(self):
        self.assertEqual(o.repository_of("123456789012.dkr.ecr.ap-southeast-2.amazonaws.com/snyk-e2e/app:v1"), "snyk-e2e/app")

    def test_keeps_dotted_repository_names(self):
        # "my.app" is a valid ECR repository segment, not a host: stripping it could widen a prefix match.
        self.assertEqual(o.repository_of("my.app/service:v1"), "my.app/service")

    def test_name_without_tag(self):
        self.assertEqual(o.repository_of("team/app"), "team/app")


class ValidationTests(Quiet):
    def test_rejects_bad_inputs(self):
        for over in ({"org_id": "nope"}, {"region": "Sydney"}, {"role_arn": "arn:aws:iam::1:user/x"}):
            with self.assertRaises(o.UsageError, msg=over):
                o.validate_inputs(make_args(**over))

    def test_token_only_goes_to_snyk_https_hosts(self):
        for bad in ("http://api.snyk.io", "https://evil.example.com", "https://snyk.io.evil.com"):
            with self.assertRaises(o.UsageError):
                o.validate_api_base(bad)
        self.assertEqual(o.validate_api_base("https://api.eu.snyk.io/"), "https://api.eu.snyk.io")

    def test_plan_and_apply_require_region_and_role(self):
        for mode in ("plan", "apply"):
            for over in ({"region": None}, {"role_arn": None}):
                with self.assertRaises(o.UsageError, msg=(mode, over)):
                    o.validate_inputs(make_args(mode, **over))

    def test_there_is_no_default_sync(self):
        with self.assertRaisesRegex(o.UsageError, "ImportAll,ImportAllNew,Regex,Recent,LastNObserved"):
            o.validate_inputs(make_args(import_policy=None, repo=None))

    def test_one_way_to_state_the_policy(self):
        with self.assertRaisesRegex(o.UsageError, "not both"):
            o.validate_inputs(make_args(policy_file="p.json"))
        with self.assertRaisesRegex(o.UsageError, "cannot be combined with --policy-file"):
            o.validate_inputs(make_args(import_policy=None, repo="^a", policy_file="p.json"))
        o.validate_inputs(make_args(import_policy=None, repo=None, policy_file="p.json"))

    def test_fields_must_belong_to_the_chosen_snyk_type(self):
        for over in ({"import_policy": "ImportAll", "repo": "^a"},
                     {"import_policy": "Recent", "repo": None, "max_age_days": 30, "limit_newest_images": 3},
                     {"import_policy": "LastNObserved", "repo": None, "limit_newest_images": 3, "tag": "^v"}):
            with self.assertRaisesRegex(o.UsageError, "not a field of", msg=over):
                o.validate_inputs(make_args(**over))

    def test_each_type_needs_its_fields(self):
        for over in ({"import_policy": "Regex", "repo": None, "tag": None},
                     {"import_policy": "Recent", "repo": None},
                     {"import_policy": "LastNObserved", "repo": None, "limit_newest_images": 0}):
            with self.assertRaises(o.UsageError, msg=over):
                o.validate_inputs(make_args(**over))

    def test_no_sync_conflicts_with_any_sync_setting(self):
        for over in ({"import_policy": "ImportAll"}, {"policy_file": "p.json"}, {"repo": "^a"}, {"tag": "^v"},
                     {"max_age_days": 3}, {"limit_newest_images": 3}, {"delete_images": True},
                     {"schedule_frequency_hours": 12}, {"policy_name": "x"}):
            args = make_args("apply", no_sync=True, **{"import_policy": None, "repo": None, **over})
            with self.assertRaises(o.UsageError, msg=over):
                o.validate_inputs(args)
        o.validate_inputs(make_args("apply", no_sync=True, import_policy=None, repo=None))  # plain --no-sync

    def test_delete_projects_requires_a_prefix(self):
        with self.assertRaises(o.UsageError):
            o.validate_inputs(make_args("teardown", delete_projects=True, repo_prefix=None))


@contextlib.contextmanager
def loopback(handler_class):
    """A throwaway HTTP server on 127.0.0.1 for tests of the real transport: loopback only, no network."""
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


class TransportTests(Quiet):
    def test_backs_off_on_rate_limit(self):
        c = FakeClient({("GET", "/v1/org/"): [(429, {}), (200, {})]})
        self.assertEqual(c.list_integrations(ORG), {})
        self.assertEqual(len(c.sleeps), 1)

    def test_retry_after_is_case_insensitive_and_tolerates_dates(self):
        self.assertEqual(o.retry_after_seconds({"retry-after": "7"}, 1), 7.0)
        self.assertEqual(o.retry_after_seconds({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, 4), 4)
        c = FakeClient({("GET", "/v1/org/"): [(429, {}, {"retry-after": "9"}), (200, {})]})
        c.list_integrations(ORG)
        self.assertEqual(c.sleeps, [9.0])

    def test_network_errors_become_clean_errors_without_the_token(self):
        class Offline(FakeClient):
            def _send(self, method, url, headers, body):
                raise urllib.error.URLError("certificate verify failed")
        with self.assertRaises(RuntimeError) as cm:
            Offline({}).list_integrations(ORG)
        self.assertIn("certificate verify failed", str(cm.exception))
        self.assertNotIn("test-token", str(cm.exception))

    def test_non_json_success_body_is_a_clean_error(self):
        c = FakeClient({("GET", "/v1/org/"): [(200, "<html>proxy login</html>")]})
        with self.assertRaisesRegex(RuntimeError, "non-JSON"):
            c.list_integrations(ORG)

    def test_redirects_are_refused_so_the_token_reaches_no_other_host(self):
        """The real transport, not FakeClient: urllib follows redirects by itself and resends the
        Authorization header to whatever host the Location names, from https to http too."""
        received = []

        class Elsewhere(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        with loopback(Elsewhere) as elsewhere:
            class Redirecting(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(302)
                    self.send_header("Location", f"{elsewhere}/collect")
                    self.end_headers()

                def log_message(self, *args):
                    pass

            with loopback(Redirecting) as snyk:
                client = o.SnykClient("test-token", "https://api.snyk.io", "2025-09-17", max_retries=0)
                with self.assertRaisesRegex(RuntimeError, "redirect") as cm:
                    client.request("GET", f"{snyk}/v1/org/{ORG}/integrations")
        self.assertEqual(received, [], "the redirect target must receive no request at all")
        self.assertNotIn("test-token", str(cm.exception))

    def test_a_connection_lost_while_reading_is_a_clean_error_without_the_token(self):
        failures = [http.client.IncompleteRead(b'{"partial":', 89), TimeoutError("timed out"),
                    ConnectionResetError(54, "Connection reset by peer")]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                class Broken(FakeClient):
                    def _send(self, method, url, headers, body, failure=failure):
                        raise failure
                with self.assertRaises(RuntimeError) as cm:
                    Broken({}).list_integrations(ORG)
                self.assertIn("while reading", str(cm.exception))
                self.assertIn(str(failure), str(cm.exception))
                self.assertNotIn("test-token", str(cm.exception))

    def test_token_never_logged_in_errors(self):
        c = FakeClient({("GET", "/v1/org/"): [(500, {"e": 1})]})
        with self.assertRaises(o.ApiError) as cm:
            c.list_integrations(ORG)
        self.assertNotIn("test-token", str(cm.exception))

    def test_get_policy_tolerates_empty_or_missing_policy(self):
        self.assertIsNone(FakeClient({("GET", "/policy?"): [(200, {})]}).get_policy(ORG, INTEGRATION))
        self.assertIsNone(FakeClient({("GET", "/policy?"): [(404, {})]}).get_policy(ORG, INTEGRATION))


class SyncWorkflowTests(Quiet):
    def test_plan_never_writes_when_integration_missing(self):
        c = FakeClient(happy_routes())
        self.assertEqual(o.run(make_args("plan"), c), 0)
        self.assertEqual(c.methods(), [("GET", f"/v1/org/{ORG}/integrations")])

    def test_plan_with_existing_integration_previews_but_never_writes(self):
        c = FakeClient(happy_routes(existing=INTEGRATION))
        self.assertEqual(o.run(make_args("plan"), c), 0)
        self.assertEqual(c.posts_to("/policy"), [])
        self.assertEqual(c.posts_to("/integrations"), [])
        self.assertTrue(c.posts_to("/policy/dry_run"), "plan should preview the sync with a dry run")

    def test_apply_creates_dry_runs_then_applies(self):
        c = FakeClient(happy_routes())
        self.assertEqual(o.run(make_args("apply"), c), 0)
        kinds = [(m, p.rsplit("/", 1)[-1]) for m, p in c.methods()]
        self.assertEqual(kinds[0], ("GET", "integrations"))
        self.assertEqual(kinds[1], ("POST", "integrations"))
        self.assertEqual(kinds[2], ("POST", "dry_run"))
        self.assertEqual(kinds[-1], ("POST", "policy"))
        self.assertEqual(c.calls[1][3], {"type": "ecr", "credentials": {"region": "ap-southeast-2", "roleArn": ROLE}})

    def test_apply_is_idempotent_reuses_integration(self):
        c = FakeClient(happy_routes(existing=INTEGRATION))
        o.run(make_args("apply"), c)
        self.assertEqual(c.posts_to("/integrations"), [])

    def test_update_credentials_only_when_asked(self):
        routes = happy_routes(existing=INTEGRATION)
        routes[("PUT", "/v1/org/")] = [(200, {})]
        c = FakeClient(routes)
        o.run(make_args("apply"), c)
        self.assertNotIn("PUT", {m for m, _ in c.methods()})
        c = FakeClient(routes)
        o.run(make_args("apply", update_credentials=True), c)
        self.assertIn(("PUT", f"/v1/org/{ORG}/integrations/{INTEGRATION}"), c.methods())

    def test_max_images_guard_blocks_apply(self):
        c = FakeClient(happy_routes(existing=INTEGRATION, tags=50))
        self.assertEqual(o.run(make_args("apply", max_images=10), c), 2)
        self.assertEqual(c.posts_to("/policy"), [])

    def test_force_overrides_guard(self):
        c = FakeClient(happy_routes(existing=INTEGRATION, tags=50))
        self.assertEqual(o.run(make_args("apply", max_images=10, force=True), c), 0)

    def test_retries_integration_create_while_iam_propagates(self):
        routes = happy_routes()
        routes[("POST", "/v1/org/")] = [(400, {"error": "could not connect"}), (400, {"error": "x"}), (200, {"id": INTEGRATION})]
        c = FakeClient(routes)
        self.assertEqual(o.run(make_args("apply"), c), 0)
        self.assertGreaterEqual(c.sleeps.count(1), 2)

    def test_does_not_retry_auth_failures(self):
        routes = happy_routes()
        routes[("POST", "/v1/org/")] = [(403, {"error": "forbidden"})]
        c = FakeClient(routes)
        with self.assertRaises(o.ApiError):
            o.run(make_args("apply"), c)
        self.assertEqual(len(c.posts_to("/integrations")), 1)

    def test_failed_dry_run_aborts_before_apply(self):
        routes = happy_routes(existing=INTEGRATION)
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("bad regex")]
        c = FakeClient(routes)
        with self.assertRaisesRegex(RuntimeError, "bad regex"):
            o.run(make_args("apply"), c)
        self.assertEqual(c.posts_to("/policy"), [])

    def test_connection_test_runs_before_the_sync_preview(self):
        c = FakeClient(happy_routes())
        o.run(make_args("apply"), c)
        kinds = [b["data"]["attributes"]["policy"]["import_policy"]["type"]
                 for m, u, h, b in c.calls if u.split("?")[0].endswith("/dry_run")]
        self.assertEqual(kinds, ["ImportAll", "Regex"])

    def test_apply_with_a_policy_file_sends_it_unchanged(self):
        doc = {"name": "n", "delete_images": True, "import_policy": {"name": "n", "type": "Or", "sub_policies": [
            {"type": "ImportAllNew"}, {"type": "Regex", "policy": {"tag": "^v"}}]}}
        path = self.write_policy(doc)
        c = FakeClient(happy_routes())
        self.assertEqual(o.run(make_args("apply", import_policy=None, repo=None, policy_file=path), c), 0)
        applied = next(b for m, u, h, b in c.calls if m == "POST" and u.split("?")[0].endswith("/policy"))
        self.assertEqual(applied["data"]["attributes"]["policy"], doc)

    def test_only_the_connection_test_is_retried_for_propagation(self):
        routes = happy_routes()
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role"), dry_run_done(1), dry_run_failed("bad regex")]
        c = FakeClient(routes)
        with self.assertRaisesRegex(o.DryRunFailed, "bad regex"):
            o.run(make_args("apply"), c)
        self.assertEqual(len(c.posts_to("/policy/dry_run")), 3)  # 2 connection attempts + 1 sync preview
        self.assertEqual(c.posts_to("/policy"), [])

    def test_policy_conflict_falls_back_to_patch(self):
        routes = happy_routes(existing=INTEGRATION)
        routes[("POST", "/policy?")] = [(409, {})]
        routes[("PATCH", "/policy?")] = [(200, {})]
        c = FakeClient(routes)
        self.assertEqual(o.run(make_args("apply"), c), 0)
        self.assertEqual(c.methods()[-1][0], "PATCH")


class ConnectOnlyTests(Quiet):
    def test_no_sync_connects_and_tests_but_sets_no_policy(self):
        c = FakeClient(happy_routes())
        self.assertEqual(o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), c), 0)
        self.assertEqual(len(c.posts_to("/integrations")), 1)
        self.assertTrue(c.posts_to("/policy/dry_run"), "connection test must run")
        self.assertEqual(c.posts_to("/policy"), [])
        dry_run_body = next(b for m, u, h, b in c.calls if u.split("?")[0].endswith("/dry_run"))
        self.assertEqual(dry_run_body["data"]["attributes"]["policy"]["import_policy"]["type"], "ImportAll")
        self.assertIn("Snyk can read the registry: 1 repositories with tagged images (3 tags) visible", self.out.getvalue())
        self.assertIn("team-a/app (3 tags)", self.out.getvalue())

    def test_connection_test_retried_while_new_credentials_propagate(self):
        routes = happy_routes()
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role"), dry_run_done(2)]
        c = FakeClient(routes)
        self.assertEqual(o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), c), 0)
        self.assertEqual(len(c.posts_to("/policy/dry_run")), 2)
        self.assertEqual(c.sleeps, [1])

    def test_connection_test_on_reused_integration_is_not_retried_and_hints_update(self):
        routes = happy_routes(existing=INTEGRATION)
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role")]
        c = FakeClient(routes)
        with self.assertRaisesRegex(o.DryRunFailed, "cannot assume role.*--update-credentials"):
            o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), c)
        self.assertEqual(len(c.posts_to("/policy/dry_run")), 1)

    def test_connection_test_still_failing_after_retries_points_at_trust_policy(self):
        routes = happy_routes()
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role")]
        c = FakeClient(routes)
        with self.assertRaisesRegex(o.DryRunFailed, "Snyk principal in the role's trust policy"):
            o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), c)
        self.assertEqual(len(c.posts_to("/policy/dry_run")), 3)  # connect_retries=3

    def test_exhausted_retries_name_the_org_missing_from_the_external_id_list(self):
        routes = happy_routes()
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role")]
        c = FakeClient(routes)
        with self.assertRaises(o.DryRunFailed) as cm:
            o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), c)
        message = str(cm.exception)
        self.assertIn(f"org {ORG} is missing from the role's sts:ExternalId list", message)
        self.assertIn("keep every existing ID", message)
        self.assertIn("--region ap-southeast-2 is not the region of the ECR registry", message)
        self.assertIn("after 3 attempts", message)
        # The failed run left the integration behind; the way back is --update-credentials, which retries.
        self.assertIn("re-run 'apply' with --update-credentials", message)
        # Only after the retries are exhausted: the per-retry lines do not carry the hint.
        retry_lines = self.err.getvalue()
        self.assertEqual(retry_lines.count("may still be propagating"), 2)
        self.assertNotIn("sts:ExternalId", retry_lines)

    def test_no_external_id_hint_when_the_first_attempt_succeeds_after_a_retry(self):
        routes = happy_routes()
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role"), dry_run_done(1)]
        c = FakeClient(routes)
        self.assertEqual(o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), c), 0)
        self.assertNotIn("sts:ExternalId", self.out.getvalue() + self.err.getvalue())

    def test_reused_integration_failure_keeps_its_own_hint(self):
        routes = happy_routes(existing=INTEGRATION)
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role")]
        with self.assertRaises(o.DryRunFailed) as cm:
            o.run(make_args("apply", no_sync=True, import_policy=None, repo=None), FakeClient(routes))
        self.assertIn("--update-credentials", str(cm.exception))
        self.assertNotIn("sts:ExternalId", str(cm.exception))

    def test_update_credentials_counts_as_fresh(self):
        routes = happy_routes(existing=INTEGRATION)
        routes[("PUT", "/v1/org/")] = [(200, {})]
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role"), dry_run_done(1)]
        c = FakeClient(routes)
        self.assertEqual(o.run(make_args("apply", no_sync=True, import_policy=None, repo=None, update_credentials=True), c), 0)

    def test_plan_with_no_sync_never_writes(self):
        c = FakeClient(happy_routes())
        self.assertEqual(o.run(make_args("plan", no_sync=True, import_policy=None, repo=None), c), 0)
        self.assertEqual(c.methods(), [("GET", f"/v1/org/{ORG}/integrations")])

    def test_plan_with_existing_integration_only_reads_and_dry_runs(self):
        c = FakeClient(happy_routes(existing=INTEGRATION))
        o.run(make_args("plan", no_sync=True, import_policy=None, repo=None), c)
        self.assertEqual(c.posts_to("/policy"), [])
        self.assertEqual(c.posts_to("/integrations"), [])


def project_page(names, nxt=None):
    page = {"data": [{"id": "p-" + n.replace("/", "_").replace(":", "_"), "attributes": {"name": n}} for n in names]}
    if nxt:
        page["links"] = {"next": nxt}
    return page


class TeardownTests(Quiet):
    def routes(self, projects=None, existing=INTEGRATION):
        r = {
            ("GET", "/v1/org/"): [(200, {"ecr": existing} if existing else {})],
            ("GET", "/policy?"): [(200, {"data": {"attributes": {"policy": {"name": "x"}}}})],
            ("DELETE", "/policy?"): [(204, {})],
            ("DELETE", "/projects/"): [(204, {})],
            ("DELETE", "/authentication"): [(200, {})],
        }
        if projects is not None:
            r[("GET", "/projects?")] = projects
        return r

    def deletes(self, c):
        return [p for m, p in c.methods() if m == "DELETE"]

    def test_dry_run_by_default_deletes_nothing(self):
        c = FakeClient(self.routes([(200, project_page(["snyk-test/app:v1"]))]))
        self.assertEqual(o.run(make_args("teardown", delete_projects=True, delete_credentials=True, repo_prefix="snyk-test/"), c), 0)
        self.assertEqual(self.deletes(c), [])

    def test_yes_deletes_policy_but_keeps_projects_unless_asked(self):
        c = FakeClient(self.routes())
        o.run(make_args("teardown", yes=True), c)
        self.assertEqual(len(self.deletes(c)), 1)
        self.assertTrue(self.deletes(c)[0].endswith("/policy"))

    def test_only_matching_ecr_projects_are_deleted(self):
        c = FakeClient(self.routes([(200, project_page(["snyk-test/app:v1", "snyk-test/app:latest", "other/app:v1"]))]))
        o.run(make_args("teardown", delete_projects=True, yes=True, repo_prefix="snyk-test/"), c)
        gone = {p.rsplit("/", 1)[-1] for p in self.deletes(c) if "/projects/" in p}
        self.assertEqual(gone, {"p-snyk-test_app_v1", "p-snyk-test_app_latest"})

    def test_follows_pagination_in_snyks_documented_link_format(self):
        # Snyk's links are relative to the REST base without the /rest prefix.
        nxt = f"/orgs/{ORG}/projects?version=2025-09-17&origins=ecr&starting_after=abc"
        c = FakeClient(self.routes([(200, project_page(["a/x:1"], nxt)), (200, project_page(["a/y:1"]))]))
        o.run(make_args("teardown", delete_projects=True, yes=True, repo_prefix="a/"), c)
        self.assertEqual(sum(1 for p in self.deletes(c) if "/projects/" in p), 2)
        second_page = [u for m, u, _, _ in c.calls if m == "GET" and "starting_after" in u]
        self.assertEqual(second_page, [f"https://api.snyk.io/rest/orgs/{ORG}/projects?version=2025-09-17&origins=ecr&starting_after=abc"])

    def test_follows_pagination_with_rest_prefixed_links_too(self):
        nxt = f"/rest/orgs/{ORG}/projects?version=2025-09-17&starting_after=abc"
        c = FakeClient(self.routes([(200, project_page(["a/x:1"], nxt)), (200, project_page(["a/y:1"]))]))
        o.run(make_args("teardown", delete_projects=True, yes=True, repo_prefix="a/"), c)
        self.assertTrue(any(u.startswith("https://api.snyk.io/rest/orgs/") and "starting_after" in u for _, u, _, _ in c.calls))

    def test_refuses_pagination_link_to_other_host(self):
        c = FakeClient(self.routes([(200, project_page(["a/x:1"], "https://evil.example.com/steal"))]))
        with self.assertRaises(RuntimeError):
            o.run(make_args("teardown", delete_projects=True, yes=True, repo_prefix="a/"), c)

    def test_credentials_removed_only_when_asked_and_confirmed(self):
        cred = f"/v1/org/{ORG}/integrations/{INTEGRATION}/authentication"
        c = FakeClient(self.routes())
        o.run(make_args("teardown", yes=True), c)
        self.assertNotIn(cred, self.deletes(c))
        c = FakeClient(self.routes())
        o.run(make_args("teardown", delete_credentials=True), c)  # dry run
        self.assertEqual(self.deletes(c), [])
        c = FakeClient(self.routes())
        o.run(make_args("teardown", delete_credentials=True, yes=True), c)
        self.assertIn(cred, self.deletes(c))

    def test_only_integration_scoped_deletes_ever_happen_never_the_org(self):
        """Teardown with every destructive flag may delete only: the sync policy, this integration's
        credentials, and ECR projects under the prefix. Never an org, integration, target or anything else."""
        c = FakeClient(self.routes([(200, project_page(["a/x:1", "b/y:1"]))]))
        o.run(make_args("teardown", delete_projects=True, delete_credentials=True, yes=True, repo_prefix="a/"), c)
        allowed = (
            f"/rest/orgs/{ORG}/container_import/{INTEGRATION}/policy",
            f"/v1/org/{ORG}/integrations/{INTEGRATION}/authentication",
            f"/rest/orgs/{ORG}/projects/p-a_x_1",
        )
        self.assertEqual(sorted(self.deletes(c)), sorted(allowed))

    def test_reports_credentials_already_removed_on_a_rerun(self):
        r = self.routes()
        r[("DELETE", "/authentication")] = [(404, {})]
        self.assertEqual(o.run(make_args("teardown", delete_credentials=True, yes=True), FakeClient(r)), 0)
        self.assertIn("Integration credentials: already removed.", self.out.getvalue())

    def test_credentials_deleted_after_policy_and_projects(self):
        c = FakeClient(self.routes([(200, project_page(["a/x:1"]))]))
        o.run(make_args("teardown", delete_projects=True, delete_credentials=True, yes=True, repo_prefix="a/"), c)
        kinds = [p.rsplit("/", 1)[-1] for p in self.deletes(c)]
        self.assertEqual(kinds[0], "policy")
        self.assertEqual(kinds[-1], "authentication")

    def test_prefix_matches_project_names_that_include_the_registry_host(self):
        host = "123456789012.dkr.ecr.ap-southeast-2.amazonaws.com"
        c = FakeClient(self.routes([(200, project_page([f"{host}/snyk-e2e/app:v1", f"{host}/other/app:v1"]))]))
        o.run(make_args("teardown", delete_projects=True, yes=True, repo_prefix="snyk-e2e/"), c)
        self.assertEqual(len([p for p in self.deletes(c) if "/projects/" in p]), 1)

    def test_without_an_integration_only_projects_can_be_removed(self):
        c = FakeClient(self.routes([(200, project_page(["a/x:1"]))], existing=None))
        self.assertEqual(o.run(make_args("teardown", delete_projects=True, delete_credentials=True, yes=True, repo_prefix="a/"), c), 0)
        self.assertEqual(self.deletes(c), [f"/rest/orgs/{ORG}/projects/p-a_x_1"])
        self.assertIn("Credentials    : none (no ECR integration)", self.out.getvalue())

    def test_missing_policy_is_not_an_error(self):
        r = self.routes()
        r[("GET", "/policy?")] = [(404, {})]
        r[("DELETE", "/policy?")] = [(404, {})]
        self.assertEqual(o.run(make_args("teardown", yes=True), FakeClient(r)), 0)

    def test_teardown_does_not_need_region_or_role(self):
        self.assertEqual(o.run(make_args("teardown", region=None, role_arn=None), FakeClient(self.routes())), 0)


class StatusTests(Quiet):
    def test_status_is_read_only_and_needs_no_region_role_or_regex(self):
        c = FakeClient({
            ("GET", "/v1/org/"): [(200, {"ecr": INTEGRATION})],
            ("GET", "/policy?"): [(200, {"data": {"attributes": {"policy": {"name": "p", "schedule_frequency_hours": 6}}}})],
            ("GET", "/projects?"): [(200, project_page(["snyk-test/app:v1.0.0"]))],
        })
        self.assertEqual(o.run(make_args("status", region=None, role_arn=None), c), 0)
        self.assertEqual({m for m, _ in c.methods()}, {"GET"})
        self.assertIn("  - snyk-test/app:v1.0.0", self.out.getvalue())

    def test_all_origins_lists_every_project_with_its_origin(self):
        page = {"data": [{"id": "1", "attributes": {"name": "snyk-e2e/app:v1.0.0", "origin": "ecr"}},
                         {"id": "2", "attributes": {"name": "team/repo", "origin": "github"}}]}
        c = FakeClient({("GET", "/v1/org/"): [(200, {})], ("GET", "/projects?"): [(200, page)]})
        o.run(make_args("status", region=None, role_arn=None, all_origins=True), c)
        unfiltered = [u for m, u, _, _ in c.calls if "/projects?" in u and "origins=" not in u]
        self.assertEqual(len(unfiltered), 1)
        self.assertIn("  * team/repo  [origin: github]", self.out.getvalue())

    def test_status_without_integration(self):
        c = FakeClient({("GET", "/v1/org/"): [(200, {})], ("GET", "/projects?"): [(200, project_page([]))]})
        self.assertEqual(o.run(make_args("status", region=None, role_arn=None), c), 0)
        self.assertIn("ECR integration: none", self.out.getvalue())


if __name__ == "__main__":
    unittest.main()
