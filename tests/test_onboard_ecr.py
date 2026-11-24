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
import unittest.mock
import urllib.error

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import onboard_ecr as o  # noqa: E402

ORG = "11111111-1111-1111-1111-111111111111"
ROLE = "arn:aws:iam::123456789012:role/snyk-ecr-read"
INTEGRATION = "22222222-2222-2222-2222-222222222222"
DEFAULT_MODE_ANSWER = {"errors": [{"status": "404", "detail": "Endpoint Not Found"}]}


class FakeClient(o.SnykClient):
    """Replays scripted responses and records every call; never touches the network.

    routes: {(method, url-substring): [response, ...]} where a response is (status, body) or
    (status, body, headers); a str body is returned verbatim, anything else as JSON. Each call pops
    the next response, and the last one repeats.

    Unless a test routes it, the mode check (call 13, GET .../closed-beta/orgs/<org>/integrations)
    answers as Snyk does for an org without the profiles feature: 404 Endpoint Not Found. Time is fake:
    `_sleep` advances `now`, which `_clock` returns.
    """

    def __init__(self, routes):
        super().__init__("test-token", "https://api.snyk.io", "2025-09-17", max_retries=2)
        self.routes = routes
        self.calls = []
        self.sleeps = []
        self.now = 1000.0

    def _sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def _clock(self):
        return self.now

    def _send(self, method, url, headers, body):
        self.calls.append((method, url, headers, json.loads(body) if body else None))
        for (m, frag), queue in self.routes.items():
            if m == method and frag in url:
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                status, payload = item[0], item[1]
                resp_headers = item[2] if len(item) > 2 else {}
                return status, resp_headers, payload if isinstance(payload, str) else json.dumps(payload)
        if method == "GET" and "/closed-beta/orgs/" in url and url.split("?")[0].endswith("/integrations"):
            return 404, {}, json.dumps(DEFAULT_MODE_ANSWER)
        raise AssertionError(f"unexpected call {method} {url}")

    def methods(self):
        return [(m, u.split("?")[0].split("snyk.io")[1]) for m, u, _, _ in self.calls]

    def after_mode_check(self):
        """methods() without the mode check that opens every run."""
        calls = self.methods()
        assert calls and calls[0] == ("GET", f"/closed-beta/orgs/{ORG}/integrations"), calls[:1]
        return calls[1:]

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
        connection=None, exact_name=False, delete_connection=False,
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


# -- profiles mode (feature 002) ------------------------------------------------------------------
ACCOUNT = "123456789012"
ROLE_B = "arn:aws:iam::111111111111:role/snyk-ecr-read"
ADDR_A = "123456789012.dkr.ecr.ap-southeast-2.amazonaws.com"


def profile_entry(integration_id, name, integration_type="ecr"):
    return {"id": integration_id, "type": "integration",
            "attributes": {"integration_type": integration_type, "profile_name": name, "has_broker": False}}


def profiles_list(*entries, nxt=None):
    page = {"data": list(entries), "links": {"next": nxt} if nxt else {}}
    return (200, page, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"})


def target_entry(target_id, integration_id, display_name="team-a/app"):
    return {"id": target_id, "attributes": {"display_name": display_name, "integration_type": "ecr"},
            "relationships": {"integration": {"data": {"id": integration_id, "type": "integration"}}}}


def ecr_project(project_id, name, target_id):
    return {"id": project_id, "attributes": {"name": name, "origin": "ecr"},
            "relationships": {"target": {"data": {"id": target_id, "type": "target"}}}}


def profile_routes(*entries, tags=3, projects=(), targets=()):
    """Call 13 answering 200 (profiles mode) with the given connections, plus the baseline's sync routes."""
    return {
        ("GET", "/closed-beta/orgs/"): [profiles_list(*entries)],
        ("POST", "/closed-beta/orgs/"): [(201, {"data": {"id": "new-conn", "type": "integration"}})],
        ("PATCH", "/closed-beta/orgs/"): [(200, {"data": {"type": "integration"}})],
        ("DELETE", "/closed-beta/orgs/"): [(204, "")],
        ("POST", "/dry_run"): [(202, {"data": {"id": "job-1", "type": "dry_run_job", "attributes": {"status": "pending"}}})],
        ("GET", "/dry_run/job-1"): [dry_run_done(tags)],
        ("GET", "/policy?"): [(404, {})],
        ("POST", "/policy?"): [(201, {"data": {"type": "container_registry_import_policy"}})],
        ("DELETE", "/policy?"): [(204, {})],
        ("GET", "/projects?"): [(200, {"data": list(projects)})],
        ("GET", "/targets?"): [(200, {"data": list(targets)})],
        ("DELETE", "/projects/"): [(204, {})],
    }


def writes(c):
    """Every call that changes something: dry runs are previews and change nothing."""
    return [(m, p) for m, p in c.methods() if m != "GET" and not p.endswith("/dry_run")]


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
        # In default mode only (profiles mode selects by provenance); checked before any write.
        c = FakeClient({})
        with self.assertRaises(o.UsageError):
            o.run(make_args("teardown", delete_projects=True, repo_prefix=None), c)
        self.assertEqual(c.after_mode_check(), [])


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
        self.assertEqual(c.after_mode_check(), [("GET", f"/v1/org/{ORG}/integrations")])

    def test_plan_with_existing_integration_previews_but_never_writes(self):
        c = FakeClient(happy_routes(existing=INTEGRATION))
        self.assertEqual(o.run(make_args("plan"), c), 0)
        self.assertEqual(c.posts_to("/policy"), [])
        self.assertEqual(c.posts_to("/integrations"), [])
        self.assertTrue(c.posts_to("/policy/dry_run"), "plan should preview the sync with a dry run")

    def test_apply_creates_dry_runs_then_applies(self):
        c = FakeClient(happy_routes())
        self.assertEqual(o.run(make_args("apply"), c), 0)
        kinds = [(m, p.rsplit("/", 1)[-1]) for m, p in c.after_mode_check()]
        self.assertEqual(kinds[0], ("GET", "integrations"))
        self.assertEqual(kinds[1], ("POST", "integrations"))
        self.assertEqual(kinds[2], ("POST", "dry_run"))
        self.assertEqual(kinds[-1], ("POST", "policy"))
        self.assertEqual(c.calls[2][3], {"type": "ecr", "credentials": {"region": "ap-southeast-2", "roleArn": ROLE}})

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
        self.assertEqual(c.after_mode_check(), [("GET", f"/v1/org/{ORG}/integrations")])

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



# == Feature 002: profiles mode ===================================================================
def conn(integration_id, name):
    return o.Connection.from_entry(profile_entry(integration_id, name))


ADDR_B = "111111111111.dkr.ecr.ap-southeast-2.amazonaws.com"
ADDR_A_US = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
PROD, STAGING = f"prod {ADDR_A}", f"staging {ADDR_B}"


def closed_beta_writes(c):
    return [(m, p) for m, p in c.methods() if m != "GET" and p.startswith("/closed-beta/")]


def body_of(c, method, fragment):
    return next(b for m, u, h, b in c.calls if m == method and fragment in u)


class ModeTests(Quiet):
    """FR-001 to FR-003 and research R1: the org decides the mode, on every run, before anything else."""

    def test_200_means_profiles_mode(self):
        c = FakeClient(profile_routes())
        self.assertEqual(o.run(make_args("status", region=None, role_arn=None), c), 0)
        self.assertTrue(self.out.getvalue().startswith(o.MODE_LINE + "\n"))

    def test_endpoint_not_found_means_default_mode_with_baseline_output(self):
        c = FakeClient(happy_routes(existing=INTEGRATION))
        self.assertEqual(o.run(make_args("plan"), c), 0)
        out = self.out.getvalue()
        self.assertNotIn("Mode:", out)
        self.assertFalse([line for line in out.splitlines() if line.startswith("[")])
        self.assertTrue(out.startswith(f"ECR integration already exists: {INTEGRATION}\n"))
        self.assertNotIn("Closed-beta calls", self.err.getvalue())

    def test_any_other_answer_stops_the_run_before_any_write(self):
        for status, body in ((404, {"errors": [{"status": "404", "detail": "Org not found"}]}), (401, {}), (403, {}),
                             (406, {}), (500, {})):
            with self.subTest(status=status):
                c = FakeClient({**happy_routes(), ("GET", "/closed-beta/orgs/"): [(status, body)]})
                with self.assertRaisesRegex(RuntimeError, f"HTTP {status}.*Nothing was changed"):
                    o.run(make_args("apply"), c)
                self.assertEqual({m for m, _ in c.methods()}, {"GET"})
                self.assertTrue(all(p.startswith("/closed-beta/") for _, p in c.methods()))

    def test_the_mode_check_is_the_first_call_of_every_subcommand(self):
        for mode in ("plan", "apply", "status", "teardown"):
            with self.subTest(mode=mode):
                routes = {**happy_routes(), ("GET", "/projects?"): [(200, project_page([]))]}
                c = FakeClient(routes)
                o.run(make_args(mode), c)
                self.assertEqual(c.methods()[0], ("GET", f"/closed-beta/orgs/{ORG}/integrations"))
                self.assertIn(f"version={o.CLOSED_BETA_VERSION}", c.calls[0][1])

    def test_profile_options_are_refused_on_a_default_mode_org_before_any_write(self):
        for over in ({"connection": "prod"}, {"connection": "prod", "exact_name": True},
                     {"mode": "teardown", "delete_connection": True, "yes": True}):
            with self.subTest(**over):
                c = FakeClient(happy_routes(existing=INTEGRATION))
                args = make_args(**{"mode": "apply", **over})
                with self.assertRaisesRegex(o.UsageError, "default mode.*Nothing was changed"):
                    o.run(args, c)
                self.assertEqual(c.after_mode_check(), [])


class ClosedBetaTransportTests(Quiet):
    """Research R12: paced by Snyk's own headers, counted, and never past a minute's wait."""

    def client(self, *answers):
        return FakeClient({("GET", "/closed-beta/orgs/"): list(answers)})

    def test_closed_beta_calls_use_the_pinned_version_and_json_api(self):
        c = self.client(profiles_list())
        c.list_closed_beta_integrations(ORG)
        method, url, headers, _ = c.calls[0]
        self.assertTrue(url.startswith("https://api.snyk.io/closed-beta/orgs/"))
        self.assertIn("version=2024-10-15", url)
        self.assertIn("limit=100", url)
        self.assertEqual(headers["Accept"], "application/vnd.api+json")

    def test_calls_are_at_least_a_second_apart(self):
        c = self.client((200, {"data": []}))
        c.list_closed_beta_integrations(ORG)
        c.list_closed_beta_integrations(ORG)
        self.assertEqual(c.sleeps, [1.0])
        self.assertEqual(c.closed_beta_calls, 2)

    def test_waits_for_the_announced_reset_when_nothing_remains(self):
        c = self.client((200, {"data": []}, {"x-ratelimit-remaining": "0", "X-RateLimit-Reset": "30"}))
        c.list_closed_beta_integrations(ORG)
        c.list_closed_beta_integrations(ORG)
        self.assertEqual(c.sleeps, [30.0])

    def test_a_wait_over_a_minute_stops_before_the_call(self):
        c = self.client((200, {"data": []}, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "3000"}))
        c.list_closed_beta_integrations(ORG)
        with self.assertRaisesRegex(o.RateLimited, "rate limit.*resets in about 3001 s") as cm:
            c.list_closed_beta_integrations(ORG)
        self.assertEqual(len(c.calls), 1)
        self.assertNotIn("test-token", str(cm.exception))

    def test_429_waits_for_the_reset_when_there_is_no_retry_after(self):
        c = self.client((429, {}, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "5"}), (200, {"data": []}))
        c.list_closed_beta_integrations(ORG)
        self.assertIn(5.0, c.sleeps)
        self.assertEqual(c.closed_beta_calls, 2)

    def test_429_with_a_long_reset_stops_at_once(self):
        c = self.client((429, {}, {"X-RateLimit-Reset": "600"}))
        with self.assertRaises(o.RateLimited):
            c.list_closed_beta_integrations(ORG)
        self.assertEqual(len(c.calls), 1)

    def test_a_profiles_run_reports_its_closed_beta_call_count(self):
        c = FakeClient(profile_routes())
        o.run(make_args("status", region=None, role_arn=None), c)
        self.assertIn("Closed-beta calls: 1", self.err.getvalue())


class ClosedBetaPagingTests(Quiet):
    def pages(self, nxt):
        return FakeClient({("GET", "/closed-beta/orgs/"): [
            profiles_list(profile_entry("c1", PROD), nxt=nxt), profiles_list(profile_entry("c2", STAGING))]})

    def test_follows_every_link_form_on_the_api_host(self):
        for nxt in (f"/orgs/{ORG}/integrations?version=2024-10-15&starting_after=c1",
                    f"/closed-beta/orgs/{ORG}/integrations?version=2024-10-15&starting_after=c1",
                    f"https://api.snyk.io/closed-beta/orgs/{ORG}/integrations?version=2024-10-15&starting_after=c1"):
            with self.subTest(nxt=nxt):
                c = self.pages(nxt)
                self.assertEqual([e["id"] for e in c.list_closed_beta_integrations(ORG)], ["c1", "c2"])
                self.assertEqual(c.calls[1][1], f"https://api.snyk.io/closed-beta/orgs/{ORG}/integrations"
                                                "?version=2024-10-15&starting_after=c1")

    def test_an_empty_or_missing_links_object_ends_the_list(self):
        for page in ({"data": [], "links": {}}, {"data": []}):
            c = FakeClient({("GET", "/closed-beta/orgs/"): [(200, page)]})
            self.assertEqual(c.list_closed_beta_integrations(ORG), [])
            self.assertEqual(len(c.calls), 1)

    def test_refuses_a_link_off_the_api_host(self):
        c = self.pages("https://evil.example.com/closed-beta/orgs/x")
        with self.assertRaisesRegex(RuntimeError, "off the Snyk API host"):
            c.list_closed_beta_integrations(ORG)


class NameTests(Quiet):
    """FR-005 and data-model.md, Names."""

    def test_default_names_carry_the_registry_address(self):
        self.assertEqual(o.registry_address("111111111111", "ap-southeast-2"), "111111111111.dkr.ecr.ap-southeast-2.amazonaws.com")
        self.assertEqual(o.connection_name(None, "111111111111", "ap-southeast-2"), ADDR_B)
        self.assertEqual(o.connection_name("prod", "111111111111", "ap-southeast-2"), f"prod {ADDR_B}")
        self.assertEqual(o.account_of(ROLE), ACCOUNT)

    def test_names_parse_back_to_label_account_and_region(self):
        self.assertEqual(o.parse_connection_name(ADDR_B), (None, "111111111111", "ap-southeast-2"))
        self.assertEqual(o.parse_connection_name(f"prod {ADDR_B}"), ("prod", "111111111111", "ap-southeast-2"))
        for other in ("Default profile", "Payments prod", "prod", "my label " + ADDR_B, None, ""):
            self.assertIsNone(o.parse_connection_name(other), other)
        self.assertFalse(conn("x", None).carries_ecr)
        self.assertEqual(conn("x", None).name, "Default profile")

    def test_labels_and_names_follow_snyks_rules(self):
        for bad in ("my prod", "-prod", "team/a", "pröd", ""):
            with self.assertRaises(o.UsageError, msg=bad):
                o.validate_label(bad)
        o.validate_label("prod-1.eu_west")
        o.validate_exact_name("Payments prod")
        with self.assertRaises(o.UsageError):
            o.validate_exact_name("a" * 256)
        with self.assertRaises(o.UsageError):
            o.validate_exact_name(" leading space")

    def test_china_and_govcloud_are_refused_in_profiles_mode_only(self):
        for role, region in (("arn:aws-cn:iam::123456789012:role/r", "cn-north-1"),
                             ("arn:aws-us-gov:iam::123456789012:role/r", "us-gov-west-1"), (ROLE, "cn-north-1")):
            with self.subTest(role=role, region=region):
                c = FakeClient(profile_routes())
                with self.assertRaisesRegex(o.UsageError, "standard partition"):
                    o.run(make_args("apply", role_arn=role, region=region), c)
                self.assertEqual(writes(c), [])
                o.validate_inputs(make_args("apply", role_arn=role, region=region))  # default mode accepts them

    def test_exact_name_needs_a_connection_and_plan_or_apply(self):
        for over in ({"exact_name": True}, {"exact_name": True, "connection": "x", "mode": "status"},
                     {"exact_name": True, "connection": "Default profile"}):
            with self.assertRaises(o.UsageError, msg=over):
                o.validate_inputs(make_args(**{"mode": "apply", **over}))


class ProfileLookupTests(Quiet):
    """Every row of data-model.md's lookup table (research R3)."""

    def resolve(self, connections, connection=None, exact_name=False, region="ap-southeast-2", update=False):
        args = make_args("apply", connection=connection, exact_name=exact_name, region=region, update_credentials=update)
        return o.resolve_connection(connections, args, ACCOUNT, region)

    def test_a_full_name_wins_over_a_label(self):
        found = self.resolve([conn("c1", PROD), conn("c2", "prod")], "prod")
        self.assertEqual(found.connection.id, "c2")
        self.assertTrue(found.warnings, "a name without a registry is used with a warning")

    def test_a_label_finds_its_connection(self):
        self.assertEqual(self.resolve([conn("c1", PROD)], "prod").connection.id, "c1")

    def test_one_label_on_two_connections_is_refused(self):
        with self.assertRaisesRegex(o.Refusal, "2 connections are labeled 'prod'") as cm:
            self.resolve([conn("c1", PROD), conn("c2", f"prod {ADDR_A_US}")], "prod")
        self.assertEqual(len(cm.exception.connections), 2)

    def test_not_found_creates_label_and_address_or_the_value_or_the_exact_name(self):
        self.assertEqual(self.resolve([], "prod").name, PROD)
        self.assertEqual(self.resolve([], f"x {ADDR_A}").name, f"x {ADDR_A}")
        exact = self.resolve([], "Payments prod", exact_name=True)
        self.assertEqual((exact.connection, exact.name), (None, "Payments prod"))
        self.assertIn("cannot check its ECR", exact.warnings[-1])

    def test_a_value_naming_another_registry_is_refused(self):
        with self.assertRaisesRegex(o.Refusal, f"names registry {ADDR_B}"):
            self.resolve([], f"prod {ADDR_B}")

    def test_without_a_name_the_connection_carrying_the_registry_is_used(self):
        self.assertEqual(self.resolve([conn("c1", PROD), conn("c2", STAGING)]).connection.id, "c1")

    def test_without_a_name_two_connections_carrying_the_registry_are_refused(self):
        with self.assertRaisesRegex(o.Refusal, f"2 connections read registry {ADDR_A}"):
            self.resolve([conn("c1", PROD), conn("c2", f"dr {ADDR_A}")])

    def test_without_a_name_and_no_match_the_address_is_the_new_name(self):
        self.assertEqual(self.resolve([conn("c2", STAGING)]).name, ADDR_A)

    def test_without_a_name_a_connection_with_no_registry_in_its_name_blocks_a_create(self):
        with self.assertRaisesRegex(o.Refusal, "'Default profile'.*may read it"):
            self.resolve([conn("c9", "Default profile"), conn("c2", STAGING)])

    def test_a_second_connection_to_one_registry_is_allowed_with_a_warning(self):
        found = self.resolve([conn("c1", PROD)], "dr")
        self.assertEqual(found.name, f"dr {ADDR_A}")
        self.assertIn("imported twice", found.warnings[0])

    def test_a_name_carrying_another_registry_needs_update_credentials(self):
        with self.assertRaisesRegex(o.Refusal, f"points at registry {ADDR_A}, not {ADDR_A_US}"):
            self.resolve([conn("c1", PROD)], "prod", region="us-east-1")
        self.assertEqual(self.resolve([conn("c1", PROD)], "prod", region="us-east-1", update=True).connection.id, "c1")


class ProfileApplyTests(Quiet):
    """US1: several ECRs in one org, each onboarded on its own."""

    def test_ac1_creates_the_named_connection_then_proves_previews_and_applies_on_it(self):
        c = FakeClient(profile_routes())
        self.assertEqual(o.run(make_args("apply", connection="prod"), c), 0)
        self.assertEqual(body_of(c, "POST", "/closed-beta/orgs/"), {"data": {"type": "integration", "attributes": {
            "integration_type": "ecr", "profile_name": PROD,
            "credentials": {"region": "ap-southeast-2", "role_arn": ROLE}}}})
        self.assertEqual(len(closed_beta_writes(c)), 1, "one closed-beta write per run (R12)")
        sync = [p for m, p in c.methods() if "/container_import/" in p]
        self.assertTrue(sync and all("/container_import/new-conn/" in p for p in sync))
        out = self.out.getvalue()
        self.assertIn(f"[{PROD}] ECR connection created: new-conn", out)
        self.assertIn(f"[{PROD}] Sync policy applied for connection {PROD};", out)

    def test_ac2_a_second_connection_never_touches_the_first(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        self.assertEqual(o.run(make_args("apply", connection="staging", role_arn=ROLE_B), c), 0)
        self.assertEqual(body_of(c, "POST", "/closed-beta/orgs/")["data"]["attributes"]["profile_name"], STAGING)
        self.assertFalse([p for _, p in c.methods() if "c1" in p])

    def test_ac3_a_rerun_reuses_the_connection_and_replaces_only_its_policy(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        self.assertEqual(o.run(make_args("apply", connection="prod"), c), 0)
        self.assertEqual(closed_beta_writes(c), [])
        self.assertEqual(c.posts_to("/policy"), [f"/rest/orgs/{ORG}/container_import/c1/policy"])

    def test_ac4_and_sc007_an_unnamed_run_names_it_after_the_registry_and_finds_it_again(self):
        c = FakeClient(profile_routes())
        o.run(make_args("apply"), c)
        self.assertEqual(body_of(c, "POST", "/closed-beta/orgs/")["data"]["attributes"]["profile_name"], ADDR_A)
        again = FakeClient(profile_routes(profile_entry("new-conn", ADDR_A)))
        self.assertEqual(o.run(make_args("apply"), again), 0)
        self.assertEqual(closed_beta_writes(again), [])

    def test_ac6_a_connection_made_before_the_feature_blocks_an_unnamed_create(self):
        c = FakeClient(profile_routes(profile_entry("c0", None)))
        with self.assertRaises(o.Refusal):
            o.run(make_args("apply"), c)
        self.assertEqual(writes(c), [])

    def test_ac7_a_name_carrying_another_registry_is_refused_without_a_write(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        with self.assertRaisesRegex(o.Refusal, f"points at registry {ADDR_A}"):
            o.run(make_args("apply", connection="prod", region="us-east-1"), c)
        self.assertEqual(writes(c), [])

    def test_ac8_a_name_without_a_registry_is_used_with_a_warning(self):
        c = FakeClient(profile_routes(profile_entry("c3", "Payments")))
        self.assertEqual(o.run(make_args("apply", connection="Payments"), c), 0)
        self.assertIn("[Payments] Warning: this connection's name does not carry its registry", self.out.getvalue())
        self.assertEqual(c.posts_to("/policy"), [f"/rest/orgs/{ORG}/container_import/c3/policy"])

    def test_update_credentials_repoints_and_renames_so_the_name_stays_true(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        self.assertEqual(o.run(make_args("apply", connection="prod", region="us-east-1", update_credentials=True), c), 0)
        self.assertEqual(body_of(c, "PATCH", "/closed-beta/orgs/"), {"data": {"id": "c1", "type": "integration", "attributes": {
            "credentials": {"region": "us-east-1", "role_arn": ROLE}, "profile_name": f"prod {ADDR_A_US}"}}})
        self.assertIn(f"[prod {ADDR_A_US}] Sync policy applied", self.out.getvalue())

    def test_update_credentials_for_the_same_registry_sends_the_credentials_only(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        o.run(make_args("apply", connection="prod", update_credentials=True), c)
        self.assertNotIn("profile_name", body_of(c, "PATCH", "/closed-beta/orgs/")["data"]["attributes"])

    def test_plan_with_update_credentials_says_what_it_would_change_and_writes_nothing(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        self.assertEqual(o.run(make_args("plan", connection="prod", region="us-east-1", update_credentials=True), c), 0)
        self.assertEqual(writes(c), [])
        self.assertIn(f"would update credentials (--update-credentials) and rename it to 'prod {ADDR_A_US}'", self.out.getvalue())

    def test_plan_never_writes(self):
        c = FakeClient(profile_routes())
        self.assertEqual(o.run(make_args("plan", connection="prod"), c), 0)
        self.assertEqual(writes(c), [])
        self.assertIn(f"[{PROD}] ECR connection missing: apply would create it", self.out.getvalue())

    def test_a_name_conflict_is_a_refusal_and_never_retried(self):
        for method in ("POST", "PATCH"):
            with self.subTest(method=method):
                routes = profile_routes(profile_entry("c1", PROD))
                routes[(method, "/closed-beta/orgs/")] = [(409, {"errors": [{"detail": "conflict"}]})]
                args = (make_args("apply", connection="staging", role_arn=ROLE_B) if method == "POST" else
                        make_args("apply", connection="prod", region="us-east-1", update_credentials=True))
                c = FakeClient(routes)
                with self.assertRaisesRegex(o.Refusal, "already has a connection named"):
                    o.run(args, c)
                self.assertEqual(len(closed_beta_writes(c)), 1)

    def test_a_second_connection_to_one_registry_warns_of_double_imports(self):
        c = FakeClient(profile_routes(profile_entry("c1", PROD)))
        self.assertEqual(o.run(make_args("apply", connection="dr"), c), 0)
        self.assertIn("its images will be imported twice", self.out.getvalue())

    def test_sc001_three_connections_across_two_accounts_and_two_regions(self):
        listed = []
        for label, role, region in (("prod", ROLE, "ap-southeast-2"), ("staging", ROLE_B, "ap-southeast-2"),
                                    ("dr", ROLE, "us-east-1")):
            c = FakeClient(profile_routes(*listed))
            self.assertEqual(o.run(make_args("apply", connection=label, role_arn=role, region=region), c), 0)
            name = body_of(c, "POST", "/closed-beta/orgs/")["data"]["attributes"]["profile_name"]
            listed.append(profile_entry(f"id-{label}", name))
        made = o.connections_from(listed)
        self.assertEqual(len(made), 3)
        self.assertEqual({x.account for x in made}, {ACCOUNT, "111111111111"})
        self.assertEqual({x.region for x in made if x.account == ACCOUNT}, {"ap-southeast-2", "us-east-1"})


class ProfileFailureHintTests(Quiet):
    def test_a_failing_connection_test_names_the_connection_and_the_profile_orgs_input(self):
        routes = profile_routes()
        routes[("GET", "/dry_run/job-1")] = [dry_run_failed("cannot assume role")]
        with self.assertRaises(o.DryRunFailed) as cm:
            o.run(make_args("apply", connection="prod", no_sync=True, import_policy=None, repo=None), FakeClient(routes))
        message = str(cm.exception)
        self.assertIn(f"connection {PROD!r} of org {ORG}", message)
        self.assertIn("snyk_profile_orgs", message)
        self.assertIn(f"--connection {PROD!r} --update-credentials", message)


class ProvenanceTests(Quiet):
    """US2: each project under the connection Snyk says imported it, never by its name."""

    def routes(self, extra=None):
        host_b = ADDR_B
        r = profile_routes(profile_entry("c1", PROD), profile_entry("c2", STAGING),
                           projects=[ecr_project("p1", "team-a/app:v1.4.0", "t1"), ecr_project("p2", "team-a/app:v1.4.0", "t2"),
                                     ecr_project("p3", f"{host_b}/team-b/svc:v1", "t1"), ecr_project("p4", "old/app:v1", "t9")],
                           targets=[target_entry("t1", "c1"), target_entry("t2", "c2"), target_entry("t9", "gone")])
        r.update(extra or {})
        return r

    def test_the_same_image_in_two_registries_appears_under_each_connection(self):
        c = FakeClient(self.routes())
        self.assertEqual(o.run(make_args("status", region=None, role_arn=None), c), 0)
        out = self.out.getvalue()
        self.assertIn(f"[{PROD}]   - team-a/app:v1.4.0", out)
        self.assertIn(f"[{STAGING}]   - team-a/app:v1.4.0", out)
        self.assertEqual({m for m, _ in c.methods()}, {"GET"})

    def test_attribution_comes_from_the_target_never_from_the_name(self):
        o.run(make_args("status", region=None, role_arn=None), FakeClient(self.routes()))
        self.assertIn(f"[{PROD}]   - {ADDR_B}/team-b/svc:v1", self.out.getvalue())
        self.assertNotIn(f"[{STAGING}]   - {ADDR_B}/team-b/svc:v1", self.out.getvalue())

    def test_a_target_naming_no_listed_connection_is_reported_as_unknown(self):
        o.run(make_args("status", region=None, role_arn=None), FakeClient(self.routes()))
        self.assertIn("Connection unknown: 1 project(s) whose target names no listed connection", self.out.getvalue())
        self.assertIn("  ? old/app:v1", self.out.getvalue())

    def test_targets_follow_pagination(self):
        nxt = f"/orgs/{ORG}/targets?version=2025-09-17&starting_after=t1"
        c = FakeClient(self.routes(extra={("GET", "/targets?"): [(200, {"data": [target_entry("t1", "c1")], "links": {"next": nxt}}),
                                                              (200, {"data": [target_entry("t2", "c2")]})]}))
        self.assertEqual(c.list_targets(ORG), {"t1": "c1", "t2": "c2"})
        self.assertTrue(any(u.startswith(f"https://api.snyk.io/rest/orgs/{ORG}/targets?") and "starting_after" in u
                            for _, u, _, _ in c.calls))

    def test_every_line_of_the_read_proof_and_preview_names_the_connection(self):
        o.run(make_args("plan", connection="prod"), FakeClient(profile_routes(profile_entry("c1", PROD))))
        lines = [l for l in self.out.getvalue().splitlines()
                 if "Snyk can read the registry" in l or "team-a/app" in l or l.startswith("Dry run")]
        self.assertTrue(lines)
        self.assertTrue(all(l.startswith(f"[{PROD}] ") for l in lines), lines)

    def test_all_origins_names_each_ecr_projects_connection(self):
        o.run(make_args("status", region=None, role_arn=None, all_origins=True), FakeClient(self.routes()))
        self.assertIn(f"  * team-a/app:v1.4.0  [origin: ecr, connection: {STAGING}]", self.out.getvalue())


class ProfileTeardownTests(Quiet):
    """US3: pause or disconnect one connection; the others keep everything."""

    def routes(self, policy=True, extra=None):
        r = profile_routes(profile_entry("c1", PROD), profile_entry("c2", STAGING),
                           projects=[ecr_project("p1", "team-a/app:v1", "t1"), ecr_project("p2", "team-a/app:v1", "t2"),
                                     ecr_project("p3", "team-b/svc:v1", "t2")],
                           targets=[target_entry("t1", "c1"), target_entry("t2", "c2")])
        if policy:
            r[("GET", "/policy?")] = [(200, {"data": {"attributes": {"policy": {"name": "x"}}}})]
        r.update(extra or {})
        return r

    def deletes(self, c):
        return [p for m, p in c.methods() if m == "DELETE"]

    def test_no_name_or_an_unknown_name_is_refused(self):
        for name in (None, "qa"):
            with self.subTest(name=name):
                c = FakeClient(self.routes())
                with self.assertRaises(o.Refusal) as cm:
                    o.run(make_args("teardown", connection=name, yes=True), c)
                self.assertEqual(len(cm.exception.connections), 2)
                self.assertEqual(writes(c), [])

    def test_no_options_pauses_only_that_connection(self):
        c = FakeClient(self.routes())
        self.assertEqual(o.run(make_args("teardown", connection="staging", yes=True), c), 0)
        self.assertEqual(self.deletes(c), [f"/rest/orgs/{ORG}/container_import/c2/policy"])

    def test_the_disconnect_dry_run_counts_the_projects_and_deletes_nothing(self):
        c = FakeClient(self.routes())
        self.assertEqual(o.run(make_args("teardown", connection="staging", delete_connection=True), c), 0)
        self.assertIn(f"[{STAGING}] Connection: will be deleted, and with it 2 project(s) imported through it", self.out.getvalue())
        self.assertEqual(writes(c), [])

    def test_a_confirmed_disconnect_deletes_policy_projects_then_the_connection(self):
        c = FakeClient(self.routes())
        args = make_args("teardown", connection="staging", delete_projects=True, delete_connection=True, yes=True)
        self.assertEqual(o.run(args, c), 0)
        self.assertEqual(self.deletes(c), [f"/rest/orgs/{ORG}/container_import/c2/policy", f"/rest/orgs/{ORG}/projects/p2",
                                           f"/rest/orgs/{ORG}/projects/p3", f"/closed-beta/orgs/{ORG}/integrations/c2"])
        self.assertFalse([p for _, p in c.methods() if "c1" in p])
        self.assertIn(f"[{STAGING}] Connection deleted; Snyk is deleting its projects.", self.out.getvalue())

    def test_projects_are_selected_by_provenance_and_narrowed_by_an_optional_prefix(self):
        c = FakeClient(self.routes())
        o.run(make_args("teardown", connection="staging", delete_projects=True, repo_prefix="team-a/", yes=True), c)
        self.assertEqual([p for p in self.deletes(c) if "/projects/" in p], [f"/rest/orgs/{ORG}/projects/p2"])

    def test_unknown_provenance_among_the_candidates_refuses_with_nothing_deleted(self):
        c = FakeClient(self.routes(extra={("GET", "/targets?"): [(200, {"data": [target_entry("t1", "c1")]})]}))
        with self.assertRaisesRegex(o.Refusal, "no recorded connection"):
            o.run(make_args("teardown", connection="staging", delete_projects=True, yes=True), c)
        self.assertEqual(writes(c), [])

    def test_a_connection_made_before_the_feature_cannot_be_disconnected(self):
        c = FakeClient(profile_routes(profile_entry("c0", None)))
        with self.assertRaisesRegex(o.Refusal, "Profile Management.*rename it there to its registry address"):
            o.run(make_args("teardown", connection="Default profile", delete_connection=True, yes=True), c)
        self.assertEqual(writes(c), [])

    def test_delete_credentials_is_refused_in_profiles_mode(self):
        c = FakeClient(self.routes())
        with self.assertRaisesRegex(o.Refusal, "--delete-connection"):
            o.run(make_args("teardown", connection="staging", delete_credentials=True, yes=True), c)
        self.assertEqual(writes(c), [])

    def test_a_connection_already_gone_is_reported(self):
        c = FakeClient(self.routes(extra={("DELETE", "/closed-beta/orgs/"): [(404, {})]}))
        self.assertEqual(o.run(make_args("teardown", connection="staging", delete_connection=True, yes=True), c), 0)
        self.assertIn("Connection: already gone.", self.out.getvalue())

    def test_a_spent_allowance_stops_before_the_policy_is_deleted(self):
        spent = (200, {"data": [profile_entry("c2", STAGING)]}, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "900"})
        c = FakeClient(self.routes(extra={("GET", "/closed-beta/orgs/"): [spent]}))
        with self.assertRaises(o.RateLimited):
            o.run(make_args("teardown", connection="staging", delete_connection=True, yes=True), c)
        self.assertEqual(writes(c), [])


class ProfileDeleteScopeTests(Quiet):
    """Constitution Principle I in profiles mode: only the named connection's policy, the connection
    itself, and projects whose target names it may ever be deleted."""

    def test_every_teardown_combination_stays_inside_the_named_connection(self):
        allowed = {f"/rest/orgs/{ORG}/container_import/c2/policy", f"/closed-beta/orgs/{ORG}/integrations/c2",
                   f"/rest/orgs/{ORG}/projects/p2", f"/rest/orgs/{ORG}/projects/p3"}
        for delete_projects in (False, True):
            for delete_connection in (False, True):
                for prefix in (None, "team-a/", "team-"):
                    with self.subTest(projects=delete_projects, connection=delete_connection, prefix=prefix):
                        c = FakeClient(ProfileTeardownTests.routes(None))
                        o.run(make_args("teardown", connection="staging", delete_projects=delete_projects,
                                        delete_connection=delete_connection, repo_prefix=prefix, yes=True), c)
                        gone = {p for m, p in c.methods() if m == "DELETE"}
                        self.assertTrue(gone <= allowed, gone - allowed)
                        self.assertFalse([p for _, p in c.methods() if p.startswith("/v1/")])


class RefusalOutputTests(Quiet):
    """contracts/cli.md: a refusal prints 'Refused: ...' and the org's connections to stderr, exit 1."""

    def test_main_prints_the_refusal_and_the_connections(self):
        fake = FakeClient(profile_routes(profile_entry("c0", None), profile_entry("c2", STAGING)))
        argv = ["apply", "--org-id", ORG, "--region", "ap-southeast-2", "--role-arn", ROLE, "--import-policy", "ImportAll"]
        with unittest.mock.patch.object(o, "SnykClient", lambda *a, **k: fake), \
                unittest.mock.patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}):
            self.assertEqual(o.main(argv), 1)
        err = self.err.getvalue()
        self.assertIn("Refused: no connection's name carries registry", err)
        self.assertIn("Connections in this org:\n  Default profile (registry not in its name)\n"
                      f"  {STAGING} (account 111111111111, region ap-southeast-2)\n", err)
        self.assertEqual(writes(fake), [])


class ProfileStatusTests(Quiet):
    """US5: every connection in one read-only report."""

    def routes(self):
        r = profile_routes(profile_entry("c1", PROD), profile_entry("c2", STAGING), profile_entry("c3", "Payments"))
        r[("GET", "/policy?")] = [(200, {"data": {"attributes": {"policy": {
            "name": "p", "import_policy": {"type": "Regex"}, "schedule_frequency_hours": 6}}}})]
        return r

    def test_lists_every_connection_with_where_it_reads_and_its_policy_and_only_reads(self):
        c = FakeClient(self.routes())
        self.assertEqual(o.run(make_args("status", region=None, role_arn=None), c), 0)
        out = self.out.getvalue()
        self.assertIn(f"[{PROD}] ECR connection: c1 (account {ACCOUNT}, region ap-southeast-2)", out)
        self.assertIn(f"[{STAGING}] ECR connection: c2 (account 111111111111, region ap-southeast-2)", out)
        self.assertIn("[Payments] ECR connection: c3 (account and region not in its name; Snyk's UI shows them under "
                      "Organization settings → Integrations → Amazon ECR → Profile Management)", out)
        self.assertEqual(out.count("Sync policy    : p (import_policy Regex; schedule_frequency_hours 6;"), 3)
        self.assertEqual({m for m, _ in c.methods()}, {"GET"})

    def test_a_named_connection_is_reported_alone(self):
        o.run(make_args("status", region=None, role_arn=None, connection="staging"), FakeClient(self.routes()))
        out = self.out.getvalue()
        self.assertIn(f"[{STAGING}] ECR connection: c2", out)
        self.assertNotIn(f"[{PROD}]", out)

    def test_an_unknown_name_is_refused(self):
        with self.assertRaises(o.Refusal):
            o.run(make_args("status", region=None, role_arn=None, connection="qa"), FakeClient(self.routes()))

if __name__ == "__main__":
    unittest.main()
