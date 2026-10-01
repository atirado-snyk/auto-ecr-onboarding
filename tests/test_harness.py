"""Safety tests for the e2e harness's throwaway-org helper (examples/sandbox/harness.py)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "examples" / "sandbox"))
import harness as h  # noqa: E402
from test_onboard_ecr import FakeClient  # noqa: E402

ORG = "33333333-3333-3333-3333-333333333333"
GROUP = "44444444-4444-4444-4444-444444444444"


def org_routes(name, status=200):
    body = {"data": {"id": ORG, "attributes": {"name": name}}} if status == 200 else {}
    return {("GET", f"/rest/orgs/{ORG}"): [(status, body)], ("DELETE", f"/v1/org/{ORG}"): [(204, {})]}


def deletes(c):
    return [p for m, p in c.methods() if m == "DELETE"]


class DeleteOrgTests(unittest.TestCase):
    def test_deletes_an_org_the_harness_created(self):
        c = FakeClient(org_routes("ecr-e2e-20261001-120000"))
        self.assertTrue(h.delete_org(c, ORG, []))
        self.assertEqual(deletes(c), [f"/v1/org/{ORG}"])

    def test_refuses_an_org_not_named_by_the_harness(self):
        c = FakeClient(org_routes("team-a-prod"))
        with self.assertRaisesRegex(h.UsageError, "only orgs named ecr-e2e-"):
            h.delete_org(c, ORG, [])
        self.assertEqual(deletes(c), [])

    def test_refuses_a_protected_org_even_if_prefixed(self):
        c = FakeClient(org_routes("ecr-e2e-x"))
        with self.assertRaisesRegex(h.UsageError, "protected"):
            h.delete_org(c, ORG, [ORG.upper()])
        self.assertEqual(c.methods(), [])  # not even looked up

    def test_already_gone_is_not_an_error(self):
        for status in (404, 403):
            c = FakeClient(org_routes("", status=status))
            self.assertFalse(h.delete_org(c, ORG, []))
            self.assertEqual(deletes(c), [])

    def test_delete_that_finds_nothing_is_already_gone(self):
        r = org_routes("ecr-e2e-x")
        r[("DELETE", f"/v1/org/{ORG}")] = [(404, {"message": "Org not found"})]
        self.assertFalse(h.delete_org(FakeClient(r), ORG, []))

    def test_rejects_malformed_ids(self):
        with self.assertRaises(h.UsageError):
            h.delete_org(FakeClient({}), "not-a-uuid", [])


class CreateOrgTests(unittest.TestCase):
    def test_creates_in_the_group_without_copying_settings(self):
        c = FakeClient({("POST", "/v1/org"): [(201, {"id": ORG})]})
        self.assertEqual(h.create_org(c, GROUP, "ecr-e2e-1"), ORG)
        self.assertEqual(c.calls[0][3], {"name": "ecr-e2e-1", "groupId": GROUP})  # no sourceOrgId

    def test_an_unknown_group_explains_group_versus_org_id(self):
        c = FakeClient({("POST", "/v1/org"): [(404, {"message": "Group not found"})]})
        with self.assertRaisesRegex(h.UsageError, "group ID, not an org ID.*harness.py groups"):
            h.create_org(c, GROUP, "ecr-e2e-1")

    def test_name_must_carry_the_harness_prefix(self):
        with self.assertRaises(h.UsageError):
            h.create_org(FakeClient({}), GROUP, "my-org")


class OrgListedTests(unittest.TestCase):
    def page(self, ids, nxt=None):
        p = {"data": [{"id": i, "attributes": {"name": "ecr-e2e-" + i[:4]}} for i in ids]}
        if nxt:
            p["links"] = {"next": nxt}
        return p

    def test_listed_and_not_listed(self):
        c = FakeClient({("GET", f"/rest/groups/{GROUP}/orgs"): [(200, self.page([ORG]))]})
        self.assertTrue(h.org_listed(c, GROUP, ORG))
        self.assertIn("name=ecr-e2e-", c.calls[0][1])  # filtered to harness orgs
        c = FakeClient({("GET", f"/rest/groups/{GROUP}/orgs"): [(200, self.page(["other"]))]})
        self.assertFalse(h.org_listed(c, GROUP, ORG))

    def test_follows_pagination(self):
        nxt = f"/groups/{GROUP}/orgs?version=2025-09-17&starting_after=abc"
        c = FakeClient({("GET", f"/rest/groups/{GROUP}/orgs"): [(200, self.page(["a"], nxt)), (200, self.page([ORG]))]})
        self.assertTrue(h.org_listed(c, GROUP, ORG))


class GroupTests(unittest.TestCase):
    def test_lists_each_group_once(self):
        c = FakeClient({("GET", "/v1/orgs"): [(200, {"orgs": [
            {"id": "a", "group": {"id": GROUP, "name": "SE Demo"}},
            {"id": "b", "group": {"id": GROUP, "name": "SE Demo"}},
            {"id": "c", "group": None},
        ]})]})
        self.assertEqual(h.list_groups(c), [(GROUP, "SE Demo")])


if __name__ == "__main__":
    unittest.main()
