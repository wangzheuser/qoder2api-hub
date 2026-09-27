"""通过生产 Handler 的 loopback 请求验证 Credits 管理路由。"""
import http.client
from http.server import ThreadingHTTPServer
import json
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import qoder_accounts as A
import qoder_proxy as P
import qoder_settings as S


class CreditsRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pool = A.AccountPool(self.temp.name)
        self.cn = self.pool.add(A.Account({"uid": "cn-account", "realm": "cn", "accessToken": "synthetic", "expiresAt": 9999999999}))
        self.intl = self.pool.add(A.Account({"uid": "intl-account", "realm": "intl", "accessToken": "synthetic", "expiresAt": 9999999999}))
        for account in (self.cn, self.intl):
            account.credits = {"remain": 42}
            account.fetch_credits = Mock(return_value={"ok": True})
            account.fetch_plan = Mock(return_value={"ok": True})
            account.checkin_status = Mock(side_effect=AssertionError("unexpected checkin"))
            account.pro_eligibility = Mock(side_effect=AssertionError("unexpected pro"))
        self.service = Mock()
        self.service.cached.return_value = None
        self.service.details.return_value = {"available": 42, "status": "ok", "campaigns": [
            {"campaignId": "campaign-one", "name": "International gift", "claimStatus": "CLAIMABLE", "actionType": "CLAIM_BENEFIT"}
        ]}
        self.service.bulk.return_value = [self.service.details.return_value]
        self.service.claim.return_value = {"claimed": True, "status": "CLAIMED"}
        self.settings = S.gateway_settings(self.temp.name)
        self.settings["credits_details_enabled"] = False
        self.panel = S.PanelSessions()
        self.token = self.panel.create()
        for guard in (patch.object(P, "POOL", self.pool), patch.object(P, "ACCOUNTS_DIR", self.temp.name),
                      patch.object(P, "PANEL", self.panel), patch.object(P.qoder_credits, "SERVICE", self.service),
                      patch.object(S, "gateway_settings", side_effect=lambda directory: dict(self.settings)),
                      patch.object(A, "http_json", side_effect=AssertionError("real network forbidden"))):
            guard.start()
            self.addCleanup(guard.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), P.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, path, payload=None, authenticated=True, headers=None):
        request_headers = dict(headers or {})
        if authenticated:
            request_headers["X-Panel-Token"] = self.token
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            conn.request("POST" if payload is not None else "GET", path,
                         body=json.dumps(payload) if payload is not None else None, headers=request_headers)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_panel_authorization_precedes_feature_gate(self):
        for path, payload in (("/accounts/credits/details", {"uid": self.cn.uid}),
                              ("/tasks/campaign/claim", {"uid": self.cn.uid, "campaign_id": "campaign-one"}),
                              ("/tasks?realm=intl", None)):
            status, body = self.request(path, payload, authenticated=False, headers={"Authorization": "Bearer synthetic-api-key"})
            self.assertEqual(status, 401)
            self.assertIn("panel", body["error"]["message"])
        self.service.details.assert_not_called()
        self.service.bulk.assert_not_called()
        self.service.claim.assert_not_called()

    def test_details_disabled_and_enabled_invalid_uid(self):
        status, body = self.request("/accounts/credits/details", {"uid": self.cn.uid})
        self.assertEqual(status, 400)
        self.assertIn("feature_disabled", json.dumps(body))
        self.service.details.assert_not_called()
        self.settings["credits_details_enabled"] = True
        status, _ = self.request("/accounts/credits/details", {"uid": "missing"})
        self.assertEqual(status, 404)
        self.service.details.assert_not_called()

    def test_details_success_forwards_account_and_force(self):
        self.settings["credits_details_enabled"] = True
        status, body = self.request("/accounts/credits/details", {"uid": self.intl.uid, "force": True})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"uid": self.intl.uid, "credits_details": self.service.details.return_value})
        self.service.details.assert_called_once_with(self.intl, force=True)

    def test_legacy_credits_default_does_not_fetch_details(self):
        for enabled in (False, True):
            self.settings["credits_details_enabled"] = enabled
            status, body = self.request("/accounts/credits", {"uid": self.cn.uid})
            self.assertEqual(status, 200)
            self.assertIn("results", body)
            self.assertIn("accounts", body)
            self.assertEqual(body["results"][0]["credits"], {"remain": 42})
        self.assertEqual(self.cn.fetch_credits.call_count, 2)
        self.service.details.assert_not_called()

    def test_legacy_explicit_details_preserves_response_shape(self):
        self.settings["credits_details_enabled"] = True
        status, body = self.request("/accounts/credits", {"uid": self.cn.uid, "details": True})
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["uid"], self.cn.uid)
        self.assertIn("accounts", body)
        self.assertIn("credits_details", json.dumps(body))
        self.service.bulk.assert_called_once_with([self.cn], force=False)

    def test_account_views_uses_cache_only(self):
        self.settings["credits_details_enabled"] = True
        self.service.cached.return_value = {"available": 9}
        rows = P.account_views(realm="intl")
        self.assertEqual([row["uid"] for row in rows], [self.intl.uid])
        self.assertEqual(rows[0]["credits_details"], {"available": 9})
        self.service.cached.assert_called_once_with(self.intl)
        self.service.details.assert_not_called()
        self.service.campaigns.assert_not_called()

    def test_campaign_claim_gate_and_single_uid(self):
        status, body = self.request("/tasks/campaign/claim", {"uid": self.intl.uid, "campaign_id": "campaign-one"})
        self.assertEqual(status, 400)
        self.assertIn("feature_disabled", json.dumps(body))
        self.settings["credits_details_enabled"] = True
        for uid, expected in ((None, 400), ("all", 400), ("missing", 404)):
            status, _ = self.request("/tasks/campaign/claim", {"uid": uid, "campaign_id": "campaign-one"})
            self.assertEqual(status, expected)
        self.service.claim.assert_not_called()
        status, body = self.request("/tasks/campaign/claim", {"uid": self.intl.uid, "campaign_id": "campaign-one"})
        self.assertEqual(status, 200)
        self.assertTrue(body["claimed"])
        self.service.claim.assert_called_once_with(self.intl, "campaign-one")

    def test_international_campaign_view_does_not_call_cn_activities(self):
        self.settings["credits_details_enabled"] = True
        status, body = self.request("/tasks?realm=intl&uid=" + self.intl.uid)
        self.assertEqual(status, 200)
        self.assertEqual(body["account"]["realm"], "intl")
        self.assertTrue(any(row["task_code"] == "campaign:campaign-one" for row in body["tasks"]))
        self.intl.checkin_status.assert_not_called()
        self.intl.pro_eligibility.assert_not_called()
        self.cn.fetch_credits.assert_not_called()

    def test_international_tasks_disabled_do_not_fetch_generic_campaigns(self):
        status, body = self.request("/tasks?realm=intl&uid=" + self.intl.uid)
        self.assertEqual(status, 200)
        self.assertEqual(body["tasks"], [])
        self.service.details.assert_not_called()
        self.intl.checkin_status.assert_not_called()
        self.intl.pro_eligibility.assert_not_called()

    def test_campaign_claim_requires_id_and_enabled_account(self):
        self.settings["credits_details_enabled"] = True
        status, _ = self.request("/tasks/campaign/claim", {"uid": self.intl.uid})
        self.assertEqual(status, 400)
        self.intl.enabled = False
        status, _ = self.request("/tasks/campaign/claim", {"uid": self.intl.uid, "campaign_id": "campaign-one"})
        self.assertEqual(status, 400)
        self.service.claim.assert_not_called()

    def test_tasks_realm_mismatch_never_fetches_other_account(self):
        self.settings["credits_details_enabled"] = True
        status, body = self.request("/tasks?realm=intl&uid=" + self.cn.uid)
        self.assertEqual(status, 200)
        self.assertEqual(body["tasks"], [])
        self.service.details.assert_not_called()
        status, _ = self.request("/tasks?realm=unknown")
        self.assertEqual(status, 400)

    def test_campaign_view_only_known_active_claim_actions_are_claimable(self):
        self.settings["credits_details_enabled"] = True
        self.service.details.return_value = {"campaigns": [
            {"campaignId": "view", "actionType": "VIEW_DETAILS", "claimStatus": "CLAIMABLE", "url": "https://example.com/details"},
            {"campaignId": "unknown", "actionType": "OTHER", "claimStatus": "CLAIMABLE", "url": "javascript:alert(1)"},
            {"campaignId": "expired", "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE", "endAt": 1},
        ]}
        status, body = self.request("/tasks?realm=intl&uid=" + self.intl.uid)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["tasks"]), 3)
        self.assertFalse(any(row["claimable"] for row in body["tasks"]))
        self.assertEqual(body["tasks"][0]["jump_url"], "https://example.com/details")
        self.assertEqual(body["tasks"][1]["jump_url"], "")
        self.service.claim.assert_not_called()


if __name__ == "__main__":
    unittest.main()
