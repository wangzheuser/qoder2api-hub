"""Credits 明细、共享并发容量和领取确认的纯离线回归。"""
from concurrent.futures import ThreadPoolExecutor
import copy
import io
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qoder_accounts as A
import qoder_credits as C


class CreditsTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.calls = []
        self.account = self.account_for("synthetic")
        self.payloads = {
            "usage": {"displayMode": "qoder", "qoderUsage": {
                "userQuota": {"used": 0, "total": 100}, "addOnQuota": {"used": 3}}},
            "summary": {"totalCredits": 12, "peakCredits": 20},
            "activity": {"currentConsecutiveDays": 0, "maxConsecutiveDays": 5},
            "campaigns": {"campaigns": [self.campaign()]},
        }
        self.service = C.CreditsService(http=self.http, clock=lambda: self.now)
        self.addCleanup(self.service.close)

    @staticmethod
    def account_for(uid, realm="cn"):
        return A.Account({"uid": uid, "realm": realm, "accessToken": "synthetic-token-" + uid})

    @staticmethod
    def campaign(**changes):
        row = {"campaignId": "gift/with?path", "campaignKey": "gift", "actionType": "CLAIM_BENEFIT",
               "claimStatus": "CLAIMABLE", "startAt": 900, "endAt": 2000,
               "benefit": {"kind": "CREDITS", "amount": 0},
               "placements": [{"type": "USAGE", "content": {"zh": {
                   "title": "活动标题", "description": "详情", "detailUrl": "https://example.invalid/info"}}}]}
        row.update(changes)
        return row

    def http(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if kwargs.get("method") == "POST":
            return {"status": "CLAIMED"}
        name = next(name for name, path in C.ENDPOINTS.items() if url.endswith(path))
        result = self.payloads[name]
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    @staticmethod
    def error(status):
        return urllib.error.HTTPError("https://example.invalid/credits", status, "synthetic", {}, io.BytesIO(b"{}"))

    def posts(self):
        return [call for call in self.calls if call[1].get("method") == "POST"]

    def test_cache_ttl_missing_zero_and_defensive_copy(self):
        self.assertIsNone(self.service.cached(self.account))
        self.assertEqual(self.calls, [])
        first = self.service.details(self.account)
        self.assertEqual(first["plan_used"], 0)
        self.assertIsNone(first["addon_total"])
        self.assertEqual(first["activity"]["current_streak_days"], 0)
        self.assertIsNone(first["activity"]["total_active_days"])
        self.assertEqual(first["campaigns"][0]["name"], "活动标题")
        first["campaigns"].clear()
        self.assertEqual(len(self.service.details(self.account)["campaigns"]), 1)
        self.assertEqual(len(self.calls), 4)
        self.now += 301
        self.assertTrue(self.service.cached(self.account)["stale"])
        self.assertEqual(len(self.calls), 4)
        self.service.details(self.account)
        self.assertEqual(len(self.calls), 8)

    def test_token_and_replacement_account_isolate_cache_and_retire_old_versions(self):
        self.service.details(self.account)
        self.account.access_token = "synthetic-new-token"
        self.assertIsNone(self.service.cached(self.account))
        self.service.details(self.account)
        self.assertEqual(len(self.calls), 8)
        replacement = self.account_for(self.account.uid)
        replacement.access_token = self.account.access_token
        self.assertIsNone(self.service.cached(replacement))
        self.service.details(replacement)
        self.assertEqual(len(self.calls), 12)
        self.assertEqual(len(self.service._cache), 1)
        self.assertNotIn(replacement.access_token, repr(self.service._cache.keys()))
        self.service.invalidate(replacement.uid)
        self.assertIsNone(self.service.cached(replacement))

    def test_force_refresh_coalesces_inflight_even_with_existing_cache(self):
        self.service.details(self.account)
        entered, release = threading.Event(), threading.Event()
        original = self.service._http

        def blocked(url, **kwargs):
            entered.set()
            self.assertTrue(release.wait(5))
            return original(url, **kwargs)

        self.service._http = blocked
        self.addCleanup(release.set)
        with ThreadPoolExecutor(max_workers=8) as callers:
            first = callers.submit(self.service.details, self.account, True)
            self.assertTrue(entered.wait(5))
            pending = [self.service._details_future(self.account, force=True) for _ in range(7)]
            self.assertTrue(all(future is pending[0] for future in pending))
            release.set()
            self.assertEqual(first.result()["total_credits"], 12)
            for future in pending:
                self.assertEqual(future.result()["total_credits"], 12)
        self.assertEqual(len(self.calls), 8)

    def test_partial_failure_keeps_successful_fields_and_previous_values(self):
        self.service.details(self.account)
        self.payloads["summary"] = self.error(503)
        self.payloads["usage"]["qoderUsage"]["userQuota"]["used"] = 5
        result = self.service.details(self.account, force=True)
        self.assertTrue(result["partial"])
        self.assertEqual(result["plan_used"], 5)
        self.assertEqual(result["total_credits"], 12)
        self.assertEqual(result["endpoint_status"]["summary"]["status"], "temporarily_unavailable")
        self.assertEqual(self.payloads["summary"].fp.closed, True)

    def test_http_200_error_envelope_preserves_previous_data(self):
        self.service.details(self.account)
        for error in ({"code": 401, "msg": "expired"}, {"success": False},
                      {"data": {"error": "provider_error"}}):
            with self.subTest(error=error):
                self.payloads["summary"] = error
                result = self.service.details(self.account, force=True)
                self.assertTrue(result["partial"])
                self.assertEqual(result["total_credits"], 12)
                self.assertNotEqual(result["endpoint_status"]["summary"]["status"], "supported")

    def test_token_refresh_during_fetch_preserves_same_account_inflight(self):
        entered, release = threading.Event(), threading.Event()
        original = self.http

        def refresh():
            self.account.access_token = "synthetic-refreshed-token"
            return True

        def blocked(url, **kwargs):
            entered.set()
            self.assertTrue(release.wait(5))
            return original(url, **kwargs)

        self.service._http = blocked
        self.addCleanup(release.set)
        with patch.object(self.account, "refresh_if_needed", side_effect=refresh), \
                ThreadPoolExecutor(max_workers=2) as callers:
            first = callers.submit(self.service.details, self.account, True)
            self.assertTrue(entered.wait(5))
            shared = self.service._details_future(self.account, force=True)
            self.assertEqual(len(self.service._inflight), 1)
            release.set()
            self.assertEqual(first.result(), shared.result())
        self.assertEqual(len(self.calls), 4)

    def test_retire_disable_or_rotate_during_campaign_query_prevents_post(self):
        original = self.http
        for change in ("retire", "disable", "token", "invalidate"):
            with self.subTest(change=change):
                self.account = self.account_for("synthetic-" + change)

                def changed(url, **kwargs):
                    result = original(url, **kwargs)
                    if url.endswith(C.ENDPOINTS["campaigns"]):
                        if change == "retire":
                            self.account._retired = True
                        elif change == "disable":
                            self.account.enabled = False
                        elif change == "token":
                            self.account.access_token = "synthetic-rotated-token"
                        else:
                            self.service.invalidate(self.account)
                    return result

                self.service._http = changed
                result = self.service.claim(self.account, "gift/with?path")
                self.assertFalse(result["claimed"])
                self.assertEqual(result["status"], "not_claimable")
        self.assertEqual(self.posts(), [])

    def test_endpoint_negative_caches_differentiate_auth_unsupported_and_transient(self):
        for code, expected, delay in ((401, "unknown", 30), (403, "unknown", 30),
                                      (404, "unsupported", 3600), (410, "unsupported", 3600),
                                      (503, "temporarily_unavailable", 30)):
            with self.subTest(code=code):
                self.service.invalidate(self.account)
                self.payloads["summary"] = self.error(code)
                result = self.service.details(self.account)
                state = result["endpoint_status"]["summary"]
                self.assertEqual(state["status"], expected)
                self.assertEqual(state["retry_at"], self.now + delay)
                before = len(self.calls)
                self.now += 29
                self.service.details(self.account)
                self.assertEqual(len(self.calls), before)
                self.payloads["summary"] = {"totalCredits": 4}
                self.service.details(self.account, force=True)
                self.assertEqual(len(self.calls), before + 4)
                self.assertEqual(self.service.cached(self.account)["total_credits"], 4)

    def test_transient_expiry_retries_only_failed_endpoint(self):
        self.payloads["summary"] = self.error(503)
        self.service.details(self.account)
        self.now += 31
        self.payloads["summary"] = {"totalCredits": 42}
        result = self.service.details(self.account)
        self.assertEqual(len(self.calls), 5)
        self.assertEqual(result["total_credits"], 42)
        self.assertFalse(result["partial"])

    def test_unsupported_endpoint_remains_negative_cached_for_one_hour(self):
        self.payloads["summary"] = self.error(404)
        self.service.details(self.account)
        self.payloads["summary"] = {"totalCredits": 99}
        self.now += 301
        result = self.service.details(self.account)
        self.assertEqual(len(self.calls), 7)
        self.assertIsNone(result["total_credits"])
        self.assertEqual(result["endpoint_status"]["summary"]["status"], "unsupported")
        self.now += 3300
        result = self.service.details(self.account)
        self.assertEqual(result["total_credits"], 99)
        self.assertFalse(result["partial"])

    def test_shared_executor_caps_four_workers_and_eight_submissions(self):
        release = threading.Event()
        four_started = threading.Event()
        lock = threading.Lock()
        active = peak = 0

        def blocked(url, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                if active == 4:
                    four_started.set()
            try:
                self.assertTrue(release.wait(5))
                return self.http(url, **kwargs)
            finally:
                with lock:
                    active -= 1

        self.service._http = blocked
        other = C.CreditsService(http=blocked, clock=lambda: self.now)
        self.addCleanup(other.close)
        self.addCleanup(release.set)
        pending = [self.service._details_future(self.account_for(str(i))) for i in range(4)]
        self.assertTrue(four_started.wait(5))
        pending.extend(other._details_future(self.account_for(str(i))) for i in range(4, 8))
        with self.assertRaises(C.CreditsBusy):
            other.details(self.account_for("overflow"))
        release.set()
        for future in pending:
            future.result()
        self.assertEqual(peak, 4)

    def test_bulk_retains_order_and_uses_realm_headers(self):
        accounts = [self.account_for(str(i), "intl" if i % 2 else "cn") for i in range(13)]
        results = self.service.bulk(accounts)
        self.assertEqual([row["uid"] for row in results], [account.uid for account in accounts])
        self.assertEqual(len(self.calls), 52)
        for url, options in self.calls:
            self.assertEqual(options["headers"]["Cosy-ClientType"], "10")
            self.assertEqual(options["retries"], 1)
            self.assertTrue(url.startswith(("https://openapi.qoder.sh/", "https://openapi.qoder.com.cn/")))

    def test_invalid_actions_dates_and_unlisted_ids_never_post(self):
        for changes in ({"actionType": "VIEW_DETAILS"}, {"actionType": "UNKNOWN"},
                        {"claimStatus": "LOCKED"}, {"startAt": 1001}, {"endAt": 999},
                        {"startAt": "bad"}):
            with self.subTest(changes=changes):
                self.payloads["campaigns"] = {"campaigns": [self.campaign(**changes)]}
                result = self.service.claim(self.account, "gift/with?path")
                self.assertFalse(result["claimed"])
                self.assertEqual(result["status"], "not_claimable")
        result = self.service.claim(self.account, "not-listed")
        self.assertFalse(result["claimed"])
        self.assertEqual(self.posts(), [])

    def test_claimed_activity_never_posts_again(self):
        self.payloads["campaigns"] = {"campaigns": [self.campaign(claimStatus="CLAIMED")]}
        result = self.service.claim(self.account, "gift/with?path")
        self.assertTrue(result["claimed"])
        self.assertEqual(result["status"], "already_claimed")
        self.assertEqual(self.posts(), [])

    def test_claim_single_encoded_post_and_confirmed_response(self):
        result = self.service.claim(self.account, "gift/with?path")
        self.assertTrue(result["claimed"])
        url, options = self.posts()[0]
        self.assertTrue(url.endswith("/gift%2Fwith%3Fpath/claim"))
        self.assertNotIn("Content-Type", options["headers"])
        self.assertEqual(options["retries"], 1)
        self.assertEqual(len(self.calls), 9)
        again = self.service.claim(self.account, "gift/with?path")
        self.assertEqual(again["status"], "already_claimed")
        self.assertEqual(len(self.posts()), 1)

    def test_2xx_without_claimed_is_not_success(self):
        original = self.http

        def reply(url, **kwargs):
            result = original(url, **kwargs)
            return {"status": "PENDING"} if kwargs["method"] == "POST" else result

        self.service._http = reply
        result = self.service.claim(self.account, "gift/with?path")
        self.assertFalse(result["ok"])
        self.assertFalse(result["claimed"])
        self.assertEqual(result["status"], "unconfirmed")
        self.assertEqual(len(self.posts()), 1)

    def test_timeout_refreshes_state_without_post_retry(self):
        original = self.http
        for confirmed in (False, True):
            with self.subTest(confirmed=confirmed):
                self.service.invalidate(self.account)
                self.calls.clear()
                self.payloads["campaigns"] = {"campaigns": [self.campaign()]}

                def timeout(url, **kwargs):
                    result = original(url, **kwargs)
                    if kwargs["method"] == "POST":
                        if confirmed:
                            self.payloads["campaigns"] = {"campaigns": [self.campaign(claimStatus="CLAIMED")]}
                        raise TimeoutError("synthetic timeout")
                    return result

                self.service._http = timeout
                result = self.service.claim(self.account, "gift/with?path")
                self.assertEqual(result["claimed"], confirmed)
                self.assertEqual(result["status"], "claimed" if confirmed else "unknown")
                self.assertEqual(len(self.posts()), 1)
                self.assertEqual(len(self.calls), 9)

    def test_repeated_clicks_merge_one_claim(self):
        entered, release = threading.Event(), threading.Event()
        original = self.http

        def blocked(url, **kwargs):
            if kwargs["method"] == "POST":
                entered.set()
                self.assertTrue(release.wait(5))
            return original(url, **kwargs)

        self.service._http = blocked
        self.addCleanup(release.set)
        with ThreadPoolExecutor(max_workers=2) as callers:
            first = callers.submit(self.service.claim, self.account, "gift/with?path")
            self.assertTrue(entered.wait(5))
            second = callers.submit(self.service.claim, self.account, "gift/with?path")
            release.set()
            self.assertTrue(first.result()["claimed"])
            self.assertTrue(second.result()["claimed"])
        self.assertEqual(len(self.posts()), 1)

    def test_campaign_failure_does_not_authorize_cached_claim_and_urls_are_filtered(self):
        self.payloads["campaigns"]["campaigns"][0]["placements"][0]["content"]["zh"]["detailUrl"] = "javascript:alert(1)"
        self.assertIsNone(self.service.details(self.account)["campaigns"][0]["url"])
        self.payloads["campaigns"] = self.error(401)
        result = self.service.claim(self.account, "gift/with?path")
        self.assertFalse(result["claimed"])
        self.assertEqual(self.posts(), [])


if __name__ == "__main__":
    unittest.main()
