"""独立复核发现的协议边界与指定账号测试回归。"""
import unittest
from unittest.mock import Mock, patch

import test_recovery as fixtures
from test_recovery import P, Response, envelope, success


class FinalBoundaryTests(unittest.TestCase):
    setUp = fixtures.RecoveryTests.setUp
    context = fixtures.RecoveryTests.context
    open_sequence = fixtures.RecoveryTests.open_sequence
    http_error = fixtures.RecoveryTests.http_error
    handler = fixtures.RecoveryTests.handler

    def test_usage_or_role_only_done_is_protocol_failure_without_replay(self):
        for body in ({"choices": [], "usage": {"total_tokens": 5}},
                     {"choices": [{"delta": {"role": "assistant"}}]}):
            with self.subTest(body=body):
                ctx = self.context()
                with self.open_sequence(Response(envelope(body), envelope("[DONE]"))):
                    with self.assertRaises(P.UpstreamStatus) as caught:
                        list(P.iter_with_recovery(ctx, {}))
                self.assertEqual(caught.exception.info.kind, "protocol")
                self.assertEqual(ctx.attempts, 1)
                self.assertFalse(ctx.business_started)
                self.assertIsNone(ctx.lease)

    def test_role_before_transient_can_recover_without_duplicate_prelude(self):
        role = envelope({"choices": [{"delta": {"role": "assistant"}}]})
        broken = Response(role, envelope({"error": "provider_error"}, 503))
        healthy = Response(role, *success().lines)
        ctx = self.context()
        with self.open_sequence(broken, healthy):
            lines = b"".join(P.iter_with_recovery(ctx, {}))
        self.assertEqual(ctx.attempts, 2)
        self.assertEqual(lines.count(b'"role": "assistant"'), 1)
        self.assertEqual(lines.count(b"recovered"), 1)

    def test_protocol_failure_keeps_classification_at_http_boundary(self):
        handler = self.handler(False)
        with self.open_sequence(Response(envelope("[DONE]"))), patch.object(P, "record_error"):
            handler._handle_inference(self.payload)
        status, response = handler._json.call_args.args
        self.assertEqual(status, 502)
        self.assertEqual(response["error"]["type"], "upstream_protocol_error")
        self.assertNotIn("自动重试", response["error"]["message"])

    def test_account_test_uses_selected_uid_and_releases_lease(self):
        chosen = self.pool.accounts[1]
        handler = self.handler(False)
        acquired = []
        original = P._open_attempt
        def opened(ctx):
            acquired.append(ctx.account.uid)
            self.assertEqual(ctx.lease.account.uid, chosen.uid)
            return original(ctx)
        with self.open_sequence(success()), patch.object(P, "_open_attempt", side_effect=opened):
            handler._handle_accounts("/accounts/test", {"uid": chosen.uid, "model": "qfmodel"})
        self.assertEqual(acquired, [chosen.uid])
        self.assertTrue(handler._json.call_args.args[1]["ok"])
        self.assertEqual(sum(a.public()["inFlight"] for a in self.pool.accounts), 0)

    def test_fixed_account_failure_never_tests_a_different_account(self):
        ctx = self.context()
        ctx.account_uid = self.pool.accounts[1].uid
        errors = [self.http_error(503, {"error": "provider_error"}) for _ in range(3)]
        with self.open_sequence(*errors):
            with self.assertRaises(P.UpstreamStatus):
                list(P.iter_with_recovery(ctx, {}))
        self.assertEqual(ctx.tried, {ctx.account_uid})
        self.assertEqual(ctx.attempts, 3)

    def test_malformed_request_is_400_before_account_selection(self):
        for responses, bad in [(True, {"input": 123}), (False, {"messages": "wrong"}),
                               (True, {"tools": ["wrong"]}), (False, {"metadata": "wrong"}),
                               (False, {"model": 1})]:
            with self.subTest(bad=bad):
                handler = self.handler(responses)
                handler._error = Mock()
                with patch.object(self.pool, "acquire") as acquire:
                    handler._handle_inference(bad, responses=responses)
                self.assertEqual(handler._error.call_args.args[0], 400)
                acquire.assert_not_called()
