"""真实恢复生成器与账号租约的离线集成回归。"""
import unittest
from unittest.mock import patch

import test_recovery as fixtures
from test_recovery import P, S, QUEUE, Response, chunk, envelope, success


class LeaseLifecycleTests(unittest.TestCase):
    # 复用已有 HTTP/SSE 设施，但不重复收集其测试用例。
    setUp = fixtures.RecoveryTests.setUp
    context = fixtures.RecoveryTests.context
    open_sequence = fixtures.RecoveryTests.open_sequence
    http_error = fixtures.RecoveryTests.http_error
    assert_no_penalties = fixtures.RecoveryTests.assert_no_penalties
    assert_all_closed = fixtures.RecoveryTests.assert_all_closed

    def counts(self):
        rows = self.pool.list_public()
        return (sum(row["inFlight"] for row in rows),
                sum(row["queueWaiting"] for row in rows))

    def assert_released(self, ctx):
        self.assertEqual(self.counts(), (0, 0))
        self.assertIsNone(ctx.lease)
        ctx.close()
        self.assertEqual(self.counts(), (0, 0))
        self.assert_all_closed()

    def test_same_account_retry_keeps_single_lease_until_success(self):
        ctx = self.context()
        leases = []
        original_open = P._open_attempt

        def opened(current):
            leases.append(current.lease)
            self.assertEqual(self.counts(), (1, 0))
            return original_open(current)

        with self.open_sequence(self.http_error(503, {"error": "provider_error"}), success()), \
                patch.object(P, "_open_attempt", side_effect=opened), \
                patch.object(self.pool, "acquire", wraps=self.pool.acquire) as acquire:
            self.assertIn(b"recovered", b"".join(P.iter_with_recovery(ctx, {})))
        self.assertEqual(acquire.call_count, 1)
        self.assertIs(leases[0], leases[1])
        self.assert_released(ctx)
        self.assert_no_penalties()

    def test_http_and_sse_queue_keep_lease_and_expose_waiting_state(self):
        for source in ("http", "sse"):
            with self.subTest(source=source):
                ctx = self.context()
                captured = []

                def poll(*args, **kwargs):
                    self.assertEqual(self.counts(), (1, 1))
                    captured.append(ctx.lease)
                    return {"isQueued": False}

                failure = (self.http_error(429, QUEUE) if source == "http"
                           else Response(envelope(QUEUE, 10605)))
                with self.open_sequence(failure, success()), \
                        patch.object(P, "_poll_queue", side_effect=poll), \
                        patch.object(self.pool, "acquire", wraps=self.pool.acquire) as acquire:
                    iterator = P.iter_with_recovery(ctx, {})
                    self.assertIn(b"recovered", next(iterator))
                    self.assertEqual(self.counts(), (1, 0))
                    self.assertIs(ctx.lease, captured[0])
                    list(iterator)
                self.assertEqual(acquire.call_count, 1)
                self.assert_released(ctx)
                self.assert_no_penalties()

    def test_account_switch_releases_old_lease_before_acquiring_new(self):
        ctx = self.context()
        selected = []
        original_acquire = self.pool.acquire

        def acquire(*args, **kwargs):
            self.assertEqual(self.counts(), (0, 0))
            lease = original_acquire(*args, **kwargs)
            selected.append(lease.account.uid)
            return lease

        failures = [self.http_error(503, {"error": "provider_error"}) for _ in range(3)]
        with self.open_sequence(*failures, success()), \
                patch.object(self.pool, "acquire", side_effect=acquire):
            self.assertIn(b"recovered", b"".join(P.iter_with_recovery(ctx, {})))
        self.assertEqual(len(selected), 2)
        self.assertNotEqual(selected[0], selected[1])
        self.assert_released(ctx)

    def test_terminal_request_failure_and_client_close_release_lease(self):
        ctx = self.context()
        with self.open_sequence(self.http_error(418, {"error": "invalid_parameter_error"})):
            with self.assertRaises(P.UpstreamStatus):
                list(P.iter_with_recovery(ctx, {}))
        self.assert_released(ctx)
        self.assert_no_penalties()

        ctx = self.context()
        with self.open_sequence(Response(chunk("partial"), chunk("unread"), envelope("[DONE]"))):
            iterator = P.iter_with_recovery(ctx, {})
            self.assertIn(b"partial", next(iterator))
            self.assertEqual(self.counts(), (1, 0))
            iterator.close()
        self.assert_released(ctx)
        self.assert_no_penalties()

    def test_only_completed_stream_clears_previous_error_display(self):
        self.pool.accounts = self.pool.accounts[:1]
        account = self.pool.accounts[0]
        account.note_error("previous failure", cooldown=-1, kind="transient")
        ctx = self.context()
        with self.open_sequence(success()):
            iterator = P.iter_with_recovery(ctx, {})
            next(iterator)
            self.assertEqual(account.last_error_kind, "transient")
            iterator.close()
        self.assertEqual(account.last_error_kind, "transient")
        self.assert_released(ctx)
        ctx = self.context()
        with self.open_sequence(success()):
            list(P.iter_with_recovery(ctx, {}))
        self.assertEqual(account.last_error, "")
        self.assertEqual(account.last_error_kind, "")
        self.assert_released(ctx)

    def test_queue_failure_and_client_disconnect_clear_both_counters(self):
        for failure in (P.qoder_queue.QueueError("queue_timeout", 429, "timeout"),
                        BrokenPipeError("client disconnected")):
            with self.subTest(failure=type(failure).__name__):
                ctx = self.context()

                def poll(*args, **kwargs):
                    self.assertEqual(self.counts(), (1, 1))
                    raise failure

                with self.open_sequence(self.http_error(429, QUEUE)), \
                        patch.object(P.qoder_queue, "wait_until_ready", side_effect=poll):
                    with self.assertRaises((P.UpstreamStatus, BrokenPipeError)):
                        list(P.iter_with_recovery(ctx, {}))
                self.assert_released(ctx)
                self.assert_no_penalties()

    def test_full_pool_returns_503_without_post_or_account_penalty(self):
        S.set_gateway(self.directory.name, {"pool_max_inflight": 1})
        leases = [self.pool.acquire(realm="cn", max_inflight=1) for _ in range(3)]
        self.addCleanup(lambda: [lease.release() for lease in leases])
        ctx = self.context()
        with patch.object(P, "_open_attempt") as opened:
            with self.assertRaises(P.UpstreamStatus) as caught:
                list(P.iter_with_recovery(ctx, {}))
        self.assertEqual(caught.exception.info.public_http_status, 503)
        self.assertEqual(caught.exception.info.kind, "pool_busy")
        opened.assert_not_called()
        self.assertEqual(self.counts(), (3, 0))
        self.assert_no_penalties()
        for lease in leases:
            lease.release()
        self.assert_released(ctx)

    def test_lower_runtime_limit_preserves_existing_streams_and_blocks_new(self):
        self.pool.accounts = self.pool.accounts[:1]
        S.set_gateway(self.directory.name, {"pool_max_inflight": 2})
        first, second = self.context(), self.context()
        with self.open_sequence(success(), success(), success()):
            first_stream = P.iter_with_recovery(first, {})
            second_stream = P.iter_with_recovery(second, {})
            self.addCleanup(first_stream.close)
            self.addCleanup(second_stream.close)
            next(first_stream)
            next(second_stream)
            self.assertEqual(self.counts(), (2, 0))
            S.set_gateway(self.directory.name, {"pool_max_inflight": 1})
            self.assertEqual(self.counts(), (2, 0))
            for finishing in (first_stream, second_stream):
                blocked = self.context()
                with self.assertRaises(P.UpstreamStatus) as caught:
                    list(P.iter_with_recovery(blocked, {}))
                self.assertEqual(caught.exception.info.kind, "pool_busy")
                list(finishing)
            self.assert_released(first)
            self.assert_released(second)
            resumed = self.context()
            self.assertIn(b"recovered", b"".join(P.iter_with_recovery(resumed, {})))
            self.assert_released(resumed)
        self.assertEqual(len(self.posts), 3)
        self.assert_no_penalties()


if __name__ == "__main__":
    unittest.main()
