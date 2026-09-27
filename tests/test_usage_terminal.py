"""终态用量写入、并发持久化与真实 handler 路径的离线回归。"""
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import test_recovery as fixtures
from test_recovery import P, Response, chunk, envelope, success


class UsageTerminalTests(unittest.TestCase):
    context = fixtures.RecoveryTests.context
    open_sequence = fixtures.RecoveryTests.open_sequence
    http_error = fixtures.RecoveryTests.http_error
    assert_all_closed = fixtures.RecoveryTests.assert_all_closed
    handler = fixtures.RecoveryTests.handler
    invoke_handler = fixtures.RecoveryTests.invoke_handler

    def setUp(self):
        fixtures.RecoveryTests.setUp(self)
        self.usage_dir = Path(self.directory.name) / "usage"
        for name, value in (("USAGE_DIR", str(self.usage_dir)),
                            ("USAGE_LOG", str(self.usage_dir / "usage.jsonl")),
                            ("USAGE_SUMMARY", str(self.usage_dir / "usage-summary.json")),
                            ("_usage", P._empty_stats())):
            patcher = patch.object(P, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(P, "log")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.usage = {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}

    def rows(self):
        path = Path(P.USAGE_LOG)
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def summary(self):
        return json.loads(Path(P.USAGE_SUMMARY).read_text(encoding="utf-8"))

    def test_success_without_usage_is_recorded_as_unknown(self):
        row = P.record_usage("qfmodel", None, realm="cn")
        self.assertEqual(row["status"], "success")
        self.assertTrue(row["usage_missing"])
        self.assertEqual(P._usage["requests"], 1)
        self.assertEqual(P._usage["unknown_usage_requests"], 1)
        self.assertEqual(P._usage["total_tokens"], 0)
        self.assertEqual(self.rows(), [row])
        self.assertEqual(self.summary(), P._usage)

    def test_failure_preserves_partial_usage_and_request_identity(self):
        ctx = self.context(realm="intl")
        ctx.account = self.pool.accounts[-1]
        ctx.queue_wait_seconds = 1.25
        with patch.object(P, "CURRENT_REALM", "cn"):
            row = P.record_error("qfmodel", 502, "partial failure", ctx=ctx, usage=self.usage, stream=True)
        self.assertEqual(row["outcome"], "failed")
        self.assertEqual(row["status"], 502)
        self.assertEqual(row["realm"], "intl")
        self.assertEqual(row["account"], ctx.account.uid)
        self.assertEqual(row["request_id"], ctx.request_id)
        self.assertEqual(row["queue_wait_ms"], 1250)
        self.assertEqual(row["total_tokens"], 10)
        self.assertFalse(row["usage_missing"])
        self.assertEqual(P._usage["errors"], 1)
        self.assertEqual(P._usage["requests"], 0)
        self.assertEqual(self.rows(), [row])
        self.assertEqual(self.summary(), P._usage)

    def test_success_uses_context_realm_after_global_switch(self):
        ctx = self.context(realm="intl")
        ctx.account = self.pool.accounts[-1]
        with patch.object(P, "CURRENT_REALM", "cn"):
            row = P.record_usage("qfmodel", self.usage, ctx=ctx)
        self.assertEqual(row["realm"], "intl")
        self.assertEqual(row["account"], ctx.account.uid)
        self.assertEqual(row["request_id"], ctx.request_id)
        self.assertTrue(P.row_matches_realm(row, "intl"))
        self.assertFalse(P.row_matches_realm(row, "cn"))

    def test_abort_has_independent_counter_and_retains_partial_usage(self):
        row = P.record_error("qfmodel", 499, "client disconnected", realm="intl",
                             account="synthetic-account", usage=self.usage,
                             outcome="client_aborted", stream=True)
        self.assertEqual(row["status"], "client_aborted")
        self.assertEqual(row["outcome"], "client_aborted")
        self.assertEqual(row["total_tokens"], 10)
        self.assertEqual(row["realm"], "intl")
        self.assertEqual(row["account"], "synthetic-account")
        self.assertEqual(P._usage["requests"], 0)
        self.assertEqual(P._usage["errors"], 0)
        self.assertEqual(P._usage["client_aborted_requests"], 1)
        self.assertEqual(self.summary(), P._usage)

    def test_concurrent_records_keep_jsonl_and_summary_consistent(self):
        barrier = threading.Barrier(8)

        def record(worker):
            barrier.wait(timeout=5)
            for index in range(8):
                if index % 2:
                    P.record_error("qfmodel", 502, "synthetic failure", realm="cn")
                else:
                    P.record_usage("qfmodel", self.usage, realm="cn")

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(record, range(8)))
        rows = self.rows()
        self.assertEqual(len(rows), 64)
        self.assertEqual(sum(row.get("status") == "success" for row in rows), 32)
        self.assertEqual(sum(row.get("outcome") == "failed" for row in rows), 32)
        self.assertEqual(P._usage["requests"], 32)
        self.assertEqual(P._usage["errors"], 32)
        self.assertEqual(P._usage["total_tokens"], 320)
        self.assertEqual(self.summary(), P._usage)

    def test_summary_write_failure_is_visible_and_future_write_recovers(self):
        with patch.object(P.os, "replace", side_effect=OSError("synthetic write failure")):
            P.record_usage("qfmodel", self.usage, realm="cn")
        self.assertEqual(P._usage["requests"], 1)
        self.assertEqual(P._usage["usage_persist_errors"], 1)
        P.record_usage("qfmodel", self.usage, realm="cn")
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(self.summary(), P._usage)
        self.assertEqual(self.summary()["usage_persist_errors"], 1)

    def test_four_handler_paths_record_one_terminal_row(self):
        for responses in (False, True):
            for stream in (False, True):
                for failed in (False, True):
                    with self.subTest(responses=responses, stream=stream, failed=failed):
                        before = len(self.rows())
                        handler = self.handler(responses)
                        upstream = (Response(chunk("partial", self.usage), envelope("provider_error", 418))
                                    if failed else success())
                        with self.open_sequence(upstream):
                            self.invoke_handler(handler, responses, stream)
                        rows = self.rows()
                        self.assertEqual(len(rows), before + 1)
                        row = rows[-1]
                        self.assertEqual(row["realm"], "cn")
                        self.assertTrue(row["request_id"])
                        self.assertTrue(row["account"].startswith("synthetic-"))
                        if failed:
                            self.assertEqual(row["outcome"], "failed")
                            self.assertEqual(row["total_tokens"], 10)
                        else:
                            self.assertEqual(row["status"], "success")
                            self.assertTrue(row["usage_missing"])
                        self.assert_all_closed()
        self.assertEqual(P._usage["requests"], 4)
        self.assertEqual(P._usage["errors"], 4)
        self.assertEqual(self.summary(), P._usage)

    def test_streaming_disconnect_records_one_abort_and_releases_lease(self):
        class Disconnected(io.BytesIO):
            def write(self, data):
                if b"partial" in data:
                    raise BrokenPipeError("synthetic disconnected client")
                return super().write(data)

        for responses in (False, True):
            with self.subTest(responses=responses):
                before = len(self.rows())
                handler = self.handler(responses)
                handler.wfile = Disconnected()
                with self.open_sequence(Response(chunk("partial", self.usage), envelope("[DONE]"))):
                    self.invoke_handler(handler, responses, True)
                rows = self.rows()
                self.assertEqual(len(rows), before + 1)
                self.assertEqual(rows[-1]["outcome"], "client_aborted")
                self.assertEqual(rows[-1]["total_tokens"], 10)
                self.assertEqual(sum(row["inFlight"] for row in self.pool.list_public()), 0)
                self.assert_all_closed()
        self.assertEqual(P._usage["requests"], 0)
        self.assertEqual(P._usage["errors"], 0)
        self.assertEqual(P._usage["client_aborted_requests"], 2)

    def test_nonstreaming_disconnect_records_abort_instead_of_success(self):
        for responses in (False, True):
            with self.subTest(responses=responses):
                before = len(self.rows())
                handler = self.handler(responses)
                handler._json.side_effect = BrokenPipeError("synthetic disconnected client")
                with self.open_sequence(success(self.usage)):
                    self.invoke_handler(handler, responses, False)
                rows = self.rows()
                self.assertEqual(len(rows), before + 1)
                self.assertEqual(rows[-1]["status"], "client_aborted")
                self.assertEqual(rows[-1]["outcome"], "client_aborted")
                self.assertEqual(rows[-1]["total_tokens"], 10)
                self.assertEqual(sum(row["inFlight"] for row in self.pool.list_public()), 0)
                self.assert_all_closed()
        self.assertEqual(P._usage["requests"], 0)
        self.assertEqual(P._usage["errors"], 0)
        self.assertEqual(P._usage["client_aborted_requests"], 2)


if __name__ == "__main__":
    unittest.main()
