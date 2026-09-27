"""索引/JSONL 接线与历史汇总兼容性。"""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import qoder_proxy as P
import qoder_settings as S


class UsageQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, value in {
            "USAGE_DIR": self.temp.name, "USAGE_LOG": str(self.root / "usage.jsonl"),
            "USAGE_SUMMARY": str(self.root / "usage-summary.json"),
            "ACCOUNTS_DIR": self.temp.name, "POOL": None, "_usage_index": None,
            "_usage": P._empty_stats(), "_usage_summary_state": {},
        }.items():
            p = patch.object(P, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(lambda: P._usage_index.close() if P._usage_index else None)
        self.rows = [dict(at=1700000000+i, model="test", account="acct"+str(i % 3),
                          realm=("cn" if i % 2 else "intl"), total_tokens=i,
                          prompt_tokens=i, completion_tokens=0, error=i % 13 == 0)
                     for i in range(60)]
        self.rows += [{"at": 1700000070, "model": "historic", "total_tokens": 2}]
        self.rows += [self.rows[-1].copy()]
        self.write_rows()

    def write_rows(self):
        Path(P.USAGE_LOG).write_text("".join(json.dumps(r)+"\n" for r in self.rows)
                                    + "invalid\n" + '{"incomplete":', encoding="utf-8")

    def enable(self):
        S.set_gateway(self.temp.name, {"usage_index_enabled": True})
        index = P._get_usage_index()
        mark = index.capture_watermark()
        deadline = time.monotonic() + 5
        while index.count(mark) is None:
            if time.monotonic() > deadline:
                self.fail("index did not catch up")
        return index

    def test_all_readers_match_index_and_scan(self):
        def snapshot():
            return {
                "pages": [P.recent_usage(7, realm=r, page=3) for r in (None, "cn", "intl", "unknown")],
                "count": P.count_usage_rows(), "accounts": P._usage_by_account_uncached(),
                "perf": P._perf_stats_uncached(20, "cn"),
                "realm": P._usage_snapshot_uncached("cn"),
                "analytics": P.compute_usage_analytics(),
            }
        expected = snapshot()
        self.enable()
        self.assertEqual(snapshot(), expected)
        self.assertEqual(expected["count"], 62)
        self.assertEqual(P.count_usage_rows("unknown"), 2)

    def test_fallback_preserves_total_and_rows_at_same_watermark(self):
        expected = P.recent_usage(9, realm="cn")
        index = self.enable()
        with patch.object(index, "recent", return_value=None):
            self.assertEqual(P.recent_usage(9, realm="cn"), expected)
        S.set_gateway(self.temp.name, {"usage_index_enabled": False})
        self.assertEqual(P.recent_usage(9, realm="cn"), expected)
        self.assertIsNone(P._usage_index)

    def test_historical_summary_is_preserved_and_reported(self):
        saved = dict(P._empty_stats(), requests=500, total_tokens=900000)
        Path(P.USAGE_SUMMARY).write_text(json.dumps(saved), encoding="utf-8")
        before = Path(P.USAGE_SUMMARY).read_bytes()
        P.load_usage_summary()
        self.assertEqual(P._usage["requests"], 500)
        self.assertEqual(P._usage_summary_state["state"], "historical_difference")
        self.assertEqual(Path(P.USAGE_SUMMARY).read_bytes(), before)

    def test_log_ahead_of_summary_rebuilds_without_losing_missing_usage(self):
        self.rows = [{"model": "test", "outcome": "success", "usage_missing": True},
                     {"model": "test", "error": True, "outcome": "client_aborted"}]
        self.write_rows()
        P.load_usage_summary()
        self.assertEqual(P._usage["requests"], 1)
        self.assertEqual(P._usage["errors"], 0)
        self.assertEqual(P._usage["unknown_usage_requests"], 1)
        self.assertEqual(P._usage["client_aborted_requests"], 1)
        self.assertEqual(json.loads(Path(P.USAGE_SUMMARY).read_text()), P._usage)

    def test_cancel_only_log_rebuilds_independent_counter(self):
        self.rows = [{"realm": "cn", "error": True, "outcome": "client_aborted"}]
        self.write_rows()
        P.load_usage_summary()
        self.assertEqual(P._usage["client_aborted_requests"], 1)
        self.assertEqual(P._usage_snapshot_uncached("cn")["errors"], 0)
        self.assertEqual(P.compute_usage_analytics()["summary"]["all_time"]["errors"], 0)

    def test_append_after_crash_tail_keeps_new_complete_record(self):
        P.record_usage("after-crash", None, realm="intl")
        page = P.recent_usage(1)
        self.assertEqual(page["total"], 63)
        self.assertEqual(page["rows"][0]["model"], "after-crash")
