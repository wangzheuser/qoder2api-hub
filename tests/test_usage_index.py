import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from qoder_usage import UsageIndex, capture_watermark, scan_rows


class UsageIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.source = Path(self.tmp.name) / "usage.jsonl"
        self.source.write_bytes(b"")
        self.index = UsageIndex(self.source).start()

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def append(self, rows):
        with self.source.open("ab") as fh:
            for row in rows:
                fh.write(json.dumps(row).encode() + b"\n")
        self.index.notify()
        return capture_watermark(self.source)

    def ready(self, mark):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            result = self.index.snapshot_rows(mark)
            if result is not None:
                return result
        self.fail(self.index.status())

    def test_snapshot_page_count_and_duplicate_content(self):
        rows = [{"at": 3 - i, "realm": "cn", "total_tokens": i} for i in range(3)]
        rows += [rows[0], {"at": 8, "realm": "intl"}, {"at": 9}]
        mark = self.append(rows)
        self.assertEqual(self.ready(mark), rows)
        self.assertEqual(self.index.count(mark), 6)
        self.assertEqual(self.index.count(mark, "unknown"), 1)
        self.append([{"at": 99}])
        self.assertEqual(self.index.recent(mark, 2, 2)["rows"], list(reversed(rows))[2:4])
        self.assertEqual(self.index.recent(mark, 2, 2)["total"], 6)
        self.assertEqual(self.index.snapshot_rows(mark, "cn", 2, True), [rows[3], rows[2]])
        self.assertEqual(scan_rows(self.source, mark), rows)

    def test_bad_blank_and_partial_lines(self):
        self.source.write_bytes(b'{"at":1}\ninvalid\n\n[]\n{"at":2}')
        mark = capture_watermark(self.source)
        self.assertEqual(self.ready(mark), [{"at": 1}])
        self.assertEqual(scan_rows(self.source, mark), [{"at": 1}])
        with self.source.open("ab") as fh:
            fh.write(b"\n")
        self.assertEqual(self.ready(capture_watermark(self.source)), [{"at": 1}, {"at": 2}])
        deadline = time.monotonic() + 2
        while self.index.status()["bad_lines"] != 2 and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(self.index.status()["bad_lines"], 2)

    def test_restart_replays_only_new_lines(self):
        mark = self.append([{"at": 1}])
        self.ready(mark)
        self.index.close()
        self.append([{"at": 2}])
        self.index = UsageIndex(self.source).start()
        self.assertEqual(self.ready(capture_watermark(self.source)), [{"at": 1}, {"at": 2}])

    def test_replace_truncate_same_size_and_boundary_rewrite(self):
        self.ready(self.append([{"at": 1}, {"at": 2}]))
        self.source.write_bytes(b'{"at":3}\n{"at":4}\n')
        mark = capture_watermark(self.source)
        self.index.notify()
        self.assertEqual(self.ready(mark), [{"at": 3}, {"at": 4}])
        self.source.write_bytes(b'{"at":5}\n')
        self.assertEqual(self.ready(capture_watermark(self.source)), [{"at": 5}])
        replacement = self.source.with_suffix(".new")
        replacement.write_bytes(b'{"at":6}\n')
        os.replace(replacement, self.source)
        self.assertEqual(self.ready(capture_watermark(self.source)), [{"at": 6}])

    def test_corrupt_and_incompatible_database_rebuild(self):
        mark = self.append([{"at": 1}])
        self.ready(mark)
        self.index.close()
        Path(self.index.db_path).write_bytes(b"not sqlite")
        self.index = UsageIndex(self.source).start()
        self.assertEqual(self.ready(mark), [{"at": 1}])
        self.index.close()
        with sqlite3.connect(self.index.db_path) as conn:
            conn.execute("PRAGMA user_version=99")
        conn.close()
        self.index = UsageIndex(self.source).start()
        self.assertEqual(self.ready(mark), [{"at": 1}])

    def test_disabled_and_unstarted_timeout(self):
        disabled = UsageIndex(self.source, enabled=False)
        self.assertIsNone(disabled.count(capture_watermark(self.source)))
        other = Path(self.tmp.name) / "other" / "usage.jsonl"
        waiting = UsageIndex(other)
        started = time.monotonic()
        self.assertIsNone(waiting.count(capture_watermark(other)))
        self.assertLess(time.monotonic() - started, .3)

    def test_out_of_range_nonfinite_numbers_normalise_and_keep_writer_alive(self):
        numbers = [10 ** 40, -(10 ** 40), float("nan"), float("inf"),
                   float("-inf"), 1e100, -(2 ** 63) - 1, 2 ** 63]
        fields = ("at", "prompt_tokens", "completion_tokens", "reasoning_tokens",
                  "cached_tokens", "total_tokens", "elapsed_ms", "ttft_ms",
                  "gen_ms", "queue_wait_ms", "credit", "tokens_per_sec")
        rows = [{"account": "invalid-number", **{field: number for field in fields}}
                for number in numbers]
        rows.append({"account": "normal", "at": 42, "total_tokens": 7})
        mark = self.append(rows)
        expected = [{"account": "invalid-number", **{field: 0 for field in fields}}
                    for _ in numbers] + [rows[-1]]
        self.assertEqual(self.ready(mark), expected)
        self.assertEqual(scan_rows(self.source, mark), expected)
        self.assertEqual(self.index.count(mark), len(rows))
        self.assertEqual(self.index.by_account(mark)[0]["total_tokens"], 7)
        self.assertTrue(self.index._thread.is_alive())
        final = self.append([{"account": "later", "total_tokens": 3}])
        self.assertEqual(self.ready(final)[-1], {"account": "later", "total_tokens": 3})

    def test_unencodable_json_string_does_not_stop_following_rows(self):
        self.source.write_bytes(b'{"note":"\\ud800","total_tokens":1}\n' +
                                b'{"total_tokens":2}\n')
        mark = capture_watermark(self.source)
        expected = [{"note": "\ud800", "total_tokens": 1}, {"total_tokens": 2}]
        self.assertEqual(self.ready(mark), expected)
        self.assertEqual(scan_rows(self.source, mark), expected)
        self.assertTrue(self.index._thread.is_alive())

    def test_locked_writer_query_falls_back_then_catches_up(self):
        self.ready(self.append([{"at": 1}]))
        lock = sqlite3.connect(self.index.db_path)
        try:
            lock.execute("BEGIN IMMEDIATE")
            mark = self.append([{"at": 2}])
            start = time.monotonic()
            self.assertIsNone(self.index.recent(mark))
            self.assertLess(time.monotonic() - start, .3)
            self.assertEqual(scan_rows(self.source, mark), [{"at": 1}, {"at": 2}])
        finally:
            lock.rollback()
            lock.close()
        self.assertEqual(self.ready(mark), [{"at": 1}, {"at": 2}])

    def test_external_reader_blocks_rebuild_without_replacing_live_wal(self):
        self.ready(self.append([{"at": 1}]))
        external = sqlite3.connect(self.index.db_path)
        try:
            external.execute("BEGIN")
            self.assertEqual(external.execute("SELECT COUNT(*) FROM usage_rows").fetchone()[0], 1)
            self.ready(self.append([{"at": 2}]))
            self.source.write_bytes(b'{"at":3}\n')
            mark = capture_watermark(self.source)
            self.index.notify()
            self.assertIsNone(self.index.snapshot_rows(mark))
            self.assertEqual(scan_rows(self.source, mark), [{"at": 3}])
            self.assertEqual(external.execute("SELECT COUNT(*) FROM usage_rows").fetchone()[0], 1)
        finally:
            external.rollback()
            external.close()
        self.assertEqual(self.ready(mark), [{"at": 3}])

    def test_uncommitted_batch_rolls_back_and_replays(self):
        mark = self.append([{"at": 1}])
        self.ready(mark)
        self.index.close()
        conn = sqlite3.connect(self.index.db_path)
        conn.execute("UPDATE index_meta SET next_offset=999999")
        conn.execute("DELETE FROM usage_rows")
        conn.close()
        self.index = UsageIndex(self.source).start()
        self.assertEqual(self.ready(mark), [{"at": 1}])

    def test_account_aggregation_and_raw_unknown_fields(self):
        rows = [{"account": "a", "model": str(i % 7), "total_tokens": i,
                 "reasoning_tokens": 2, "extra": {"keep": True}} for i in range(14)]
        rows.append({"account": "a", "error": "failed", "total_tokens": 999})
        rows.append({"total_tokens": 1})
        mark = self.append(rows)
        self.ready(mark)
        result = self.index.by_account(mark)
        self.assertEqual(result[0]["requests"], 14)
        self.assertEqual(result[0]["total_tokens"], 91)
        self.assertEqual(result[0]["reasoning_tokens"], 28)
        self.assertEqual(result[0]["models"], [(str(i), 2) for i in range(5)])
        self.assertEqual(result[1]["account"], "(unattributed)")
        self.assertEqual(self.index.snapshot_rows(mark), rows)


def benchmark():
    """Run explicitly; keep the 100k source and SQLite files in a temp directory."""
    import platform
    import statistics
    import ast
    import subprocess
    original_source = subprocess.run(
        ["git", "show", "HEAD:qoder_proxy.py"], check=True,
        capture_output=True, text=True, encoding="utf-8").stdout
    wanted = {"count_usage_rows", "recent_usage", "row_matches_realm"}
    tree = ast.parse(original_source)
    functions = ast.Module(body=[node for node in tree.body
                                 if isinstance(node, ast.FunctionDef) and node.name in wanted], type_ignores=[])
    original = {"os": os, "json": json, "POOL": None, "log": lambda *args: None}
    exec(compile(functions, "<HEAD usage readers only>", "exec"), original)
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "usage.jsonl"
        expected = [{"at": 1700000000 + i, "realm": "cn" if i % 2 else "intl",
                     "account": str(i % 20), "model": str(i % 7),
                     "total_tokens": i % 500, "reasoning_tokens": i % 31,
                     "request_id": str(i)} for i in range(100000)]
        source.write_text("".join(json.dumps(row) + "\n" for row in expected), encoding="utf-8")
        mark = capture_watermark(source)
        index = UsageIndex(source).start()
        try:
            start = time.perf_counter()
            while index.count(mark) != len(expected):
                if time.perf_counter() - start > 60:
                    raise AssertionError(index.status())
            build = time.perf_counter() - start
            assert index.snapshot_rows(mark) == expected
            for realm in (None, "cn", "intl", "unknown"):
                filtered = [row for row in expected if not realm or row["realm"] == realm]
                for page in (1, 2, 1000):
                    result = index.recent(mark, 100, page, realm)
                    current = min(page, max(1, (len(filtered) + 99) // 100))
                    assert result["total"] == len(filtered)
                    assert result["rows"] == list(reversed(filtered))[(current-1)*100:current*100]
            index.recent(mark)
            timings = {"indexed_ms": [], "scan_ms": []}
            for _ in range(12):
                start = time.perf_counter()
                result = index.recent(mark)
                timings["indexed_ms"].append((time.perf_counter() - start) * 1000)
                start = time.perf_counter()
                rows = scan_rows(source, mark)
                old = {"total": len(rows), "rows": rows[-100:][::-1]}
                timings["scan_ms"].append((time.perf_counter() - start) * 1000)
                assert result["total"] == old["total"] and result["rows"] == old["rows"]
            original["USAGE_LOG"] = str(source)
            original_comparison = {}
            for realm in (None, "cn"):
                old_samples, new_samples = [], []
                original["recent_usage"](100, realm, 1)
                index.recent(mark, 100, 1, realm)
                for _ in range(12):
                    start = time.perf_counter()
                    old_result = original["recent_usage"](100, realm, 1)
                    old_samples.append((time.perf_counter() - start) * 1000)
                    start = time.perf_counter()
                    new_result = index.recent(mark, 100, 1, realm)
                    new_samples.append((time.perf_counter() - start) * 1000)
                    assert old_result == new_result
                original_comparison[realm or "all"] = {
                    "original_samples_ms": old_samples, "indexed_samples_ms": new_samples,
                    "original_p95_ms": max(old_samples), "indexed_p95_ms": max(new_samples),
                    "speedup_median": statistics.median(old_samples) / statistics.median(new_samples),
                    "correctness": "PASS"}
            planner = sqlite3.connect(Path(index.db_path).as_uri() + "?mode=ro", uri=True)
            try:
                generation = planner.execute("SELECT source_generation FROM index_meta").fetchone()[0]
                plans = {}
                cases = {
                    "previous_bounded_realm_count": ("SELECT COUNT(*) FROM usage_rows WHERE source_generation=? AND byte_offset<? AND realm=?", [generation, mark.size, "cn"]),
                    "exact_boundary_realm_count": ("SELECT COUNT(*) FROM usage_rows WHERE realm=?", ["cn"]),
                    "exact_boundary_all_count": ("SELECT COUNT(*) FROM usage_rows", []),
                    "realm_page": ("SELECT raw_json FROM usage_rows WHERE source_generation=? AND byte_offset<? AND realm=? ORDER BY byte_offset DESC LIMIT 100", [generation, mark.size, "cn"])}
                for name, (sql, args) in cases.items():
                    plans[name] = planner.execute("EXPLAIN QUERY PLAN " + sql, args).fetchall()
            finally:
                planner.close()
            result = {"query_plans": plans, "original_head_comparison": original_comparison,
                      "original_baseline": "git HEAD functions extracted by AST; module not imported; POOL=None",
                      "rows": len(expected), "platform": platform.platform(),
                      "processor": platform.processor(), "cpu_count": os.cpu_count(),
                      "python": platform.python_version(), "build_seconds": build,
                      "correctness": "PASS", "samples": timings,
                      "indexed_p95_ms": sorted(timings["indexed_ms"])[-1],
                      "speedup_median": statistics.median(timings["scan_ms"]) / statistics.median(timings["indexed_ms"])}
            output = Path(__file__).resolve().parents[1] / ".omx/artifacts/p0-p2/S4-index-benchmark.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            print(json.dumps({key: value for key, value in result.items() if key != "samples"}))
        finally:
            index.close()


if __name__ == "__main__":
    import sys
    if "--benchmark" in sys.argv:
        benchmark()
    else:
        unittest.main()
