"""账号租约并发、替换竞争与冷却持久化的离线回归。"""
import concurrent.futures
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from qoder_accounts import Account, AccountPool, PoolBusy


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pool = AccountPool(self.temp.name)
        self.account = self.pool.add(self.make())

    def make(self, uid="one", realm="cn", **fields):
        return Account(dict(uid=uid, realm=realm, accessToken="synthetic", expiresAt=time.time() + 3600, **fields))

    def acquire(self, **kwargs):
        return self.pool.acquire(realm="cn", model="test-model", **kwargs)

    def test_twenty_requests_two_slots(self):
        barrier = threading.Barrier(20)
        held = threading.Event()
        acquired = []
        lock = threading.Lock()
        def run(_):
            barrier.wait()
            try:
                lease = self.acquire(max_inflight=2)
            except PoolBusy:
                return "busy"
            with lock:
                acquired.append(lease)
                if len(acquired) == 2:
                    held.set()
            held.wait(2)
            return "acquired"
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(run, range(20)))
        self.assertEqual(results.count("acquired"), 2)
        self.assertEqual(self.account.public()["inFlight"], 2)
        for lease in acquired:
            lease.release()
            lease.release()
        self.assertEqual(self.account.public()["inFlight"], 0)

    def test_realm_and_replacement_keep_capacity(self):
        with self.assertRaises(ValueError):
            self.pool.add(self.make(realm="intl"))
        intl = self.pool.add(self.make(uid="international", realm="intl"))
        old = self.acquire(max_inflight=1)
        replacement = self.pool.add(self.make())
        with self.assertRaises(PoolBusy):
            self.acquire(max_inflight=1)
        other = self.pool.acquire(realm="intl", max_inflight=1)
        self.assertIs(other.account, intl)
        old.release()
        current = self.acquire(max_inflight=1)
        self.assertIs(current.account, replacement)
        current.release()
        other.release()
        restarted = AccountPool(self.temp.name)
        self.assertEqual({a.realm for a in restarted.load()}, {"cn", "intl"})

    def test_queue_and_lowered_limit(self):
        first, second = self.acquire(), self.acquire()
        first.set_queue_waiting(True)
        self.assertEqual(self.account.public()["queueWaiting"], 1)
        with self.assertRaises(PoolBusy):
            self.acquire(max_inflight=1)
        first.release()
        first.set_queue_waiting(True)
        with self.assertRaises(PoolBusy):
            self.acquire(max_inflight=1)
        second.release()
        self.assertEqual(self.account.public()["queueWaiting"], 0)

    def test_affinity_is_preserved_until_alternate_acquired(self):
        first = self.acquire(session_key="s", max_inflight=1)
        with self.assertRaises(PoolBusy):
            self.acquire(session_key="s", max_inflight=1)
        self.assertEqual(self.pool.affinity.get("s"), "one")
        second_account = self.pool.add(self.make(uid="two"))
        second = self.acquire(session_key="s", max_inflight=1)
        self.assertIs(second.account, second_account)
        first.release()
        second.release()

    def test_refresh_is_merged_and_pool_lock_not_held(self):
        self.account.expires_at = time.time() - 1
        entered, resume = threading.Event(), threading.Event()
        calls = []
        def refresh():
            calls.append(1)
            entered.set()
            self.assertTrue(resume.wait(3))
            self.account.expires_at = time.time() + 3600
            return True
        with patch.object(self.account, "refresh", side_effect=refresh):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                one = executor.submit(self.acquire)
                self.assertTrue(entered.wait(3))
                two = executor.submit(self.acquire)
                self.assertEqual(self.pool.get("one"), self.account)
                resume.set()
                leases = [one.result(3), two.result(3)]
        self.assertEqual(len(calls), 1)
        for lease in leases:
            lease.release()

    def test_refresh_exception_releases(self):
        self.account.expires_at = 1
        with patch.object(self.account, "refresh", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                self.acquire()
        self.assertFalse(self.pool._leases)

    def test_delete_during_refresh_does_not_recreate_file(self):
        self.account.expires_at = 1
        entered, resume = threading.Event(), threading.Event()
        def refresh():
            entered.set()
            resume.wait(3)
            self.account.expires_at = time.time() + 3600
            self.account.save(self.temp.name)
            return True
        with patch.object(self.account, "refresh", side_effect=refresh):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self.acquire)
                self.assertTrue(entered.wait(3))
                self.pool.remove("one")
                resume.set()
                self.assertIsNone(future.result(3))
        self.assertFalse(Path(self.account.path).exists())
        self.assertFalse(self.pool._leases)

    def test_replace_during_refresh_does_not_overwrite_credentials(self):
        old = self.account
        old.expires_at = 1
        entered, resume = threading.Event(), threading.Event()
        def refresh():
            entered.set()
            resume.wait(3)
            old.access_token = "old-refreshed"
            old.expires_at = time.time() + 3600
            old.save(self.temp.name)
            return True
        with patch.object(old, "refresh", side_effect=refresh):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self.acquire)
                self.assertTrue(entered.wait(3))
                replacement = self.make()
                replacement.access_token = "new-credential"
                self.pool.add(replacement)
                resume.set()
                self.assertIsNone(future.result(3))
        self.assertEqual(json.loads(Path(replacement.path).read_text())["accessToken"], "new-credential")
        self.assertFalse(self.pool._leases)

    def test_cooldown_alias_survives_restart_and_success(self):
        lease = self.acquire()
        self.account.note_error("throttle", model="claude-sonnet-4", cooldown=60, kind="model_rate_limit")
        lease.mark_success()
        lease.release()
        restarted = AccountPool(self.temp.name)
        accounts = restarted.load()
        self.assertEqual(len(accounts), 1)
        self.assertIsNone(restarted.acquire(realm="cn", model="claude-sonnet-4"))
        self.assertEqual(accounts[0].last_error_kind, "model_rate_limit")
        raw = (Path(self.temp.name) / ".runtime" / "pool-state.json").read_text()
        self.assertNotIn("synthetic", raw)
        self.assertNotIn("accessToken", json.dumps(accounts[0].public()))

    def test_state_filters_bad_and_orphan_records(self):
        runtime = Path(self.temp.name) / ".runtime"
        runtime.mkdir()
        path = runtime / "pool-state.json"
        path.write_text(json.dumps({"version": 1, "accounts": [
            {"realm": "cn", "uid": "one", "modelCooldowns": {"expired": 1, "bad": "future", "inf": float("inf"), "valid": time.time() + 60}},
            {"realm": "cn", "uid": "missing", "modelCooldowns": {"x": time.time() + 60}},
        ]}))
        pool = AccountPool(self.temp.name)
        self.assertEqual(list(pool.load()[0].model_cooldowns), ["valid"])
        path.write_text("bad json")
        self.assertFalse(pool.load()[0].model_cooldowns)

    def test_success_does_not_write_unchanged_state(self):
        lease = self.acquire()
        with patch.object(self.pool, "save_state") as save:
            lease.mark_success()
        save.assert_not_called()
        lease.release()

    def test_state_disk_failure_does_not_interrupt_business(self):
        with patch.object(self.pool, "_save_state", side_effect=OSError("disk full")):
            self.account.note_error("busy", model="test-model")
            self.account.clear_error(force=True)
        lease = self.acquire()
        self.assertIsNotNone(lease)
        lease.release()

    def test_parallel_save_and_cooldown(self):
        def update(index):
            self.account.note_error("busy", model="model-%d" % index, kind="model_rate_limit")
            self.account.save(self.temp.name)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(update, range(20)))
        pool = AccountPool(self.temp.name)
        self.assertEqual(len(pool.load()[0].model_cooldowns), 20)
        self.assertEqual(list(Path(self.temp.name).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
