"""同账号额度刷新与活动领取的离线并发回归。"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qoder_accounts as A
import qoder_credits as C


class ObservedRLock:
    """保持真实 RLock 语义，只报告确实发生的锁等待。"""
    def __init__(self):
        self.lock = threading.RLock()
        self.contended = threading.Event()

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            self.contended.set()
            if not self.lock.acquire(timeout=5):
                raise TimeoutError("同账号操作锁等待超时")
        return self

    def __exit__(self, *args):
        self.lock.release()


class CreditsConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.calls_lock = threading.Lock()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.blocker_entered = [threading.Event(), threading.Event()]
        self.blocker_release = threading.Event()
        self.claimed = False
        self.first_get = True
        self.account = self.account_for("target")
        self.service = C.CreditsService(http=self.http, clock=lambda: 1000)
        self.observed_lock = ObservedRLock()
        self.service._operation(self.account)["lock"] = self.observed_lock
        self.refresh_patch = patch.object(A.Account, "refresh_if_needed", return_value=True)
        self.refresh_patch.start()

    def tearDown(self):
        self.release.set()
        self.blocker_release.set()
        self.service.close()
        self.refresh_patch.stop()

    @staticmethod
    def account_for(uid):
        return A.Account({"uid": uid, "realm": "intl", "accessToken": "synthetic-" + uid})

    def http(self, url, **kwargs):
        uid = kwargs["headers"]["Authorization"].removeprefix("Bearer synthetic-")
        method = kwargs.get("method", "GET")
        endpoint = "claim" if method == "POST" else next(
            name for name, path in C.ENDPOINTS.items() if url.endswith(path))
        with self.calls_lock:
            self.calls.append((uid, method, endpoint))
            pause = uid == "target" and method == "GET" and self.first_get
            if pause:
                self.first_get = False
        if uid.startswith("blocker-"):
            self.blocker_entered[int(uid[-1])].set()
            if not self.blocker_release.wait(5):
                raise TimeoutError("占位 worker 未释放")
        if pause:
            self.entered.set()
            if not self.release.wait(5):
                raise TimeoutError("首次额度查询未释放")
        if method == "POST":
            self.claimed = True
            return {"status": "CLAIMED"}
        if endpoint == "campaigns":
            return {"campaigns": [{"campaignId": "gift", "actionType": "CLAIM_BENEFIT",
                "claimStatus": "CLAIMED" if self.claimed else "CLAIMABLE",
                "startAt": 900, "endAt": 2000}]}
        if endpoint == "usage":
            return {"displayMode": "qoder", "qoderUsage": {"userQuota": {"used": 0, "total": 100}}}
        if endpoint == "summary":
            return {"totalCredits": 10 if self.claimed else 0, "peakCredits": 100}
        return {"currentConsecutiveDays": 0}

    def run_overlap(self, claim_first):
        callers = ThreadPoolExecutor(max_workers=4)
        try:
            blockers = [callers.submit(self.service.details, self.account_for("blocker-" + str(i)), True)
                        for i in range(2)]
            for event in self.blocker_entered:
                self.assertTrue(event.wait(3), "两个共享 worker 应已被占用")
            if claim_first:
                claim = callers.submit(self.service.claim, self.account, "gift")
            else:
                detail = callers.submit(self.service.details, self.account, True)
            self.assertTrue(self.entered.wait(3), "首次同账号查询应进入 HTTP")
            if claim_first:
                detail = callers.submit(self.service.details, self.account, True)
            else:
                claim = callers.submit(self.service.claim, self.account, "gift")
            self.assertTrue(self.observed_lock.contended.wait(3), "第二操作必须等待同账号锁")
            self.assertEqual(C._executor._max_workers, 4)
            self.release.set()
            # 另外两个 worker 继续占用；领取必须在当前 worker 直接完成后刷新。
            claim_result = claim.result(timeout=3)
            detail_result = detail.result(timeout=3)
            self.assertTrue(claim_result["claimed"])
            self.assertEqual(claim_result["credits_details"]["campaigns"][0]["claimStatus"], "CLAIMED")
            self.assertEqual(detail_result["campaigns"][0]["claimStatus"],
                             "CLAIMED" if claim_first else "CLAIMABLE")
            cached = self.service.cached(self.account)
            self.assertEqual(cached["campaigns"][0]["claimStatus"], "CLAIMED")
            self.assertEqual(cached["total_credits"], 10)
            target_calls = [call for call in self.calls if call[0] == "target"]
            self.assertEqual([method for _, method, _ in target_calls], ["GET"] * 4 + ["POST"] + ["GET"] * 4)
            self.assertEqual([endpoint for _, _, endpoint in target_calls[:4]], list(C.ENDPOINTS))
            self.assertEqual([endpoint for _, _, endpoint in target_calls[5:]], list(C.ENDPOINTS))
            self.blocker_release.set()
            for future in blockers:
                future.result(timeout=3)
        finally:
            self.release.set()
            self.blocker_release.set()
            callers.shutdown(wait=True)
        acquired = 0
        try:
            for _ in range(8):
                self.assertTrue(C._slots.acquire(timeout=2), "Credits 任务槽未归还")
                acquired += 1
            self.assertFalse(C._slots.acquire(blocking=False))
            self.assertEqual(self.service._inflight, {})
            self.assertEqual(self.service._claims, {})
        finally:
            for _ in range(acquired):
                C._slots.release()

    def test_claim_first_details_reuses_postclaim_snapshot_with_four_workers(self):
        self.run_overlap(claim_first=True)

    def test_details_first_claim_reuses_precheck_with_four_workers(self):
        self.run_overlap(claim_first=False)


if __name__ == "__main__":
    unittest.main()
