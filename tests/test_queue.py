"""队列预算、协议边界、取消和名额释放的离线验证。"""
import io
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import qoder_queue as queue


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.calls = []
        self.slots = threading.BoundedSemaphore(1)
        self.patcher = patch.object(queue, "QUEUE_SLOTS", self.slots)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def wait(self, responses, budget=30, callback=None, cost=0, initial=None):
        responses = iter(responses)

        def poll(*args):
            self.calls.append((self.clock(), args))
            self.clock.now += cost
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        return queue.wait_until_ready("request-1", "model-1", "MODEL", initial,
                                      budget, poll, callback, self.clock, self.clock.sleep)

    def assert_slot_released(self):
        self.assertTrue(self.slots.acquire(blocking=False))
        self.slots.release()

    def test_immediate_query_and_ready(self):
        result = self.wait([{"data": {"isQueued": False}}])
        self.assertEqual(result, queue.WaitResult(0.0, 1))
        self.assertEqual(self.calls, [(0.0, ("request-1", "model-1", "MODEL", 5.0))])
        self.assert_slot_released()

    def test_queued_unavailable_then_ready(self):
        result = self.wait([{"isQueued": True}, {"serviceAvailable": False},
                            {"isQueued": False}])
        self.assertEqual(result, queue.WaitResult(6.0, 3))
        self.assertEqual(self.clock.sleeps, [1.0] * 6)

    def test_clamp_and_explicit_ready_delay(self):
        result = self.wait([{"isQueued": True, "retryAfterSeconds": 0},
                            {"isQueued": True, "retryAfterSeconds": 300},
                            {"isQueued": False, "retryAfterSeconds": 2}], budget=40)
        self.assertEqual(result, queue.WaitResult(33.0, 3))

    def test_invalid_retry_uses_default(self):
        result = self.wait([{"isQueued": True, "retryAfterSeconds": "NaN"},
                            {"isQueued": False}])
        self.assertEqual(result.waited_seconds, 3.0)

    def test_new_queue_type_is_used_by_later_polls(self):
        self.wait([{"isQueued": True, "queueType": "SERVICE"},
                   {"isQueued": True}, {"isQueued": False}])
        self.assertEqual([args[2] for _, args in self.calls],
                         ["MODEL", "SERVICE", "SERVICE"])

    def test_ready_explicit_zero_does_not_sleep(self):
        result = self.wait([{"isQueued": False, "retryAfterSeconds": 0}], budget=.5)
        self.assertEqual(result, queue.WaitResult(0.0, 1))
        self.assertEqual(self.clock.sleeps, [])

    def test_http_error_response_closed_for_all_exit_paths(self):
        for status, budget, cancel in ((404, 30, False), (410, 30, False),
                                       (401, 30, False), (403, 30, False),
                                       (503, 30, False), (503, .5, False),
                                       (503, 30, True)):
            with self.subTest(status=status, budget=budget, cancel=cancel):
                response = io.BytesIO(b"error body")
                error = HTTPError("https://example.invalid", status, "error", {}, response)
                calls = 0

                def callback():
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        self.assertTrue(response.closed)
                        if cancel:
                            raise BrokenPipeError("client gone")

                if status == 503 and budget == 30 and not cancel:
                    self.wait([error, {"isQueued": False}], callback=callback, cost=.5)
                else:
                    with self.assertRaises(BrokenPipeError if cancel else queue.QueueError):
                        self.wait([error], budget=budget, callback=callback, cost=.5)
                self.assertTrue(response.closed)
                self.assert_slot_released()

    def test_malformed_and_contradictory_states_fail(self):
        for response in ({"queueCount": 0}, {"serviceAvailable": True},
                         {"isQueued": "false"},
                         {"isQueued": False, "serviceAvailable": False},
                         {"isQueued": True, "data": {"isQueued": False}}, []):
            with self.subTest(response=response):
                with self.assertRaises(queue.QueueError) as raised:
                    self.wait([response] * 3)
                self.assertEqual(raised.exception.code, "queue_poll_failed")
                self.assertEqual(raised.exception.poll_count, 3)
                self.assertEqual(raised.exception.waited_seconds, 6.0)
                self.assert_slot_released()

    def test_valid_state_resets_failure_counter(self):
        result = self.wait([{}, {}, {"isQueued": True}, {}, {}, {"isQueued": False}])
        self.assertEqual(result.poll_count, 6)

    def test_missing_endpoint_and_auth_stop_immediately(self):
        for status in (404, 410, 401, 403):
            with self.subTest(status=status):
                with self.assertRaises(queue.QueueError) as raised:
                    self.wait([HTTPError("https://example.invalid", status, "error", {}, None)], cost=.5)
                self.assertEqual(raised.exception.code, "queue_endpoint_unavailable"
                                 if status in (404, 410) else "queue_poll_failed")
                self.assertEqual(raised.exception.http_status, 503)
                self.assertEqual(raised.exception.waited_seconds, .5)
                self.assertEqual(raised.exception.poll_count, 1)
                self.assert_slot_released()

    def test_failed_get_time_counts_towards_budget(self):
        with self.assertRaises(queue.QueueError) as raised:
            self.wait([TimeoutError(), TimeoutError()], budget=4, cost=2)
        self.assertEqual(raised.exception.code, "queue_timeout")
        self.assertEqual(raised.exception.waited_seconds, 4.0)
        self.assertEqual(len(self.calls), 1)
        self.assert_slot_released()

    def test_ready_response_at_budget_does_not_resume(self):
        with self.assertRaises(queue.QueueError) as raised:
            self.wait([{"isQueued": False}], budget=2, cost=2)
        self.assertEqual(raised.exception.code, "queue_timeout")
        self.assertEqual(self.calls[0][1][-1], 2)

    def test_explicit_ready_delay_exhausts_budget(self):
        with self.assertRaises(queue.QueueError) as raised:
            self.wait([{"isQueued": False, "retryAfterSeconds": 10}], budget=2)
        self.assertEqual(raised.exception.waited_seconds, 2)
        self.assertEqual(raised.exception.code, "queue_timeout")

    def test_second_queue_only_uses_remaining_budget(self):
        first = self.wait([{"isQueued": True}, {"isQueued": False}], budget=5)
        with self.assertRaises(queue.QueueError) as raised:
            self.wait([{"isQueued": True}], budget=5 - first.waited_seconds)
        self.assertEqual(raised.exception.waited_seconds, 2)
        self.assertEqual(self.clock(), 5)
        self.assertEqual(len(self.calls), 3)

    def test_zero_budget_does_not_query(self):
        with self.assertRaises(queue.QueueError) as raised:
            self.wait([], budget=0)
        self.assertEqual(raised.exception.code, "queue_timeout")
        self.assertEqual(self.calls, [])
        self.assert_slot_released()

    def test_full_capacity_never_queries_or_sleeps(self):
        self.slots.acquire()
        try:
            with self.assertRaises(queue.QueueError) as raised:
                self.wait([])
            self.assertEqual(raised.exception.code, "gateway_queue_full")
            self.assertEqual(raised.exception.http_status, 503)
            self.assertEqual(self.calls, [])
            self.assertEqual(self.clock.sleeps, [])
            self.assertFalse(self.slots.acquire(blocking=False))
        finally:
            self.slots.release()

    def test_cancellation_before_and_after_get_and_during_sleep(self):
        for cancel_at in (1, 2, 4):
            with self.subTest(cancel_at=cancel_at):
                self.calls.clear()
                calls = 0

                def callback():
                    nonlocal calls
                    calls += 1
                    if calls == cancel_at:
                        raise BrokenPipeError("client gone")

                with self.assertRaises(BrokenPipeError) as raised:
                    self.wait([{"isQueued": True}], callback=callback)
                self.assertEqual(len(self.calls), 0 if cancel_at == 1 else 1)
                self.assertEqual(raised.exception.waited_seconds, 1 if cancel_at == 4 else 0)
                self.assert_slot_released()


if __name__ == "__main__":
    unittest.main()
