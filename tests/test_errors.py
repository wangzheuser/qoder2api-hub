"""错误分类的离线边界回归。"""
import json
import unittest

from qoder_errors import (ErrorParseLimit, classify, extract_nodes,
                          extract_queue_info, public_error_type)


class ErrorClassificationTests(unittest.TestCase):
    def test_nested_queue_and_payload(self):
        detail = {"error": {"body": json.dumps({"code": 10605,
                  "queueInfo": {"modelKey": "model-1", "queueCount": 2}})}}
        info = classify(503, detail)
        self.assertEqual((info.kind, info.scope, info.public_http_status),
                         ("queued", "request", 429))
        self.assertEqual(info.upstream_code, "10605")
        self.assertEqual(info.queue_info["modelKey"], "model-1")
        self.assertEqual(extract_queue_info(extract_nodes(detail))["queueCount"], 2)

    def test_real_queue_shape_and_normalization(self):
        expected = {"isQueued": True, "modelKey": "claude-sonnet", "queueCount": 3,
                    "queueType": "MODEL", "serviceAvailable": False,
                    "waitTime": 12.5, "retryAfterSeconds": 2.0}
        for wrapper in ("data", "body", "queue", "queueInfo"):
            detail = {"code": 10605, wrapper: expected}
            self.assertEqual(classify(429, detail).queue_info, expected)
        alternate = {"is_queued": True, "MODEL_KEY": "claude-sonnet", "queue-count": "3",
                     "queue_type": "MODEL", "service_available": False,
                     "wait_time": "12.5", "retry_after_seconds": "2"}
        self.assertEqual(classify(10605, {"data": {"queue": alternate}}).queue_info, expected)
        self.assertEqual(classify(200, {"statusCodeValue": 10605, "data": expected}).kind, "queued")
        self.assertEqual(classify(10605, expected).public_http_status, 429)
        self.assertEqual(classify(12153).kind, "dead_session")
        self.assertEqual(classify(12153).public_http_status, 401)
        self.assertEqual(classify(200, {"statusCodeValue": 12153}).kind, "dead_session")

    def test_queue_field_validation(self):
        invalid = {"isQueued": "false", "serviceAvailable": 1, "modelKey": {},
                   "queueCount": True, "queueType": False, "waitTime": "inf",
                   "retryAfterSeconds": float("nan"), "unknown": "ignored"}
        self.assertIsNone(extract_queue_info(extract_nodes(invalid)))
        for field in ("queueCount", "waitTime", "retryAfterSeconds"):
            for value in (-1, "NaN", float("inf"), {}, True):
                self.assertIsNone(extract_queue_info(extract_nodes({field: value})))
        self.assertIsNone(extract_queue_info(extract_nodes({"queueCount": 1.5})))
        self.assertEqual(extract_queue_info(extract_nodes({"isQueued": False,
                         "queueCount": 0, "serviceAvailable": True})),
                         {"isQueued": False, "queueCount": 0, "serviceAvailable": True})

    def test_all_wrappers_and_sse(self):
        for field in ("error", "data", "body", "message", "cause", "result", "details"):
            with self.subTest(field=field):
                self.assertEqual(classify(429, {field: 'data: {"errorCode":"10605"}'}).kind, "queued")

    def test_no_queue_from_ordinary_text(self):
        for detail in ("10605", "稍后重试", "服务繁忙", {"message": "编号10605，稍后重试"},
                       {"content": '{"code":10605,"isQueued":true}'},
                       {"data": {"content": "isQueued=true queueCount=3 10605"}},
                       {"code": 106050}, {"code": True}):
            with self.subTest(detail=detail):
                self.assertNotEqual(classify(429, detail).kind, "queued")

    def test_request_fault_precedes_provider_failure(self):
        for text, kind in (("DataInspectionFailed", "content"),
                           ("SensitiveContent", "content"),
                           ("context_length_exceeded", "context"),
                           ("invalid_parameter_error", "request")):
            for status in (418, 500, 429):
                with self.subTest(text=text, status=status):
                    info = classify(status, "provider_error " + text)
                    self.assertEqual((info.kind, info.scope, info.public_http_status), (kind, "request", 400))

    def test_account_and_unknown_errors(self):
        for status, detail, expected in ((401, "", "auth"), (403, "", "forbidden"),
                (403, "TOKEN_EXPIRE", "dead_session"), (403, "12153", "dead_session"),
                (400, {"code": 12153}, "dead_session"),
                (401, "Offline user session not found", "dead_session"),
                (402, "", "quota"), (429, "insufficient_quota", "quota"),
                (429, "", "model_rate"), (422, "unknown", "request"),
                (418, "provider_error", "transient"), (503, "", "transient")):
            with self.subTest(status=status, detail=detail):
                self.assertEqual(classify(status, detail).kind, expected)
        self.assertEqual(classify(422).public_http_status, 422)
        self.assertEqual(classify(429).retry_after_seconds, 60)

    def test_retry_after_numeric_and_date(self):
        self.assertEqual(classify(429, {"resetAfter": 17}, {"Retry-After": "4"}).retry_after_seconds, 4)
        headers = {"Date": "Wed, 01 Jan 2025 00:00:00 GMT",
                   "Retry-After": "Wed, 01 Jan 2025 00:00:12 GMT"}
        self.assertEqual(classify(429, headers=headers).retry_after_seconds, 12)
        self.assertEqual(classify(429, {"resetAt": 1735689619},
                                  {"Date": headers["Date"]}).retry_after_seconds, 19)
        for value in ("nan", "inf", "-1", True):
            self.assertEqual(classify(429, headers={"Retry-After": value}).retry_after_seconds, 60)
        self.assertEqual(classify(429, headers={"Retry-After": "1e100"}).retry_after_seconds, 86400)

    def test_limits_and_unicode_size(self):
        for detail in ("x" * 65537, "中" * 21846, list(range(128))):
            with self.subTest(detail_type=type(detail)):
                self.assertEqual(classify(429, detail).kind, "protocol")
                with self.assertRaises(ErrorParseLimit):
                    extract_nodes(detail)
        detail = "error"
        for _ in range(9):
            detail = {"error": detail}
        self.assertEqual(classify(500, detail).kind, "protocol")
        self.assertEqual(len(extract_nodes("x" * 65536)), 1)
        self.assertEqual(len(extract_nodes(list(range(127)))), 128)
        self.assertEqual(classify(400, b"\xff").kind, "request")

    def test_bad_json_and_cycle(self):
        self.assertEqual(classify(400, '{"error":').kind, "request")
        cyclic = {}
        cyclic["error"] = cyclic
        info = classify(500, cyclic)
        self.assertEqual(public_error_type(info), "upstream_protocol_error")
        self.assertEqual(classify(None).upstream_http_status, 502)


if __name__ == "__main__":
    unittest.main()
