"""设置持久化及协议入口的离线行为回归。"""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qoder_proxy as P
import qoder_settings as S
import qoder_accounts as A


class Response:
    def __init__(self, error=False):
        self.error = error
        self.closed = False

    def __iter__(self):
        if self.error:
            yield b'data: {"statusCodeValue":418,"body":"provider_error"}\n\n'
        else:
            body = {"choices": [{"delta": {"content": "recovered"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}}
            yield ("data: " + json.dumps({"statusCodeValue": 200, "body": json.dumps(body)}) + "\n\n").encode()
            yield b'data: {"body":"[DONE]"}\n\n'

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class SettingsTests(unittest.TestCase):
    def test_defaults_merge_preserves_secrets_and_future_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(S.gateway_settings(directory), S.GATEWAY_DEFAULTS)
            S.save(directory, {"api_key": "synthetic-key", "gateway": {"future": 7}})
            S.set_gateway(directory, {"queue_enabled": True, "pool_max_inflight": 2})
            self.assertTrue(S.gateway_settings(directory)["queue_enabled"])
            data = S.load(directory)
            self.assertEqual(data["api_key"], "synthetic-key")
            self.assertEqual(data["gateway"]["future"], 7)

    def test_invalid_patch_leaves_file_unchanged(self):
        invalid = [{"queue_enabled": "false"}, {"pool_max_inflight": True},
                   {"pool_max_inflight": 17}, {"queue_max_wait_seconds": 0},
                   {"queue_max_wait_seconds": 2.5}, {"typo": 1}, []]
        with tempfile.TemporaryDirectory() as directory:
            S.set_gateway(directory, {"queue_enabled": False})
            path = Path(S.settings_path(directory))
            before = path.read_bytes()
            for values in invalid:
                with self.subTest(values=values), self.assertRaises(ValueError):
                    S.set_gateway(directory, values)
                self.assertEqual(before, path.read_bytes())

    def test_invalid_disk_value_uses_default(self):
        with tempfile.TemporaryDirectory() as directory:
            S.save(directory, {"gateway": {"queue_enabled": "yes", "pool_max_inflight": 2}})
            self.assertFalse(S.gateway_settings(directory)["queue_enabled"])
            self.assertEqual(S.gateway_settings(directory)["pool_max_inflight"], 2)


class ResponsesRetryTests(unittest.TestCase):
    def test_normalized_request_reused_by_both_paths(self):
        for stream in (False, True):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as directory:
                handler = P.Handler.__new__(P.Handler)
                handler.headers = {}
                handler.path = "/v1/responses"
                handler.wfile = io.BytesIO()
                handler.send_response = Mock()
                handler.send_header = Mock()
                handler.end_headers = Mock()
                handler._request_realm = lambda: "cn"
                handler._json = Mock()
                payload = {"model": "qfmodel", "input": "hello", "stream": stream,
                           "tools": [{"type": "custom", "name": "apply_patch", "description": "patch"}]}
                original = copy.deepcopy(payload)
                responses = [Response(error=True), Response()]
                pool = A.AccountPool(directory)
                pool.add(A.Account({"uid": "synthetic-account", "realm": "cn", "accessToken": "dt-test", "expiresAt": 9999999999}))
                with patch.object(P, "_open_attempt", side_effect=responses) as opened, \
                     patch.object(P, "POOL", pool), patch.object(P, "ACCOUNTS_DIR", directory), \
                     patch.object(P, "record_usage"), patch.object(P, "record_error"), \
                     patch.object(P.time, "sleep"):
                    handler._handle_responses(payload)
                self.assertEqual(opened.call_count, 2)
                first, second = [call.args[0].payload for call in opened.call_args_list]
                self.assertEqual(first, second)
                self.assertIn("messages", second)
                self.assertEqual(second["tools"][0]["name"], "apply_patch")
                self.assertEqual(second["tools"][0]["type"], "function")
                self.assertEqual(payload, original)
                self.assertTrue(all(r.closed for r in responses))


class AccountErrorPolicyTests(unittest.TestCase):
    def test_http_request_faults_never_rotate_or_punish(self):
        for status, detail in [(400, "invalid_parameter_error"),
                               (418, "DataInspectionFailed"),
                               (403, "permission denied"),
                               (429, '{"code":10605}')]:
            with self.subTest(status=status, detail=detail), tempfile.TemporaryDirectory() as directory:
                pool = A.AccountPool(directory)
                for uid in ("one", "two"):
                    pool.add(A.Account({"uid": uid, "realm": "cn", "accessToken": "dt-synthetic", "expiresAt": 9999999999}))
                error = urllib.error.HTTPError("https://example.invalid", status, "failure", {}, io.BytesIO(detail.encode()))
                with patch.object(P, "POOL", pool), patch.object(P, "validate_public_http_url", side_effect=lambda u: u), \
                     patch.object(P.urllib.request, "urlopen", side_effect=error) as opened, \
                     patch.object(P, "ACCOUNTS_DIR", directory):
                    context = P.RequestContext({"model": "qfmodel", "messages": [
                        {"role": "user", "content": "hello"}]}, "cn", options={"queue_enabled": False})
                    with self.assertRaises(P.UpstreamStatus):
                        list(P.iter_with_recovery(context, {}))
                self.assertEqual(opened.call_count, 1)
                self.assertTrue(all(a.enabled and a.cooldown_until == 0 and not a.model_cooldowns for a in pool.accounts))
                self.assertFalse(pool._leases)


if __name__ == "__main__":
    unittest.main()
