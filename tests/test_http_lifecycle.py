"""用 loopback HTTP 验证真实头部、SSE 帧和终态；上游请求仅重定向本机。"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qoder_accounts as A
import qoder_proxy as P
import qoder_settings as S


def envelope(body, status=200):
    return ("data: " + json.dumps({"statusCodeValue": status,
                                  "body": body if isinstance(body, str) else json.dumps(body)}) + "\n\n").encode()


class HTTPFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.posts = 0
        self.mode = "success"
        self.real_urlopen = urllib.request.urlopen
        owner = self

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                owner.posts += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(envelope({"choices": [{"delta": {"content": "hello"}}]}))
                if owner.mode == "partial_error":
                    self.wfile.write(envelope({"code": "provider_error"}, 418))
                else:
                    self.wfile.write(envelope({"choices": [{"delta": {}, "finish_reason": "stop"}],
                                              "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}}))
                    self.wfile.write(envelope("[DONE]"))

        class Gateway(P.Handler):
            def _authorized(self):
                return True

            def _request_realm(self, explicit=None):
                return "cn"

        self.upstream = self.server(Upstream)
        pool = A.AccountPool(self.temp.name)
        pool.add(A.Account({"uid": "loopback", "realm": "cn", "accessToken": "dt-fake", "expiresAt": 9999999999}))
        for guard in [patch.object(P, "POOL", pool), patch.object(P, "ACCOUNTS_DIR", self.temp.name),
                      patch.object(P, "validate_public_http_url", side_effect=lambda url: url),
                      patch.object(P.urllib.request, "urlopen", side_effect=self.redirect),
                      patch.object(P, "record_usage"), patch.object(P, "record_error")]:
            guard.start()
            self.addCleanup(guard.stop)
        self.gateway = self.server(Gateway)

    def server(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.addCleanup(close)
        return server

    def redirect(self, request, timeout=None):
        url = "http://127.0.0.1:%d/fixture" % self.upstream.server_port
        req = urllib.request.Request(url, data=request.data, headers=dict(request.header_items()), method=request.method)
        return self.real_urlopen(req, timeout=timeout)

    def request(self, responses, stream):
        body = {"model": "qfmodel", "stream": stream}
        body.update({"input": "hello"} if responses else {"messages": [{"role": "user", "content": "hello"}]})
        conn = http.client.HTTPConnection("127.0.0.1", self.gateway.server_port, timeout=5)
        try:
            conn.request("POST", "/v1/responses" if responses else "/v1/chat/completions",
                         body=json.dumps(body), headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            return response.status, response.read().decode()
        finally:
            conn.close()

    def test_four_paths_emit_one_success_and_accounting_call(self):
        for responses in (False, True):
            for stream in (False, True):
                with self.subTest(responses=responses, stream=stream):
                    P.record_usage.reset_mock()
                    P.record_error.reset_mock()
                    status, body = self.request(responses, stream)
                    self.assertEqual(status, 200)
                    self.assertIn("hello", body)
                    if stream:
                        if responses:
                            self.assertEqual(body.count("event: response.created\n"), 1)
                            self.assertEqual(body.count("event: response.completed\n"), 1)
                        else:
                            self.assertEqual(body.count("data: [DONE]"), 1)
                    else:
                        self.assertIsInstance(json.loads(body), dict)
                    P.record_usage.assert_called_once()
                    P.record_error.assert_not_called()

    def test_partial_stream_has_single_failure_no_replay(self):
        self.mode = "partial_error"
        for responses in (False, True):
            with self.subTest(responses=responses):
                before = self.posts
                status, body = self.request(responses, True)
                self.assertEqual(status, 200)
                self.assertEqual(self.posts, before + 1)
                if responses:
                    self.assertEqual(body.count("event: response.created\n"), 1)
                    self.assertEqual(body.count("event: response.failed\n"), 1)
                    self.assertNotIn("event: response.completed\n", body)
                    frames = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
                    seq = [frame["sequence_number"] for frame in frames]
                    self.assertEqual(seq, list(range(1, len(seq) + 1)))
                else:
                    self.assertEqual(body.count("data: [DONE]"), 1)
                    self.assertEqual(body.count("hello"), 1)


if __name__ == "__main__":
    unittest.main()
