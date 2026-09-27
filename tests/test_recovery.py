"""共享恢复层的离线 HTTP/SSE 行为与资源边界回归。"""
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
import qoder_accounts as A
import qoder_proxy as P
import qoder_settings as S
from qoder_sign import qoder_decode


def envelope(body, status=200):
    if isinstance(body, dict):
        body = json.dumps(body)
    return ("data: " + json.dumps({"statusCodeValue": status, "body": body}) + "\n\n").encode()


def chunk(content="recovered", usage=None):
    body = {"choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]}
    if usage is not None:
        body["usage"] = usage
    return envelope(body)


QUEUE = {"code": 10605, "data": {"isQueued": True, "modelKey": "qfmodel",
         "queueCount": 1, "queueType": "MODEL", "retryAfterSeconds": 0}}


class Response:
    def __init__(self, *lines):
        self.lines = lines
        self.closed = False
        self.headers = {}

    def __iter__(self):
        for line in self.lines:
            if isinstance(line, Exception):
                raise line
            yield line

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def success(usage=None):
    return Response(chunk(usage=usage), envelope("[DONE]"))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        old_pool = A._ACTIVE_POOL
        self.addCleanup(setattr, A, "_ACTIVE_POOL", old_pool)
        self.pool = A.AccountPool(self.directory.name)
        self.pool.accounts = [A.Account({"uid": "synthetic-" + str(i), "realm": realm,
                                        "accessToken": "synthetic-token-" + str(i)})
                              for i, realm in enumerate(("cn", "cn", "cn", "intl"))]
        for target, name, value in ((P, "POOL", self.pool), (P, "ACCOUNTS_DIR", self.directory.name)):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for patcher in (patch.object(P, "validate_public_http_url", side_effect=lambda url: url),
                        patch.object(P.qoder_catalog, "models_for_realm", return_value=[]),
                        patch.object(P.time, "sleep")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.payload = {"model": "qfmodel", "messages": [{"role": "user", "content": "hello"}],
                        "tools": [{"type": "function", "function": {"name": "fixture_tool",
                                   "parameters": {"type": "object", "properties": {}}}}]}
        self.posts = []
        self.bodies = []
        self.resources = []

    def context(self, realm="cn", enabled=True):
        options = dict(S.GATEWAY_DEFAULTS, queue_enabled=enabled)
        ctx = P.RequestContext(copy.deepcopy(self.payload), realm, session_key="synthetic-session", options=options)
        self.addCleanup(ctx.close)
        return ctx

    def open_sequence(self, *outcomes):
        iterator = iter(outcomes)
        def opened(req, **kwargs):
            self.assertEqual(req.get_method(), "POST")
            self.posts.append(req)
            self.bodies.append(json.loads(qoder_decode(req.data.decode())))
            outcome = next(iterator)
            self.resources.append(outcome)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return patch.object(P.urllib.request, "urlopen", side_effect=opened)

    def http_error(self, status, body):
        stream = io.BytesIO(json.dumps(body).encode())
        return urllib.error.HTTPError("https://synthetic.invalid/chat", status, "fixture", {}, stream)

    def assert_no_penalties(self):
        for account in self.pool.accounts:
            self.assertTrue(account.enabled)
            self.assertEqual(account.cooldown_until, 0)
            self.assertFalse(account.model_cooldowns)

    def assert_all_closed(self):
        for resource in self.resources:
            if isinstance(resource, urllib.error.HTTPError):
                self.assertTrue(resource.fp is None or resource.fp.closed)
            else:
                self.assertTrue(resource.closed)

    def test_http_and_sse_queue_resume_keeps_account_ids_and_payload(self):
        for kind in ("http403", "http429", "sse"):
            with self.subTest(kind=kind):
                self.posts.clear()
                self.bodies.clear()
                self.resources.clear()
                ctx = self.context()
                failure = (Response(envelope(QUEUE, 10605)) if kind == "sse"
                           else self.http_error(int(kind[4:]), QUEUE))
                with self.open_sequence(failure, success()), \
                     patch.object(P, "_poll_queue", return_value={"isQueued": False}) as poll:
                    output = b"".join(P.iter_with_recovery(ctx, {}))
                self.assertIn(b"recovered", output)
                self.assertEqual(len(self.posts), 2)
                self.assertEqual(poll.call_count, 1)
                ids = ("request_id", "chat_record_id", "request_set_id", "session_id")
                for field in ids:
                    self.assertEqual(self.bodies[0][field], self.bodies[1][field])
                self.assertEqual(self.bodies[0]["business"]["id"], self.bodies[1]["business"]["id"])
                self.assertEqual(self.bodies[0]["messages"], self.bodies[1]["messages"])
                self.assertEqual(self.bodies[0]["tools"], self.bodies[1]["tools"])
                self.assertEqual(self.posts[0].get_header("Cosy-user"), self.posts[1].get_header("Cosy-user"))
                self.assertEqual(ctx.queue_recoveries, 1)
                self.assert_no_penalties()
                ctx.close()
                self.assert_all_closed()

    def test_disabled_queue_never_polls_or_penalizes(self):
        ctx = self.context(enabled=False)
        with self.open_sequence(self.http_error(429, QUEUE)), patch.object(P, "_poll_queue") as poll:
            with self.assertRaises(P.UpstreamStatus) as caught:
                list(P.iter_with_recovery(ctx, {}))
        self.assertEqual(caught.exception.info.public_http_status, 429)
        self.assertEqual(len(self.posts), 1)
        poll.assert_not_called()
        self.assert_no_penalties()
        ctx.close()
        self.assert_all_closed()

    def test_repeated_queue_is_bounded_without_penalties(self):
        ctx = self.context()
        outcomes = [self.http_error(429, QUEUE) for _ in range(7)]
        with self.open_sequence(*outcomes), patch.object(P, "_poll_queue", return_value={"isQueued": False}) as poll:
            with self.assertRaises(P.UpstreamStatus):
                list(P.iter_with_recovery(ctx, {}))
        self.assertLessEqual(len(self.posts), 6)
        self.assertLessEqual(poll.call_count, 2)
        self.assert_no_penalties()
        ctx.close()
        self.assert_all_closed()

    def test_transient_post_and_account_budgets(self):
        ctx = self.context()
        with self.open_sequence(*[self.http_error(503, {"error": "provider_error"}) for _ in range(7)]):
            with self.assertRaises(P.UpstreamStatus):
                list(P.iter_with_recovery(ctx, {}))
        self.assertEqual(len(self.posts), 6)
        self.assertLessEqual(len({req.get_header("Cosy-user") for req in self.posts}), 3)
        ctx.close()
        self.assert_all_closed()

    def test_http_and_sse_share_same_account_retry_budget(self):
        ctx = self.context()
        with self.open_sequence(self.http_error(503, {"error": "provider_error"}),
                                Response(envelope("provider_error", 418)),
                                self.http_error(503, {"error": "provider_error"}), success()):
            output = b"".join(P.iter_with_recovery(ctx, {}))
        self.assertIn(b"recovered", output)
        self.assertEqual(len(self.posts), 4)
        users = [req.get_header("Cosy-user") for req in self.posts]
        self.assertEqual(users[:3], [users[0]] * 3)
        self.assertNotEqual(users[2], users[3])
        ctx.close()
        self.assert_all_closed()

    def test_closing_iterator_releases_open_response(self):
        ctx = self.context()
        with self.open_sequence(Response(chunk("partial"), chunk("unread"), envelope("[DONE]"))):
            iterator = P.iter_with_recovery(ctx, {})
            self.assertIn(b"partial", next(iterator))
            iterator.close()
        self.assertEqual(len(self.posts), 1)
        self.assert_all_closed()

    def test_request_faults_end_immediately_without_penalty(self):
        for detail in ("invalid_parameter_error", "DataInspectionFailed", "context_length_exceeded"):
            with self.subTest(detail=detail):
                self.posts.clear()
                self.resources.clear()
                ctx = self.context()
                with self.open_sequence(self.http_error(418, {"error": detail})), patch.object(P, "_poll_queue") as poll:
                    with self.assertRaises(P.UpstreamStatus) as caught:
                        list(P.iter_with_recovery(ctx, {}))
                self.assertEqual(caught.exception.info.scope, "request")
                self.assertEqual(len(self.posts), 1)
                poll.assert_not_called()
                self.assert_no_penalties()
                ctx.close()
                self.assert_all_closed()

    def test_partial_output_never_replayed(self):
        ctx = self.context()
        with self.open_sequence(Response(chunk("partial"), envelope("provider_error", 418))):
            iterator = P.iter_with_recovery(ctx, {})
            self.assertIn(b"partial", next(iterator))
            with self.assertRaises(P.UpstreamStatus):
                list(iterator)
        self.assertEqual(len(self.posts), 1)
        ctx.close()
        self.assert_all_closed()

    def test_empty_and_truncated_eof_are_protocol_errors(self):
        for lines in ((), (b'data: {"body":',), (chunk("partial"),)):
            with self.subTest(lines=lines):
                self.posts.clear()
                self.resources.clear()
                ctx = self.context()
                with self.open_sequence(Response(*lines)):
                    with self.assertRaises(P.UpstreamStatus) as caught:
                        list(P.iter_with_recovery(ctx, {}))
                self.assertEqual(caught.exception.info.kind, "protocol")
                self.assertEqual(len(self.posts), 1)
                ctx.close()
                self.assert_all_closed()

    def test_success_usage_replaces_stale_holder(self):
        ctx = self.context()
        usage = {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}
        holder = {"usage": {"total_tokens": 999}}
        with self.open_sequence(self.http_error(503, {"error": "provider_error"}), success(usage)):
            list(P.iter_with_recovery(ctx, holder))
        self.assertEqual(holder["usage"], usage)
        ctx.close()
        self.assert_all_closed()

    def test_recovery_never_crosses_realm(self):
        ctx = self.context(realm="intl")
        with self.open_sequence(self.http_error(429, QUEUE), success()), \
             patch.object(P, "_poll_queue", return_value={"isQueued": False}):
            list(P.iter_with_recovery(ctx, {}))
        self.assertEqual(ctx.account.realm, "intl")
        gateway = A.get_realm_config("intl")["gateway"]
        self.assertTrue(all(req.full_url.startswith(gateway) for req in self.posts))
        self.assert_no_penalties()
        ctx.close()
        self.assert_all_closed()

    def handler(self, responses):
        handler = P.Handler.__new__(P.Handler)
        handler.headers = {}
        handler.path = "/v1/responses" if responses else "/v1/chat/completions"
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler._json = Mock()
        handler._request_realm = lambda: "cn"
        handler._cross_realm_error = lambda model, realm: ""
        return handler

    def invoke_handler(self, handler, responses, stream):
        payload = copy.deepcopy(self.payload)
        payload["stream"] = stream
        if responses:
            payload["input"] = "hello"
            payload.pop("messages")
            payload["tools"] = [{"type": "custom", "name": "fixture_tool", "description": "fixture"}]
            handler._handle_responses(payload)
        else:
            handler._handle_inference(payload)

    def events(self, handler):
        result = []
        for line in handler.wfile.getvalue().splitlines():
            if line.startswith(b"data: ") and line != b"data: [DONE]":
                result.append(json.loads(line[6:]))
        return result

    def test_four_handler_paths_queue_recovery_outputs_once(self):
        options = dict(S.GATEWAY_DEFAULTS, queue_enabled=True)
        for responses in (False, True):
            for stream in (False, True):
                for origin in ("http", "sse"):
                    with self.subTest(responses=responses, stream=stream, origin=origin):
                        self.posts.clear()
                        self.bodies.clear()
                        self.resources.clear()
                        handler = self.handler(responses)
                        failure = (self.http_error(403, QUEUE) if origin == "http"
                                   else Response(envelope(QUEUE, 10605)))
                        with self.open_sequence(failure, success()), \
                             patch.object(P, "_poll_queue", return_value={"isQueued": False}), \
                             patch.object(S, "gateway_settings", return_value=options), \
                             patch.object(P, "record_usage") as usage, patch.object(P, "record_error") as error:
                            self.invoke_handler(handler, responses, stream)
                        self.assertEqual(len(self.posts), 2)
                        self.assertEqual(self.bodies[0]["messages"], self.bodies[1]["messages"])
                        self.assertEqual(self.bodies[0]["tools"], self.bodies[1]["tools"])
                        usage.assert_called_once()
                        error.assert_not_called()
                        if stream:
                            handler.send_response.assert_called_once_with(200)
                            handler._json.assert_not_called()
                            if responses:
                                types = [event.get("type") for event in self.events(handler)]
                                self.assertEqual(types.count("response.created"), 1)
                                self.assertEqual(types.count("response.completed"), 1)
                                self.assertNotIn("response.failed", types)
                            else:
                                self.assertEqual(handler.wfile.getvalue().count(b"data: [DONE]"), 1)
                                self.assertEqual(handler.wfile.getvalue().count(b"recovered"), 1)
                        else:
                            handler._json.assert_called_once()
                            status, body = handler._json.call_args.args
                            self.assertEqual(status, 200)
                            self.assertIn("recovered", json.dumps(body))
                            self.assertEqual(handler.wfile.getvalue(), b"")
                        self.assert_no_penalties()
                        self.assert_all_closed()

    def test_four_handler_paths_queue_timeout_terminal_error(self):
        options = dict(S.GATEWAY_DEFAULTS, queue_enabled=True)
        def timeout(*args, on_wait=None, **kwargs):
            if on_wait:
                on_wait()
            raise P.qoder_queue.QueueError("queue_timeout", 429, "fixture queue timeout", 120, 1)
        for responses in (False, True):
            for stream in (False, True):
                with self.subTest(responses=responses, stream=stream):
                    self.posts.clear()
                    self.resources.clear()
                    handler = self.handler(responses)
                    with self.open_sequence(self.http_error(429, QUEUE)), \
                         patch.object(P.qoder_queue, "wait_until_ready", side_effect=timeout), \
                         patch.object(S, "gateway_settings", return_value=options), \
                         patch.object(P, "record_usage") as usage, patch.object(P, "record_error") as error:
                        self.invoke_handler(handler, responses, stream)
                    usage.assert_not_called()
                    error.assert_called_once()
                    self.assertEqual(len(self.posts), 1)
                    if stream:
                        handler.send_response.assert_called_once_with(200)
                        handler._json.assert_not_called()
                        self.assertIn(b": queue waiting", handler.wfile.getvalue())
                        events = self.events(handler)
                        if responses:
                            created = [e for e in events if e.get("type") == "response.created"]
                            failed = [e for e in events if e.get("type") == "response.failed"]
                            self.assertEqual(len(created), 1)
                            self.assertEqual(len(failed), 1)
                            self.assertEqual(created[0]["response"]["id"], failed[0]["response"]["id"])
                            self.assertEqual(failed[0]["response"]["error"]["code"], "queue_timeout")
                            self.assertFalse(any(e.get("type") == "response.completed" for e in events))
                        else:
                            self.assertEqual(handler.wfile.getvalue().count(b"data: [DONE]"), 1)
                            self.assertEqual(len([e for e in events if "error" in e]), 1)
                    else:
                        handler._json.assert_called_once()
                        self.assertEqual(handler._json.call_args.args[0], 429)
                        self.assertEqual(handler.wfile.getvalue(), b"")
                    self.assert_no_penalties()
                    self.assert_all_closed()

    def test_four_handler_paths_partial_failure_has_one_terminal_record(self):
        for responses in (False, True):
            for stream in (False, True):
                with self.subTest(responses=responses, stream=stream):
                    self.posts.clear()
                    self.resources.clear()
                    handler = self.handler(responses)
                    with self.open_sequence(Response(chunk("partial"), envelope("provider_error", 418))), \
                         patch.object(P, "record_usage") as usage, patch.object(P, "record_error") as error:
                        self.invoke_handler(handler, responses, stream)
                    self.assertEqual(len(self.posts), 1)
                    usage.assert_not_called()
                    error.assert_called_once()
                    if stream:
                        handler.send_response.assert_called_once_with(200)
                        handler._json.assert_not_called()
                        events = self.events(handler)
                        if responses:
                            created = [e for e in events if e.get("type") == "response.created"]
                            failed = [e for e in events if e.get("type") == "response.failed"]
                            self.assertEqual(len(created), 1)
                            self.assertEqual(len(failed), 1)
                            self.assertEqual(created[0]["response"]["id"], failed[0]["response"]["id"])
                            self.assertFalse(any(e.get("type") == "response.completed" for e in events))
                        else:
                            self.assertEqual(handler.wfile.getvalue().count(b"partial"), 1)
                            self.assertEqual(handler.wfile.getvalue().count(b"data: [DONE]"), 1)
                    else:
                        handler._json.assert_called_once()
                        self.assertEqual(handler._json.call_args.args[0], 502)
                        self.assertEqual(handler.wfile.getvalue(), b"")
                    self.assert_all_closed()


if __name__ == "__main__":
    unittest.main()
