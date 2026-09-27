"""队列 GET 的实际方法、查询参数及 COSY 空 body 签名。"""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qoder_accounts as A
import qoder_proxy as P


class QueueWireTests(unittest.TestCase):
    def test_empty_get_body_and_signature(self):
        ctx = P.RequestContext({"model": "qfmodel"}, "cn")
        ctx.account = A.Account({"uid": "queue-wire", "realm": "cn", "accessToken": "dt-fixture"})
        response = io.BytesIO(b'{"data":{"isQueued":false}}')
        with patch.object(P, "validate_public_http_url", side_effect=lambda u: u), \
             patch.object(P.urllib.request, "urlopen", return_value=response) as opened:
            self.assertFalse(P._poll_queue(ctx, "set /a", "model&x", "queue /中文", 5)["data"]["isQueued"])
        request = opened.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        self.assertEqual(parse_qs(urlparse(request.full_url).query),
                         {"requestSetId": ["set /a"], "modelKey": ["model&x"], "queueType": ["queue /中文"]})
        headers = {k.lower(): v for k, v in request.header_items()}
        _, payload, signature = headers["authorization"].split(".")
        path = urlparse(request.full_url).path.removeprefix("/algo")
        raw = "\n".join((payload, headers["cosy-key"], headers["cosy-date"], "", path))
        self.assertEqual(signature, hashlib.md5(raw.encode()).hexdigest())
        self.assertEqual(headers["x-request-id"], "set /a")
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
