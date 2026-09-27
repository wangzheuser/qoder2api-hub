"""测试进程隔离；不读取本机模型目录，不允许实际网络连接。"""
import atexit
import os
import socket
import tempfile
from unittest.mock import patch


def install(local_credentials=False):
    root = tempfile.TemporaryDirectory(prefix="qoder-offline-")
    root.forbidden_attempts = []
    atexit.register(root.cleanup)
    env = patch.dict(os.environ, {
        "ACCOUNTS_DIR": os.path.join(root.name, "accounts"),
        "QD_PROXY_USAGE_DIR": os.path.join(root.name, "usage"),
        "QD_PROXY_DEFAULT_REALM": "cn",
    })
    env.start()
    atexit.register(env.stop)

    def blocked(*args, **kwargs):
        root.forbidden_attempts.append("network-or-credential-access")
        raise AssertionError("offline test attempted real network or credential access")

    # DNS 只为已 mock 的 HTTP 请求提供固定公网地址；连接操作仍一律阻止。
    def fake_dns(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    for target, replacement in (
        ("socket.socket.connect", blocked),
        ("socket.socket.connect_ex", blocked),
        ("socket.socket.sendto", blocked),
        ("socket.create_connection", blocked),
        ("socket.getaddrinfo", fake_dns),
        ("urllib.request.urlopen", blocked),
    ):
        guard = patch(target, replacement)
        guard.start()
        atexit.register(guard.stop)

    import qoder_proxy as proxy
    import qoder_catalog as catalog
    import qoder_accounts as accounts
    proxy.ACCOUNTS_DIR = os.environ["ACCOUNTS_DIR"]
    proxy.REALM_STATE_FILE = os.path.join(proxy.ACCOUNTS_DIR, "active_realm.json")
    proxy.read_local_models = lambda realm=None: []
    catalog._official_text_cache = dict(catalog._EMBEDDED_MODEL_TEXT)
    if not local_credentials:
        accounts.scan_desktop_credentials = blocked
    return root
