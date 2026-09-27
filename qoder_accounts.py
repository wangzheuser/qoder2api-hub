"""qoder_accounts.py —— Qoder 双区域账号池、OAuth 设备授权与凭证生命周期

覆盖与 WorkBuddy 网关同等完整的账号能力：

  - 双区域常量表 REALM_CONFIGS（国内 qoder.com.cn / 国际 qoder.com）
  - OAuth 设备授权（PKCE S256，浏览器授权 + /deviceToken/poll 轮询，
    dt- 30 天 / drt- 1 年）——免桌面客户端一键登录
  - PAT 导入（pt- 长期令牌 -> jobToken 交换 jt-/jrt-）
  - 按 token 前缀路由的刷新（drt- -> deviceToken/refresh；
    jrt- -> jobToken/refresh，失败回落 PAT 重新交换）
  - 每日签到 / 额度（quota）/ 套餐（plan）查询
  - 会话亲和（同一对话固定落到同一账号）与轮询负载
  - 账号导入导出（Dry-Run 预检）与 JSON 持久化（原子写）
"""
import base64
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import uuid

from qoder_fingerprint import derive_id, generate_request_id
from qoder_catalog import resolve_upstream_key


def _model_key(model, realm):
    return resolve_upstream_key(model, realm=realm) if model else None

# ---------------------------------------------------------------------------
# 区域常量（逆向自官方桌面/CLI 客户端）
# ---------------------------------------------------------------------------
REALM_CONFIGS = {
    "cn": {
        "name": "国内版 (China)",
        "openapi": "https://openapi.qoder.com.cn",
        "gateway": "https://gateway.qoder.com.cn",
        "website": "https://qoder.com.cn",
        "client_id": "1c5e33e1-364d-4ce6-b02c-acaa81274a5c",
        "redirect_uri": "qoder-work-cn://",
        "domain": "qoder.com.cn",
        "ua": "QoderWork/1.1.34",
        "has_checkin": True,       # 官方：仅国内版有每日签到 (sash daily-check-in)
        "send_client_id": True,    # CN 设备授权 URL: client_id + machine_id + redirect_uri
        "send_redirect_uri": True,
        "nonce_dashed": True,      # CN nonce 使用带横线 uuid
        "home_dir": ".qoder-cn",   # 官方客户端本地目录（凭证 / 模型目录缓存）
        "app_dir": "com.qodercn.app.stable",   # 桌面 App Roaming 数据目录
    },
    "intl": {
        "name": "国际版 (Global)",
        "openapi": "https://openapi.qoder.sh",
        "gateway": "https://api3.qoder.sh",
        "website": "https://qoder.com",
        "client_id": "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb",
        "redirect_uri": "qoder://aicoding.aicoding-agent/login-success",
        "domain": "qoder.com",
        "ua": "Qoder/1.1.34",
        "has_checkin": False,      # 官方：国际版无签到接口 (见 cpa docs/PROTOCOL.md)
        "send_client_id": True,    # Intl 设备授权 URL: client_id + machine_id (无 redirect_uri)
        "send_redirect_uri": False,
        "nonce_dashed": False,     # intl nonce 为 32-hex uuid-simple
        "home_dir": ".qoder",
        "app_dir": "com.qoder.app.stable",
    },
}

CLIENT_UA = "Go-http-client/2.0"
LOGIN_TTL_SECONDS = 600
DEFAULT_USER_TYPE = "personal_professional_trial"

# 业务端点（全部挂 openapi 基址，纯 Bearer，无 COSY 签名）
PATH_DEVICE_POLL = "/api/v1/deviceToken/poll"
PATH_DEVICE_REFRESH = "/api/v1/deviceToken/refresh"
PATH_JOB_EXCHANGE = "/api/v1/jobToken/exchange"
PATH_JOB_REFRESH = "/api/v1/jobToken/refresh"
PATH_USERINFO = "/api/v1/userinfo"
PATH_QUOTA = "/api/v2/quota/usage"
PATH_PLAN = "/api/v2/user/plan"
PATH_CHECKIN_STATUS = "/sash/api/v1/me/daily-check-in/status"
PATH_CHECKIN_CLAIM = "/sash/api/v1/me/daily-check-in/claim"
PATH_PRO_ELIGIBILITY = "/sash/api/v1/me/pro-upgrade/eligibility"
PATH_PRO_CLAIM = "/sash/api/v1/me/pro-upgrade/claim"

# 会话死亡标记：上游主动吊销离线会话，刷新已无意义，需要重新登录。
SESSION_DEAD_MARKERS = ("TOKEN_EXPIRE", "12153", "Offline user session not found")


def session_dead(msg):
    s = str(msg or "")
    return any(m in s for m in SESSION_DEAD_MARKERS)


def get_realm_config(realm):
    return REALM_CONFIGS.get(realm) or REALM_CONFIGS["cn"]


def detect_realm_from_domain(domain):
    d = str(domain or "").lower()
    if "qoder.sh" in d or (d.endswith("qoder.com") and "qoder.com.cn" not in d) \
            or "qoder.com/" in d:
        return "intl"
    return "cn"


def normalize_epoch(value):
    if isinstance(value, bool):
        return 0
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    if not math.isfinite(number) or number <= 0:
        return 0
    if number > 1e11:      # 毫秒
        number /= 1000.0
    return int(number)


# ---------------------------------------------------------------------------
# 带重试的 HTTP JSON 工具
# ---------------------------------------------------------------------------
# 198.18.0.0/15 (RFC 2544 benchmarking) 与 fdfe:dcba:9876::/48 被 Clash/mihomo
# 等本地代理用作 fake-IP DNS 段：开启透明代理的机器上所有公网域名都会解析到
# 这些网段。命中它说明 DNS 已被本机代理接管、真实 IP 不可见，此时跳过解析级
# 校验（名称级校验已完成）。
_FAKEIP_NETS = [
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("2001:2::/48"),
    ipaddress.ip_network("fdfe:dcba:9876::/48"),
]


def _host_boundary_violation(ip, allow_local):
    """True when the resolved/IP address must be refused."""
    if ip.is_loopback:
        return not allow_local
    if (ip.is_private or ip.is_reserved or ip.is_link_local
            or ip.is_multicast or ip.is_unspecified):
        return True
    return False


def validate_public_http_url(url, allow_local=False):
    """SSRF 防护：仅允许 http/https，且 host 不得指向本机/私有/保留网段。

    上游网关与 openapi 域名均为公网地址；任何指向 localhost、回环、内网或
    保留地址的 URL 一律拒绝，防止上游配置或导入数据把请求引向内网。
    allow_local 仅供显式面向本机网关的开发/验证脚本开启（如 _verify_models.py），
    服务端请求路径一律使用默认 False。
    """
    parsed = urllib.parse.urlsplit(str(url or ""))
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs are allowed")
    host = (parsed.hostname or "").strip().strip("[]").lower()
    if not host:
        raise ValueError("URL host is required")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        if not allow_local:
            raise ValueError("requests to localhost are not allowed")
        return url
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _host_boundary_violation(literal, allow_local):
            raise ValueError(
                "requests to private/reserved address %s are not allowed" % literal)
        return url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("cannot resolve URL host %r: %s" % (host, exc))
    addrs = []
    for info in infos:
        addr = str(info[4][0]).strip("[]")
        try:
            addrs.append(ipaddress.ip_address(addr))
        except ValueError:
            raise ValueError("URL host resolved to a non-IP address: %r" % addr)
    if addrs and all(any(ip in net for net in _FAKEIP_NETS) for ip in addrs):
        return url  # fake-IP DNS：真实 IP 不可见，名称级校验已通过
    for ip in addrs:
        if _host_boundary_violation(ip, allow_local):
            raise ValueError(
                "requests to private/reserved address %s are not allowed" % ip)
    return url


def _retryable(exc):
    """Transient network faults worth another attempt (TLS resets, timeouts, 5xx)."""
    if isinstance(exc, ssl.SSLError):
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    if isinstance(exc, urllib.error.URLError):
        return True
    if isinstance(exc, (TimeoutError, ConnectionResetError, ConnectionAbortedError, OSError)):
        return True
    return False


def http_json(url, data=None, method=None, headers=None, timeout=30,
              retries=3, backoff=1.0, log=None):
    """urlopen + json decode with retries. 所有 openapi 调用统一走这里。"""
    validate_public_http_url(url)
    attempts = max(1, int(retries or 1))
    last = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            last = exc
            if attempt >= attempts or not _retryable(exc):
                break
            if log:
                log("network retry %d/%d after %s" % (attempt, attempts, exc))
            time.sleep(backoff * attempt)
    raise last


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
class Account(object):
    def __init__(self, data, path=None):
        data = data or {}
        self.path = path
        self.uid = str(data.get("uid") or "")
        self.nickname = str(data.get("nickname") or "")
        self.domain = str(data.get("domain") or "")
        self.realm = str(data.get("realm") or detect_realm_from_domain(self.domain))
        if self.realm not in REALM_CONFIGS:
            self.realm = "cn"
        if not self.domain:
            self.domain = get_realm_config(self.realm)["domain"]
        self.platform = str(data.get("platform") or "CLI")
        self.access_token = str(data.get("accessToken") or "")
        self.refresh_token = str(data.get("refreshToken") or "")
        self.personal_token = str(data.get("personalToken") or "")
        self.expires_at = normalize_epoch(data.get("expiresAt"))
        self.added_at = data.get("addedAt") or time.time()
        self.source = str(data.get("source") or "oauth")
        self.enabled = data.get("enabled", True)
        self.last_error = str(data.get("lastError") or "")
        self.cooldown_until = float(data.get("cooldownUntil") or 0)
        # 按模型粒度的限流冷却：上游频控只针对单模型，不能拖垮整个账号。
        self.model_cooldowns = {}
        self.credits = data.get("credits") or None
        self.plan = str(data.get("plan") or "")
        self.last_checkin = data.get("lastCheckin") or None
        self.user_type = str(data.get("userType") or "") or DEFAULT_USER_TYPE
        self.organization_id = str(data.get("organizationId") or "")
        self.organization_name = str(data.get("organizationName") or "")
        self._save_lock = threading.RLock()
        self._refresh_lock = threading.RLock()
        self._health_lock = threading.RLock()
        self._retired = False
        self._pool = None
        self._error_version = 0
        self.last_error_kind = ""

    # -- 持久化 ------------------------------------------------------------
    def to_dict(self):
        return {
            "uid": self.uid,
            "nickname": self.nickname,
            "domain": self.domain,
            "realm": self.realm,
            "platform": self.platform,
            "accessToken": self.access_token,
            "refreshToken": self.refresh_token,
            "personalToken": self.personal_token,
            "expiresAt": self.expires_at,
            "addedAt": self.added_at,
            "source": self.source,
            "enabled": self.enabled,
            "lastError": self.last_error,
            "cooldownUntil": self.cooldown_until,
            "credits": self.credits,
            "plan": self.plan,
            "lastCheckin": self.last_checkin,
            "userType": self.user_type,
            "organizationId": self.organization_id,
            "organizationName": self.organization_name,
        }

    def public(self):
        exp = self.expires_at
        result = {
            "uid": self.uid,
            "nickname": self.nickname or (self.uid[:8] if self.uid else "?"),
            "domain": self.domain,
            "realm": self.realm,
            "platform": self.platform,
            "enabled": bool(self.enabled),
            "source": self.source,
            "tokenFamily": token_family(self),
            "expiresAt": exp,
            "expiresIn": _human_delta(exp - time.time()) if exp else None,
            "hasRefreshToken": bool(self.refresh_token),
            "hasPAT": bool(self.personal_token),
            "lastError": self.last_error,
            "inCooldown": self.cooldown_until > time.time(),
            "cooldownFor": round(max(0.0, self.cooldown_until - time.time())) or None,
            "addedAt": self.added_at,
            "file": os.path.basename(self.path) if self.path else None,
            "credits": self.credits,
            "plan": self.plan,
            "lastCheckin": self.last_checkin,
            "canCheckin": bool(get_realm_config(self.realm)["has_checkin"]),
            "userType": self.user_type,
            "machineId": derive_id(self.uid, "machine"),
            "sessionId": derive_id(self.uid, "session"),
        }
        result.update(self._pool.health(self) if self._pool else {
            "inFlight": 0, "maxInflight": 0, "queueWaiting": 0,
            "modelCooldowns": dict(self.model_cooldowns),
            "lastErrorKind": self.last_error_kind,
        })
        return result

    def save(self, directory):
        with self._save_lock:
            if self._retired:
                return self.path
            return self._save(directory)

    def _save(self, directory):
        base = Path(directory).resolve()
        base.mkdir(parents=True, exist_ok=True)
        safe_uid = re.sub(r"[^A-Za-z0-9_-]", "_", str(self.uid or "")).strip("_ ")
        name = (safe_uid or uuid.uuid4().hex) + ".json"
        path = base / name
        if self.path and Path(self.path).parent.resolve() == base:
            path = Path(self.path)
        tmp = base / (path.name + "." + uuid.uuid4().hex + ".tmp")
        if not (path.is_relative_to(base) and tmp.is_relative_to(base)):
            raise ValueError("invalid path for account save")
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, path)
        self.path = str(path)
        return self.path

    def delete(self):
        with self._save_lock:
            self._retired = True
            if self.path and os.path.exists(self.path):
                os.remove(self.path)

    # -- 健康与冷却 --------------------------------------------------------
    def ready(self, model=None):
        model = _model_key(model, self.realm)
        if not self.enabled or not self.access_token:
            return False
        if self.cooldown_until > time.time():
            return False
        if model and self.model_cooldowns.get(model, 0.0) > time.time():
            return False
        exp = self.expires_at
        if not exp:
            return True
        remaining = exp - time.time()
        if remaining > 240:          # 剩余 >4 分钟直接用（jt- 24h / dt- 30d）
            return True
        if remaining > 0:
            self.refresh_if_needed()
            return True
        return self.refresh_if_needed()

    def refresh_if_needed(self):
        with self._refresh_lock:
            if not self.expires_at or self.expires_at - time.time() > 240:
                return True
            return self.refresh()

    def note_error(self, message, cooldown=60, single_account=False, model=None, until=None, kind=None):
        model = _model_key(model, self.realm)
        with self._health_lock:
            self._error_version += 1
            self.last_error = str(message)[:200]
            self.last_error_kind = str(kind or "")
            if model:
                wait = max(1.0, float(until) - time.time()) if until else (
                    3.0 if single_account else float(cooldown))
                self.model_cooldowns[model] = max(self.model_cooldowns.get(model, 0), time.time() + wait)
            else:
                self.cooldown_until = max(self.cooldown_until, time.time() + (3 if single_account else cooldown))
        if self._pool:
            self._pool.save_state()
        if self.path:
            self.save(os.path.dirname(self.path))

    def throttle_wait(self, model=None):
        """Seconds until this account can serve `model` again (0 = right now)."""
        model = _model_key(model, self.realm)
        if not self.enabled or not self.access_token:
            return 0.0
        now = time.time()
        wait = max(0.0, self.cooldown_until - now)
        if model:
            wait = max(wait, max(0.0, self.model_cooldowns.get(model, 0.0) - now))
        return wait

    def clear_error(self, model=None, force=False, version=None):
        with self._health_lock:
            now = time.time()
            if version is not None and version != self._error_version:
                return
            before = (dict(self.model_cooldowns), self.cooldown_until, self.last_error, self.last_error_kind)
            self.model_cooldowns = {k: v for k, v in self.model_cooldowns.items()
                                    if not force and v > now}
            if force or self.cooldown_until <= now:
                self.cooldown_until = 0
            if not self.cooldown_until and not self.model_cooldowns:
                self.last_error = ""
                self.last_error_kind = ""
            changed = before != (self.model_cooldowns, self.cooldown_until, self.last_error, self.last_error_kind)
        if changed and self._pool:
            self._pool.save_state()

    # -- 出站头 ------------------------------------------------------------
    def headers(self, purpose="openapi"):
        cfg = get_realm_config(self.realm)
        return {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": CLIENT_UA,
            "Authorization": "Bearer " + self.access_token,
            "X-Request-ID": generate_request_id(self.uid),
            "X-Machine-ID": derive_id(self.uid, "machine"),
            "X-Session-ID": derive_id(self.uid, "session"),
            "Origin": cfg["website"],
            "Referer": cfg["website"] + "/",
        }

    # -- 刷新（按 token 前缀路由） ----------------------------------------
    def refresh(self):
        with self._refresh_lock:
            return self._refresh()

    def _refresh(self):
        """刷新 access token。drt- 走 deviceToken，jrt-/PAT 走 jobToken。

        PAT 永不覆盖活跃的 OAuth 会话，只做 jrt- 过期后的最终兜底。
        """
        cfg = get_realm_config(self.realm)
        base = cfg["openapi"]
        # 1) OAuth 设备族
        if self.refresh_token.startswith("drt-"):
            return self._post_token(base + PATH_DEVICE_REFRESH,
                                    {"refresh_token": self.refresh_token}, kind="device")
        # 2) jobToken 族：jrt- 优先，失败回落 PAT 重新交换
        if self.refresh_token:
            if self._post_token(base + PATH_JOB_REFRESH,
                                {"refresh_token": self.refresh_token}, kind="job"):
                return True
        if self.personal_token:
            if self._post_token(base + PATH_JOB_EXCHANGE,
                                {"personal_token": self.personal_token}, kind="job"):
                return True
        if not self.refresh_token and not self.personal_token:
            self.last_error = "no refresh token; sign in again"
        return False

    def _post_token(self, url, payload, kind):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": CLIENT_UA,
        }
        try:
            data = http_json(url, data=json.dumps(payload).encode(), method="POST",
                             headers=headers, timeout=30)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            self.last_error = "refresh failed: HTTP %d %s" % (exc.code, body[:160])
            if exc.code in (401, 403) and session_dead(body):
                self.enabled = False
                self.last_error = "session dead (TOKEN_EXPIRE): re-login required"
            return False
        except Exception as exc:
            self.last_error = "refresh failed: %s" % exc
            return False

        if kind == "device":
            token = data.get("token") or data.get("device_token") or ""
            refresh = data.get("refresh_token") or self.refresh_token
            exp = _device_expiry(data)
        else:
            token = data.get("token") or ""
            refresh = data.get("refresh_token") or self.refresh_token
            if data.get("expires_in"):
                exp = int(time.time() + int(data["expires_in"]) / 1000)
            else:
                exp = self.expires_at
        if not token:
            self.last_error = "refresh returned no token"
            return False
        self.access_token = token
        self.refresh_token = refresh
        self.expires_at = exp or self.expires_at
        self.clear_error()
        if self.path and os.path.exists(os.path.dirname(self.path)):
            self.save(os.path.dirname(self.path))
        try:
            from qoder_sign import SESSIONS
            SESSIONS.invalidate(self.uid)   # 旧 COSY 会话携带旧 token，必须重建
        except Exception:
            pass
        return True

    # -- 签到 / 额度 / 套餐 ------------------------------------------------
    def can_checkin(self):
        if not get_realm_config(self.realm)["has_checkin"]:
            return False
        if not self.last_checkin:
            return True
        today_str = time.strftime("%Y-%m-%d")
        return not str(self.last_checkin).startswith(today_str)

    def checkin_status(self):
        """GET daily-check-in/status -> (ok, summary|error)。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_CHECKIN_STATUS
        try:
            q = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=2)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return False, "HTTP %d %s" % (exc.code, body[:160])
        except Exception as exc:
            return False, str(exc)
        last = ""
        if q.get("lastClaimedAt"):
            try:
                last = time.strftime("%Y-%m-%d",
                                     time.localtime(int(q["lastClaimedAt"])))
            except Exception:
                last = ""
        today = time.strftime("%Y-%m-%d")
        status = str(q.get("status") or "")
        return True, {
            "status": status,
            "active": status in ("CLAIMABLE", "CLAIMED"),
            "today_checked_in": status == "CLAIMED" and last == today,
            "streak_days": int(q.get("currentStreakDays") or 0),
            "total_claim_days": int(q.get("totalClaimDays") or 0),
            "reward_credits": int(q.get("rewardCredits") or 0),
            "total_reward_credits": int(q.get("totalRewardCredits") or 0),
            "next_claim_at": int(q.get("nextClaimAt") or 0),
            "last_claimed_at": int(q.get("lastClaimedAt") or 0),
            "reward_expires_at": int(q.get("rewardExpiresAt") or 0),
        }

    def checkin(self):
        """每日签到：先查状态，未签则领取。返回 {ok, msg, ...}。"""
        if not get_realm_config(self.realm)["has_checkin"]:
            return {"ok": False, "error": "checkin is not available for this realm"}
        ok, st = self.checkin_status()
        if not ok:
            return {"ok": False, "error": st}
        if st["today_checked_in"]:
            return {"ok": True, "already": True, "msg": "今日已签到",
                    "streak_days": st["streak_days"], "reward_credits": st["reward_credits"]}
        if not st["active"]:
            # CLAIMABLE / CLAIMED 之外的状态（如 DISABLED：活动批次下线），
            # 不发起无意义的 claim，按"活动未开放"成功跳过。
            return {"ok": True, "disabled": True, "status": st.get("status"),
                    "msg": "官方签到活动未开放 (status=%s)" % (st.get("status") or "?")}
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_CHECKIN_CLAIM
        try:
            res = http_json(url, data=b"{}", method="POST",
                            headers=self.headers(), timeout=15, retries=1)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            # 上游并发/重复领取返回 409 ALREADY_CLAIMED —— 归一化为“已签”
            if "ALREADY_CLAIMED" in body:
                self._stamp_checkin()
                return {"ok": True, "already": True, "msg": "今日已签到"}
            return {"ok": False, "error": "HTTP %d %s" % (exc.code, body[:160])}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        if str(res.get("result") or "") == "ALREADY_CLAIMED" or res.get("success") is False and "ALREADY" in str(res.get("error") or ""):
            self._stamp_checkin()
            return {"ok": True, "already": True, "msg": "今日已签到"}
        if res.get("success") is False:
            # 复查一次：上游可能已记账
            ok2, st2 = self.checkin_status()
            if ok2 and st2["today_checked_in"]:
                self._stamp_checkin()
                return {"ok": True, "already": True, "msg": "今日已签到（复查确认）"}
            return {"ok": False, "error": str(res.get("error") or res)[:160]}
        reward = int(res.get("rewardCredits") or 0)
        self._stamp_checkin()
        return {"ok": True, "msg": "签到成功 +%d 积分" % reward,
                "reward_credits": reward}

    def _stamp_checkin(self):
        self.last_checkin = time.strftime("%Y-%m-%d %H:%M:%S")
        if self.path and os.path.exists(os.path.dirname(self.path)):
            self.save(os.path.dirname(self.path))

    def fetch_credits(self):
        """GET /api/v2/quota/usage -> 聚合基础额度 + 赠送/签到额度。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_QUOTA
        try:
            q = http_json(url, method="GET", headers=self.headers(), timeout=30)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        uq = q.get("userQuota") or {}
        aq = q.get("addOnQuota") or {}

        def _num(d, k):
            try:
                return float(d.get(k) or 0)
            except Exception:
                return 0.0

        remain = int(_num(uq, "remaining") + _num(aq, "remaining"))
        used = int(_num(uq, "used") + _num(aq, "used"))
        size = int(_num(uq, "total") + _num(aq, "total"))
        self.credits = {
            "remain": remain,
            "used": used,
            "size": size,
            "exceeded": bool(q.get("isQuotaExceeded")),
            "usage_pct": q.get("totalUsagePercentage"),
            "expires_at": normalize_epoch(q.get("expiresAt")),
            "packages": [
                {"name": "基础额度", "remain": int(_num(uq, "remaining")),
                 "used": int(_num(uq, "used")), "size": int(_num(uq, "total"))},
                {"name": "赠送/签到额度", "remain": int(_num(aq, "remaining")),
                 "used": int(_num(aq, "used")), "size": int(_num(aq, "total"))},
            ],
            "updated_at": time.time(),
            "updated_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if self.path and os.path.exists(os.path.dirname(self.path)):
            self.save(os.path.dirname(self.path))
        return {"ok": True, "credits": self.credits}

    def fetch_plan(self):
        """GET /api/v2/user/plan -> 套餐名（Pro Trial 等）。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PLAN
        try:
            p = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=1)
        except Exception:
            return self.plan
        name = str(p.get("plan_tier_name") or p.get("user_type") or "")
        if name and name != self.plan:
            self.plan = name
            if self.path and os.path.exists(os.path.dirname(self.path)):
                self.save(os.path.dirname(self.path))
        return name

    # -- Pro 升级包（一次性 +1800） ---------------------------------------
    def pro_eligibility(self):
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PRO_ELIGIBILITY
        try:
            m = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=1)
            return True, bool(m.get("eligible"))
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 403, 410):
                # 端点不存在 / 活动已下线：查询成功，只是不可领取
                return True, False
            return False, "HTTP %d" % exc.code
        except Exception as exc:
            return False, str(exc)

    def pro_claim(self):
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PRO_CLAIM
        try:
            m = http_json(url, data=b"{}", method="POST", headers=self.headers(),
                          timeout=15, retries=1)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            if exc.code == 409 or "ALREADY" in body:
                return {"ok": True, "already": True, "msg": "Pro 升级包已领取过"}
            return {"ok": False, "error": "HTTP %d %s" % (exc.code, body[:160])}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        if m.get("success") is False:
            return {"ok": False, "error": str(m.get("message") or m)[:160]}
        return {"ok": True, "msg": "Pro 升级包领取成功", "data": m}


def token_family(acc):
    """返回账号当前的凭证族：device(OAuth) / job(PAT交换) / pat。"""
    rt = acc.refresh_token or ""
    if rt.startswith("drt-"):
        return "device"
    if rt.startswith("jrt-"):
        return "job"
    if (acc.access_token or "").startswith("pt-"):
        return "pat"
    return "unknown"


def _device_expiry(data):
    """deviceToken 响应的过期时间：expires_in(ms) / expires_at(RFC3339)，默认 30 天。"""
    if data.get("expires_in"):
        return int(time.time() + int(data["expires_in"]) / 1000)
    if data.get("expires_at"):
        try:
            import datetime
            dt = datetime.datetime.strptime(str(data["expires_at"])[:19],
                                             "%Y-%m-%dT%H:%M:%S")
            return int(dt.timestamp())
        except Exception:
            pass
    return int(time.time()) + 30 * 86400


def _human_delta(seconds):
    if seconds is None:
        return None
    if seconds <= 0:
        return "expired"
    days = seconds / 86400.0
    if days >= 1:
        return "%.0f days" % days
    hours = seconds / 3600.0
    if hours >= 1:
        return "%.1f hours" % hours
    return "%d min" % int(seconds / 60)


# ---------------------------------------------------------------------------
# 会话亲和（同一对话固定同一账号，上游按账号缓存 prompt prefix）
# ---------------------------------------------------------------------------
class SessionAffinity(object):
    def __init__(self, ttl=7200, max_entries=5000):
        self.ttl = ttl
        self.max_entries = max_entries
        self.bindings = {}
        self._lock = threading.Lock()

    def get(self, key):
        if not key:
            return None
        with self._lock:
            entry = self.bindings.get(key)
            if not entry:
                return None
            uid, exp = entry
            if time.time() > exp:
                self.bindings.pop(key, None)
                return None
            self.bindings[key] = (uid, time.time() + self.ttl)
            return uid

    def bind(self, key, uid):
        if not key or not uid:
            return
        with self._lock:
            if len(self.bindings) >= self.max_entries:
                now = time.time()
                self.bindings = {k: v for k, v in self.bindings.items() if v[1] > now}
            self.bindings[key] = (uid, time.time() + self.ttl)

    def unbind(self, key):
        if not key:
            return
        with self._lock:
            self.bindings.pop(key, None)


# ---------------------------------------------------------------------------
# AccountPool
# ---------------------------------------------------------------------------
_ACTIVE_POOL = None


def add_to_pool(account):
    """把导入的账号写入活动账号池（AccountPool 构造时自注册）。"""
    if _ACTIVE_POOL is None:
        raise RuntimeError("account pool not initialised")
    return _ACTIVE_POOL.add(account)


class PoolBusy(RuntimeError):
    """合格账号的并发容量已用尽。"""


class AccountLease:
    def __init__(self, pool, account):
        self._pool = pool
        self.account = account
        self._lease_id = uuid.uuid4().hex
        self.acquired_at = time.time()
        self.phase = "active"
        self.error_version = account._error_version

    @property
    def lease_id(self):
        return self._lease_id

    def release(self):
        with self._pool._lock:
            self._pool._leases.pop(self.lease_id, None)
            self.phase = "released"

    def set_queue_waiting(self, waiting):
        with self._pool._lock:
            if self.lease_id in self._pool._leases:
                self.phase = "queue" if waiting else "active"

    def mark_success(self):
        self.account.clear_error(version=self.error_version)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.release()


class AccountPool(object):
    def __init__(self, directory, log=None):
        global _ACTIVE_POOL
        self.dir = directory
        self.log = log or (lambda msg: None)
        self.accounts = []
        self.logins = {}
        self._lock = threading.RLock()
        self._cursor = 0
        self._leases = {}
        self._max_inflight = 0
        self._state_lock = threading.RLock()
        self.affinity = SessionAffinity()
        _ACTIVE_POOL = self

    def load(self):
        with self._lock:
            self.accounts = []
            if not os.path.isdir(self.dir):
                return self.accounts
            for name in sorted(os.listdir(self.dir)):
                if not name.endswith(".json"):
                    continue
                if name in ("settings.json", "active_realm.json"):
                    continue
                path = os.path.join(self.dir, name)
                try:
                    with open(path, encoding="utf-8") as fh:
                        account = Account(json.load(fh), path)
                except Exception as exc:
                    self.log("account %s unreadable: %s" % (name, exc))
                    continue
                if account.uid:
                    account._pool = self
                    self.accounts.append(account)
            self._load_state()
            return self.accounts

    def _load_state(self):
        try:
            with open(os.path.join(self.dir, ".runtime", "pool-state.json"), encoding="utf-8") as fh:
                state = json.load(fh)
            if state.get("version") != 1:
                return
            rows = state.get("accounts", [])
            current = {(a.realm, a.uid): a for a in self.accounts}
            for row in rows:
                account = current.get((row.get("realm"), row.get("uid")))
                if account is None:
                    continue
                cooldowns = row.get("modelCooldowns", {})
                if not isinstance(cooldowns, dict):
                    continue
                for model, expiry in cooldowns.items():
                    if isinstance(expiry, (float, int)) and not isinstance(expiry, bool) and math.isfinite(expiry) and expiry > time.time():
                        key = _model_key(model, account.realm)
                        account.model_cooldowns[key] = max(account.model_cooldowns.get(key, 0), expiry)
                account.last_error_kind = str(row.get("lastErrorKind") or "")[:80]
        except FileNotFoundError:
            pass
        except (ValueError, TypeError, AttributeError, OSError) as exc:
            self.log("pool state unreadable: %s" % exc)

    def save_state(self):
        try:
            self._save_state()
        except OSError as exc:
            self.log("pool state save failed: %s" % exc)

    def _save_state(self):
        # 写锁内取得最新对象状态，避免较早快照晚落盘。
        with self._state_lock:
            snapshot = tuple(self.accounts)
            rows = []
            for account in snapshot:
                if account._retired:
                    continue
                with account._health_lock:
                    cooldowns = {k: v for k, v in account.model_cooldowns.items() if v > time.time()}
                    if cooldowns or account.last_error_kind:
                        rows.append({"realm": account.realm, "uid": account.uid,
                                     "modelCooldowns": cooldowns, "lastErrorKind": account.last_error_kind})
            base = Path(self.dir) / ".runtime"
            base.mkdir(parents=True, exist_ok=True)
            path = base / "pool-state.json"
            tmp = base / (uuid.uuid4().hex + ".tmp")
            tmp.write_text(json.dumps({"version": 1, "accounts": rows}, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)

    def health(self, account):
        with self._lock:
            leases = [lease for lease in self._leases.values()
                      if (lease.account.realm, lease.account.uid) == (account.realm, account.uid)]
            with account._health_lock:
                cooldowns = {k: v for k, v in account.model_cooldowns.items() if v > time.time()}
            return {"inFlight": len(leases), "maxInflight": self._max_inflight,
                    "queueWaiting": sum(lease.phase == "queue" for lease in leases),
                    "modelCooldowns": cooldowns,
                    "lastErrorKind": account.last_error_kind}

    def acquire(self, realm=None, model=None, session_key=None, exclude=None, max_inflight=0):
        excluded = set(exclude or ())
        model_keys = {r: _model_key(model, r) for r in REALM_CONFIGS}
        busy = False
        while True:
            lease = None
            with self._lock:
                self._max_inflight = max_inflight
                snapshot = [a for a in self.accounts if (not realm or a.realm == realm) and a.uid not in excluded]
                if snapshot:
                    start = self._cursor % len(snapshot)
                    candidates = snapshot[start:] + snapshot[:start]
                    bound = self.affinity.get(session_key) if session_key else None
                    candidates.sort(key=lambda a: a.uid != bound)
                    for account in candidates:
                        key = model_keys[account.realm]
                        if not self._eligible(account, key):
                            continue
                        count = sum((l.account.realm, l.account.uid) == (account.realm, account.uid)
                                    for l in self._leases.values())
                        if max_inflight and count >= max_inflight:
                            busy = True
                            continue
                        account._pool = self
                        lease = AccountLease(self, account)
                        self._leases[lease.lease_id] = lease
                        self._cursor += 1
                        break
            if lease is None:
                if busy:
                    raise PoolBusy("account_pool_busy")
                return None
            account = lease.account
            try:
                refreshed = account.refresh_if_needed()
                with self._lock:
                    valid = (refreshed and account in self.accounts and
                             self._eligible(account, model_keys[account.realm]))
                    if valid:
                        if session_key:
                            self.affinity.bind(session_key, account.uid)
                        return lease
            except Exception:
                lease.release()
                raise
            lease.release()
            excluded.add(account.uid)

    @staticmethod
    def _eligible(account, model):
        now = time.time()
        return (not account._retired and account.enabled and bool(account.access_token)
                and account.cooldown_until <= now and account.model_cooldowns.get(model, 0) <= now)

    def list_public(self, realm=None):
        with self._lock:
            accs = self.accounts if (not realm or realm == "all") else \
                [a for a in self.accounts if a.realm == realm]
            return [a.public() for a in accs]

    def get(self, uid):
        with self._lock:
            for account in self.accounts:
                if account.uid == uid:
                    return account
        return None

    def add(self, account):
        with self._lock:
            if any(a.uid == account.uid and a.realm != account.realm for a in self.accounts):
                raise ValueError("account uid belongs to a different realm")
            existing = next((a for a in self.accounts if (a.realm, a.uid) == (account.realm, account.uid)), None)
            # 持有旧对象写锁直到持久化及对象交换结束，阻止刷新晚写覆盖新凭证。
            with existing._save_lock if existing is not None else account._save_lock:
                if existing is not None:
                    account.added_at = existing.added_at
                    account.path = existing.path
                    if not account.credits and existing.credits:
                        account.credits = existing.credits
                    if not account.plan and existing.plan:
                        account.plan = existing.plan
                    if not account.last_checkin and existing.last_checkin:
                        account.last_checkin = existing.last_checkin
                    if not account.personal_token and existing.personal_token:
                        account.personal_token = existing.personal_token
                    with existing._health_lock:
                        account.model_cooldowns = dict(existing.model_cooldowns)
                        account.last_error_kind = existing.last_error_kind
                        account._error_version = existing._error_version
                account.save(self.dir)
                if existing is not None:
                    if existing is not account:
                        existing._retired = True
                    self.accounts[self.accounts.index(existing)] = account
                else:
                    self.accounts.append(account)
                account._pool = self
            return account

    def remove(self, uid):
        with self._lock:
            account = self.get(uid)
            if account is None:
                return False
            account.delete()
            self.accounts.remove(account)
            return True

    # -- 选择与健康 --------------------------------------------------------
    def count_ready(self, realm=None, model=None):
        with self._lock:
            snapshot = [a for a in self.accounts if not realm or a.realm == realm]
        return sum(1 for a in snapshot if a.enabled and a.access_token and
                   a.ready(model=model))

    def pick_for_session(self, realm=None, session_key=None, exclude=None, model=None):
        exclude = exclude or set()
        if session_key:
            bound_uid = self.affinity.get(session_key)
            if bound_uid and bound_uid not in exclude:
                account = self.get(bound_uid)
                if account and account.realm == realm and account.ready(model=model):
                    return account
                self.affinity.unbind(session_key)
        account = self.pick(realm=realm, exclude=exclude, model=model)
        if account and session_key:
            self.affinity.bind(session_key, account.uid)
        return account

    def pick(self, realm=None, exclude=None, model=None):
        exclude = exclude or set()
        with self._lock:
            snapshot = [a for a in self.accounts if not realm or a.realm == realm]
            start = self._cursor
        total = len(snapshot)
        if total == 0:
            return None
        for offset in range(total):
            index = (start + offset) % total
            account = snapshot[index]
            if account.uid in exclude:
                continue
            if account.ready(model=model):
                with self._lock:
                    self._cursor = (index + 1) % total
                return account
        return None

    def representative(self, realm=None):
        with self._lock:
            candidates = [a for a in self.accounts if not realm or a.realm == realm]
            for account in candidates:
                if account.access_token:
                    return account
            return candidates[0] if candidates else None

    def set_enabled(self, uid, enabled):
        account = self.get(uid)
        if account is None:
            return None
        account.enabled = bool(enabled)
        if enabled:
            account.clear_error(force=True)
        account.save(self.dir)
        return account.public()

    def set_all_enabled(self, enabled, realm=None):
        with self._lock:
            for account in self.accounts:
                if realm and account.realm != realm:
                    continue
                account.enabled = bool(enabled)
                if enabled:
                    account.clear_error(force=True)
                account.save(self.dir)

    # -- 导入 / 导出 -------------------------------------------------------
    def preview_import_rows(self, rows, realm=None, overwrite=False):
        """报告 import_rows() 会做什么，不触碰账号池（Dry-Run）。"""
        return self._import_rows(rows, realm, overwrite, commit=False)

    def import_rows(self, rows, realm=None, overwrite=False):
        """逐行导入，返回四类结果及非阻断 warnings；覆盖前保存原文件。"""
        return self._import_rows(rows, realm, overwrite, commit=True)

    def _import_rows(self, rows, realm, overwrite, commit):
        report = {key: [] for key in ("added", "updated", "skipped", "invalid", "warnings")}
        seen = set()
        for index, row in enumerate(rows):
            try:
                kwargs = normalise_import_row(row, realm=realm)
            except (ValueError, TypeError) as exc:
                report["invalid"].append({"index": index + 1, "reason": str(exc)})
                continue
            uid = kwargs["uid"]
            if uid in seen:
                report["skipped"].append({"uid": uid, "reason": "duplicate inside the document"})
                continue
            seen.add(uid)
            with self._lock:
                existing = self.get(uid)
                if existing and existing.realm != kwargs["realm"]:
                    report["invalid"].append({"index": index + 1, "reason": "account uid belongs to a different realm"})
                    continue
                if existing and not overwrite:
                    report["skipped"].append({"uid": uid, "reason": "already exists"})
                    continue
                if commit:
                    try:
                        if existing and existing.path:
                            with existing._save_lock:
                                backup_dir = Path(self.dir) / ".runtime" / "import-backups"
                                backup_dir.mkdir(parents=True, exist_ok=True)
                                backup = backup_dir / (uuid.uuid4().hex + ".json")
                                backup.write_bytes(Path(existing.path).read_bytes())
                        self.add(Account(kwargs))
                    except Exception:
                        report["invalid"].append({"index": index + 1, "reason": "account backup or save failed"})
                        continue
                report["updated" if existing else "added"].append(uid)
                if "auth_user_info_raw" in row and kwargs["expiresAt"] <= time.time():
                    report["warnings"].append({"index": index + 1, "uid": uid, "reason": "首次使用需刷新"})
        return report

    # -- OAuth 设备授权登录 ------------------------------------------------
    @staticmethod
    def _local_machine_id(realm):
        """读取本机官方客户端的 machine_id（优先，保持设备一致），缺则生成。"""
        cfg = get_realm_config(realm)
        home = os.path.join(os.path.expanduser("~"), cfg["home_dir"], ".auth")
        p = os.path.join(home, "machine_id")
        try:
            with open(p, encoding="utf-8") as fh:
                mid = fh.read().strip()
            if mid:
                return mid
        except Exception:
            pass
        return str(uuid.uuid4())

    def start_login(self, realm="cn", platform="CLI"):
        """构造 PKCE 设备授权 URL（浏览器打开完成授权）。

        双区 URL 参数差异（官方逆向）：
          CN   : challenge, challenge_method, nonce(带横线), redirect_uri,
                 client_id, machine_id
          Intl : challenge, challenge_method, nonce(32-hex), client_id,
                 machine_id（新协议带 client_id/machine_id、不带 redirect_uri）
        """
        cfg = get_realm_config(realm)
        verifier, challenge = _make_pkce()
        nonce = uuid.uuid4().hex if not cfg["nonce_dashed"] else str(uuid.uuid4())
        q = {
            "challenge": challenge,
            "challenge_method": "S256",
            "nonce": nonce,
        }
        if cfg.get("send_redirect_uri"):
            q["redirect_uri"] = cfg["redirect_uri"]
        if cfg.get("send_client_id"):
            q["client_id"] = cfg["client_id"]
            q["machine_id"] = self._local_machine_id(realm)
        auth_url = cfg["website"] + "/device/selectAccounts?" + urllib.parse.urlencode(q)
        state = "qd-%d" % time.time_ns()
        with self._lock:
            self.logins[state] = {
                "created": time.time(),
                "verifier": verifier,
                "nonce": nonce,
                "region": realm,
                "platform": platform,
            }
        return {"state": state, "authUrl": auth_url, "realm": realm,
                "platform": platform}

    def poll_login(self, state):
        state = str(state or "").strip()
        with self._lock:
            info = self.logins.get(state)
        if not info:
            return {"status": "unknown",
                    "message": "state not recognised - start the login again"}
        if time.time() - info["created"] > LOGIN_TTL_SECONDS:
            with self._lock:
                self.logins.pop(state, None)
            return {"status": "expired", "message": "login window expired - start again"}
        realm = info.get("region") or "cn"
        cfg = get_realm_config(realm)
        q = urllib.parse.urlencode({
            "nonce": info["nonce"],
            "verifier": info["verifier"],
            "challenge_method": "S256",
        })
        url = cfg["openapi"] + PATH_DEVICE_POLL + "?" + q
        validate_public_http_url(url)
        req = urllib.request.Request(url, method="GET", headers={
            "Accept": "application/json",
            "User-Agent": "QoderWork",
        })
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                status = resp.status
        except urllib.error.HTTPError as exc:
            # 404 / 202 = 用户尚未完成授权（继续轮询）
            if exc.code in (404, 202):
                return {"status": "pending",
                        "message": "等待浏览器完成 Qoder 设备授权"}
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            return {"status": "error", "message": "poll http %d %s" % (exc.code, body[:160])}
        except Exception as exc:
            return {"status": "pending", "message": "poll error: %s" % exc}
        if status in (404, 202):
            return {"status": "pending", "message": "等待浏览器完成 Qoder 设备授权"}
        try:
            data = json.loads(raw)
        except Exception:
            return {"status": "pending", "message": "waiting for grant"}
        token = data.get("token") or data.get("device_token") or ""
        if not token:
            return {"status": "pending", "message": "waiting for token"}

        uid = str(data.get("user_id") or "")
        nickname = ""
        # 拉取 userinfo 补全昵称/用户类型（尽力而为，不阻塞入库）
        try:
            ui_url = cfg["openapi"] + PATH_USERINFO
            validate_public_http_url(ui_url)
            req_ui = urllib.request.Request(ui_url, method="GET", headers={
                "Accept": "application/json",
                "User-Agent": CLIENT_UA,
                "Authorization": "Bearer " + token,
            })
            with urllib.request.urlopen(req_ui, timeout=15) as resp_ui:
                ui = json.loads(resp_ui.read().decode("utf-8"))
            uid = str(ui.get("id") or uid)
            nickname = str(ui.get("name") or "")
            user_type = str(ui.get("user_type") or "") or DEFAULT_USER_TYPE
            org_id = str(ui.get("organization_id") or "")
            org_name = str(ui.get("organization_name") or "")
        except Exception:
            user_type, org_id, org_name = DEFAULT_USER_TYPE, "", ""

        account = Account({
            "uid": uid or ("q-" + uuid.uuid4().hex[:24]),
            "nickname": nickname or ("u" + (uid[-8:] if uid else "")),
            "domain": cfg["domain"],
            "realm": realm,
            "platform": info.get("platform") or "CLI",
            "accessToken": token,
            "refreshToken": data.get("refresh_token") or "",
            "expiresAt": _device_expiry(data),
            "source": "oauth",
            "enabled": True,
            "userType": user_type,
            "organizationId": org_id,
            "organizationName": org_name,
        })
        self.add(account)
        with self._lock:
            self.logins.pop(state, None)
        return {"status": "ok", "account": account.public()}

    def cancel_login(self, state):
        with self._lock:
            return self.logins.pop(state, None) is not None

    # -- PAT 导入 ----------------------------------------------------------
    def import_pat(self, pat, realm="cn"):
        """导入 pt- 个人访问令牌：交换 jobToken 并拉取身份后入库。"""
        pat = str(pat or "").strip()
        if not pat.startswith("pt-"):
            raise ValueError("PAT must start with pt-")
        cfg = get_realm_config(realm)
        data = http_json(cfg["openapi"] + PATH_JOB_EXCHANGE,
                         data=json.dumps({"personal_token": pat}).encode(),
                         method="POST",
                         headers={"Content-Type": "application/json",
                                  "Accept": "application/json",
                                  "User-Agent": CLIENT_UA},
                         timeout=30)
        token = data.get("token") or ""
        if not token:
            raise ValueError("jobToken exchange returned no token")
        uid, nickname, user_type, org_id, org_name = "", "", DEFAULT_USER_TYPE, "", ""
        try:
            ui = http_json(cfg["openapi"] + PATH_USERINFO, method="GET",
                           headers={"Accept": "application/json",
                                    "User-Agent": CLIENT_UA,
                                    "Authorization": "Bearer " + token},
                           timeout=15, retries=2)
            uid = str(ui.get("id") or "")
            nickname = str(ui.get("name") or "")
            user_type = str(ui.get("user_type") or "") or DEFAULT_USER_TYPE
            org_id = str(ui.get("organization_id") or "")
            org_name = str(ui.get("organization_name") or "")
        except Exception:
            pass
        if data.get("expires_in"):
            exp = int(time.time() + int(data["expires_in"]) / 1000)
        else:
            exp = int(time.time()) + 24 * 3600
        account = Account({
            "uid": uid or ("p-" + uuid.uuid4().hex[:24]),
            "nickname": nickname or ("u" + (uid[-8:] if uid else uid[:8])),
            "domain": cfg["domain"],
            "realm": realm,
            "platform": "CLI",
            "accessToken": token,
            "refreshToken": data.get("refresh_token") or "",
            "personalToken": pat,
            "expiresAt": exp,
            "source": "pat",
            "enabled": True,
            "userType": user_type,
            "organizationId": org_id,
            "organizationName": org_name,
        })
        self.add(account)
        return account


def _make_pkce():
    """RFC 7636 S256: (verifier, challenge)。"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    raw = os.urandom(64)
    verifier = "".join(alphabet[b % len(alphabet)] for b in raw)
    challenge = __import__("hashlib").sha256(verifier.encode("ascii")).digest()
    import base64 as _b64
    return verifier, _b64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# 本机已登录凭证的只读探测与导入（与 wb 网关的桌面扫描同构，双区都支持）
#
# 两类官方存储：
#   1. 桌面 App（Electron）： %APPDATA%\com.qoder[.cn].app.stable\auth.v1.dat
#      布局 "v10" + AES-256-GCM；密钥在同目录 Local State 的
#      os_crypt.encrypted_key（DPAPI 保护）-> 剥 "DPAPI" 前缀 -> DPAPI 解出。
#      明文 schema: {schemaVersion, token(dt-), refreshToken(drt-), expiresAt,
#                    user:{id,name,email,...}}
#   2. CLI/官方客户端： ~/.qoder[.cn]/.auth/user[.{profile}]
#      AES-128-CBC key=iv=machine_id 前 16 字符，标准 Base64（strict padding）；
#      明文 UserInfo JSON（或明文以 "{" 开头的兼容形态）。
# 扫描全程只读；看板两步确认后才写入网关账号池。
# ---------------------------------------------------------------------------
def _read_chromium_os_crypt_key(app_dir):
    """Local State.os_crypt.encrypted_key -> DPAPI 解出的 32 字节 AES key。"""
    import base64 as _b64
    from qoder_sign import dpapi_unprotect
    p = os.path.join(app_dir, "Local State")
    with open(p, encoding="utf-8") as fh:
        state = json.load(fh)
    ek = (state.get("os_crypt") or {}).get("encrypted_key")
    if not ek:
        raise RuntimeError("Local State has no os_crypt.encrypted_key")
    blob = _b64.b64decode(ek)
    if blob[:5] != b"DPAPI":
        raise RuntimeError("unexpected encrypted_key header %r" % blob[:5])
    return dpapi_unprotect(blob[5:])


def _roaming_app_dir(cfg):
    base = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(base, cfg["app_dir"])


def _load_app_auth(realm):
    """解出桌面 App auth.v1.dat 的明文 dict；失败抛异常。"""
    from qoder_sign import chromium_decrypt_v10
    cfg = get_realm_config(realm)
    app_dir = _roaming_app_dir(cfg)
    key = _read_chromium_os_crypt_key(app_dir)
    with open(os.path.join(app_dir, "auth.v1.dat"), "rb") as fh:
        blob = fh.read()
    plain = chromium_decrypt_v10(blob, key)
    data = json.loads(plain.decode("utf-8"))
    if not isinstance(data, dict) or not data.get("token"):
        raise RuntimeError("auth.v1.dat has unexpected schema")
    return data


def _load_cli_user(realm, path, machine_key):
    """解 CLI 端 ~/.qoder*/.auth/user（AES-128-CBC）或明文兼容形态。"""
    from qoder_sign import aes_cbc_decrypt
    with open(path, encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw.startswith("{"):
        return json.loads(raw)
    key = (machine_key or "")[:16].encode("utf-8")
    if len(key) != 16:
        raise RuntimeError("machine_id shorter than 16 bytes")
    pt = aes_cbc_decrypt(base64.b64decode(raw), key, key)
    return json.loads(pt.decode("utf-8"))


def scan_desktop_credentials():
    """只读探测本机双区已登录凭证。返回候选列表（不含任何明文令牌）。"""
    found = []
    for realm in ("intl", "cn"):
        cfg = get_realm_config(realm)
        # 1) 桌面 App (auth.v1.dat)
        item = {
            "kind": "app",
            "path": os.path.join(_roaming_app_dir(cfg), "auth.v1.dat"),
            "file": "auth.v1.dat",
            "realm": realm,
            "realmName": cfg["name"],
            "domain": cfg["domain"],
            "readable": False,
            "valid": False,
            "uid": "",
            "nickname": "",
            "expiresAt": 0,
            "error": "",
        }
        try:
            data = _load_app_auth(realm)
            user = data.get("user") or {}
            item["readable"] = True
            exp = normalize_epoch(data.get("expiresAt")) or 0
            if not exp and data.get("token"):
                # expiresAt 是 RFC3339 -> normalize_epoch 处理不了，单独解析
                try:
                    import datetime
                    exp = int(datetime.datetime.strptime(
                        str(data["expiresAt"])[:19], "%Y-%m-%dT%H:%M:%S"
                    ).timestamp())
                except Exception:
                    exp = 0
            token_prefix = str(data.get("token") or "")[:3]
            item.update({
                "valid": token_prefix == "dt-" or bool(data.get("refreshToken")),
                "uid": str(user.get("id") or ""),
                "nickname": str(user.get("name") or ""),
                "expiresAt": exp,
                "expiresIn": _human_delta(exp - time.time()) if exp else None,
            })
        except FileNotFoundError:
            item["error"] = "not found (未登录或未安装该版本客户端)"
        except Exception as exc:
            item["error"] = str(exc)
        found.append(item)

        # 2) CLI 端 user / user.{profile}
        auth_dir = os.path.join(os.path.expanduser("~"), cfg["home_dir"], ".auth")
        if os.path.isdir(auth_dir):
            machine_key = ""
            try:
                with open(os.path.join(auth_dir, "machine_id"),
                          encoding="utf-8") as fh:
                    machine_key = fh.read().strip()
            except Exception:
                pass
            try:
                names = [n for n in os.listdir(auth_dir)
                         if n == "user" or n.startswith("user.")]
            except Exception:
                names = []
            for n in names:
                p = os.path.join(auth_dir, n)
                cli_item = {
                    "kind": "cli",
                    "path": p,
                    "file": n,
                    "realm": realm,
                    "realmName": cfg["name"],
                    "domain": cfg["domain"],
                    "readable": False,
                    "valid": False,
                    "uid": "",
                    "nickname": "",
                    "expiresAt": 0,
                    "error": "",
                }
                try:
                    data = _load_cli_user(realm, p, machine_key)
                    token = str(data.get("access_token") or "")
                    cli_item["readable"] = True
                    exp = normalize_epoch(data.get("expire_time"))
                    cli_item.update({
                        "valid": token.startswith(("dt-", "jt-")),
                        "uid": str(data.get("uid") or ""),
                        "nickname": str(data.get("name") or ""),
                        "expiresAt": exp,
                        "expiresIn": _human_delta(exp - time.time()) if exp else None,
                    })
                except Exception as exc:
                    cli_item["error"] = str(exc)
                found.append(cli_item)
    return found


def import_desktop_credential(path=None, realm=None):
    """把扫描到的凭证导入账号池。path=None 时导入扫描到的全部有效项。"""
    if not path:
        imported, errors = [], []
        for item in scan_desktop_credentials():
            if not item.get("valid"):
                continue
            try:
                imported.append(import_desktop_credential(
                    path=item["path"], realm=item["realm"]))
            except Exception as exc:
                errors.append("%s/%s: %s" % (item["realm"], item["file"], exc))
        if errors:
            raise RuntimeError("; ".join(errors[:3]))
        return imported

    # 定位该 path 归属的 realm（按扫描结果匹配；否则按目录名猜）
    target_realm = realm
    matched = None
    for item in scan_desktop_credentials():
        if os.path.abspath(item["path"]) == os.path.abspath(path):
            matched = item
            target_realm = item["realm"]
            break
    if target_realm not in REALM_CONFIGS:
        target_realm = "cn"
    cfg = get_realm_config(target_realm)

    token = refresh = ""
    uid = nickname = ""
    exp = 0
    base = os.path.basename(path)
    if base == "auth.v1.dat":
        data = _load_app_auth(target_realm)
        token = str(data.get("token") or "")
        refresh = str(data.get("refreshToken") or "")
        user = data.get("user") or {}
        uid = str(user.get("id") or "")
        nickname = str(user.get("name") or "")
        try:
            import datetime
            exp = int(datetime.datetime.strptime(
                str(data.get("expiresAt") or "")[:19], "%Y-%m-%dT%H:%M:%S"
            ).timestamp())
        except Exception:
            exp = 0
    else:
        auth_dir = os.path.dirname(path)
        machine_key = ""
        try:
            with open(os.path.join(auth_dir, "machine_id"),
                      encoding="utf-8") as fh:
                machine_key = fh.read().strip()
        except Exception:
            pass
        data = _load_cli_user(target_realm, path, machine_key)
        token = str(data.get("access_token") or "")
        refresh = str(data.get("refresh_token") or "")
        uid = str(data.get("uid") or "")
        nickname = str(data.get("name") or "")
        exp = normalize_epoch(data.get("expire_time"))

    if not token:
        raise RuntimeError("credential has no access token")
    if not uid:
        uid = "d-" + uuid.uuid4().hex[:24]
    account = Account({
        "uid": uid,
        "nickname": nickname or uid[:8],
        "domain": cfg["domain"],
        "realm": target_realm,
        "platform": "CLI",
        "accessToken": token,
        "refreshToken": refresh,
        "expiresAt": exp or (int(time.time()) + 30 * 86400),
        "source": "desktop-app",
        "enabled": True,
    })
    return add_to_pool(account)


# ---------------------------------------------------------------------------
# 导入 / 导出（与 WorkBuddy 网关同构的文档格式）
# ---------------------------------------------------------------------------
EXPORT_FORMAT = "qoder-accounts"
EXPORT_VERSION = 1

# 描述运行期状态而非凭证本身的字段：导入时导出可查、但绝不信任。
VOLATILE_FIELDS = ("cooldownUntil", "lastError", "credits", "lastCheckin", "plan")


def account_to_export(account):
    data = account.to_dict()
    data.pop("path", None)
    return data


def build_export_document(accounts, realm=None, include_secrets=True, uids=None):
    wanted = None
    if uids is not None:
        wanted = {str(u) for u in uids}
    rows = []
    for account in accounts:
        if realm and account.realm != realm:
            continue
        if wanted is not None and account.uid not in wanted:
            continue
        row = account_to_export(account)
        if not include_secrets:
            row.pop("accessToken", None)
            row.pop("refreshToken", None)
            row.pop("personalToken", None)
        rows.append(row)
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(rows),
        "accounts": rows,
    }


def _coerce_account_rows(blob):
    """把任意受支持的容器规整成账号 dict 列表。返回 (rows, error)。"""
    if isinstance(blob, list):
        rows = blob
    elif isinstance(blob, dict) and isinstance(blob.get("accounts"), list):
        rows = blob["accounts"]
    elif isinstance(blob, dict):
        looks_like_account = (
            blob.get("accessToken")
            or isinstance(blob.get("auth"), dict)
            or isinstance(blob.get("account"), dict)
            or "auth_user_info_raw" in blob
        )
        if not looks_like_account:
            keys = ", ".join(sorted(blob.keys())[:6]) or "none"
            return [], ("not an account document (expected an accounts array, "
                        "a list, or an account object; got keys: %s)" % keys)
        rows = [blob]
    else:
        return [], "expected an object or a list of accounts"

    out = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            return [], "account #%d is not an object" % (index + 1)
        out.append(row)
    if not out:
        return [], "no accounts found in the document"
    return out, ""


def _adapt_cockpit_row(row, realm):
    """Cockpit 纯转换：严格校验原始凭证，错误仅包含字段名。"""
    if realm not in ("cn", "intl"):
        raise ValueError("Cockpit requires explicit realm: cn or intl")
    raw = row.get("auth_user_info_raw")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, RecursionError):
            raise ValueError("auth_user_info_raw must be a JSON object") from None
    if not isinstance(raw, dict):
        raise ValueError("auth_user_info_raw must be a JSON object")

    def text(value, field):
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError(field + " must be a string")
        return value.strip()

    token = text(raw.get("token"), "auth_user_info_raw.token")
    if not token:
        raise ValueError("auth_user_info_raw.token is required")
    uid = text(raw.get("id"), "auth_user_info_raw.id") or text(row.get("user_id"), "user_id")
    if not re.sub(r"[^A-Za-z0-9_-]", "_", uid).strip("_ "):
        raise ValueError("auth_user_info_raw.id or user_id is required")
    expires = normalize_epoch(raw.get("expireTime"))
    if not expires:
        raise ValueError("auth_user_info_raw.expireTime must be a finite positive epoch")
    refresh = text(raw.get("refreshToken"), "auth_user_info_raw.refreshToken")
    if expires <= time.time() and not refresh:
        raise ValueError("expired Cockpit credential requires refreshToken")
    return {"uid": uid, "accessToken": token, "refreshToken": refresh,
            "nickname": text(raw.get("name"), "auth_user_info_raw.name") or text(row.get("display_name"), "display_name"),
            "expiresAt": expires, "realm": realm, "domain": get_realm_config(realm)["domain"]}


def normalise_import_row(row, realm=None):
    """把一行导入数据规整成 Account kwargs；无可用凭证时 raise ValueError。"""
    if not isinstance(row, dict):
        raise ValueError("account row must be an object")
    if "auth_user_info_raw" in row:
        row = _adapt_cockpit_row(row, realm)
    auth = row.get("auth") if isinstance(row.get("auth"), dict) else None
    profile = row.get("account") if isinstance(row.get("account"), dict) else None

    def pick(key, default=None):
        for layer in (row, auth, profile):
            if isinstance(layer, dict) and layer.get(key) not in (None, ""):
                return layer.get(key)
        return default

    token = str(pick("accessToken") or "").strip()
    if not token:
        raise ValueError("no accessToken")
    detected = str(realm or pick("realm") or "").strip().lower()
    if detected not in ("cn", "intl"):
        detected = detect_realm_from_domain(pick("domain"))
    cfg = get_realm_config(detected)
    raw_uid = str(pick("uid") or "").strip()
    uid = re.sub(r"[^A-Za-z0-9_-]", "_", raw_uid).strip("_ ")
    if not uid:
        uid = "p-" + uuid.uuid4().hex[:24]
    exp = normalize_epoch(pick("expiresAt"))
    if not exp:
        exp = int(time.time()) + 3600
    return {
        "uid": uid,
        "nickname": str(pick("nickname") or ""),
        "domain": str(pick("domain") or cfg["domain"]),
        "realm": detected,
        "platform": str(pick("platform") or "CLI"),
        "accessToken": token,
        "refreshToken": str(pick("refreshToken") or ""),
        "personalToken": str(pick("personalToken") or ""),
        "expiresAt": exp,
        "source": "import",
        "enabled": True,
        "userType": str(pick("userType") or "") or DEFAULT_USER_TYPE,
        "organizationId": str(pick("organizationId") or ""),
        "organizationName": str(pick("organizationName") or ""),
        "lastError": "",
        "cooldownUntil": 0.0,
    }
