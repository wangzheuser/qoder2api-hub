"""Credits 明细缓存与手动活动领取；不改变旧 quota/usage 余额口径。"""
from concurrent.futures import Future, ThreadPoolExecutor
import copy
import hashlib
import math
import threading
import time
import urllib.error
import urllib.parse
import weakref

import qoder_accounts


ENDPOINTS = {
    "usage": "/sash/api/v2/me/usage",
    "summary": "/sash/api/v1/ai-conversations/credits-summary",
    "activity": "/sash/api/v1/ai-conversations/seat-activity",
    "campaigns": "/sash/api/v1/me/campaigns",
}
TTL = 300
_executor = None
_executor_lock = threading.Lock()
_slots = threading.BoundedSemaphore(8)


class CreditsBusy(RuntimeError):
    """进程共享的 Credits 刷新任务已达到提交上限。"""


class _EndpointError(ValueError):
    def __init__(self, code=None):
        self.code = (int(code) if type(code) is int or (isinstance(code, str) and code.isdigit()) else None)
        super().__init__("credits endpoint returned an error envelope")


def _submit(fn, wait=False):
    global _executor
    if not _slots.acquire(blocking=wait):
        raise CreditsBusy("credits refresh capacity reached")
    try:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="credits")
            future = _executor.submit(fn)
        future.add_done_callback(lambda completed: _slots.release())
        return future
    except BaseException:
        _slots.release()
        raise


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def _text(value):
    return value if isinstance(value, str) else ""


def _object(value):
    return value if isinstance(value, dict) else {}


def _url(value):
    value = _text(value).strip()
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme in ("http", "https") and parsed.hostname
                and not parsed.username and not parsed.password
                and not any(ord(char) < 32 for char in value)):
            return value
    except ValueError:
        pass
    return None


def _campaign(row):
    if not isinstance(row, dict) or not _text(row.get("campaignId")):
        return None
    result = {key: _text(row.get(key)) for key in
              ("campaignId", "campaignKey", "actionType", "claimStatus")}
    result.update({key: _number(row.get(key)) for key in ("startAt", "endAt")})
    result["validity_valid"] = all(row.get(key) is None or _number(row[key]) is not None
                                   for key in ("startAt", "endAt"))
    benefit = _object(row.get("benefit"))
    result["benefit"] = {"kind": _text(benefit.get("kind")), "amount": _number(benefit.get("amount"))}
    result.update(name=result["campaignKey"] or result["campaignId"], description="", url=None)
    placements = row.get("placements")
    if not isinstance(placements, list):
        placements = []
    for preferred in ("POPUP", "USAGE"):
        for placement in placements:
            if not isinstance(placement, dict) or placement.get("type") != preferred:
                continue
            content = _object(placement.get("content"))
            translated = _object(content.get("zh")) or _object(content.get("en"))
            result.update(name=_text(translated.get("title")) or result["name"],
                          description=_text(translated.get("description")),
                          url=_url(translated.get("detailUrl")))
            return result
    return result


def _parse(endpoint, payload):
    if not isinstance(payload, dict):
        raise ValueError("credits endpoint returned a non-object")
    root = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    for node in (payload, root):
        code = node.get("code", node.get("statusCode"))
        if (node.get("error") or node.get("success") is False
                or (code is not None and code not in (0, 200, "0", "200", "SUCCESS"))):
            raise _EndpointError(code)
    if endpoint == "usage":
        usage = _object(root.get("qoderUsage"))
        plan, addon = _object(usage.get("userQuota")), _object(usage.get("addOnQuota"))
        return {"display_mode": _text(root.get("displayMode")) or None,
                "user_type": _text(usage.get("userType")) or None,
                "plan_used": _number(plan.get("used")), "plan_total": _number(plan.get("total")),
                "addon_used": _number(addon.get("used")), "addon_total": _number(addon.get("total"))}
    if endpoint == "summary":
        return {"total_credits": _number(root.get("totalCredits")),
                "peak_credits": _number(root.get("peakCredits"))}
    if endpoint == "activity":
        return {"activity": {"current_streak_days": _number(root.get("currentConsecutiveDays")),
                             "longest_streak_days": _number(root.get("maxConsecutiveDays")),
                             "total_active_days": _number(root.get("cumulativeActiveDays"))}}
    campaigns = root.get("campaigns")
    if not isinstance(campaigns, list):
        raise ValueError("campaigns endpoint omitted its campaigns list")
    return {"campaigns": [parsed for row in campaigns if (parsed := _campaign(row)) is not None],
            "campaign_url": _url(root.get("campaignUrl"))}


def _empty(account):
    return {"uid": account.uid, "realm": account.realm, "fetched_at": None,
            "stale": True, "partial": True, "endpoint_status": {},
            "plan_used": None, "plan_total": None, "addon_used": None, "addon_total": None,
            "total_credits": None, "peak_credits": None, "display_mode": None, "user_type": None,
            "activity": {"current_streak_days": None, "longest_streak_days": None, "total_active_days": None},
            "campaigns": [], "campaign_url": None}


class CreditsService:
    def __init__(self, http=None, clock=None):
        self._http = http
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._cache = {}
        self._endpoints = {}
        self._expires = {}
        self._inflight = {}
        self._claims = {}
        self._confirmed = {}
        self._epochs = {}
        self._active = {}
        self._closed = False
        self._operations = weakref.WeakKeyDictionary()

    def _operation(self, account):
        with self._lock:
            state = self._operations.get(account)
            if state is None:
                state = {"lock": threading.RLock(), "version": 0, "snapshot": None, "key": None}
                self._operations[account] = state
            return state

    @staticmethod
    def _key(account):
        credentials = "\0".join(str(getattr(account, name, "")) for name in
                                 ("access_token", "refresh_token", "personal_token"))
        return (account.realm, account.uid, hashlib.sha256(credentials.encode()).hexdigest(), id(account))

    def _activate(self, account):
        key = self._key(account)
        with self._lock:
            identity = key[:2]
            if self._active.get(identity) != key:
                previous = self._active.get(identity)
                self.invalidate(uid=account.uid, realm=account.realm,
                                _credential_change=previous is not None and previous[3] == id(account))
                self._active[identity] = key
        return key

    def cached(self, account):
        """仅返回当前凭证对应的缓存副本，绝不触发网络或刷新令牌。"""
        key = self._activate(account)
        with self._lock:
            value = self._cache.get(key)
            if value is None:
                return None
            result = copy.deepcopy(value)
            result["stale"] = self._clock() >= self._expires.get(key, 0)
            return result

    def invalidate(self, account=None, uid=None, realm=None, _credential_change=False):
        if isinstance(account, str):
            uid, account = account, None
        if account is not None:
            uid, realm = account.uid, account.realm
        with self._lock:
            identities = set(self._active) | {key[:2] for key in self._inflight}
            identities |= {key[0][:2] for key in self._claims}
            for identity in identities:
                if (uid is None or identity[1] == uid) and (realm is None or identity[0] == realm):
                    if not _credential_change:
                        self._epochs[identity] = self._epochs.get(identity, 0) + 1
            for identity in list(self._active):
                if (uid is None or identity[1] == uid) and (realm is None or identity[0] == realm):
                    self._active.pop(identity, None)
            keys = set(self._cache) | set(self._endpoints)
            for key in keys:
                if (uid is None or key[1] == uid) and (realm is None or key[0] == realm):
                    self._cache.pop(key, None)
                    self._expires.pop(key, None)
                    self._endpoints.pop(key, None)
                    for claimed in [entry for entry in self._confirmed if entry[0] == key]:
                        self._confirmed.pop(claimed, None)
            self._prune_epochs()

    def _prune_epochs(self):
        live = set(self._active) | {key[:2] for key in self._inflight}
        live |= {key[0][:2] for key in self._claims}
        self._epochs = {key: value for key, value in self._epochs.items() if key in live}

    def _start(self, mapping, key, operation, wait=False):
        with self._lock:
            if self._closed:
                raise RuntimeError("credits service is closed")
            existing = mapping.get(key)
            if existing is not None:
                return existing
            promise = Future()
            mapping[key] = promise

        def run():
            try:
                promise.set_result(operation())
            except BaseException as exc:
                promise.set_exception(exc)
            finally:
                with self._lock:
                    if mapping.get(key) is promise:
                        mapping.pop(key, None)
                    self._prune_epochs()
        try:
            _submit(run, wait=wait)
        except BaseException as exc:
            with self._lock:
                if mapping.get(key) is promise:
                    mapping.pop(key, None)
            promise.set_exception(exc)
        return promise

    def _details_future(self, account, force=False, wait=False):
        key = self._activate(account)
        identity = (account.realm, account.uid, id(account))
        with self._lock:
            running = self._inflight.get(identity)
            if running is not None:
                return running
            if not force and key in self._cache and self._clock() < self._expires.get(key, 0):
                result = Future()
                result.set_result(copy.deepcopy(self._cache[key]))
                return result
            epoch = self._epochs.get(key[:2], 0)
        return self._start(self._inflight, identity, lambda: self._fetch(account, force, epoch), wait=wait)

    def details(self, account, force=False):
        return copy.deepcopy(self._details_future(account, force).result())

    def bulk(self, accounts, force=False):
        """分批提交并保持原顺序，所有调用共享进程级 4/8 容量。"""
        accounts = list(accounts)
        result = []
        for offset in range(0, len(accounts), 4):
            futures = [self._details_future(account, force, wait=True)
                       for account in accounts[offset:offset + 4]]
            result.extend(copy.deepcopy(future.result()) for future in futures)
        return result

    def _request(self, account, endpoint, method="GET"):
        headers = account.headers()
        headers.update({"Cosy-ClientType": "10", "User-Agent": "Qoder", "Accept": "application/json"})
        if method == "POST":
            headers.pop("Content-Type", None)
        base = qoder_accounts.get_realm_config(account.realm)["openapi"]
        return (self._http or qoder_accounts.http_json)(base + endpoint, method=method,
                                                       headers=headers, timeout=15, retries=1)

    def _usable(self, account, epoch):
        with self._lock:
            active = self._active.get((account.realm, account.uid))
            return (not getattr(account, "_retired", False) and account.enabled and bool(account.access_token)
                    and self._epochs.get((account.realm, account.uid), 0) == epoch
                    and active is not None and active[3] == id(account))

    def _fetch(self, account, force=False, epoch=None, _identity_out=None, _observed_version=None):
        # 已在 worker 中，直接协调同账号刷新；不提交子任务，避免线程池互等。
        state = self._operation(account)
        version = state["version"] if _observed_version is None else _observed_version
        with state["lock"]:
            if (state["version"] != version and state["snapshot"] is not None
                    and state["key"] == self._key(account)
                    and self._usable(account, epoch)):
                if _identity_out is not None:
                    _identity_out["key"] = state["key"]
                return copy.deepcopy(state["snapshot"])
            identity = {}
            result = self._fetch_once(account, force, epoch, identity)
            state.update(version=state["version"] + 1, snapshot=copy.deepcopy(result), key=identity.get("key"))
            if _identity_out is not None:
                _identity_out.update(identity)
            return result

    def _fetch_once(self, account, force=False, epoch=None, _identity_out=None):
        # 刷新沿用账号自身锁；所有网络都运行在共享 worker 中。
        if epoch is None:
            with self._lock:
                epoch = self._epochs.get((account.realm, account.uid), 0)
        if not self._usable(account, epoch) or not account.refresh_if_needed():
            result = _empty(account)
            result["endpoint_status"] = {name: {"status": "unknown", "http_status": 401, "retry_at": None}
                                         for name in ENDPOINTS}
            return result
        key = self._key(account)
        if _identity_out is not None:
            _identity_out["key"] = key
        with self._lock:
            active = self._active.get(key[:2])
            if active is not None and active[3] == id(account) and active != key:
                key = self._activate(account)
            entries = copy.deepcopy(self._endpoints.get(key, {}))
        result = _empty(account)
        for name, path in ENDPOINTS.items():
            previous = entries.get(name, {})
            if not force and self._clock() < previous.get("expires", 0):
                entry = previous
            else:
                status, code, expires = "supported", 200, self._clock() + TTL
                data = previous.get("data", {})
                try:
                    if not self._usable(account, epoch) or self._key(account) != key:
                        raise _EndpointError(401)
                    data = _parse(name, self._request(account, path))
                except urllib.error.HTTPError as exc:
                    code = exc.code
                    exc.close()
                    status = ("unsupported" if code in (404, 410) else
                              "unknown" if code in (401, 403) else "temporarily_unavailable")
                    expires = self._clock() + (3600 if status == "unsupported" else 30)
                except _EndpointError as exc:
                    code = exc.code
                    status = ("unknown" if code in (401, 403) else "temporarily_unavailable")
                    expires = self._clock() + 30
                except Exception:
                    status, code, expires = "temporarily_unavailable", None, self._clock() + 30
                entry = {"data": data, "status": status, "http_status": code, "expires": expires}
                entries[name] = entry
            result.update(copy.deepcopy(entry.get("data", {})))
            result["endpoint_status"][name] = {
                "status": entry["status"], "http_status": entry["http_status"],
                "retry_at": None if entry["status"] == "supported" else entry["expires"]}
        result["fetched_at"] = self._clock()
        result["stale"] = False
        result["partial"] = any(entry["status"] != "supported" for entry in entries.values())
        with self._lock:
            if (self._usable(account, epoch) and self._key(account) == key
                    and self._active.get(key[:2]) == key):
                self._cache[key] = copy.deepcopy(result)
                self._endpoints[key] = entries
                self._expires[key] = min(entry["expires"] for entry in entries.values())
        return result

    def claim(self, account, campaign_id):
        if not isinstance(campaign_id, str) or not campaign_id:
            return self._claim_result(False, "not_claimable", "活动标识无效", self.cached(account))
        cache_key = self._activate(account)
        key = ((account.realm, account.uid, id(account)), campaign_id)
        with self._lock:
            epoch = self._epochs.get(cache_key[:2], 0)
        return copy.deepcopy(self._start(self._claims, key, lambda: self._claim(account, campaign_id, epoch)).result())

    @staticmethod
    def _claim_result(claimed, status, message, snapshot):
        return {"ok": claimed, "claimed": claimed, "status": status,
                "message": message, "credits_details": snapshot}

    @staticmethod
    def _find(snapshot, campaign_id):
        return next((row for row in snapshot.get("campaigns", []) if row["campaignId"] == campaign_id), None)

    def _claim(self, account, campaign_id, epoch):
        state = self._operation(account)
        version = state["version"]
        with state["lock"]:
            return self._claim_locked(account, campaign_id, epoch, version)

    def _claim_locked(self, account, campaign_id, epoch, version):
        identity = {}
        snapshot = self._fetch(account, force=True, epoch=epoch, _identity_out=identity,
                               _observed_version=version)
        key = (identity.get("key", self._key(account)), campaign_id)
        campaign = self._find(snapshot, campaign_id)
        if snapshot["endpoint_status"].get("campaigns", {}).get("status") != "supported" or campaign is None:
            return self._claim_result(False, "not_claimable", "活动查询未确认该活动", snapshot)
        with self._lock:
            confirmed = self._confirmed.get(key, 0) > self._clock()
        if campaign["claimStatus"] == "CLAIMED" or confirmed:
            return self._claim_result(True, "already_claimed", "活动已经领取", snapshot)
        now = self._clock()
        if (campaign["actionType"] != "CLAIM_BENEFIT" or campaign["claimStatus"] != "CLAIMABLE"
                or not campaign["validity_valid"]
                or (campaign["startAt"] is not None and campaign["startAt"] > now)
                or (campaign["endAt"] is not None and campaign["endAt"] <= now)):
            return self._claim_result(False, "not_claimable", "活动当前不可领取", snapshot)
        claimed, status = False, "unconfirmed"
        try:
            if not self._usable(account, epoch) or self._key(account) != key[0]:
                return self._claim_result(False, "not_claimable", "账号状态或凭证已变更，请重新查询活动", snapshot)
            path = ENDPOINTS["campaigns"] + "/" + urllib.parse.quote(campaign_id, safe="") + "/claim"
            reply = self._request(account, path, method="POST")
            claimed = any(_object(node).get("status") == "CLAIMED" for node in
                          (reply, _object(reply).get("data")))
            status = "claimed" if claimed else "unconfirmed"
        except urllib.error.HTTPError as exc:
            status = "failed"
            exc.close()
        except Exception:
            # 超时/连接异常时请求可能已到达服务端，禁止自动补发 POST。
            status = "unknown"
        refreshed = self._fetch(account, force=True, epoch=epoch)
        latest = self._find(refreshed, campaign_id)
        if (refreshed["endpoint_status"].get("campaigns", {}).get("status") == "supported"
                and latest is not None and latest["claimStatus"] == "CLAIMED"):
            claimed, status = True, "claimed"
        if claimed:
            with self._lock:
                self._confirmed[key] = self._clock() + TTL
        message = ("领取已确认，额度以刷新结果为准" if claimed else
                   "领取结果未知，已重新查询活动，请确认后再操作" if status == "unknown" else
                   "上游未确认领取成功")
        return self._claim_result(claimed, status, message, refreshed)

    def close(self):
        """主进程停机时等待共享 worker 完成，不中断已发出的领取。"""
        global _executor
        with self._lock:
            self._closed = True
        with _executor_lock:
            if _executor is not None:
                _executor.shutdown(wait=True)
                _executor = None


SERVICE = CreditsService()
