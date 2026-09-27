"""有界排队状态机；网络签名、响应输出和账号状态由调用方负责。"""
from dataclasses import dataclass
import threading
import time
from urllib.error import HTTPError

from qoder_errors import extract_nodes, extract_queue_info


QUEUE_SLOTS = threading.BoundedSemaphore(16)


@dataclass(frozen=True)
class WaitResult:
    waited_seconds: float
    poll_count: int


class QueueError(Exception):
    def __init__(self, code, http_status, message, waited_seconds=0.0, poll_count=0):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.message = message
        self.waited_seconds = waited_seconds
        self.poll_count = poll_count


def _state(payload):
    if not isinstance(payload, dict):
        raise ValueError("queue response must be an object")
    nodes = extract_nodes(payload)
    # 重复状态也必须一致，不能由遍历顺序决定是否恢复请求。
    states = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            name = str(key).replace("_", "").replace("-", "").lower()
            if name not in {"isqueued", "serviceavailable"}:
                continue
            if not isinstance(value, bool) or (name in states and states[name] != value):
                raise ValueError("invalid or contradictory queue state")
            states[name] = value
    queued = states.get("isqueued")
    available = states.get("serviceavailable")
    if queued is False and available is False:
        raise ValueError("contradictory queue readiness")
    if queued is None and available is not False:
        raise ValueError("queue readiness is missing")
    return queued is False, extract_queue_info(nodes) or {}


def _interval(info, default=3.0):
    value = info.get("retryAfterSeconds")
    return default if value is None else max(1.0, min(30.0, value))


def wait_until_ready(request_set_id, model_key, queue_type, initial,
                     remaining_seconds, poll, on_wait=None,
                     clock=time.monotonic, sleep=time.sleep):
    """首次立即 GET，ready 后返回；所有 GET 和等待共同消耗剩余预算。

    poll(request_set_id, model_key, queue_type, timeout) 返回完整 JSON dict；
    timeout 最大 5 秒。HTTP 异常通过 code/status/status_code 表达状态码。
    on_wait() 在 GET 前后和最长 1 秒等待切片中执行；异常原样传播，并附加
    waited_seconds/poll_count（异常允许写属性时），供调用方记录取消耗时。
    initial 仅提供查询失败后的初始等待间隔，不能替代 GET 就绪证据。
    """
    start = clock()
    deadline = start + max(0.0, remaining_seconds)
    count = 0

    def elapsed():
        return max(0.0, clock() - start)

    def fail(code, status, message):
        raise QueueError(code, status, message, elapsed(), count)

    def budget():
        left = deadline - clock()
        if left <= 0:
            fail("queue_timeout", 429, "upstream queue wait budget exhausted")
        return left

    def callback():
        if on_wait is not None:
            on_wait()

    def pause(seconds):
        end = clock() + seconds
        while clock() < end:
            callback()
            sleep(min(1.0, end - clock(), budget()))
        callback()
        budget()

    if not QUEUE_SLOTS.acquire(blocking=False):
        fail("gateway_queue_full", 503, "gateway queue capacity exhausted")
    try:
        failures = 0
        info = extract_queue_info(extract_nodes(initial or {})) or {}
        while True:
            budget()
            callback()
            timeout = min(5.0, budget())
            count += 1
            try:
                payload = poll(request_set_id, model_key, queue_type, timeout)
            except Exception as exc:
                status = next((getattr(exc, name, None) for name in
                               ("code", "status", "status_code")
                               if isinstance(getattr(exc, name, None), int)), None)
                if isinstance(exc, HTTPError):
                    try:
                        exc.close()
                    except OSError:
                        pass
                callback()
                budget()
                if status in {404, 410}:
                    fail("queue_endpoint_unavailable", 503, "upstream queue endpoint unavailable")
                if status in {401, 403}:
                    fail("queue_poll_failed", 503, "upstream queue authentication failed")
                failures += 1
            else:
                callback()
                budget()
                try:
                    ready, current = _state(payload)
                except ValueError:
                    failures += 1
                else:
                    failures = 0
                    info = current
                    queue_type = info.get("queueType", queue_type)
                    if ready:
                        if "retryAfterSeconds" in info:
                            pause(min(30.0, info["retryAfterSeconds"]))
                        budget()
                        return WaitResult(elapsed(), count)
            if failures >= 3:
                fail("queue_poll_failed", 503, "upstream queue query failed three consecutive times")
            pause(_interval(info))
    except BaseException as exc:
        # 保留客户端取消异常类型，避免调用方把断连当作可重试的服务错误。
        try:
            exc.waited_seconds = elapsed()
            exc.poll_count = count
        except (AttributeError, TypeError):
            pass
        raise
    finally:
        QUEUE_SLOTS.release()
