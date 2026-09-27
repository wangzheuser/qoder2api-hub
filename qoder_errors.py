"""有界上游错误解析与分类；不访问账号状态、不执行重试。"""
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
import json
import math
import re

MAX_DETAIL_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_NODES = 128
_WRAPPERS = {"error", "data", "body", "message", "cause", "result", "details"}
_CODE_FIELDS = {"code", "errorcode", "businesscode", "bizcode", "statuscode", "statuscodevalue"}


class ErrorParseLimit(ValueError):
    """上游错误超出解析预算或包含循环结构。"""


@dataclass(frozen=True)
class ErrorInfo:
    kind: str
    scope: str
    upstream_http_status: int
    upstream_code: object
    public_http_status: int
    message: str
    retry_after_seconds: float = None
    queue_info: dict = None


def _key(value):
    return str(value).replace("_", "").replace("-", "").lower()


def extract_nodes(detail):
    """返回有界深度优先节点列表；仅包装字段中的字符串继续解 JSON。

    根深度为 0，最多 128 节点，输入 UTF-8 表示最多 64 KiB；超限抛
    ErrorParseLimit。JSON/SSE 字符串包装各占一层，普通文本保持原样。
    """
    if isinstance(detail, bytes):
        if len(detail) > MAX_DETAIL_BYTES:
            raise ErrorParseLimit("upstream error exceeds 64 KiB")
        detail = detail.decode("utf-8", "replace")
    try:
        chunks = [detail] if isinstance(detail, str) else json.JSONEncoder(ensure_ascii=False).iterencode(detail)
        size = 0
        for chunk in chunks:
            size += len(chunk.encode("utf-8"))
            if size > MAX_DETAIL_BYTES:
                raise ErrorParseLimit("upstream error exceeds 64 KiB")
    except (RecursionError, TypeError, ValueError) as exc:
        raise ErrorParseLimit(str(exc)) from exc
    nodes = []
    stack = [(detail, 0, True)]
    while stack:
        value, depth, parse_string = stack.pop()
        if depth > MAX_DEPTH or len(nodes) >= MAX_NODES:
            raise ErrorParseLimit("upstream error exceeds depth/node budget")
        nodes.append(value)
        if isinstance(value, dict):
            if len(value) + len(stack) + len(nodes) > MAX_NODES:
                raise ErrorParseLimit("upstream error exceeds node budget")
            stack.extend((v, depth + 1, str(k).lower() in _WRAPPERS)
                         for k, v in reversed(list(value.items())))
        elif isinstance(value, list):
            if len(value) + len(stack) + len(nodes) > MAX_NODES:
                raise ErrorParseLimit("upstream error exceeds node budget")
            stack.extend((v, depth + 1, True) for v in reversed(value))
        elif isinstance(value, str) and parse_string:
            raw = value.strip()
            if raw.startswith("data:"):
                raw = raw[5:].strip()
            if raw.startswith(("{", "[", '"')):
                try:
                    decoded = json.loads(raw)
                except RecursionError as exc:
                    raise ErrorParseLimit("upstream JSON exceeds depth budget") from exc
                except ValueError:
                    continue
                stack.append((decoded, depth + 1, True))
    return nodes


def extract_queue_info(nodes):
    """提取已验证的队列协议字段，统一 camelCase；未知/无效字段忽略。"""
    result = {}
    fields = {"isqueued": "isQueued", "modelkey": "modelKey", "queuecount": "queueCount",
              "queuetype": "queueType", "serviceavailable": "serviceAvailable",
              "waittime": "waitTime", "retryafterseconds": "retryAfterSeconds"}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            name = fields.get(_key(key))
            if name is None:
                continue
            if name in {"isQueued", "serviceAvailable"}:
                if not isinstance(value, bool):
                    continue
            elif name == "modelKey":
                if not isinstance(value, str) or not value.strip():
                    continue
            elif name == "queueType":
                if isinstance(value, bool) or not isinstance(value, (str, int)):
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
            else:
                if isinstance(value, bool):
                    continue
                try:
                    value = float(value)
                except (ValueError, TypeError, OverflowError):
                    continue
                if not math.isfinite(value) or value < 0:
                    continue
                if name == "queueCount":
                    if not value.is_integer():
                        continue
                    value = int(value)
            result.setdefault(name, value)
    return result or None


def _seconds(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return min(number, 86400.0) if math.isfinite(number) and number >= 0 else None


def _retry_after(nodes, headers):
    header_map = {str(k).lower(): v for k, v in (headers or {}).items()}
    # Date 作为时钟锚点，保证相同参数产生相同结果，不依赖本机时钟。
    def date(value):
        try:
            parsed = parsedate_to_datetime(str(value))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except (ValueError, TypeError, OverflowError):
            return None
    anchor = date(header_map.get("date"))
    raw = header_map.get("retry-after")
    seconds = _seconds(raw)
    if seconds is not None:
        return seconds
    target = date(raw)
    if target is not None and anchor is not None:
        return _seconds(max(0, (target - anchor).total_seconds()))
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            name = _key(key)
            if name in {"retryafter", "retryafterseconds", "resetafter", "resetafterseconds"}:
                seconds = _seconds(value)
            elif name in {"reset", "resetat", "resettimestamp"} and anchor is not None:
                try:
                    target = float(value)
                    seconds = _seconds(max(0, target - anchor.timestamp())) if math.isfinite(target) else None
                except (ValueError, TypeError, OverflowError):
                    seconds = None
            else:
                continue
            if seconds is not None:
                return seconds
    return None


def classify(status, detail="", headers=None):
    """纯分类函数；HTTP-date/绝对 reset 需上游 Date 作为确定性时间锚点。"""
    try:
        status = int(status)
    except (TypeError, ValueError, OverflowError):
        status = 502
    try:
        nodes = extract_nodes(detail)
    except ErrorParseLimit as exc:
        return ErrorInfo("protocol", "service", status, None, 502, str(exc))
    codes = [v for node in nodes if isinstance(node, dict)
             for k, v in node.items() if _key(k) in _CODE_FIELDS
             and isinstance(v, (str, int)) and not isinstance(v, bool)]
    code = codes[0] if codes else None
    text = "\n".join(n for n in nodes if isinstance(n, str))
    low = text.lower()
    message = text[:600] or "upstream HTTP %s" % status
    retry = _retry_after(nodes, headers)

    def result(kind, scope, public_status, selected_code=code):
        return ErrorInfo(kind, scope, status, selected_code, public_status, message,
                         retry if kind in {"queued", "model_rate", "quota", "transient"} else None,
                         extract_queue_info(nodes) if kind == "queued" else None)

    if status == 10605 or any(str(v).strip() == "10605" for v in codes):
        return result("queued", "request", 429, "10605")
    if any(s in low for s in ("datainspectionfailed", "inappropriate content",
                             "input text data may contain", "contentfilter", "sensitivecontent")):
        return result("content", "request", 400)
    if any(s in low for s in ("context_length_exceeded", "context length", "maximum context",
                             "context window", "上下文超长")):
        return result("context", "request", 400)
    if any(s in low for s in ("invalid_parameter_error", "invalid_request_error", '"range of ')):
        return result("request", "request", 400)
    if status == 12153 or any(str(v) == "12153" for v in codes) or re.search(r"\b12153\b", low) or any(s in low for s in (
            "token_expire", "offline user session not found", "sessiondead")):
        return result("dead_session", "account", 401)
    if status == 401 or any(s in low for s in ("authentication_error", "invalid_token", "invalid token", "invalid credential")):
        return result("auth", "account", 401)
    if status == 402 or any(s in low for s in ("insufficient_quota", "quota_exceeded", "quota exceeded",
            "quota exhausted", "insufficient credits", "credit exhausted", "credits exhausted", "额度不足", "额度耗尽")):
        return result("quota", "account", 429)
    if status == 429 or any(s in low for s in ("rate_limit_exceeded", "rate limit exceeded", "model_rate_limit", "too many requests")):
        info = result("model_rate", "model", 429)
        return ErrorInfo(info.kind, info.scope, status, code, 429, message, retry if retry is not None else 60.0)
    if status == 403 or "permission_error" in low:
        return result("forbidden", "request", 403)
    if status == 418 or status >= 500 or "provider_error" in low:
        return result("transient", "service", 503 if status == 503 else 502)
    if 400 <= status < 500:
        return result("request", "request", status)
    return result("protocol", "service", 502)


def public_error_type(info):
    """稳定的协议错误类型；HTTP 状态单独由 ErrorInfo 提供。"""
    return {"queued": "upstream_queued", "model_rate": "rate_limit_error",
            "quota": "insufficient_quota", "auth": "authentication_error",
            "dead_session": "authentication_error", "forbidden": "permission_error",
            "request": "invalid_request_error", "content": "content_policy_rejected",
            "context": "context_length_exceeded", "transient": "upstream_transient_error",
            "protocol": "upstream_protocol_error", "pool_busy": "server_busy"}[info.kind]
