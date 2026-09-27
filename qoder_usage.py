"""Rebuildable JSONL usage index; the source log remains authoritative."""
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class Watermark:
    identity: str
    size: int
    digest: str


def _identity(stat):
    return "%s:%s" % (stat.st_dev, stat.st_ino)


def _digest(fh, offset):
    fh.seek(max(0, offset - 256))
    return hashlib.sha256(fh.read(min(256, offset))).hexdigest()


def capture_watermark(source_path):
    """Call under the JSONL append lock to capture its completed boundary."""
    try:
        with open(source_path, "rb") as fh:
            stat = os.fstat(fh.fileno())
            end = stat.st_size
            while end:
                start = max(0, end - 8192)
                fh.seek(start)
                block = fh.read(end - start)
                found = block.rfind(b"\n")
                if found >= 0:
                    end = start + found + 1
                    break
                end = start
            return Watermark(_identity(stat), end, _digest(fh, end))
    except FileNotFoundError:
        return Watermark("missing", 0, hashlib.sha256(b"").hexdigest())


def _matches(fh, mark):
    stat = os.fstat(fh.fileno())
    return (_identity(stat) == mark.identity and stat.st_size >= mark.size
            and _digest(fh, mark.size) == mark.digest)


def scan_rows(source_path, watermark, realm=None, limit=None, newest=False):
    """Read only complete rows from one validated source snapshot."""
    rows = []
    if watermark.identity == "missing":
        return rows
    with open(source_path, "rb") as fh:
        if not _matches(fh, watermark):
            raise OSError("usage source changed during snapshot")
        fh.seek(0)
        while fh.tell() < watermark.size:
            raw = fh.readline(watermark.size - fh.tell())
            if not raw.endswith(b"\n"):
                break
            try:
                row = json.loads(raw)
                if isinstance(row, dict) and (not realm or (row.get("realm") or "unknown") == realm):
                    rows.append(_normalise_numbers(row))
            except (ValueError, UnicodeError, RecursionError):
                pass
        if not _matches(fh, watermark):
            raise OSError("usage source changed during snapshot")
    if newest:
        rows.reverse()
    return rows if limit is None else rows[:limit]


_FIELDS = ("prompt_tokens", "completion_tokens", "reasoning_tokens",
           "cached_tokens", "total_tokens")


def _text(value, default=""):
    return value if isinstance(value, str) and value else default


def _number(value):
    # SQLite binds Python ints as signed 64-bit values. Use the same bounded
    # finite domain for floats, JSONL fallback rows, and indexed aggregates.
    if not isinstance(value, (int, float)) or not -(2 ** 63) <= value <= 2 ** 63 - 1:
        return 0
    if isinstance(value, float) and not math.isfinite(value):
        return 0
    return value


def _normalise_numbers(row):
    for key in (*_FIELDS, "at", "elapsed_ms", "ttft_ms", "gen_ms", "queue_wait_ms",
                "credit", "tokens_per_sec"):
        if key in row:
            row[key] = _number(row[key])
    return row


class UsageIndex:
    """One background writer and independent, bounded read transactions."""

    def __init__(self, source_path, enabled=True):
        self.source_path = os.path.abspath(source_path)
        self.db_path = os.path.join(os.path.dirname(self.source_path), "usage-index.sqlite3")
        self.enabled = enabled
        self._event = threading.Event()
        self._stop = threading.Event()
        self._condition = threading.Condition()
        self._thread = None
        self._db_gate = threading.RLock()
        self._state = "building" if enabled else "disabled"
        self._error = ""
        self._offset = 0
        self._bad = 0

    def start(self):
        if self.enabled and self._thread is None:
            self._thread = threading.Thread(target=self._run, name="usage-index", daemon=True)
            self._thread.start()
        return self

    def notify(self):
        self._event.set()

    def close(self, timeout=2):
        self._stop.set()
        self._event.set()
        if self._thread:
            self._thread.join(timeout)

    def capture_watermark(self):
        return capture_watermark(self.source_path)

    def status(self):
        try:
            size = os.path.getsize(self.source_path)
        except OSError:
            size = 0
        return {"state": self._state, "processed_bytes": self._offset,
                "source_bytes": size, "bad_lines": self._bad, "last_error": self._error}

    def _schema(self, conn):
        conn.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA busy_timeout=2000;
            CREATE TABLE IF NOT EXISTS usage_rows (
                source_generation TEXT, byte_offset INTEGER, at REAL,
                realm TEXT, account TEXT, model TEXT, error INTEGER,
                prompt_tokens REAL, completion_tokens REAL, reasoning_tokens REAL,
                cached_tokens REAL, total_tokens REAL, raw_json TEXT,
                request_id TEXT, status TEXT, stream INTEGER, elapsed_ms REAL,
                ttft_ms REAL, gen_ms REAL, queue_wait_ms REAL,
                PRIMARY KEY(source_generation, byte_offset));
            CREATE INDEX IF NOT EXISTS usage_realm_at ON usage_rows(realm, at DESC);
            CREATE INDEX IF NOT EXISTS usage_account_at ON usage_rows(account, at DESC);
            CREATE INDEX IF NOT EXISTS usage_at ON usage_rows(at DESC);
            CREATE TABLE IF NOT EXISTS index_meta (
                source_path TEXT, source_generation TEXT, next_offset INTEGER,
                source_identity TEXT, boundary_digest TEXT, schema_version INTEGER);
            CREATE TABLE IF NOT EXISTS index_bad_lines (
                source_generation TEXT, byte_offset INTEGER, reason TEXT,
                PRIMARY KEY(source_generation, byte_offset));
            PRAGMA user_version=1;
        """)
        if not conn.execute("SELECT 1 FROM index_meta").fetchone():
            conn.execute("INSERT INTO index_meta VALUES (?,?,?,?,?,1)",
                         (self.source_path, uuid.uuid4().hex, 0, "", hashlib.sha256(b"").hexdigest()))
            conn.commit()

    def _open_writer(self):
        conn = sqlite3.connect(self.db_path, timeout=2)
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise sqlite3.DatabaseError("unsupported usage index schema")
            if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise sqlite3.DatabaseError("usage index integrity check failed")
            self._schema(conn)
            return conn
        except Exception:
            conn.close()
            raise

    def _catch_up(self, conn):
        mark = self.capture_watermark()
        meta = conn.execute("SELECT * FROM index_meta").fetchone()
        _, generation, offset, identity, digest, _ = meta
        if identity:
            if mark.identity != identity or mark.size < offset:
                raise ValueError("usage source replaced or truncated")
            if identity != "missing":
                with open(self.source_path, "rb") as fh:
                    if _digest(fh, offset) != digest:
                        raise ValueError("usage consumed boundary changed")
        else:
            conn.execute("UPDATE index_meta SET source_identity=?", (mark.identity,))
            conn.commit()
        if mark.identity == "missing":
            return
        with open(self.source_path, "rb") as fh:
            if not _matches(fh, mark):
                raise ValueError("usage source changed")
            fh.seek(offset)
            while offset < mark.size and not self._stop.is_set():
                with conn:
                    for _ in range(500):
                        if offset >= mark.size:
                            break
                        start = offset
                        raw = fh.readline(mark.size - offset)
                        offset = fh.tell()
                        try:
                            row = json.loads(raw)
                            if not isinstance(row, dict):
                                raise ValueError("non-object JSON")
                            row = _normalise_numbers(row)
                            encoded = json.dumps(row, ensure_ascii=True, separators=(",", ":"))
                        except (ValueError, UnicodeError, OverflowError, RecursionError):
                            if raw.strip():
                                conn.execute("INSERT OR IGNORE INTO index_bad_lines VALUES (?,?,?)",
                                             (generation, start, "invalid JSON object"))
                            continue
                        conn.execute("INSERT OR IGNORE INTO usage_rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                     (generation, start, _number(row.get("at")),
                                      _text(row.get("realm"), "unknown"), _text(row.get("account"), "(unattributed)"),
                                      _text(row.get("model"), "?"), int(bool(row.get("error"))),
                                      *[_number(row.get(key)) for key in _FIELDS],
                                      encoded,
                                      _text(row.get("request_id")), _text(row.get("status")),
                                      int(bool(row.get("stream"))),
                                      *[_number(row.get(key)) for key in
                                        ("elapsed_ms", "ttft_ms", "gen_ms", "queue_wait_ms")]))
                    digest = _digest(fh, offset)
                    fh.seek(offset)
                    conn.execute("UPDATE index_meta SET next_offset=?, boundary_digest=?", (offset, digest))
                self._offset = offset
                with self._condition:
                    self._condition.notify_all()
        self._bad = conn.execute("SELECT COUNT(*) FROM index_bad_lines").fetchone()[0]
        self._offset = offset

    def _rebuild(self):
        with self._db_gate:
            self._rebuild_locked()

    def _rebuild_locked(self):
        self._state = "building"
        temporary = self.db_path + "." + uuid.uuid4().hex + ".rebuild"
        conn = sqlite3.connect(temporary, timeout=2)
        try:
            self._schema(conn)
            self._catch_up(conn)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
            conn = None
            with self._db_gate:
                if any(os.path.exists(self.db_path + suffix) for suffix in ("-wal", "-shm")):
                    raise sqlite3.OperationalError("usage index sidecars still in use")
                os.replace(temporary, self.db_path)
        finally:
            if conn:
                conn.close()
            for path in (temporary, temporary + "-wal", temporary + "-shm"):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass

    def _run(self):
        conn = None
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            while not self._stop.is_set():
                try:
                    if conn is None:
                        try:
                            conn = self._open_writer()
                        except sqlite3.DatabaseError:
                            self._rebuild()
                            conn = self._open_writer()
                    try:
                        self._catch_up(conn)
                    except ValueError:
                        with self._db_gate:
                            if conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
                                raise sqlite3.OperationalError("usage index readers busy")
                            conn.close()
                            conn = None
                            self._rebuild()
                            conn = self._open_writer()
                    self._state, self._error = "ready", ""
                except (OSError, sqlite3.Error, ValueError) as exc:
                    self._state, self._error = "degraded", type(exc).__name__
                    if conn:
                        conn.close()
                        conn = None
                with self._condition:
                    self._condition.notify_all()
                self._event.wait(1)
                self._event.clear()
        finally:
            if conn:
                conn.close()

    def _query(self, mark, callback):
        if not self.enabled or self._stop.is_set():
            return None
        deadline = time.monotonic() + .2
        self.notify()
        while True:
            conn = None
            if not self._db_gate.acquire(timeout=max(0, deadline - time.monotonic())):
                return None
            try:
                conn = sqlite3.connect(Path(self.db_path).as_uri() + "?mode=ro", uri=True, timeout=.005)
                conn.execute("BEGIN")
                meta = conn.execute("SELECT * FROM index_meta").fetchone()
                if meta and meta[3] == mark.identity and meta[2] >= mark.size:
                    if mark.identity != "missing":
                        with open(self.source_path, "rb") as fh:
                            indexed = Watermark(meta[3], meta[2], meta[4])
                            if not _matches(fh, mark):
                                return None
                            if not _matches(fh, indexed):
                                raise ValueError("usage index source boundary changed")
                    result = callback(conn, meta[1])
                    return result
            except (sqlite3.Error, OSError, ValueError):
                self._state = "degraded"
                self._error = "index query unavailable"
            finally:
                if conn:
                    conn.close()
                self._db_gate.release()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            with self._condition:
                self._condition.wait(min(remaining, .02))

    @staticmethod
    def _where(mark, generation, realm=None):
        sql = "source_generation=? AND byte_offset<?"
        args = [generation, mark.size]
        if realm:
            sql += " AND realm=?"
            args.append(realm)
        return sql, args

    def _count_rows(self, conn, watermark, generation, realm):
        # The exact indexed boundary can use SQLite covering COUNT indexes.
        # Older snapshots retain the generation/offset bound.
        offset = conn.execute("SELECT next_offset FROM index_meta").fetchone()[0]
        if offset == watermark.size:
            if realm:
                return conn.execute("SELECT COUNT(*) FROM usage_rows WHERE realm=?", (realm,)).fetchone()[0]
            return conn.execute("SELECT COUNT(*) FROM usage_rows").fetchone()[0]
        where, args = self._where(watermark, generation, realm)
        return conn.execute("SELECT COUNT(*) FROM usage_rows WHERE " + where, args).fetchone()[0]

    def count(self, watermark, realm=None):
        def query(conn, generation):
            return self._count_rows(conn, watermark, generation, realm)
        return self._query(watermark, query)

    def recent(self, watermark, limit=100, page=1, realm=None):
        limit, page = max(1, int(limit)), max(1, int(page))
        def query(conn, generation):
            where, args = self._where(watermark, generation, realm)
            total = self._count_rows(conn, watermark, generation, realm)
            pages = max(1, (total + limit - 1) // limit)
            current = min(page, pages)
            rows = conn.execute("SELECT raw_json FROM usage_rows WHERE " + where +
                                " ORDER BY byte_offset DESC LIMIT ? OFFSET ?",
                                args + [limit, (current - 1) * limit])
            return {"total": total, "page": current, "limit": limit, "total_pages": pages,
                    "rows": [json.loads(row[0]) for row in rows]}
        return self._query(watermark, query)

    def snapshot_rows(self, watermark, realm=None, limit=None, newest=False):
        def query(conn, generation):
            where, args = self._where(watermark, generation, realm)
            sql = "SELECT raw_json FROM usage_rows WHERE " + where + " ORDER BY byte_offset " + ("DESC" if newest else "ASC")
            if limit is not None:
                sql += " LIMIT ?"
                args.append(max(0, int(limit)))
            return [json.loads(row[0]) for row in conn.execute(sql, args)]
        return self._query(watermark, query)

    def by_account(self, watermark):
        def query(conn, generation):
            where, args = self._where(watermark, generation)
            sql = "SELECT account, model, COUNT(*), " + ", ".join("SUM(" + key + ")" for key in _FIELDS)
            groups = conn.execute(sql + " FROM usage_rows WHERE " + where + " AND error=0 GROUP BY account, model ORDER BY MIN(byte_offset)", args)
            buckets = {}
            for account, model, count, *values in groups:
                bucket = buckets.setdefault(account, {"account": account, "requests": 0,
                                                       **{key: 0 for key in _FIELDS}, "models": {}})
                bucket["requests"] += count
                bucket["models"][model] = count
                for key, value in zip(_FIELDS, values):
                    bucket[key] += value
            result = sorted(buckets.values(), key=lambda row: -row["total_tokens"])
            for bucket in result:
                bucket["models"] = sorted(bucket["models"].items(), key=lambda row: -row[1])[:5]
            return result
        return self._query(watermark, query)
