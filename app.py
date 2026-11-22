#!/usr/bin/env python3
"""
GasGuard Cloud Server: multi-device Flask backend + Gemini AI + persistent storage
Author : Muhammad Irtaza
Pairs with: GasGuard_ESP32.ino  (POST /api/telemetry every ~2 s per device)

What this server does
---------------------
* FLEET: any number of ESP32 nodes (gasguard-D8B6C4, kitchen-node, lab-node ...) register
  themselves by sending telemetry. Each device has its own isolated state, history and decision.
* SAFETY FLOOR: the reply to the ESP32 is computed locally and instantly. If a device reports
  local_state == "DANGER", or the gas value reaches the emergency level, the answer is always
  DANGER + fan ON, no matter what Gemini, the database or the cloud network is doing.
* GEMINI (gemini-3.5-flash-lite, google-genai SDK, no custom timeout / thinking_config):
    - live trend analysis in a background worker (never blocks the ESP32 request),
    - a scheduled safety audit for every active device (default every 3 hours).
* STORAGE: SQLite (gasguard_data.db) by default; PostgreSQL / Supabase when SUPABASE_DB_URL or
  DATABASE_URL is set. Telemetry, events and audit reports survive restarts.
* DASHBOARD: dark, mobile-first single page: device switcher, Web Audio siren, browser
  notifications, live status and the audit history.
* CLOUD: reads PORT, binds 0.0.0.0, uses waitress, has CORS + /healthz, handles SIGTERM.

Environment variables (all optional except the Gemini key if you want AI)
-------------------------------------------------------------------------
  GEMINI_API_KEY         Gemini key (without it everything runs on local rules)
  GEMINI_MODEL           default gemini-3.5-flash-lite
  PORT                   default 5000 (PaaS sets this)
  SUPABASE_DB_URL / DATABASE_URL   postgresql://... (needs: pip install psycopg2-binary)
  SQLITE_PATH            default gasguard_data.db (point it at a persistent disk on a PaaS)
  AUDIT_INTERVAL_SECONDS default 10800 (3 h)     AUDIT_TEST_MODE=1 -> 60 s test cycle
  DEVICE_API_KEY         if set, telemetry must send ?key=... or header X-API-Key
  ADMIN_TOKEN            if set, /api/fan, /api/test-alarm and /api/audit/run need header X-Admin-Token
  CORS_ORIGINS           default * (or a comma separated list of allowed origins)

Run: pip install flask google-genai waitress psycopg2-binary   then   python app.py
Run as ONE process (state lives in memory + the database).
"""

from __future__ import annotations

import atexit
import hmac
import json
import logging
import math
import os
import queue
import re
import signal
import socket
import sqlite3
import statistics
import threading
import time
from collections import deque
from typing import Any, Callable, Optional

from flask import Flask, Response, jsonify, request

try:  # official SDK: pip install google-genai
    from google import genai
    from google.genai import types
    GENAI_IMPORTED = True
except Exception:  # SDK missing -> rule-based fallback only
    genai = None
    types = None
    GENAI_IMPORTED = False

# =============================================================================
# CONFIG
# =============================================================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()   # or paste a key here (not recommended)
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "").strip() or "gemini-3.5-flash-lite"
GEMINI_TIMEOUT_S = 8          # live analysis deadline, enforced by our worker (NOT passed to the SDK)
AUDIT_GEMINI_TIMEOUT_S = 30   # audit deadline, same mechanism

# ---- Cloud / network ----
HOST = "0.0.0.0"                                  # reachable from outside the container
PORT = int(os.environ.get("PORT", 5000))          # PaaS (Render, Railway, Fly.io, Koyeb) injects PORT
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").strip() or "*"
DEVICE_API_KEY = os.environ.get("DEVICE_API_KEY", "").strip()   # optional shared secret for ESP32 nodes
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()         # optional secret for fan override / audit run

# ---- Storage ----
DATABASE_URL = (os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL") or "").strip()
SQLITE_PATH = os.environ.get("SQLITE_PATH", "gasguard_data.db")
TELEMETRY_LOG_MIN_INTERVAL_S = 5.0   # a SAFE reading is stored at most this often (alarm states: every reading)
TELEMETRY_RETENTION_DAYS = 14

# ---- Fleet ----
MAX_DEVICES = 50
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
OFFLINE_AFTER_S = 8.0        # no telemetry for this long -> device offline
HISTORY_LEN = 30             # rolling readings kept per device
GEMINI_CONTEXT_LEN = 10      # how many of them are sent to Gemini
TREND_LEN = 60               # sparkline points
EVENT_LEN = 60

# ---- 3-hour audit ----
AUDIT_INTERVAL_SECONDS = int(os.environ.get("AUDIT_INTERVAL_SECONDS", "10800"))      # 3 hours
AUDIT_TEST_MODE = os.environ.get("AUDIT_TEST_MODE", "0").strip().lower() in ("1", "true", "yes", "on")
if AUDIT_TEST_MODE:
    AUDIT_INTERVAL_SECONDS = 60                    # fast verification cycle
AUDIT_WINDOW_SECONDS = AUDIT_INTERVAL_SECONDS      # each audit covers the last interval
AUDIT_MIN_SAMPLES = 2 if AUDIT_TEST_MODE else 5    # devices with fewer samples are skipped (inactive)
REPORTS_MAX = 200
BASELINE_STABLE_RANGE = 40.0                       # baseline range <= this: "stable"
BASELINE_DRIFT_RANGE = 100.0                       # <= this: "minor drift", above: "significant drift"

# ---- Gemini live-analysis throttling ----
GEMINI_HARD_MIN_INTERVAL_S = 3.0
GEMINI_MIN_INTERVAL_S = 10.0
GEMINI_IDLE_INTERVAL_S = 600.0
GEMINI_JUMP_COUNTS = 60
GEMINI_MAX_CALLS_PER_HOUR = 120
GEMINI_ERROR_BACKOFF_S = 20
GEMINI_RATE_LIMIT_BACKOFF_S = 90
GEMINI_CONFIG_ERROR_BACKOFF_S = 300
NOTABLE_EXCESS = 50
NOTABLE_DELTA = 6
AI_RESULT_MAX_AGE_S = 900
AI_INVALIDATE_JUMP = 100

# ---- Firmware thresholds (keep in sync with the .ino) ----
FW_WARN_EXCESS = 120
FW_DANGER_EXCESS = 400
FW_EMERGENCY_ABS = 3200        # at/above this the server forces DANGER + fan ON by itself
ALERT_SPIKE_EXCESS = 150       # dashboard alarm if gas is this far above baseline, even if state is SAFE

FAN_OVERRIDE_DEFAULT_MIN = 10          # manual fan override length when the caller sends no duration_minutes
FAN_OVERRIDE_MAX_MIN = 240             # upper bound for a custom duration (4 h)
FAN_OVERRIDE_TTL_S = FAN_OVERRIDE_DEFAULT_MIN * 60
TEST_ALARM_WINDOW_S = 4.0              # how long a dashboard "test buzzer & LED" request stays pending
STATES = ("SAFE", "WARNING", "DANGER")
FAN_CMDS = ("AUTO", "ON", "OFF")
LEVEL_FOR_STATE = {"SAFE": "ok", "WARNING": "warn", "DANGER": "danger"}
VERDICT_RANK = {"SAFE": 0, "CAUTION": 1, "ACTION REQUIRED": 2}

# =============================================================================
# APP + SHARED STATE (everything below is guarded by LOCK unless noted)
# =============================================================================
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
logging.getLogger("werkzeug").setLevel(logging.WARNING)
log = logging.getLogger("gasguard")
START_TIME = time.time()

LOCK = threading.Lock()
DEVICES: dict[str, dict[str, Any]] = {}          # the fleet registry: device_id -> isolated device state
EVENTS: deque = deque(maxlen=EVENT_LEN)           # newest first
REPORTS: deque = deque(maxlen=REPORTS_MAX)        # audit reports, newest first
LATEST_DEVICE_ID: Optional[str] = None
AUDIT = {"next_run": 0.0, "last_run": 0.0, "running": False}

GEMINI_READY = GENAI_IMPORTED and bool(GEMINI_API_KEY)
GEMINI = {
    "status": "idle" if GEMINI_READY else ("no_key" if GENAI_IMPORTED else "sdk_missing"),
    "last_error": "",
    "next_allowed": 0.0,
    "call_times": deque(),
}
JOBS: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=32)
DB_QUEUE: "queue.Queue[tuple[str, tuple]]" = queue.Queue(maxsize=20000)
_audit_run_lock = threading.Lock()


# =============================================================================
# SMALL HELPERS
# =============================================================================
def _to_float(v: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    if f != f or f in (float("inf"), float("-inf")):
        return default
    return f


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _norm_state(s: Any, default: str = "SAFE") -> str:
    s = str(s or "").strip().upper()
    return s if s in STATES else default


def _utc_hms(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(ts))


def _fmt_dur(seconds: float) -> str:
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def _secret_ok(expected: str, supplied: Optional[str]) -> bool:
    """Constant-time check. An empty 'expected' means the feature is disabled (open)."""
    if not expected:
        return True
    return bool(supplied) and hmac.compare_digest(expected.encode(), supplied.encode())


# =============================================================================
# DATABASE ADAPTER (SQLite default, PostgreSQL/Supabase optional)
# =============================================================================
class Database:
    """Tiny thread-safe adapter. SQL is written with '?' placeholders and translated for Postgres.
    Methods never raise: failures are logged (throttled) and reported through the return value,
    so a database outage can never affect the safety path."""

    def __init__(self, url: str, sqlite_path: str) -> None:
        self.url = url
        self.sqlite_path = sqlite_path
        self.kind = "postgres" if url else "sqlite"
        self.ok = False
        self._lock = threading.Lock()
        self._conn: Any = None
        self._retry_after = 0.0
        self._last_log = 0.0

    # ---- connection handling ----
    def _connect(self) -> Any:
        if self.kind == "postgres":
            import psycopg2  # pip install psycopg2-binary
            conn = psycopg2.connect(self.url, connect_timeout=8)
            conn.autocommit = False
            return conn
        folder = os.path.dirname(os.path.abspath(self.sqlite_path))
        os.makedirs(folder, exist_ok=True)
        conn = sqlite3.connect(self.sqlite_path, check_same_thread=False, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _fail(self, e: Exception) -> None:
        self.ok = False
        self._retry_after = time.time() + 10
        if time.time() - self._last_log > 30:
            self._last_log = time.time()
            log.warning("[db:%s] %s: %s", self.kind, type(e).__name__, e)

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.kind == "postgres" else sql

    def _run(self, fn: Callable[[Any], Any], default: Any = None) -> Any:
        with self._lock:
            if self._conn is None:
                if time.time() < self._retry_after:
                    return default
                try:
                    self._conn = self._connect()
                except Exception as e:  # noqa: BLE001
                    self._fail(e)
                    return default
            try:
                result = fn(self._conn)
                self.ok = True
                return result
            except Exception as e:  # noqa: BLE001
                self._fail(e)
                try:
                    self._conn.rollback()
                except Exception:  # noqa: BLE001
                    pass
                if self.kind == "postgres":       # drop a possibly dead connection, reconnect next time
                    try:
                        self._conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                    self._conn = None
                return default

    # ---- public API ----
    def init_schema(self) -> bool:
        pg = self.kind == "postgres"
        pk = "BIGSERIAL PRIMARY KEY" if pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
        real = "DOUBLE PRECISION" if pg else "REAL"
        stmts = [
            f"""CREATE TABLE IF NOT EXISTS telemetry_logs (
                id {pk}, device_id TEXT NOT NULL, ts {real} NOT NULL,
                gas {real}, baseline {real}, delta {real}, local_state TEXT, ai_state TEXT,
                risk_score INTEGER, fan_command TEXT, fan_on INTEGER, wifi_rssi {real}, uptime_ms {real})""",
            "CREATE INDEX IF NOT EXISTS idx_tel_dev_ts ON telemetry_logs (device_id, ts)",
            f"""CREATE TABLE IF NOT EXISTS audit_reports (
                id {pk}, device_id TEXT NOT NULL, period_start {real}, period_end {real},
                created_ts {real} NOT NULL, verdict TEXT, source TEXT, report_text TEXT, stats_json TEXT)""",
            "CREATE INDEX IF NOT EXISTS idx_rep_dev_ts ON audit_reports (device_id, created_ts)",
            f"""CREATE TABLE IF NOT EXISTS events_log (
                id {pk}, ts {real} NOT NULL, level TEXT, device_id TEXT, msg TEXT)""",
            "CREATE INDEX IF NOT EXISTS idx_evt_ts ON events_log (ts)",
        ]

        def fn(conn: Any) -> bool:
            cur = conn.cursor()
            for s in stmts:
                cur.execute(s)
            conn.commit()
            return True
        return bool(self._run(fn, False))

    def executemany(self, sql: str, rows: list) -> bool:
        if not rows:
            return True
        sql = self._sql(sql)

        def fn(conn: Any) -> bool:
            cur = conn.cursor()
            cur.executemany(sql, rows)
            conn.commit()
            return True
        return bool(self._run(fn, False))

    def execute(self, sql: str, params: tuple = ()) -> bool:
        sql = self._sql(sql)

        def fn(conn: Any) -> bool:
            cur = conn.cursor()
            cur.execute(sql, params)
            conn.commit()
            return True
        return bool(self._run(fn, False))

    def query(self, sql: str, params: tuple = ()) -> Optional[list]:
        """Returns a list of rows, or None if the database is unavailable."""
        sql = self._sql(sql)

        def fn(conn: Any) -> list:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            conn.commit()
            return rows
        return self._run(fn, None)


DB = Database(DATABASE_URL, SQLITE_PATH)

SQL_TEL = ("INSERT INTO telemetry_logs (device_id, ts, gas, baseline, delta, local_state, ai_state, risk_score, "
           "fan_command, fan_on, wifi_rssi, uptime_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
SQL_EVT = "INSERT INTO events_log (ts, level, device_id, msg) VALUES (?,?,?,?)"
SQL_REP = ("INSERT INTO audit_reports (device_id, period_start, period_end, created_ts, verdict, source, "
           "report_text, stats_json) VALUES (?,?,?,?,?,?,?,?)")


def _db_enqueue(kind: str, row: tuple) -> None:
    """Non-blocking hand-off to the writer thread (safe to call while holding LOCK)."""
    try:
        DB_QUEUE.put_nowait((kind, row))
    except queue.Full:
        pass  # drop rather than ever block the request path


def _write_batch(batch: list) -> list:
    """Writes a batch; returns the items that could NOT be written (to retry later)."""
    failed: list = []
    tel = [r for k, r in batch if k == "tel"]
    evt = [r for k, r in batch if k == "evt"]
    if tel and not DB.executemany(SQL_TEL, tel):
        failed += [("tel", r) for r in tel]
    if evt and not DB.executemany(SQL_EVT, evt):
        failed += [("evt", r) for r in evt]
    return failed


def _db_writer() -> None:
    pending: list = []
    while True:
        if len(pending) < 5000:
            try:
                pending.append(DB_QUEUE.get(timeout=1.5))
                end = time.time() + 0.8              # gather a short batch
                while len(pending) < 2000 and time.time() < end:
                    try:
                        pending.append(DB_QUEUE.get(timeout=0.2))
                    except queue.Empty:
                        break
            except queue.Empty:
                pass
        if pending:
            pending = _write_batch(pending)
            if pending:                               # DB down: keep (bounded) and retry later
                pending = pending[-5000:]
                time.sleep(5)


def flush_db() -> None:
    """Write everything still queued (called on shutdown)."""
    batch: list = []
    while True:
        try:
            batch.append(DB_QUEUE.get_nowait())
        except queue.Empty:
            break
    if batch:
        _write_batch(batch)


atexit.register(flush_db)


def init_storage() -> None:
    global DB
    if not DB.init_schema() and DB.kind == "postgres":
        log.warning("PostgreSQL unreachable -> falling back to local SQLite (%s)", SQLITE_PATH)
        DB = Database("", SQLITE_PATH)
        DB.init_schema()
    log.info("Storage: %s (%s)", DB.kind, "ready" if DB.ok else "NOT available, running memory-only")


# =============================================================================
# EVENTS + DEVICE REGISTRY
# =============================================================================
WINDOW_MAXLEN = int(AUDIT_WINDOW_SECONDS / 2) + 500


def _add_event_locked(level: str, msg: str, device_id: Optional[str] = None, ts: Optional[float] = None) -> None:
    """Caller must hold LOCK."""
    ts = ts or time.time()
    EVENTS.appendleft({"t": ts, "level": level, "msg": msg, "device_id": device_id})
    _db_enqueue("evt", (ts, level, device_id, msg[:300]))
    log.info("[event] %s", msg)


def _create_device_locked(device_id: str) -> dict[str, Any]:
    """Register a new node. Every device gets its own isolated state."""
    dev = {
        "device_id": device_id,
        "first_seen": time.time(),
        "last_seen": 0.0,
        "online": False,
        "telemetry": None,
        "prev_uptime": None,
        "history": deque(maxlen=HISTORY_LEN),        # recent readings (dicts)
        "trend": deque(maxlen=TREND_LEN),            # sparkline values
        "window": deque(maxlen=WINDOW_MAXLEN),       # audit samples: (ts, gas, baseline, delta, state, fan_on)
        "last_logged": 0.0,
        "ai_result": None,
        "decision": None,
        "inflight": False,
        "last_gemini_t": 0.0,
        "last_gemini_gas": None,
        "fan_override": None,
        "fan_override_until": 0.0,
        "test_alarm_until": 0.0,                     # one-shot hardware self-test flag (consumed by telemetry)
    }
    DEVICES[device_id] = dev
    return dev


# =============================================================================
# SAFETY FLOOR + RULE-BASED ENGINE
# =============================================================================
def _effective_local_state(t: dict[str, Any]) -> str:
    """The state the server will ENFORCE regardless of Gemini: the device's own DANGER, or an
    absolute emergency gas level."""
    if t["local_state"] == "DANGER" or t["gas"] >= FW_EMERGENCY_ABS:
        return "DANGER"
    return t["local_state"]


def _rule_decision(dev: dict[str, Any]) -> dict[str, Any]:
    t = dev["telemetry"]
    state = _effective_local_state(t)
    excess = t["gas"] - t["baseline"]

    if state == "DANGER":
        risk = 75 + int(_clamp((excess - FW_DANGER_EXCESS) / 40.0, 0, 25))
        if t["gas"] >= FW_EMERGENCY_ABS:
            risk = 100
            reason = f"Gas reached the emergency level ({t['gas']:.0f} counts)."
        else:
            reason = f"Device confirmed a high gas level ({excess:+.0f} counts over baseline)."
        action = "Ventilate, shut off the gas source, avoid flames and switches, leave if the smell persists."
        fan = "ON"
    elif state == "WARNING":
        frac = _clamp((excess - FW_WARN_EXCESS) / float(FW_DANGER_EXCESS - FW_WARN_EXCESS), 0, 1)
        risk = 35 + int(39 * frac)
        reason = f"Device sees a sustained rise ({excess:+.0f} counts over baseline)."
        action = "Check for a gas source and keep ventilation ready."
        fan = "AUTO"
    else:
        frac = _clamp(excess / float(FW_WARN_EXCESS), 0, 1)
        risk = 3 + int(31 * frac)
        reason = "Reading is near clean-air baseline."
        action = "No action needed."
        fan = "AUTO"
    return {"ai_state": state, "risk_score": risk, "reason": reason + " (local rules)",
            "action": action, "fan_command": fan, "source": "local-rules"}


def _sanitize_fan(state: str, cmd: str) -> str:
    if state == "DANGER":
        return "ON"
    if state == "SAFE" and cmd == "ON":
        return "AUTO"
    return cmd if cmd in FAN_CMDS else "AUTO"


def _result_applicable(dev: dict[str, Any], res: dict[str, Any], now: float) -> bool:
    t = dev["telemetry"]
    return (now - res["t"] <= AI_RESULT_MAX_AGE_S
            and res["local_at"] == t["local_state"]
            and abs(t["gas"] - res["gas_at"]) < AI_INVALIDATE_JUMP)


def _decide_locked(dev: dict[str, Any], now: float) -> dict[str, Any]:
    """Caller must hold LOCK. Pure local computation: no network, no database."""
    t = dev["telemetry"]
    res = dev["ai_result"]
    if res and _result_applicable(dev, res, now):
        d = {k: res[k] for k in ("ai_state", "risk_score", "reason", "action", "fan_command")}
        d["source"] = "gemini"
        d["age_s"] = round(now - res["t"], 1)
    else:
        d = _rule_decision(dev)
        d["age_s"] = 0.0

    # SAFETY FLOOR: Gemini (or any manual override) can never lower a DANGER.
    floor = _effective_local_state(t) == "DANGER"
    if floor and d["ai_state"] != "DANGER":
        d = _rule_decision(dev)
        d["source"] = "local-failsafe"
        d["age_s"] = 0.0
    if floor:
        d["ai_state"] = "DANGER"
        d["risk_score"] = max(int(d["risk_score"]), 75)

    d["fan_command"] = _sanitize_fan(d["ai_state"], d["fan_command"])

    ov = dev["fan_override"]
    if ov:
        if now >= dev["fan_override_until"]:
            dev["fan_override"] = None
            _add_event_locked("info", f"{dev['device_id']}: manual fan override expired", dev["device_id"])
        elif not (ov == "OFF" and d["ai_state"] == "DANGER"):   # OFF is ignored in DANGER
            d["fan_command"] = ov
    return d


def _refresh_decision_locked(dev: dict[str, Any], now: float) -> dict[str, Any]:
    d = _decide_locked(dev, now)
    prev = dev["decision"]["ai_state"] if dev["decision"] else None
    if prev is not None and prev != d["ai_state"]:
        _add_event_locked(LEVEL_FOR_STATE[d["ai_state"]],
                          f"{dev['device_id']}: AI {prev} -> {d['ai_state']} (risk {d['risk_score']}): {d['reason'][:100]}",
                          dev["device_id"])
    dev["decision"] = d
    return d


def _fan_expected_on(effective_local: str, d: dict[str, Any]) -> bool:
    """Mirror of the firmware fan logic (the firmware does not report the relay state)."""
    if effective_local == "DANGER" or d["fan_command"] == "ON":
        return True
    if d["fan_command"] == "OFF":
        return False
    return d["ai_state"] == "DANGER"


# =============================================================================
# GEMINI: shared plumbing
# =============================================================================
_client = None
_client_lock = threading.Lock()


def _get_client():
    """Plain client: no http_options / timeout / deadline (the model rejects them with 400)."""
    global _client
    with _client_lock:
        if _client is None:
            _client = genai.Client(api_key=GEMINI_API_KEY)
        return _client


def _run_with_deadline(fn: Callable[..., Any], timeout_s: float, *args: Any) -> Any:
    """Run fn in a helper thread and give up after timeout_s (replaces an SDK-level timeout)."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = fn(*args)
        except BaseException as e:  # noqa: BLE001 - re-raised below
            box["error"] = e

    th = threading.Thread(target=run, name="gemini-call", daemon=True)
    th.start()
    th.join(timeout_s)
    if th.is_alive():
        raise TimeoutError(f"no Gemini reply within {timeout_s}s")
    if "error" in box:
        raise box["error"]
    return box["result"]


def _classify_gemini_error(e: Exception) -> tuple[str, float]:
    low = str(e)
    code = getattr(e, "code", None)
    if code == 429 or "RESOURCE_EXHAUSTED" in low or "429" in low[:60]:
        return "rate_limited", GEMINI_RATE_LIMIT_BACKOFF_S
    if code in (400, 401, 403, 404) or any(k in low[:80] for k in ("NOT_FOUND", "INVALID_ARGUMENT", "PERMISSION_DENIED")):
        return "config_error", GEMINI_CONFIG_ERROR_BACKOFF_S
    if isinstance(e, ValueError):
        return "bad_output", 5.0
    return "error", GEMINI_ERROR_BACKOFF_S


def _gemini_note_failure_locked(status: str, err: str, backoff: float, now: float) -> None:
    prev = GEMINI["status"]
    GEMINI["status"], GEMINI["last_error"], GEMINI["next_allowed"] = status, err, now + backoff
    if prev != status:
        _add_event_locked("warn", f"Gemini {status}: using local rules ({err[:90]})")


def _gemini_note_success_locked() -> None:
    prev = GEMINI["status"]
    GEMINI["status"], GEMINI["last_error"] = "ok", ""
    if prev in ("rate_limited", "bad_output", "error", "config_error"):
        _add_event_locked("ok", "Gemini recovered")


def _gemini_available_locked(now: float) -> bool:
    if not GEMINI_READY or now < GEMINI["next_allowed"]:
        return False
    calls = GEMINI["call_times"]
    while calls and now - calls[0] > 3600:
        calls.popleft()
    return len(calls) < GEMINI_MAX_CALLS_PER_HOUR


# =============================================================================
# GEMINI: live per-device analysis (background worker, never in the request path)
# =============================================================================
SYSTEM_PROMPT = """You are the decision engine of "GasGuard", a prototype gas-leak monitor built around an ESP32 and an MQ-2 sensor (reacts to LPG/propane, butane, methane, hydrogen and smoke; it is NOT selective).
You receive JSON with the latest reading and recent history of ONE device. Reply with ONE JSON object only.

How to read the data
- gas: smoothed 12-bit ADC count (0..4095). Higher means more combustible gas or smoke.
- baseline: the device's slowly adapting clean-air level. excess_over_baseline = gas - baseline is the number that matters.
- delta_per_100ms_sample: change of the smoothed value between device samples (about 100 ms apart). History entries are about 2 s apart; use them to judge the trend.
- local_state: the device's own SAFE/WARNING/DANGER after its own noise filtering. WARNING starts near +120 over baseline, DANGER near +400, and about 3200 absolute is an emergency.

Decision rules
1. A brief isolated spike (one or two readings) that falls back toward baseline while local_state is SAFE -> SAFE with low risk.
2. Sustained or steadily rising readings, even below the device's WARNING level -> WARNING (early warning).
3. A fast rise, or sustained high excess near or above the DANGER level -> DANGER.
4. If local_state is DANGER you must answer DANGER.
5. If local_state is WARNING and history shows a short spike that already returned close to baseline, SAFE is allowed; otherwise stay WARNING or higher.
6. When unsure between two levels, choose the safer (higher) one.
Risk score ranges: SAFE 0-34, WARNING 35-74, DANGER 75-100.
fan_command: "ON" for DANGER; "AUTO" otherwise, except "ON" for a clearly rising WARNING. Use "OFF" almost never.
Never claim to know the gas type; an MQ-2 cannot identify it.

Output exactly this JSON, no markdown, no extra keys:
{"ai_state":"SAFE|WARNING|DANGER","risk_score":0-100,"reason":"max 160 chars: what the trend shows and whether it looks like a real leak or just noise","action":"max 120 chars: one clear safety step for the user","fan_command":"AUTO|ON|OFF"}"""


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        a, b = text.find("{"), text.rfind("}")
        if a == -1 or b <= a:
            raise ValueError("no JSON object in Gemini reply")
        data = json.loads(text[a:b + 1])
    if not isinstance(data, dict):
        raise ValueError("Gemini JSON is not an object")
    return data


def _validate_ai(data: dict[str, Any]) -> dict[str, Any]:
    state = str(data.get("ai_state", "")).strip().upper()
    if state not in STATES:
        raise ValueError(f"bad ai_state: {data.get('ai_state')!r}")
    risk = _to_float(data.get("risk_score"))
    if risk is None:
        raise ValueError("bad risk_score")
    risk = int(round(_clamp(risk, 0, 100)))
    if state == "SAFE":
        risk = min(risk, 34)
    elif state == "WARNING":
        risk = int(_clamp(risk, 35, 74))
    else:
        risk = max(risk, 75)
    fan = str(data.get("fan_command", "AUTO")).strip().upper()
    return {"ai_state": state, "risk_score": risk,
            "reason": str(data.get("reason", "")).strip()[:200] or "No explanation provided.",
            "action": str(data.get("action", "")).strip()[:160] or "Stay alert.",
            "fan_command": fan if fan in FAN_CMDS else "AUTO"}


def _call_gemini(payload: dict[str, Any]) -> dict[str, Any]:
    resp = _get_client().models.generate_content(
        model=GEMINI_MODEL,
        contents="Analyze this GasGuard reading. Answer with the JSON object only.\n" + json.dumps(payload),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.2,
            max_output_tokens=512,
            response_mime_type="application/json",
        ),
    )
    text = (getattr(resp, "text", None) or "").strip()
    if not text:
        raise ValueError("empty Gemini reply")
    return _validate_ai(_extract_json(text))


def _gemini_worker() -> None:
    while True:
        job = JOBS.get()
        result, status, err, backoff = None, "ok", "", 0.0
        try:
            result = _run_with_deadline(_call_gemini, GEMINI_TIMEOUT_S, job["payload"])
        except Exception as e:  # noqa: BLE001 - every failure degrades to the rule engine
            err = f"{type(e).__name__}: {e}"[:200]
            status, backoff = _classify_gemini_error(e)
        now = time.time()
        with LOCK:
            dev = DEVICES.get(job["device_id"])
            if dev is not None:
                dev["inflight"] = False
            if result is None:
                _gemini_note_failure_locked(status, err, backoff, now)
            else:
                _gemini_note_success_locked()
                if dev is not None:
                    result.update({"t": now, "local_at": job["local"], "gas_at": job["gas"]})
                    dev["ai_result"] = result
                    _refresh_decision_locked(dev, now)


def _should_call_gemini_locked(dev: dict[str, Any], now: float, state_changed: bool) -> bool:
    if dev["inflight"] or not _gemini_available_locked(now):
        return False
    since = now - dev["last_gemini_t"]
    if since < GEMINI_HARD_MIN_INTERVAL_S:
        return False
    t = dev["telemetry"]
    excess = t["gas"] - t["baseline"]
    last_gas = dev["last_gemini_gas"]
    jump = last_gas is not None and abs(t["gas"] - last_gas) >= GEMINI_JUMP_COUNTS
    if state_changed or jump:
        return True
    interesting = t["local_state"] != "SAFE" or excess >= NOTABLE_EXCESS or abs(t["delta"]) >= NOTABLE_DELTA
    return since >= (GEMINI_MIN_INTERVAL_S if interesting else GEMINI_IDLE_INTERVAL_S)


def _build_payload_locked(dev: dict[str, Any], now: float) -> dict[str, Any]:
    t = dev["telemetry"]
    hist = list(dev["history"])[:-1][-GEMINI_CONTEXT_LEN:]
    return {
        "device_id": dev["device_id"],
        "current": {"gas": round(t["gas"]), "baseline": round(t["baseline"], 1),
                    "excess_over_baseline": round(t["gas"] - t["baseline"], 1),
                    "delta_per_100ms_sample": round(t["delta"], 1), "local_state": t["local_state"]},
        "recent_history_oldest_first": [
            {"seconds_ago": round(now - s["t"], 1), "gas": round(s["gas"]),
             "delta": round(s["delta"], 1), "local_state": s["local_state"]} for s in hist],
        "firmware_thresholds_for_context": {"warning_excess": FW_WARN_EXCESS, "danger_excess": FW_DANGER_EXCESS,
                                            "emergency_absolute": FW_EMERGENCY_ABS},
    }


# =============================================================================
# 3-HOUR SAFETY AUDIT
# =============================================================================
def compute_audit_stats(samples: list, t0: float, t1: float) -> dict[str, Any]:
    """samples: [(ts, gas, baseline, delta, local_state, fan_on), ...] sorted by ts."""
    n = len(samples)
    ts = [s[0] for s in samples]
    gas = [s[1] for s in samples]
    base = [s[2] for s in samples]
    st = [s[4] for s in samples]
    fan = [s[5] for s in samples]
    exc = [g - b for g, b in zip(gas, base)]

    def point(i: int, v: float) -> dict[str, Any]:
        return {"value": round(v, 1), "ts": ts[i], "utc": _utc_hms(ts[i])}

    i_min = min(range(n), key=gas.__getitem__)
    i_max = max(range(n), key=gas.__getitem__)
    i_pk = max(range(n), key=exc.__getitem__)

    warn_ev = danger_ev = 0                  # episodes = entries into a state
    prev = "SAFE"
    for s in st:
        if s != prev:
            if s == "DANGER":
                danger_ev += 1
            elif s == "WARNING" and prev == "SAFE":
                warn_ev += 1
        prev = s

    gap_cap = max(30.0, TELEMETRY_LOG_MIN_INTERVAL_S * 3)   # longer gaps = device offline, not counted
    time_in = {"WARNING": 0.0, "DANGER": 0.0}
    fan_s = covered = 0.0
    for i in range(n - 1):
        dt = ts[i + 1] - ts[i]
        if dt <= 0 or dt > gap_cap:
            continue
        covered += dt
        if st[i] in time_in:
            time_in[st[i]] += dt
        if fan[i]:
            fan_s += dt

    b_range = max(base) - min(base)
    drift = base[-1] - base[0]
    stability = ("stable" if b_range <= BASELINE_STABLE_RANGE
                 else "minor drift" if b_range <= BASELINE_DRIFT_RANGE else "significant drift")
    return {
        "samples": n, "period_start": t0, "period_end": t1,
        "coverage_pct": round(100.0 * covered / max(1.0, t1 - t0), 1),
        "gas_min": point(i_min, gas[i_min]), "gas_max": point(i_max, gas[i_max]),
        "peak_excess": point(i_pk, exc[i_pk]), "gas_mean": round(statistics.fmean(gas), 1),
        "warning_events": warn_ev, "danger_events": danger_ev,
        "warning_s": round(time_in["WARNING"]), "danger_s": round(time_in["DANGER"]),
        "fan_run_s": round(fan_s),
        "baseline": {"min": round(min(base), 1), "max": round(max(base), 1), "mean": round(statistics.fmean(base), 1),
                     "std": round(statistics.pstdev(base), 2) if n > 1 else 0.0, "range": round(b_range, 1),
                     "drift": round(drift, 1), "stability": stability},
    }


def _rule_verdict(stats: dict[str, Any]) -> str:
    if (stats["danger_events"] > 0 or stats["peak_excess"]["value"] >= FW_DANGER_EXCESS
            or stats["gas_max"]["value"] >= FW_EMERGENCY_ABS):
        return "ACTION REQUIRED"
    if (stats["warning_events"] > 0 or stats["peak_excess"]["value"] >= FW_WARN_EXCESS
            or stats["baseline"]["stability"] == "significant drift"):
        return "CAUTION"
    return "SAFE"


def _rule_audit(stats: dict[str, Any]) -> tuple[list[str], str]:
    b = stats["baseline"]
    bullets = [
        f"Gas ranged {stats['gas_min']['value']:.0f} to {stats['gas_max']['value']:.0f} counts (mean {stats['gas_mean']:.0f}); "
        f"the peak was {stats['peak_excess']['value']:+.0f} over baseline at {stats['peak_excess']['utc']} UTC.",
        f"{stats['danger_events']} danger and {stats['warning_events']} warning episode(s); "
        f"{_fmt_dur(stats['danger_s'])} in danger, {_fmt_dur(stats['warning_s'])} in warning; fan ran {_fmt_dur(stats['fan_run_s'])}.",
        f"Clean-air baseline is {b['stability']} (range {b['range']:.0f}, drift {b['drift']:+.0f}); data coverage {stats['coverage_pct']}%.",
    ]
    return bullets, _rule_verdict(stats)


AUDIT_SYSTEM_PROMPT = """You are the safety auditor of "GasGuard", a prototype gas-leak monitor (ESP32 + MQ-2 sensor, which is not gas-selective).
You receive aggregated statistics for ONE device over a fixed period and write a concise, professional safety audit.

Format rules (strict):
- Exactly 3 bullet lines, each starting with "- " and at most 220 characters:
  1) gas levels: min, max and the peak above baseline with its UTC time;
  2) hazard episodes (warning/danger counts and durations) and how long the fan ran;
  3) clean-air baseline stability/drift and data coverage, ending with one practical recommendation.
- Then one final line exactly "VERDICT: SAFE", "VERDICT: CAUTION" or "VERDICT: ACTION REQUIRED".
- Use only the numbers provided, never invent data, do not claim to know the gas type. Times are UTC.
- Plain text only (no markdown besides the leading "- ")."""


def _call_gemini_audit(device_id: str, stats: dict[str, Any]) -> tuple[list[str], Optional[str]]:
    payload = {"device_id": device_id,
               "period_minutes": round((stats["period_end"] - stats["period_start"]) / 60.0, 1),
               "stats": stats,
               "firmware_thresholds": {"warning_excess": FW_WARN_EXCESS, "danger_excess": FW_DANGER_EXCESS,
                                       "emergency_absolute": FW_EMERGENCY_ABS}}
    resp = _get_client().models.generate_content(
        model=GEMINI_MODEL,
        contents="Write the safety audit for this device.\n" + json.dumps(payload),
        config=types.GenerateContentConfig(system_instruction=AUDIT_SYSTEM_PROMPT, temperature=0.2,
                                           max_output_tokens=1024),
    )
    text = (getattr(resp, "text", None) or "").strip()
    if not text:
        raise ValueError("empty Gemini audit reply")
    bullets: list[str] = []
    verdict: Optional[str] = None
    for line in text.splitlines():
        s = line.strip().replace("**", "")
        m = re.match(r"^verdict\s*:\s*(safe|caution|action required)", s, re.I)
        if m:
            verdict = m.group(1).upper()
        elif s and s[0] in "-*\u2022" and len(s) > 2:
            bullets.append(s.lstrip("-*\u2022 ").strip()[:260])
    if len(bullets) < 3:
        raise ValueError("audit reply did not contain 3 bullets")
    return bullets[:3], verdict


def _build_report(device_id: str, stats: dict[str, Any], t0: float, t1: float) -> dict[str, Any]:
    bullets, verdict = _rule_audit(stats)
    rule_verdict, source = verdict, "local-rules"
    with LOCK:
        allowed = _gemini_available_locked(time.time())
        if allowed:
            GEMINI["call_times"].append(time.time())
    if allowed:
        try:
            g_bullets, g_verdict = _run_with_deadline(_call_gemini_audit, AUDIT_GEMINI_TIMEOUT_S, device_id, stats)
            bullets, source = g_bullets, "gemini"
            # the AI may add caution but never downplay what the numbers show
            verdict = max((g_verdict or rule_verdict, rule_verdict), key=lambda v: VERDICT_RANK[v])
            with LOCK:
                _gemini_note_success_locked()
        except Exception as e:  # noqa: BLE001
            status, backoff = _classify_gemini_error(e)
            with LOCK:
                _gemini_note_failure_locked(status, f"{type(e).__name__}: {e}"[:200], backoff, time.time())
    now = time.time()
    return {"id": f"{device_id}:{int(now)}", "device_id": device_id, "period_start": t0, "period_end": t1,
            "created_ts": now, "verdict": verdict, "source": source, "bullets": bullets, "stats": stats}


def run_audit_cycle(only_device: Optional[str] = None) -> int:
    """Audit every active device (or one). Returns the number of reports created, -1 if busy."""
    if not _audit_run_lock.acquire(blocking=False):
        return -1
    made = 0
    try:
        t1 = time.time()
        t0 = t1 - AUDIT_WINDOW_SECONDS
        with LOCK:
            AUDIT["running"] = True
            targets = [(did, [s for s in dev["window"] if s[0] >= t0])
                       for did, dev in DEVICES.items() if only_device in (None, did)]
        for did, samples in targets:
            if len(samples) < AUDIT_MIN_SAMPLES:
                continue                                    # inactive in this period
            try:
                report = _build_report(did, compute_audit_stats(samples, t0, t1), t0, t1)
            except Exception as e:  # noqa: BLE001 - one bad device must not stop the others
                log.exception("audit failed for %s: %s", did, e)
                continue
            with LOCK:
                REPORTS.appendleft(report)
                _add_event_locked("warn" if report["verdict"] != "SAFE" else "ok",
                                  f"Safety audit for {did}: {report['verdict']}", did)
            DB.executemany(SQL_REP, [(did, t0, t1, report["created_ts"], report["verdict"], report["source"],
                                      "\n".join(report["bullets"]), json.dumps(report["stats"]))])
            made += 1
    finally:
        with LOCK:
            AUDIT["running"] = False
            AUDIT["last_run"] = time.time()
        _audit_run_lock.release()
    return made


def _audit_scheduler() -> None:
    now = time.time()
    with LOCK:
        last = max((r["created_ts"] for r in REPORTS), default=0.0)
        nxt = (last + AUDIT_INTERVAL_SECONDS) if last else (now + AUDIT_INTERVAL_SECONDS)
        nxt = max(nxt, now + 30)                    # after a restart: catch up shortly after boot
        AUDIT["next_run"] = nxt
    last_prune = 0.0
    while True:
        time.sleep(1.0)
        now = time.time()
        if now >= nxt:
            try:
                run_audit_cycle()
            except Exception as e:  # noqa: BLE001
                log.exception("audit cycle crashed: %s", e)
            nxt = time.time() + AUDIT_INTERVAL_SECONDS
            with LOCK:
                AUDIT["next_run"] = nxt
        if now - last_prune > 3600:                 # hourly housekeeping
            last_prune = now
            DB.execute("DELETE FROM telemetry_logs WHERE ts < ?", (now - TELEMETRY_RETENTION_DAYS * 86400,))
            DB.execute("DELETE FROM events_log WHERE ts < ?", (now - 30 * 86400,))


# =============================================================================
# STARTUP: load persisted state, start workers
# =============================================================================
def load_state_from_db() -> None:
    global LATEST_DEVICE_ID
    now = time.time()
    rows = DB.query("SELECT DISTINCT device_id FROM telemetry_logs WHERE ts >= ?", (now - 7 * 86400,)) or []
    cols = "ts, gas, baseline, delta, local_state, fan_on, wifi_rssi, uptime_ms"
    for (did,) in rows[:MAX_DEVICES]:
        if not DEVICE_ID_RE.match(str(did)):
            continue
        last = DB.query(f"SELECT {cols} FROM telemetry_logs WHERE device_id=? ORDER BY ts DESC LIMIT 1", (did,))
        win = DB.query(f"SELECT {cols} FROM telemetry_logs WHERE device_id=? AND ts>=? ORDER BY ts",
                       (did, now - AUDIT_WINDOW_SECONDS)) or []
        if not last:
            continue
        r = last[0]
        with LOCK:
            dev = _create_device_locked(did)
            dev["telemetry"] = {"gas": r[1], "baseline": r[2], "delta": r[3] or 0.0, "local_state": _norm_state(r[4]),
                                "wifi_rssi": r[6], "uptime_ms": r[7]}
            dev["last_seen"] = dev["last_logged"] = r[0]
            for w in win:
                dev["window"].append((w[0], w[1], w[2], w[3] or 0.0, _norm_state(w[4]), int(w[5] or 0)))
            for w in (win or last)[-HISTORY_LEN:]:
                dev["history"].append({"t": w[0], "gas": w[1], "delta": w[3] or 0.0, "local_state": _norm_state(w[4])})
            for w in (win or last)[-TREND_LEN:]:
                dev["trend"].append(round(w[1]))
            dev["decision"] = _rule_decision(dev)
            if LATEST_DEVICE_ID is None or dev["last_seen"] > DEVICES[LATEST_DEVICE_ID]["last_seen"]:
                LATEST_DEVICE_ID = did
    evts = DB.query("SELECT ts, level, device_id, msg FROM events_log ORDER BY ts DESC LIMIT ?", (EVENT_LEN,)) or []
    reps = DB.query("SELECT device_id, period_start, period_end, created_ts, verdict, source, report_text, stats_json "
                    "FROM audit_reports ORDER BY created_ts DESC LIMIT ?", (REPORTS_MAX,)) or []
    with LOCK:
        for e in reversed(evts):
            EVENTS.appendleft({"t": e[0], "level": e[1] or "info", "msg": e[3] or "", "device_id": e[2]})
        for r in reversed(reps):
            try:
                REPORTS.appendleft({"id": f"{r[0]}:{int(r[3])}", "device_id": r[0], "period_start": r[1],
                                    "period_end": r[2], "created_ts": r[3], "verdict": r[4], "source": r[5],
                                    "bullets": (r[6] or "").split("\n"), "stats": json.loads(r[7] or "{}")})
            except (ValueError, TypeError):
                continue
    log.info("Restored %d device(s), %d event(s), %d report(s) from storage", len(DEVICES), len(evts), len(reps))


def _watchdog() -> None:
    while True:
        time.sleep(1.0)
        now = time.time()
        with LOCK:
            for dev in DEVICES.values():
                if dev["online"] and now - dev["last_seen"] > OFFLINE_AFTER_S:
                    dev["online"] = False
                    _add_event_locked("warn", f"{dev['device_id']} went offline", dev["device_id"])


_started = False
_start_lock = threading.Lock()


def ensure_started() -> None:
    global _started
    if _started:
        return
    with _start_lock:
        if _started:
            return
        init_storage()
        load_state_from_db()
        for target, name in ((_db_writer, "db-writer"), (_gemini_worker, "gemini-worker"),
                             (_watchdog, "watchdog"), (_audit_scheduler, "audit-scheduler")):
            threading.Thread(target=target, name=name, daemon=True).start()
        _started = True


# =============================================================================
# HTTP: hooks (start-up, CORS, headers)
# =============================================================================
@app.before_request
def _before() -> None:
    ensure_started()


@app.after_request
def _after(resp: Response) -> Response:
    origin = request.headers.get("Origin", "")
    if CORS_ORIGINS == "*":
        resp.headers["Access-Control-Allow-Origin"] = "*"
    elif origin and origin in [o.strip() for o in CORS_ORIGINS.split(",")]:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, X-Admin-Token"
    resp.headers["Access-Control-Max-Age"] = "600"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    if request.path.startswith("/api/") or request.path == "/healthz":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def _admin_denied() -> Optional[tuple[Response, int]]:
    if not _secret_ok(ADMIN_TOKEN, request.headers.get("X-Admin-Token")):
        return jsonify(error="admin token required"), 401
    return None


# =============================================================================
# API
# =============================================================================
@app.route("/api/telemetry", methods=["POST"])
def api_telemetry():
    """ESP32 -> server. Must stay fast: no network and no database call in this handler."""
    global LATEST_DEVICE_ID
    if not _secret_ok(DEVICE_API_KEY, request.headers.get("X-API-Key") or request.args.get("key")):
        return jsonify(error="invalid or missing device API key"), 401
    body = request.get_json(silent=True, force=True)
    if not isinstance(body, dict):
        return jsonify(error="body must be a JSON object"), 400
    gas = _to_float(body.get("gas"))
    if gas is None:
        return jsonify(error="'gas' is required and must be a number"), 400
    device_id = str(body.get("device_id") or "unknown").strip()
    if not DEVICE_ID_RE.match(device_id):
        return jsonify(error="device_id must be 1-48 chars of letters, digits, . _ -"), 400

    sample = {
        "gas": gas,
        "baseline": _to_float(body.get("baseline"), gas),
        "delta": _to_float(body.get("delta"), 0.0),
        "local_state": _norm_state(body.get("local_state")),
        "wifi_rssi": _to_float(body.get("wifi_rssi")),
        "uptime_ms": _to_float(body.get("uptime_ms")),
    }
    now = time.time()

    with LOCK:
        dev = DEVICES.get(device_id)
        if dev is None:                                   # auto-register a new node
            if len(DEVICES) >= MAX_DEVICES:
                return jsonify(error="device limit reached"), 429
            dev = _create_device_locked(device_id)
            _add_event_locked("info", f"New device registered: {device_id}", device_id)
        LATEST_DEVICE_ID = device_id

        if not dev["online"]:
            _add_event_locked("ok", f"{device_id} online", device_id)
            dev["online"] = True
        up, prev_up = sample["uptime_ms"], dev["prev_uptime"]
        if up is not None and prev_up is not None and up < prev_up - 1000:
            _add_event_locked("info", f"{device_id} rebooted", device_id)
        dev["prev_uptime"] = up

        prev_local = dev["telemetry"]["local_state"] if dev["telemetry"] else None
        dev["telemetry"] = sample
        dev["last_seen"] = now
        dev["history"].append({"t": now, "gas": gas, "delta": sample["delta"], "local_state": sample["local_state"]})
        dev["trend"].append(round(gas))

        state_changed = prev_local is not None and prev_local != sample["local_state"]
        if state_changed:
            _add_event_locked(LEVEL_FOR_STATE[sample["local_state"]],
                              f"{device_id}: device {prev_local} -> {sample['local_state']} "
                              f"(gas {gas:.0f}, {gas - sample['baseline']:+.0f} vs baseline)", device_id)

        if _should_call_gemini_locked(dev, now, state_changed):      # queue an analysis; never wait for it
            job = {"device_id": device_id, "payload": _build_payload_locked(dev, now),
                   "local": sample["local_state"], "gas": gas}
            dev["inflight"] = True
            dev["last_gemini_t"] = now
            dev["last_gemini_gas"] = gas
            GEMINI["call_times"].append(now)
            try:
                JOBS.put_nowait(job)
            except queue.Full:
                dev["inflight"] = False
                GEMINI["call_times"].pop()

        d = _refresh_decision_locked(dev, now)
        fan_on = _fan_expected_on(_effective_local_state(sample), d)

        # persistent log + 3-hour audit window (SAFE readings throttled, alarm states stored in full)
        if state_changed or sample["local_state"] != "SAFE" or now - dev["last_logged"] >= TELEMETRY_LOG_MIN_INTERVAL_S:
            dev["last_logged"] = now
            dev["window"].append((now, gas, sample["baseline"], sample["delta"], sample["local_state"], int(fan_on)))
            _db_enqueue("tel", (device_id, now, gas, sample["baseline"], sample["delta"], sample["local_state"],
                                d["ai_state"], int(d["risk_score"]), d["fan_command"], int(fan_on),
                                sample["wifi_rssi"], sample["uptime_ms"]))
        # One-shot hardware self-test: true while the request is pending, consumed by this reply.
        test_alarm = now < dev["test_alarm_until"]
        if test_alarm:
            dev["test_alarm_until"] = 0.0
        reply = {"ai_state": d["ai_state"], "risk_score": int(d["risk_score"]), "fan_command": d["fan_command"],
                 "test_alarm": bool(test_alarm)}
    return jsonify(reply)


def _pick_device_locked(device_id: Optional[str]) -> Optional[dict[str, Any]]:
    if device_id and device_id in DEVICES:
        return DEVICES[device_id]
    if LATEST_DEVICE_ID and LATEST_DEVICE_ID in DEVICES:
        return DEVICES[LATEST_DEVICE_ID]
    return next(iter(DEVICES.values()), None)


def _fleet_locked(now: float) -> list[dict[str, Any]]:
    """One compact summary per device: drives the device switcher and the alarms."""
    fleet = []
    for did in sorted(DEVICES):
        dev = DEVICES[did]
        t, d = dev["telemetry"], dev["decision"]
        if t is None or d is None:
            continue
        age = now - dev["last_seen"]
        online = age <= OFFLINE_AFTER_S
        excess = t["gas"] - t["baseline"]
        alarm = None
        if online:
            if d["ai_state"] == "DANGER":
                alarm = "danger"
            elif d["ai_state"] == "WARNING" or excess >= ALERT_SPIKE_EXCESS:
                alarm = "warning"
        fleet.append({"device_id": did, "online": online, "ai_state": d["ai_state"], "local_state": t["local_state"],
                      "risk_score": int(d["risk_score"]), "gas": round(t["gas"]), "baseline": round(t["baseline"], 1),
                      "excess": round(excess, 1), "fan_on": _fan_expected_on(_effective_local_state(t), d),
                      "alarm": alarm, "last_seen_age_s": round(age, 1)})
    return fleet


@app.route("/api/status", methods=["GET"])
def api_status():
    now = time.time()
    with LOCK:
        gem = {"enabled": GEMINI_READY, "status": GEMINI["status"], "last_error": GEMINI["last_error"],
               "model": GEMINI_MODEL, "calls_last_hour": sum(1 for c in GEMINI["call_times"] if now - c <= 3600)}
        common = {"server_time": now, "events": list(EVENTS)[:25], "gemini": gem, "fleet": _fleet_locked(now),
                  "storage": {"kind": DB.kind, "ok": DB.ok},
                  "audit": {"interval_s": AUDIT_INTERVAL_SECONDS, "test_mode": AUDIT_TEST_MODE,
                            "next_run": AUDIT["next_run"], "last_run": AUDIT["last_run"], "running": AUDIT["running"]},
                  "admin_required": bool(ADMIN_TOKEN)}
        dev = _pick_device_locked(request.args.get("device_id"))
        if dev is None or dev["telemetry"] is None:
            return jsonify(is_online=False, device_id=None, last_seen_age_s=None, telemetry=None, ai=None,
                           fan=None, trend=[], **common)
        d = _refresh_decision_locked(dev, now)
        t = dev["telemetry"]
        age = now - dev["last_seen"]
        override_left = max(0, int(math.ceil(dev["fan_override_until"] - now))) if dev["fan_override"] else 0
        out = {
            "is_online": age <= OFFLINE_AFTER_S,
            "device_id": dev["device_id"],
            "last_seen_age_s": round(age, 1),
            "telemetry": {**t, "excess": round(t["gas"] - t["baseline"], 1)},
            "ai": {k: d[k] for k in ("ai_state", "risk_score", "reason", "action", "fan_command", "source", "age_s")},
            "fan": {"command": d["fan_command"],
                    "expected_on": _fan_expected_on(_effective_local_state(t), d),
                    "override": dev["fan_override"], "override_remaining_s": override_left},
            "trend": list(dev["trend"]),
            **common,
        }
    return jsonify(out)


@app.route("/api/fan", methods=["POST"])
def api_fan():
    """Manual fan override for ONE device (AUTO clears it). Timed: duration_minutes (default 10)."""
    denied = _admin_denied()
    if denied:
        return denied
    body = request.get_json(silent=True, force=True)
    body = body if isinstance(body, dict) else {}
    cmd = str(body.get("command", "")).strip().upper()
    if cmd not in FAN_CMDS:
        return jsonify(error="command must be AUTO, ON or OFF"), 400
    duration_min = float(FAN_OVERRIDE_DEFAULT_MIN)
    if cmd != "AUTO" and body.get("duration_minutes") is not None:
        dm = _to_float(body.get("duration_minutes"))
        if dm is None or dm <= 0:
            return jsonify(error="duration_minutes must be a positive number"), 400
        duration_min = _clamp(dm, 1.0, float(FAN_OVERRIDE_MAX_MIN))
    now = time.time()
    with LOCK:
        dev = _pick_device_locked(str(body.get("device_id") or ""))
        if dev is None:
            return jsonify(error="no device has connected yet"), 404
        if cmd == "AUTO":
            dev["fan_override"] = None
            dev["fan_override_until"] = 0.0
            _add_event_locked("info", f"{dev['device_id']}: manual fan override cancelled (AUTO)", dev["device_id"])
        else:
            dev["fan_override"] = cmd
            dev["fan_override_until"] = now + duration_min * 60.0       # fan_override_until = now + minutes * 60
            _add_event_locked("info", f"{dev['device_id']}: manual fan override {cmd} for {duration_min:g} min",
                              dev["device_id"])
        if dev["telemetry"]:
            _refresh_decision_locked(dev, now)
        did = dev["device_id"]
        left = max(0, int(math.ceil(dev["fan_override_until"] - now))) if dev["fan_override"] else 0
    return jsonify(ok=True, command=cmd, device_id=did, duration_minutes=(0 if cmd == "AUTO" else duration_min),
                   override_remaining_s=left)


@app.route("/api/test-alarm", methods=["POST"])
def api_test_alarm():
    """Dashboard 'Test Buzzer & LED' for ONE device. Sets a short one-shot flag that the next telemetry reply
    delivers as "test_alarm": true. The firmware runs a 2 s buzzer + LED test (never during DANGER)."""
    denied = _admin_denied()
    if denied:
        return denied
    body = request.get_json(silent=True, force=True)
    body = body if isinstance(body, dict) else {}
    now = time.time()
    with LOCK:
        dev = _pick_device_locked(str(body.get("device_id") or ""))
        if dev is None:
            return jsonify(error="no device has connected yet"), 404
        dev["test_alarm_until"] = now + TEST_ALARM_WINDOW_S
        _add_event_locked("info", f"{dev['device_id']}: hardware self-test requested (buzzer + LED, 2 s)", dev["device_id"])
        did = dev["device_id"]
        online = (now - dev["last_seen"]) <= OFFLINE_AFTER_S
    return jsonify(ok=True, device_id=did, device_online=online, window_s=TEST_ALARM_WINDOW_S)


@app.route("/api/reports", methods=["GET"])
def api_reports():
    did = (request.args.get("device_id") or "").strip()
    limit = int(_clamp(_to_float(request.args.get("limit"), 20), 1, REPORTS_MAX))
    with LOCK:
        items = [r for r in REPORTS if not did or r["device_id"] == did][:limit]
    return jsonify(reports=items, interval_s=AUDIT_INTERVAL_SECONDS)


@app.route("/api/audit/run", methods=["POST"])
def api_audit_run():
    """Run an audit now (for verification). Optional JSON: {"device_id": "..."}."""
    denied = _admin_denied()
    if denied:
        return denied
    body = request.get_json(silent=True, force=True)
    did = str((body or {}).get("device_id") or "").strip() if isinstance(body, dict) else ""
    if _audit_run_lock.locked():
        return jsonify(error="an audit is already running"), 409
    threading.Thread(target=run_audit_cycle, args=(did or None,), name="audit-now", daemon=True).start()
    return jsonify(ok=True, message="audit started"), 202


@app.route("/api/history", methods=["GET"])
def api_history():
    """Stored readings from the database (default last 3 h) for one device."""
    with LOCK:
        dev = _pick_device_locked(request.args.get("device_id"))
        did = dev["device_id"] if dev else None
    if not did:
        return jsonify(error="no device"), 404
    hours = _clamp(_to_float(request.args.get("hours"), 3.0), 0.01, 24 * TELEMETRY_RETENTION_DAYS)
    limit = int(_clamp(_to_float(request.args.get("limit"), 500), 10, 2000))
    rows = DB.query("SELECT ts, gas, baseline, delta, local_state, ai_state, risk_score, fan_on FROM telemetry_logs "
                    "WHERE device_id=? AND ts>=? ORDER BY ts DESC LIMIT ?", (did, time.time() - hours * 3600, limit))
    if rows is None:
        return jsonify(error="storage unavailable"), 503
    rows.reverse()
    return jsonify(device_id=did, rows=[{"t": r[0], "gas": r[1], "baseline": r[2], "delta": r[3], "local_state": r[4],
                                         "ai_state": r[5], "risk_score": r[6], "fan_on": bool(r[7])} for r in rows])


@app.route("/healthz")
def healthz():
    """Health check for the PaaS (Render/Railway/Fly/Koyeb)."""
    return jsonify(ok=True, uptime_s=round(time.time() - START_TIME), devices=len(DEVICES),
                   storage=DB.kind, storage_ok=DB.ok, gemini=GEMINI["status"])


@app.route("/manifest.webmanifest")
def manifest():
    data = {"name": "GasGuard", "short_name": "GasGuard", "start_url": "/", "display": "standalone",
            "background_color": "#0f1622", "theme_color": "#0f1622",
            "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}]}
    return Response(json.dumps(data), mimetype="application/manifest+json")


@app.route("/icon.svg")
def icon():
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">'
           '<rect width="128" height="128" rx="28" fill="#0f1622"/>'
           '<path d="M28 84a40 40 0 1 1 72 0" fill="none" stroke="#3ddc9a" stroke-width="12" stroke-linecap="round"/>'
           '<path d="M64 84 82 52" stroke="#e9eef7" stroke-width="9" stroke-linecap="round"/>'
           '<circle cx="64" cy="84" r="9" fill="#e9eef7"/></svg>')
    return Response(svg, mimetype="image/svg+xml")


SERVICE_WORKER_JS = """self.addEventListener('install', function(){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });
self.addEventListener('notificationclick', function(e){
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type:'window', includeUncontrolled:true}).then(function(list){
    for (var i = 0; i < list.length; i++) { if ('focus' in list[i]) return list[i].focus(); }
    if (self.clients.openWindow) return self.clients.openWindow('/');
  }));
});
"""


@app.route("/sw.js")
def service_worker():
    """Needed so phones can show notification banners (works on HTTPS / localhost)."""
    resp = Response(SERVICE_WORKER_JS, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/")
def dashboard():
    resp = Response(DASHBOARD_HTML, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


# =============================================================================
# DASHBOARD (single file, no external assets)
# =============================================================================
DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f1622">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="GasGuard">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<title>GasGuard</title>
<style>
:root{
  --bg:#0f1622; --surface:#17202f; --line:#27344a; --text:#e9eef7; --muted:#8fa0b8;
  --safe:#3ddc9a; --warn:#f5b83d; --danger:#ff5d52; --none:#6f7e95; --accent:var(--none);
  --font:ui-rounded,"SF Pro Rounded","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;
}
*{box-sizing:border-box;margin:0}
html{background:var(--bg);color:var(--text);font-family:var(--font);-webkit-text-size-adjust:100%}
body{min-height:100vh;padding:max(14px,env(safe-area-inset-top)) max(14px,env(safe-area-inset-right)) max(28px,env(safe-area-inset-bottom)) max(14px,env(safe-area-inset-left))}
main{max-width:720px;margin:0 auto;display:grid;gap:18px;transition:opacity .3s}
body.stale main{opacity:.55}
.banner{position:sticky;top:8px;z-index:6;max-width:720px;margin:0 auto 10px;padding:10px 14px;border-radius:10px;background:#3a2a12;border:1px solid var(--warn);color:#ffe2a3;font-size:14px}
.alarm{position:sticky;top:8px;z-index:7;max-width:720px;margin:0 auto 12px;padding:12px 14px;border-radius:12px;display:flex;gap:12px;align-items:center;justify-content:space-between;background:#561612;border:2px solid var(--danger);animation:flash 1s ease-in-out infinite}
.alarm.warning{background:#4a3511;border-color:var(--warn);animation:none}
.alarm strong{display:block;font-size:17px}
.alarm span{font-size:14px;color:#ffd9d6}
.alarm.warning span{color:#ffe9b9}
@keyframes flash{0%,100%{box-shadow:0 0 0 0 rgba(255,93,82,0)}50%{box-shadow:0 0 0 9px rgba(255,93,82,.3)}}
header{display:flex;justify-content:space-between;align-items:center;gap:12px}
h1{font-size:22px;font-weight:800;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px;margin-top:2px;word-break:break-all}
.pill{display:flex;align-items:center;gap:8px;padding:7px 12px;border-radius:999px;background:var(--surface);border:1px solid var(--line);font-size:13px;font-weight:600;white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--none)}
.pill.on .dot{background:var(--safe);box-shadow:0 0 0 4px rgba(61,220,154,.18)} .pill.off .dot{background:var(--danger)}

.fleet{display:flex;gap:10px;overflow-x:auto;padding:2px 2px 8px;scroll-snap-type:x proximity}
.dev{--c:var(--none);flex:0 0 auto;min-width:138px;text-align:left;padding:10px 12px;border-radius:12px;border:1px solid var(--line);border-left:6px solid var(--c);background:var(--surface);color:var(--text);cursor:pointer;scroll-snap-align:start;font-family:var(--font)}
.dev.safe{--c:var(--safe)} .dev.warning{--c:var(--warn)} .dev.danger{--c:var(--danger)} .dev.off{opacity:.65}
.dev[aria-current="true"]{outline:2px solid var(--text);outline-offset:1px}
.dev:focus-visible{outline:3px solid var(--safe);outline-offset:2px}
.dev .n{font-weight:700;font-size:14px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dev .g{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.15}
.dev .s{font-size:12px;color:var(--muted)}

.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.btn{padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--text);font:600 14px var(--font);cursor:pointer}
.btn[aria-pressed="true"]{background:var(--text);color:var(--bg);border-color:var(--text)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn:focus-visible,select:focus-visible{outline:3px solid var(--safe);outline-offset:2px}
select{padding:9px 10px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--text);font:600 14px var(--font)}
.hint{color:var(--muted);font-size:13px;line-height:1.4}

.hero{background:var(--surface);border:1px solid var(--line);border-left:8px solid var(--accent);border-radius:16px;padding:18px 18px 14px;display:grid;gap:16px}
.hero.st-safe{--accent:var(--safe)} .hero.st-warning{--accent:var(--warn)} .hero.st-danger{--accent:var(--danger)} .hero.st-none{--accent:var(--none)}
.hero.st-danger{animation:pulse 1.2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(255,93,82,0)}50%{box-shadow:0 0 0 8px rgba(255,93,82,.22)}}
.hero-top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px}
.muted{color:var(--muted);font-size:13px}
.state{font-size:clamp(36px,12vw,56px);font-weight:900;line-height:1;letter-spacing:-.02em;color:var(--accent);margin:6px 0 4px}
.gas{text-align:right}
.gas-val{font-size:clamp(34px,10vw,48px);font-weight:800;font-variant-numeric:tabular-nums;line-height:1}
.risk-head{display:flex;justify-content:space-between;font-size:13px;color:var(--muted);margin-bottom:6px}
.risk-head b{color:var(--text);font-variant-numeric:tabular-nums}
.bar{height:12px;border-radius:7px;background:#223049;overflow:hidden}
#riskFill{height:100%;width:0;border-radius:7px;background:var(--accent);transition:width .5s ease}
#spark{width:100%;height:64px;display:block}

h2{font-size:15px;font-weight:700;margin-bottom:6px}
.analysis{display:grid;gap:12px;padding:0 2px}
.analysis p{font-size:16px;line-height:1.45;max-width:62ch}
dl.stats{display:grid;grid-template-columns:repeat(2,1fr);border-top:1px solid var(--line)}
.stat{padding:12px 4px;border-bottom:1px solid var(--line)}
.stat:nth-child(odd){padding-right:12px;border-right:1px solid var(--line)}
.stat:nth-child(even){padding-left:14px}
.stat dt{color:var(--muted);font-size:13px}
.stat dd{font-size:19px;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}
.fan-row{display:flex;gap:8px;margin-top:8px}
.fan-row .btn{flex:1;padding:12px 0}
.fan-sub{color:var(--muted);font-size:13px;margin:14px 0 2px}
.fan-custom{display:flex;gap:8px;margin-top:8px}
.fan-custom input{flex:1;min-width:0;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--text);font:600 14px var(--font)}
.fan-custom input:focus-visible{outline:3px solid var(--safe);outline-offset:2px}
.fan-custom .btn{flex:0 0 auto;padding:11px 20px}
.fan-badge{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-top:12px;padding:10px 12px;border-radius:12px;background:rgba(61,220,154,.12);border:1px solid var(--safe)}
.fan-badge[hidden]{display:none}
.fan-badge.off{background:rgba(245,184,61,.12);border-color:var(--warn)}
.fan-badge b{font-size:15px;font-variant-numeric:tabular-nums}
.fan-badge .btn{padding:8px 14px}

ul#events{list-style:none;padding:0;border-top:1px solid var(--line)}
ul#events li{display:grid;grid-template-columns:auto 1fr;gap:10px;padding:9px 2px;border-bottom:1px solid var(--line);font-size:14px;line-height:1.35}
ul#events time{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
ul#events li.ok span{color:var(--safe)} ul#events li.warn span{color:var(--warn)} ul#events li.danger span{color:var(--danger)}
.empty{color:var(--muted);font-size:14px;padding:10px 2px}

.audit-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;margin-bottom:10px}
.reports{display:grid;gap:12px}
.report{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:var(--surface);display:grid;gap:8px}
.report-top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.report-top b{font-size:15px}
.chip{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:800}
.v-safe{background:rgba(61,220,154,.16);color:var(--safe)} .v-caution{background:rgba(245,184,61,.18);color:var(--warn)} .v-action{background:rgba(255,93,82,.2);color:var(--danger)}
.report ul{padding-left:18px;display:grid;gap:5px;font-size:14.5px;line-height:1.4}
.report .mini{font-size:12.5px;color:var(--muted);line-height:1.4}
footer{color:var(--muted);font-size:12px;text-align:center}
@media (prefers-reduced-motion:reduce){.hero.st-danger,.alarm{animation:none}#riskFill{transition:none}}
</style>
</head>
<body>
<div id="banner" class="banner" hidden>Can't reach the GasGuard server. Showing the last known data and retrying.</div>
<div id="alarm" class="alarm" role="alert" hidden>
  <div><strong id="alarmTitle"></strong><span id="alarmText"></span></div>
  <button class="btn" id="alarmMute" type="button">Mute</button>
</div>
<main>
  <header>
    <div><h1>GasGuard</h1><p id="devId" class="sub">Waiting for an ESP32 to report</p></div>
    <div id="pill" class="pill off" role="status"><span class="dot"></span><span id="pillText">Offline</span></div>
  </header>

  <section aria-label="Devices">
    <div id="fleet" class="fleet"></div>
    <p id="fleetEmpty" class="empty">No devices yet. Point an ESP32 at /api/telemetry and it registers itself.</p>
  </section>

  <section>
    <div class="tools">
      <button class="btn" id="sirenBtn" type="button" aria-pressed="true">Siren: on</button>
      <button class="btn" id="notifBtn" type="button" aria-pressed="false">Enable safety alerts</button>
      <button class="btn" id="testBtn" type="button">Test siren</button>
      <button class="btn" id="hwTestBtn" type="button" disabled>Test Buzzer &amp; LED (2s)</button>
      <select id="scope" aria-label="Which devices trigger alarms">
        <option value="all">Alarm: all devices</option>
        <option value="selected">Alarm: selected device</option>
      </select>
    </div>
    <p id="audioHint" class="hint" style="margin-top:8px">Tap anywhere once to arm the siren. Browsers block sound until you interact with the page.</p>
    <p id="notifHint" class="hint"></p>
    <p id="hwTestHint" class="hint"></p>
  </section>

  <section id="hero" class="hero st-none" aria-live="polite">
    <div class="hero-top">
      <div>
        <div class="muted">AI verdict</div>
        <div id="state" class="state">No data</div>
        <div id="source" class="muted">Waiting for the first reading</div>
      </div>
      <div class="gas"><div id="gas" class="gas-val">--</div><div class="muted">MQ-2 count</div></div>
    </div>
    <div>
      <div class="risk-head"><span>Gemini risk score</span><b id="riskTxt">0%</b></div>
      <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" id="riskBar"><div id="riskFill"></div></div>
    </div>
    <canvas id="spark" aria-label="Recent gas readings"></canvas>
  </section>

  <section class="analysis">
    <div><h2>Why</h2><p id="reason">No analysis yet.</p></div>
    <div><h2>What to do</h2><p id="action">Nothing to do yet.</p></div>
  </section>

  <section>
    <dl class="stats">
      <div class="stat"><dt>Baseline</dt><dd id="base">--</dd></div>
      <div class="stat"><dt>Above baseline</dt><dd id="excess">--</dd></div>
      <div class="stat"><dt>Delta</dt><dd id="delta">--</dd></div>
      <div class="stat"><dt>Device state</dt><dd id="local">--</dd></div>
      <div class="stat"><dt>Fan command</dt><dd id="fanCmd">--</dd></div>
      <div class="stat"><dt>Fan (expected)</dt><dd id="fanOn">--</dd></div>
      <div class="stat"><dt>Wi-Fi signal</dt><dd id="rssi">--</dd></div>
      <div class="stat"><dt>Device uptime</dt><dd id="uptime">--</dd></div>
    </dl>
  </section>

  <section>
    <h2>Fan control (selected device)</h2>
    <div class="fan-row" id="fanRow">
      <button class="btn" data-cmd="AUTO" aria-pressed="true">Auto</button>
      <button class="btn" data-cmd="OFF" aria-pressed="false">Force off</button>
    </div>
    <p class="fan-sub">Run the fan for:</p>
    <div class="fan-row" id="fanPresets">
      <button class="btn" data-min="2" type="button">2m</button>
      <button class="btn" data-min="5" type="button">5m</button>
      <button class="btn" data-min="15" type="button">15m</button>
    </div>
    <div class="fan-custom">
      <input id="fanMin" type="number" min="1" max="240" step="1" inputmode="numeric" placeholder="Custom minutes" aria-label="Custom fan duration in minutes">
      <button class="btn" id="fanStart" type="button">Start</button>
    </div>
    <div id="fanBadge" class="fan-badge" hidden role="status">
      <b id="fanBadgeTxt"></b>
      <button class="btn" id="fanCancel" type="button">Cancel / Auto</button>
    </div>
    <p id="fanNote" class="hint" style="margin-top:8px">Auto follows the AI and the device's own safety logic.</p>
  </section>

  <section>
    <h2>Recent events</h2>
    <ul id="events"></ul>
    <p id="noEvents" class="empty">No events yet.</p>
  </section>

  <section>
    <div class="audit-head">
      <h2 style="margin:0">3-Hour Safety Audits</h2>
      <div class="tools">
        <select id="repScope" aria-label="Audit scope"><option value="device">This device</option><option value="all">All devices</option></select>
        <button class="btn" id="auditRun" type="button">Run audit now</button>
      </div>
    </div>
    <p id="auditInfo" class="hint" style="margin-bottom:10px">Loading audit schedule...</p>
    <div id="reports" class="reports"></div>
    <p id="noReports" class="empty">No audit reports yet. The first one is generated after the first audit interval.</p>
  </section>
  <footer id="foot">Gemini status unknown</footer>
</main>

<script>
(function(){
"use strict";
const $ = id => document.getElementById(id);
function el(tag, cls, text){ const e = document.createElement(tag); if(cls) e.className = cls; if(text != null) e.textContent = text; return e; }
const LS = {
  get(k, d){ try{ const v = localStorage.getItem(k); return v === null ? d : v; }catch(e){ return d; } },
  set(k, v){ try{ localStorage.setItem(k, v); }catch(e){} }
};
const GEMINI_TEXT = {
  idle:"Gemini is ready", ok:"Gemini is active",
  no_key:"Gemini is off: GEMINI_API_KEY is not set, using local rules",
  sdk_missing:"Gemini is off: google-genai is not installed, using local rules",
  rate_limited:"Gemini is rate-limited, using local rules for now",
  bad_output:"Gemini returned an unusable answer, using local rules",
  config_error:"Gemini rejected the request (check model name and API key), using local rules",
  error:"Gemini is unreachable, using local rules"
};
const SOURCE_TEXT = {"gemini":"Analysed by Gemini", "local-rules":"Local rules (Gemini not used for this reading)", "local-failsafe":"Device fail-safe override"};
const rank = a => a === "danger" ? 2 : a === "warning" ? 1 : 0;

let selectedId = LS.get("gg_device", "");
let muted = LS.get("gg_muted", "0") === "1";
let alertsOn = LS.get("gg_alerts", "0") === "1";
let lastData = null, failCount = 0, busy = false, timer = null, prevState = null, lastSpark = null;
let realAlarm = null, swReg = null;
const lastAlarm = {}, lastNotifyAt = {};

/* ---------- formatting ---------- */
function fmtUptime(ms){
  if(ms == null) return "--";
  let s = Math.floor(ms/1000), d = Math.floor(s/86400); s %= 86400;
  const h = Math.floor(s/3600); s %= 3600; const m = Math.floor(s/60);
  return d ? d+"d "+h+"h" : h ? h+"h "+m+"m" : m+"m "+(s%60)+"s";
}
function fmtDur(s){
  s = Math.max(0, Math.round(s));
  if(s < 60) return s+"s";
  const m = Math.floor(s/60); if(m < 60) return m+"m "+(s%60)+"s";
  return Math.floor(m/60)+"h "+(m%60)+"m";
}
function fmtRssi(r){
  if(r == null) return "--";
  const q = r >= -55 ? "Excellent" : r >= -67 ? "Good" : r >= -75 ? "Fair" : "Weak";
  return q+" ("+Math.round(r)+" dBm)";
}
function num(v, digits){ return v == null ? "--" : Number(v).toFixed(digits == null ? 0 : digits); }
function signed(v, digits){ if(v == null) return "--"; const n = Number(v); return (n > 0 ? "+" : "") + n.toFixed(digits || 0); }
function clock(ts){ return new Date(ts*1000).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}); }
function clockS(ts){ return new Date(ts*1000).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"}); }
function dateTime(ts){ return new Date(ts*1000).toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"}); }
function cssVar(name){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

/* ---------- sparkline ---------- */
function drawSpark(values, baseline, color){
  lastSpark = {values:values, baseline:baseline, color:color};
  const c = $("spark"), dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight;
  if(!w || !h) return;
  c.width = w*dpr; c.height = h*dpr;
  const g = c.getContext("2d"); g.setTransform(dpr,0,0,dpr,0,0); g.clearRect(0,0,w,h);
  if(!values || values.length < 2) return;
  let lo = Math.min.apply(null, values), hi = Math.max.apply(null, values);
  if(baseline != null){ lo = Math.min(lo, baseline); hi = Math.max(hi, baseline); }
  if(hi - lo < 40){ const mid = (hi+lo)/2; lo = mid-20; hi = mid+20; }
  const y = v => h-4 - (v-lo)/(hi-lo)*(h-8), step = w/(values.length-1);
  if(baseline != null){
    g.strokeStyle = "rgba(143,160,184,.55)"; g.setLineDash([4,4]); g.lineWidth = 1;
    g.beginPath(); g.moveTo(0,y(baseline)); g.lineTo(w,y(baseline)); g.stroke(); g.setLineDash([]);
  }
  g.strokeStyle = color; g.lineWidth = 2.5; g.lineJoin = "round"; g.beginPath();
  values.forEach((v,i) => i ? g.lineTo(i*step,y(v)) : g.moveTo(0,y(v)));
  g.stroke();
}

/* ---------- Web Audio siren (dual-tone, alternating) ---------- */
let actx = null, siren = null;
function ensureAudio(){
  if(!actx){
    const AC = window.AudioContext || window.webkitAudioContext;
    if(!AC) return null;
    try{ actx = new AC(); }catch(e){ return null; }
  }
  return actx;
}
function audioReady(){ return !!actx && actx.state === "running"; }
function updateAudioHint(){
  const supported = !!(window.AudioContext || window.webkitAudioContext), h = $("audioHint");
  if(!supported){ h.hidden = false; h.textContent = "This browser has no Web Audio support, so the siren sound is unavailable. Visual alarms still work."; return; }
  h.hidden = audioReady();
}
function startSiren(level, force){
  if(muted && !force){ stopSiren(); return; }
  const ctx = ensureAudio();
  if(!ctx || ctx.state !== "running") return;          // locked until the user taps once
  if(siren && siren.level === level) return;
  stopSiren();
  const danger = level === "danger";
  const master = ctx.createGain(); master.gain.value = danger ? 0.55 : 0.2; master.connect(ctx.destination);
  const lp = ctx.createBiquadFilter(); lp.type = "lowpass"; lp.frequency.value = 3500; lp.connect(master);
  const o1 = ctx.createOscillator(); o1.type = "square";
  const g1 = ctx.createGain(); g1.gain.value = 0.6; o1.connect(g1); g1.connect(lp);
  const o2 = ctx.createOscillator(); o2.type = "sine";
  const g2 = ctx.createGain(); g2.gain.value = 0.5; o2.connect(g2); g2.connect(lp);
  const hi = [960, 1440], lo = [700, 1050]; let flip = false;
  o1.frequency.value = hi[0]; o2.frequency.value = hi[1];
  o1.start(); o2.start();
  const iv = setInterval(() => {                        // alternate the two tones: hi-lo, hi-lo ...
    const t = ctx.currentTime, f = flip ? hi : lo; flip = !flip;
    o1.frequency.setTargetAtTime(f[0], t, 0.03); o2.frequency.setTargetAtTime(f[1], t, 0.03);
  }, danger ? 420 : 800);
  siren = {level:level, iv:iv, nodes:[o1,o2,g1,g2,lp,master]};
}
function stopSiren(){
  if(!siren) return;
  clearInterval(siren.iv);
  siren.nodes.forEach(n => { try{ if(n.stop) n.stop(); n.disconnect(); }catch(e){} });
  siren = null;
}
function unlockAudio(){
  const ctx = ensureAudio();
  if(!ctx) { updateAudioHint(); return; }
  if(ctx.state === "running"){ updateAudioHint(); return; }
  ctx.resume().then(() => { updateAudioHint(); if(lastData) evaluateAlarms(lastData); }).catch(() => {});
}
["pointerdown","touchend","click","keydown"].forEach(ev => window.addEventListener(ev, unlockAudio, {passive:true}));

function paintSirenBtn(){
  const b = $("sirenBtn");
  b.textContent = muted ? "Siren: muted" : "Siren: on";
  b.setAttribute("aria-pressed", String(!muted));
  $("alarmMute").textContent = muted ? "Unmute" : "Mute";
}
function toggleMute(){
  muted = !muted; LS.set("gg_muted", muted ? "1" : "0"); paintSirenBtn();
  if(muted) stopSiren(); else { unlockAudio(); if(lastData) evaluateAlarms(lastData); }
}
$("sirenBtn").addEventListener("click", toggleMute);
$("alarmMute").addEventListener("click", toggleMute);
$("testBtn").addEventListener("click", () => {
  unlockAudio();
  setTimeout(() => {
    if(!audioReady()) return;
    startSiren("danger", true);
    setTimeout(() => { if(!realAlarm) stopSiren(); }, 1800);
  }, 120);
});

/* ---------- browser notifications ---------- */
function paintNotifBtn(){
  const b = $("notifBtn"), supported = "Notification" in window;
  b.setAttribute("aria-pressed", String(alertsOn));
  b.textContent = alertsOn ? "Safety alerts: on" : "Enable safety alerts";
  $("notifHint").textContent = !supported ? "This browser does not support notifications."
    : (Notification.permission === "denied" ? "Notifications are blocked. Allow them in the browser's site settings."
    : alertsOn ? "A banner appears when a device enters WARNING or DANGER. Keep this page open (a background tab is fine)." : "");
}
async function showAlert(title, body, tag){
  if(!alertsOn || !("Notification" in window) || Notification.permission !== "granted") return;
  const opts = {body:body, tag:tag, renotify:true, icon:"/icon.svg", vibrate:[300,100,300]};
  try{ if(swReg){ await swReg.showNotification(title, opts); return; } }catch(e){}
  try{ new Notification(title, opts); }catch(e){}
}
$("notifBtn").addEventListener("click", async () => {
  if(!("Notification" in window)){ paintNotifBtn(); return; }
  if(alertsOn){ alertsOn = false; LS.set("gg_alerts", "0"); paintNotifBtn(); return; }
  let perm = Notification.permission;
  if(perm === "default"){ try{ perm = await Notification.requestPermission(); }catch(e){ perm = "denied"; } }
  alertsOn = perm === "granted"; LS.set("gg_alerts", alertsOn ? "1" : "0"); paintNotifBtn();
  if(alertsOn) showAlert("GasGuard alerts enabled", "You will be notified when a device reports a hazard.", "gg-enabled");
});
if("serviceWorker" in navigator && window.isSecureContext){
  navigator.serviceWorker.register("/sw.js").then(() => navigator.serviceWorker.ready).then(r => { swReg = r; }).catch(() => {});
}

/* ---------- alarm evaluation (siren + banner + notifications) ---------- */
function notifyAlarm(f){
  const nowMs = Date.now();
  if(lastNotifyAt[f.device_id] && nowMs - lastNotifyAt[f.device_id] < 20000) return;
  lastNotifyAt[f.device_id] = nowMs;
  const title = (f.alarm === "danger" ? "DANGER: " : "WARNING: ") + f.device_id;
  const body = "Gas " + f.gas + " (" + signed(f.excess) + " vs baseline). Fan " + (f.fan_on ? "running" : "off") + ".";
  showAlert(title, body, "gg-" + f.device_id);
  if(navigator.vibrate){ try{ navigator.vibrate([250,120,250]); }catch(e){} }
}
function evaluateAlarms(d){
  const fleet = d.fleet || [];
  const inScope = fleet.filter(f => $("scope").value === "all" || f.device_id === selectedId);
  let worst = null;
  inScope.forEach(f => { if(rank(f.alarm) > rank(worst && worst.alarm)) worst = f; });
  realAlarm = worst ? worst.alarm : null;

  const box = $("alarm");
  if(worst){
    const more = inScope.filter(f => f.alarm).length - 1;
    box.hidden = false; box.className = "alarm" + (worst.alarm === "warning" ? " warning" : "");
    $("alarmTitle").textContent = (worst.alarm === "danger" ? "DANGER: " : "WARNING: ") + worst.device_id;
    $("alarmText").textContent = "Gas " + worst.gas + " (" + signed(worst.excess) + " vs baseline). Fan " +
      (worst.fan_on ? "ON" : "off") + (more > 0 ? ". +" + more + " more device" + (more > 1 ? "s" : "") : "") +
      (!audioReady() && !muted ? ". Tap the screen to enable sound." : "");
    startSiren(worst.alarm, false);
  }else{
    box.hidden = true; stopSiren();
  }
  inScope.forEach(f => {
    const prev = lastAlarm[f.device_id] || null, cur = f.alarm || null;
    if(cur && rank(cur) > rank(prev)) notifyAlarm(f);
    lastAlarm[f.device_id] = cur;
  });
}
$("scope").value = LS.get("gg_scope", "all");
$("scope").addEventListener("change", () => { LS.set("gg_scope", $("scope").value); if(lastData) evaluateAlarms(lastData); });

/* ---------- fleet (device switcher) ---------- */
const devBtns = new Map();
function renderFleet(fleet){
  const box = $("fleet");
  $("fleetEmpty").hidden = fleet.length > 0;
  const seen = new Set();
  fleet.forEach(f => {
    seen.add(f.device_id);
    let b = devBtns.get(f.device_id);
    if(!b){
      b = el("button", "dev"); b.type = "button";
      b.append(el("div","n"), el("div","g"), el("div","s"));
      b.addEventListener("click", () => selectDevice(f.device_id));
      devBtns.set(f.device_id, b); box.appendChild(b);
    }
    b.className = "dev " + (f.online ? f.ai_state.toLowerCase() : "off");
    b.setAttribute("aria-current", String(f.device_id === selectedId));
    b.children[0].textContent = f.device_id;
    b.children[1].textContent = num(f.gas);
    b.children[2].textContent = f.online ? f.ai_state + (f.fan_on ? " \u00b7 fan on" : "") : "offline";
  });
  devBtns.forEach((b, id) => { if(!seen.has(id)){ b.remove(); devBtns.delete(id); } });
}
function selectDevice(id){
  selectedId = id; LS.set("gg_device", id); prevState = null;
  clearTimeout(timer); poll(); loadReports();
}

/* ---------- main render ---------- */
function render(d){
  const online = !!d.is_online, t = d.telemetry, ai = d.ai;
  document.body.classList.toggle("stale", !online && !!t);
  renderFleet(d.fleet || []);
  $("pill").className = "pill " + (online ? "on" : "off");
  $("pillText").textContent = online ? "ESP32 online" : (t ? "Offline for " + fmtDur(d.last_seen_age_s) : "Offline");
  $("devId").textContent = d.device_id || "Waiting for an ESP32 to report";

  const hero = $("hero");
  if(!t || !ai){
    hero.className = "hero st-none";
    $("state").textContent = "No data"; $("source").textContent = "Waiting for the first reading";
    $("gas").textContent = "--"; $("riskTxt").textContent = "0%"; $("riskFill").style.width = "0%";
    drawSpark([], null, cssVar("--none")); document.title = "GasGuard";
  }else{
    hero.className = "hero st-" + (online ? ai.ai_state.toLowerCase() : "none");
    $("state").textContent = online ? ai.ai_state : "No signal";
    let src = SOURCE_TEXT[ai.source] || ai.source;
    if(ai.source === "gemini" && ai.age_s != null) src += ", " + Math.round(ai.age_s) + "s ago";
    $("source").textContent = online ? src : "Showing the last reading from " + fmtDur(d.last_seen_age_s) + " ago";
    $("gas").textContent = num(t.gas);
    $("riskTxt").textContent = ai.risk_score + "%"; $("riskFill").style.width = ai.risk_score + "%";
    $("riskBar").setAttribute("aria-valuenow", ai.risk_score);
    $("reason").textContent = ai.reason; $("action").textContent = ai.action;
    $("base").textContent = num(t.baseline, 1); $("excess").textContent = signed(t.excess);
    $("delta").textContent = signed(t.delta, 1); $("local").textContent = t.local_state;
    $("fanCmd").textContent = ai.fan_command + (d.fan.override ? " (manual)" : "");
    $("fanOn").textContent = d.fan.expected_on ? "Running" : "Stopped";
    $("rssi").textContent = fmtRssi(t.wifi_rssi); $("uptime").textContent = fmtUptime(t.uptime_ms);

    const current = d.fan.override || "AUTO";
    document.querySelectorAll("#fanRow .btn").forEach(b => { b.setAttribute("aria-pressed", String(b.dataset.cmd === current)); b.disabled = false; });
    document.querySelectorAll("#fanPresets .btn").forEach(b => { b.disabled = false; });
    $("fanStart").disabled = false; $("fanMin").disabled = false; $("fanCancel").disabled = false;
    $("hwTestBtn").disabled = hwTestBusy;
    syncFanTimer(d.fan.override, d.fan.override_remaining_s, d.device_id);
    $("fanNote").textContent = d.fan.override
      ? "Manual override active. A DANGER state always forces the fan on."
      : "Auto follows the AI and the device's own safety logic.";
    const col = online ? "--" + (ai.ai_state === "DANGER" ? "danger" : ai.ai_state === "WARNING" ? "warn" : "safe") : "--none";
    drawSpark(d.trend, t.baseline, cssVar(col));
    document.title = online ? "GasGuard: " + ai.ai_state : "GasGuard: offline";
    prevState = online ? ai.ai_state : null;
  }
  renderEvents(d.events);
  const g = d.gemini, s = d.storage;
  $("foot").textContent = (g ? (GEMINI_TEXT[g.status] || g.status) + (g.enabled ? " (" + g.model + ", " + g.calls_last_hour + " calls/h)" : "") : "") +
    (s ? " \u00b7 Storage: " + s.kind + (s.ok ? "" : " (unavailable)") : "");
  renderAuditInfo(d);
}
function renderEvents(events){
  const ul = $("events"); ul.textContent = "";
  $("noEvents").hidden = !!(events && events.length);
  (events || []).forEach(ev => {
    const li = el("li", ev.level || "info");
    li.append(el("time", null, clockS(ev.t)), el("span", null, ev.msg));
    ul.appendChild(li);
  });
}

/* ---------- audits ---------- */
function renderAuditInfo(d){
  const a = d.audit; if(!a) return;
  const every = a.test_mode ? "every 60 s (test mode)" : "every " + fmtDur(a.interval_s);
  const wait = a.next_run ? Math.max(0, a.next_run - d.server_time) : null;
  $("auditInfo").textContent = (a.running ? "An audit is running now. " : "") + "Audits run " + every +
    (wait != null ? ". Next one in " + fmtDur(wait) + "." : ".");
}
function renderReports(list){
  const box = $("reports"); box.textContent = "";
  $("noReports").hidden = list.length > 0;
  list.forEach(r => {
    const s = r.stats || {}, card = el("div", "report");
    const top = el("div", "report-top");
    top.append(el("b", null, r.device_id + "  \u00b7  " + dateTime(r.period_start) + " to " + dateTime(r.period_end)));
    const vc = r.verdict === "SAFE" ? "v-safe" : r.verdict === "CAUTION" ? "v-caution" : "v-action";
    top.append(el("span", "chip " + vc, r.verdict));
    card.appendChild(top);
    const ul = el("ul"); (r.bullets || []).forEach(b => ul.appendChild(el("li", null, b))); card.appendChild(ul);
    const bits = [];
    if(s.gas_max) bits.push("Max " + num(s.gas_max.value) + " at " + clock(s.gas_max.ts));
    if(s.gas_min) bits.push("Min " + num(s.gas_min.value));
    if(s.peak_excess) bits.push("Peak " + signed(s.peak_excess.value) + " over baseline");
    if(s.warning_events != null) bits.push(s.warning_events + " warning / " + s.danger_events + " danger");
    if(s.fan_run_s != null) bits.push("Fan " + fmtDur(s.fan_run_s));
    if(s.baseline) bits.push("Baseline " + s.baseline.stability);
    bits.push(r.source === "gemini" ? "Written by Gemini" : "Local-rules summary");
    card.appendChild(el("div", "mini", bits.join("  \u00b7  ")));
    box.appendChild(card);
  });
}
async function loadReports(){
  try{
    const scopeAll = $("repScope").value === "all" || !selectedId;
    const q = scopeAll ? "" : "&device_id=" + encodeURIComponent(selectedId);
    const r = await fetch("/api/reports?limit=20" + q, {cache:"no-store"});
    if(!r.ok) throw new Error("HTTP " + r.status);
    renderReports((await r.json()).reports || []);
  }catch(e){ /* keep the previous list on a network hiccup */ }
}
$("repScope").value = LS.get("gg_repscope", "device");
$("repScope").addEventListener("change", () => { LS.set("gg_repscope", $("repScope").value); loadReports(); });

async function adminFetch(url, opts, retried){
  opts = opts || {};
  opts.headers = Object.assign({"Content-Type":"application/json"}, opts.headers || {});
  const tok = LS.get("gg_admin", "");
  if(tok) opts.headers["X-Admin-Token"] = tok;
  const r = await fetch(url, opts);
  if(r.status === 401 && !retried){
    const t = window.prompt("This action needs the admin token (ADMIN_TOKEN set on the server):");
    if(t){ LS.set("gg_admin", t.trim()); return adminFetch(url, opts, true); }
  }
  return r;
}
$("auditRun").addEventListener("click", async () => {
  const b = $("auditRun"); b.disabled = true;
  try{
    const r = await adminFetch("/api/audit/run", {method:"POST", body:JSON.stringify({device_id:selectedId})});
    $("auditInfo").textContent = r.status === 202 ? "Audit requested. The report appears here in a few seconds."
      : r.status === 409 ? "An audit is already running." : "Couldn't start the audit (HTTP " + r.status + ").";
    if(r.status === 202){ setTimeout(loadReports, 6000); setTimeout(loadReports, 20000); }
  }catch(e){ $("auditInfo").textContent = "Couldn't reach the server."; }
  setTimeout(() => { b.disabled = false; }, 4000);
});

/* ---------- fan control ---------- */
let fanTimer = {mode:null, deadline:0, device:null};
function fmtMS(sec){
  sec = Math.max(0, Math.ceil(sec));
  const m = Math.floor(sec / 60), r = sec % 60;
  return m + "m " + String(r).padStart(2, "0") + "s";
}
function paintFanBadge(){
  const badge = $("fanBadge");
  if(!fanTimer.mode){ badge.hidden = true; return; }
  const left = (fanTimer.deadline - performance.now()) / 1000;
  if(left <= 0){ badge.hidden = true; return; }
  badge.hidden = false;
  badge.classList.toggle("off", fanTimer.mode === "OFF");
  $("fanBadgeTxt").textContent = "Fan " + fanTimer.mode + ": " + fmtMS(left) + " remaining";
}
function syncFanTimer(mode, remaining, deviceId){
  if(!mode || !(remaining > 0)){ fanTimer = {mode:null, deadline:0, device:deviceId}; paintFanBadge(); return; }
  const target = performance.now() + remaining * 1000;
  // keep the local clock smooth; only re-anchor when it drifts from the server by more than 2 s (or mode/device changed)
  if(fanTimer.mode !== mode || fanTimer.device !== deviceId || Math.abs(fanTimer.deadline - target) > 2000){
    fanTimer = {mode:mode, deadline:target, device:deviceId};
  }
  paintFanBadge();
}
setInterval(paintFanBadge, 1000);

async function sendFan(payload){
  const btns = document.querySelectorAll("#fanRow .btn, #fanPresets .btn, #fanStart, #fanCancel");
  btns.forEach(b => { b.disabled = true; });
  try{
    const r = await adminFetch("/api/fan", {method:"POST", body:JSON.stringify(Object.assign({device_id:selectedId}, payload))});
    if(!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    syncFanTimer(j.command === "AUTO" ? null : j.command, j.override_remaining_s, j.device_id);
  }catch(e){ $("fanNote").textContent = "Couldn't change the fan mode. Check the connection (or the admin token) and try again."; }
  clearTimeout(timer); poll();
}
document.querySelectorAll("#fanRow .btn").forEach(b => { b.disabled = true; b.addEventListener("click", () => sendFan({command:b.dataset.cmd})); });
document.querySelectorAll("#fanPresets .btn").forEach(b => { b.disabled = true; b.addEventListener("click", () => sendFan({command:"ON", duration_minutes:Number(b.dataset.min)})); });
$("fanStart").disabled = true; $("fanMin").disabled = true; $("fanCancel").disabled = true;
$("fanStart").addEventListener("click", () => {
  const v = Number($("fanMin").value);
  if(!isFinite(v) || v < 1 || v > 240){ $("fanNote").textContent = "Enter a duration between 1 and 240 minutes."; return; }
  sendFan({command:"ON", duration_minutes:Math.round(v)});
});
$("fanMin").addEventListener("keydown", e => { if(e.key === "Enter"){ e.preventDefault(); $("fanStart").click(); } });
$("fanCancel").addEventListener("click", () => sendFan({command:"AUTO"}));

/* ---------- hardware self-test (buzzer + LED, 2 s) ---------- */
let hwTestBusy = false;
$("hwTestBtn").addEventListener("click", async () => {
  if(hwTestBusy) return;
  hwTestBusy = true;
  const b = $("hwTestBtn"), hint = $("hwTestHint"), label = b.textContent;
  b.disabled = true; b.textContent = "Testing...";
  try{
    const r = await adminFetch("/api/test-alarm", {method:"POST", body:JSON.stringify({device_id:selectedId})});
    if(!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    hint.textContent = j.device_online
      ? "Self-test sent. The device buzzes and lights its LED for 2 s within a few seconds. A gas DANGER state always overrides the test."
      : "Self-test queued, but the device looks offline, so it may not run.";
  }catch(e){ hint.textContent = "Couldn't send the self-test. Check the connection (or the admin token)."; }
  setTimeout(() => { hwTestBusy = false; b.textContent = label; b.disabled = !(lastData && lastData.telemetry); }, 4000);
});

/* ---------- polling ---------- */
async function poll(){
  if(busy) return; busy = true;
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 5000);
  let data = null;
  try{
    const q = selectedId ? "?device_id=" + encodeURIComponent(selectedId) : "";
    const r = await fetch("/api/status" + q, {cache:"no-store", signal:ctl.signal});
    if(!r.ok) throw new Error("HTTP " + r.status);
    data = await r.json(); failCount = 0; $("banner").hidden = true;
  }catch(e){
    failCount++;
    if(failCount >= 3){ $("banner").hidden = false; document.body.classList.add("stale"); }
  }finally{ clearTimeout(to); busy = false; }
  if(data){
    lastData = data;
    if(data.device_id && data.device_id !== selectedId){ selectedId = data.device_id; LS.set("gg_device", selectedId); loadReports(); }
    try{ render(data); }catch(e){ console.error("render failed", e); }
    try{ evaluateAlarms(data); }catch(e){ console.error("alarm check failed", e); }
  }
  schedule();
}
function schedule(){
  clearTimeout(timer);
  const delay = failCount ? Math.min(1500 * Math.pow(2, failCount), 8000) : (document.hidden ? 4000 : 1500);
  timer = setTimeout(poll, delay);
}
document.addEventListener("visibilitychange", () => { if(!document.hidden){ clearTimeout(timer); poll(); } });
window.addEventListener("resize", () => { if(lastSpark) drawSpark(lastSpark.values, lastSpark.baseline, lastSpark.color); });

if(alertsOn && !("Notification" in window && Notification.permission === "granted")){ alertsOn = false; LS.set("gg_alerts", "0"); }
paintSirenBtn(); paintNotifBtn(); updateAudioHint();
poll(); loadReports(); setInterval(loadReports, 30000);
})();
</script>
</body>
</html>
"""


# =============================================================================
# MAIN
# =============================================================================
def _lan_ip() -> str:
    """Best-effort laptop IPv4 for the hint (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def _graceful_exit(signum: int, _frame: Any) -> None:
    """PaaS stops containers with SIGTERM: flush queued rows to the database first."""
    log.info("Signal %s received: flushing database and shutting down", signum)
    flush_db()
    raise SystemExit(0)


def main() -> None:
    ensure_started()
    if GEMINI_READY:
        log.info("Gemini enabled (model %s)", GEMINI_MODEL)
    elif not GENAI_IMPORTED:
        log.warning("google-genai not installed -> rule-based decisions only (pip install google-genai)")
    else:
        log.warning("GEMINI_API_KEY not set -> rule-based decisions only")
    if not DEVICE_API_KEY:
        log.warning("DEVICE_API_KEY not set: anyone who knows the URL can post telemetry (fine on a home network)")
    if not ADMIN_TOKEN:
        log.warning("ADMIN_TOKEN not set: anyone can use fan override / run audits (set it when hosting publicly)")

    ip = _lan_ip()
    print("\n" + "=" * 66)
    print(f" GasGuard server on {HOST}:{PORT} | storage: {DB.kind} | audits every {AUDIT_INTERVAL_SECONDS}s")
    print(f"  Dashboard (same Wi-Fi)  : http://{ip}:{PORT}/")
    print(f"  ESP32 backend URL       : http://{ip}:{PORT}/api/telemetry")
    print("=" * 66 + "\n")

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _graceful_exit)
        except (ValueError, OSError):
            pass
    try:
        from waitress import serve  # production WSGI server
    except ImportError:
        log.warning("waitress not installed -> using the Flask dev server (pip install waitress)")
        app.run(host=HOST, port=PORT, threaded=True, debug=False)
    else:
        serve(app, host=HOST, port=PORT, threads=8)


if __name__ == "__main__":
    main()
