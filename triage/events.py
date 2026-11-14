"""Turn raw log lines into normalised events with a UTC time and a file:line citation.

Handles: Markdown exports (log lines inside ``` fences, or table rows), CSV/TSV, JSON lines,
key=value, Apache combined, syslog, "ACTION proto a.b.c.d:p -> e.f.g.h:p" firewall lines and
Windows Security events (EventID=...). Files that log a session when it CLOSES get their
event time moved back to the session start (close time - duration), and keep both.
"""
from __future__ import annotations

import csv
import io
import json
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote

from .ingest import SourceFile, read_table
from .timeparse import (RE_APACHE, RE_ISO, RE_SLASH, RE_SYSLOG, UTC, TimeCtx, fmt_tz, parse_ts, slash_hint,
                        tz_from_text, uses)

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
RE_IP = re.compile(rf"(?<![\d.]){IP}(?!\.?\d)")
RE_KV = re.compile(r"([A-Za-z_][\w.-]*)=(\"[^\"]*\"|\S+)")
RE_APACHE_LINE = re.compile(
    rf'^({IP}|\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (.*?) (HTTP/[\d.]+)" (\d{{3}}) (\S+)(?: "([^"]*)" "([^"]*)")?')
RE_SYSLOG_LINE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]{8}\s(\S+)\s([\w./-]+)(?:\[\d+\])?:\s(.*)$")
RE_FW = re.compile(rf"\b(ALLOW|ACCEPT|PERMIT|PASS|DENY|DROP|REJECT|BLOCK)\b\s+(?:(tcp|udp|icmp)\s+)?({IP})(?::(\d+))?"
                   rf"\s*->\s*({IP})(?::(\d+))?", re.I)

K_SRC = ("src_ip", "src", "source_ip", "source", "client_ip", "clientip", "remote_ip", "remote_addr", "sender_ip", "ip")
K_DST = ("dst_ip", "dst", "dest_ip", "destination_ip", "destination", "dest", "target_ip")
K_USER = ("user", "username", "account", "user_name", "login", "userid")
K_HOST = ("host", "hostname", "device", "server", "dst_host", "computer", "node")
K_TIME = ("timestamp", "@timestamp", "ts", "time", "datetime", "date", "event_time", "eventtime", "logged_at")
K_LEASE = ("assigned_ip", "vpn_ip", "tunnel_ip", "internal_ip", "lease_ip", "virtual_ip")
EXTRA = ("sender", "recipient", "subject", "verdict", "spf", "dkim", "action", "urls", "user_agent", "rule", "reason",
         "geo", "country", "session", "mfa", "msgid", "score", "service", "workstation", "target", "caller", "result",
         "alert id", "alert_id", "description", "sensor", "mac", "lease", "protocol", "size", "direction", "src_port")

# Windows Security event IDs -> (category, subtype)
WIN = {"4624": ("auth_success", "logon"), "4625": ("auth_fail", "logon_failed"), "4634": ("auth_logout", "logoff"),
       "4647": ("auth_logout", "logoff"), "4740": ("auth_fail", "lockout"), "4768": ("auth_success", "tgt"),
       "4769": ("auth_success", "service_ticket"), "4771": ("auth_fail", "kerberos_failed"),
       "4672": ("other", "privileged"), "4724": ("other", "password_reset"), "4723": ("other", "password_change"),
       "4720": ("other", "account_created"), "4728": ("other", "group_change"), "4732": ("other", "group_change")}

RE_FAIL = re.compile(r"fail|invalid|denied|incorrect|reject|bad_password|unsuccess|locked", re.I)
RE_OK = re.compile(r"accepted|success|session opened|logged in|authenticated|granted", re.I)
RE_OUT = re.compile(r"session closed|session_end|session end|logout|logged out|logoff|disconnect", re.I)
RE_AUTHISH = re.compile(r"password|login|logon|logoff|logged|authenticat|sshd|session|vpn|kerberos|logout|mfa|\bauth\b", re.I)


@dataclass
class Event:
    ts: datetime                   # UTC; for close-logged sessions this is the computed START
    file: str
    line: int
    raw_ts: str
    kind: str
    category: str = "other"        # auth_fail auth_success auth_logout web fw_allow fw_deny email dhcp alert other
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: str = ""
    user: str = ""
    host: str = ""
    url: str = ""
    status: str = ""
    bytes_out: int = 0
    end: datetime | None = None    # session end (when known)
    reporter: str = ""             # device that wrote the line (vpn01, DC01, fw-int01 ...)
    extra: dict = field(default_factory=dict)
    raw: str = ""

    @property
    def cite(self) -> str:
        return f"{self.file}:L{self.line}"

    @property
    def sub(self) -> str:
        return self.extra.get("subtype", "")

    def brief(self) -> str:
        return self.raw if len(self.raw) <= 220 else self.raw[:217] + "..."


def norm_user(u: str) -> str:
    u = str(u or "").strip().strip('"')
    if "\\" in u:
        u = u.rsplit("\\", 1)[-1]
    return u.lower()


def parse_duration(v) -> float | None:
    if v in (None, ""):
        return None
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|sec|secs|seconds|m|min|mins|h|hr|hours)?\s*", str(v), re.I)
    if not m:
        return None
    n, u = float(m.group(1)), (m.group(2) or "s").lower()
    return n / 1000 if u == "ms" else n * 60 if u.startswith("m") and u != "ms" else n * 3600 if u.startswith("h") else n


def _first(d: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return ""


def _normalise(d: dict) -> dict:
    if "@" in str(d.get("from", "")) and not d.get("sender"):
        d["sender"] = d["from"]
    if "@" in str(d.get("to", "")) and not d.get("recipient"):
        d["recipient"] = d["to"]
    if d.get("url_host") and not d.get("urls"):
        d["urls"] = [d["url_host"]]
    c = str(d.get("client", ""))
    if RE_IP.fullmatch(c) and not _first(d, K_SRC):
        d["src_ip"] = c
    return d


def _fields(raw: str, row: dict | None) -> dict:
    if row is not None:
        return _normalise({str(k).lower(): v for k, v in row.items()})
    s = raw.strip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return _normalise({str(k).lower(): v for k, v in obj.items()})
        except json.JSONDecodeError:
            pass
    m = RE_APACHE_LINE.match(s)
    if m:
        d = dict(src_ip=m.group(1), method=m.group(4), url=m.group(5), status_code=m.group(7), size=m.group(8),
                 user_agent=m.group(10) or "")
        if m.group(2) != "-":
            d["user"] = m.group(2)
        return d
    d: dict = {}
    for k, v in RE_KV.findall(s):
        d.setdefault(k.lower(), v.strip('"'))
    m = RE_FW.search(s)
    if m:
        d.update(action=m.group(1), protocol=m.group(2) or "", src_ip=m.group(3), src_port=m.group(4) or "",
                 dst_ip=m.group(5), dst_port=m.group(6) or "")
    m = RE_SYSLOG_LINE.match(s)
    if m:
        d.setdefault("host", m.group(1))
        d["process"] = m.group(2)
        msg = m.group(3)
        mm = re.search(rf"for (?:invalid user )?(\S+) from ({IP})", msg)
        if mm:
            d.setdefault("user", mm.group(1)); d.setdefault("src_ip", mm.group(2))
        mm = re.search(r"for user (\S+)", msg) or re.search(r"sudo:\s+(\S+) :", s)
        if mm:
            d.setdefault("user", mm.group(1).strip("'\""))
    if not _first(d, K_SRC):
        mm = re.search(rf"from ({IP})", s)
        if mm:
            d["src_ip"] = mm.group(1)
    return _normalise(d)


def _reporter(raw: str, ts_raw: str) -> str:
    i = raw.find(ts_raw)
    rest = (raw[i + len(ts_raw):] if i >= 0 else raw).lstrip(" |]\t")
    m = re.match(r"([A-Za-z][\w.-]*)(.?)", rest)
    if m and m.group(2) != "=" and re.search(r"\d", m.group(1)):
        return m.group(1)
    return ""


def _categorise(ev: Event, d: dict, kind: str, eid: str) -> tuple[str, str]:
    low = ev.raw.lower()
    if kind == "ids":
        return "alert", ""
    if kind == "dhcp" or "dhcpack" in low:
        return "dhcp", ""
    if ev.url and ev.status.isdigit():
        return "web", ""
    if kind == "email" or (d.get("recipient") and d.get("sender")):
        return "email", ""
    if eid in WIN:
        cat, sub = WIN[eid]
        if cat == "auth_success" and RE_FAIL.search(str(d.get("result", ""))):
            cat = "auth_fail"
        if eid == "4624" and re.search(r"type\s*10|remote ?desktop|remoteinteractive", low):
            sub = "remote_logon"
        return cat, sub
    act = str(d.get("action", "")).lower()
    if ev.src_ip and ev.dst_ip and (kind == "firewall" or act or ev.dst_port):
        return ("fw_deny" if re.search(r"deny|denied|drop|block|reject", act or low) else "fw_allow"), ""
    if RE_AUTHISH.search(low):
        if RE_OUT.search(low):
            return "auth_logout", ("vpn_end" if "session_end" in low or "session end" in low else "")
        if RE_FAIL.search(low):
            return "auth_fail", ("mfa_failed" if "mfa" in low else "")
        if RE_OK.search(low):
            return "auth_success", ""
    return "other", ""


def _build(sf: SourceFile, line_no: int, raw: str, row: dict | None, ctx: TimeCtx) -> Event | None:
    d = _fields(raw, row)
    p = None
    if row is not None:
        for k, v in row.items():
            if v and any(t in k.lower() for t in ("time", "date")):
                p = parse_ts(str(v), ctx)
                if p:
                    break
    elif raw.lstrip().startswith("{"):
        t = _first(d, K_TIME)
        p = parse_ts(t, ctx) if t else None
    p = p or parse_ts(raw, ctx)
    if p is None:
        return None
    ev = Event(ts=p.utc, file=sf.path, line=line_no, raw_ts=p.raw, kind=sf.kind, raw=raw.strip())
    ev.src_ip, ev.dst_ip = _first(d, K_SRC), _first(d, K_DST)
    if ev.src_ip and not RE_IP.fullmatch(ev.src_ip):
        ev.extra["src_name"], ev.src_ip = ev.src_ip, ""
    if ev.dst_ip and not RE_IP.fullmatch(ev.dst_ip):
        ev.extra["dst_name"], ev.dst_ip = ev.dst_ip, ""
    ev.dst_port = _first(d, ("dst_port", "dest_port", "dport", "destination_port", "port"))
    ev.user = norm_user(_first(d, K_USER))
    ev.host = _first(d, K_HOST)
    ev.url = unquote(str(d.get("url") or d.get("request") or d.get("uri") or d.get("path") or ""))
    ev.status = str(d.get("status_code") or d.get("status") or d.get("response") or "")
    bts = {k: int(v) for k, v in d.items() if (k.startswith("bytes") or k.endswith("bytes") or k == "size")
           and re.fullmatch(r"\d+", str(v))}
    ev.extra["bytes"] = bts
    ev.bytes_out = next((bts[k] for k in ("bytes_out", "bytes_sent", "out_bytes", "tx_bytes") if k in bts), 0)
    dur = parse_duration(d.get("duration"))
    if dur is not None:
        ev.extra["duration_s"] = dur
    lease = _first(d, K_LEASE)
    if lease:
        ev.extra["assigned_ip"] = lease
    for k in EXTRA:
        if d.get(k) not in (None, ""):
            ev.extra[k] = d[k]
    eid = str(d.get("eventid") or d.get("event_id") or "")
    if eid:
        ev.extra["eventid"] = eid
        if not ev.user:
            ev.user = norm_user(d.get("caller") or d.get("target") or "")
            if ev.user and not re.fullmatch(r"[a-z][\w.-]*", ev.user):
                ev.user = ""
    if d.get("recipient") and not ev.user and str(d.get("direction", "inbound")).lower() != "outbound":
        ev.user = norm_user(str(d["recipient"]).split("@")[0])
    ev.reporter = _reporter(raw, p.raw)
    ev.category, sub = _categorise(ev, d, sf.kind, eid)
    if sub:
        ev.extra["subtype"] = sub
    return ev


# ------------------------------------------------------- time zone per file
def file_time_ctx(sf: SourceFile, files: dict[str, SourceFile], overrides: dict[str, str]) -> TimeCtx:
    """Time zone of a log: override file > header comment > a sheet that names the file > UTC (flagged)."""
    for key, val in overrides.items():
        if key in (sf.path, sf.name):
            tz = tz_from_text(val if val.upper().startswith(("UTC", "GMT")) else f"UTC{val}")
            if tz:
                return TimeCtx(tz=tz, tz_source=f"timezones.json override ({fmt_tz(tz)})", tz_assumed=False)
    for i, l in enumerate(sf.lines[:8]):
        if l.lstrip().startswith(("#", ";", "//")) and re.search(r"time ?zone|\btz\b|utc|gmt", l, re.I):
            tz = tz_from_text(l)
            if tz:
                return TimeCtx(tz=tz, tz_source=f"{fmt_tz(tz)}, stated in the file header ({sf.cite(i + 1)})", tz_assumed=False)
    needle = sf.name.lower()
    order = sorted(files.values(), key=lambda o: (o.kind != "coverage", o.path))
    for other in order:
        if other.is_log or other.path == sf.path:
            continue
        for i, l in enumerate(other.lines):
            low = l.lower()
            if needle not in low:
                continue
            cite = other.cite(i + 1)
            ctx = TimeCtx()
            if re.search(r"(logged|written|recorded)[^|.]*\b(clos\w*|ends?|ended)\b", low):
                ctx.logged_at, ctx.logged_at_cite = "close", cite
            elif re.search(r"(logged|written|recorded)[^|.]*\b(start\w*|begin\w*|open\w*)\b", low):
                ctx.logged_at, ctx.logged_at_cite = "start", cite
            tz = tz_from_text(l)
            if tz:
                ctx.tz, ctx.tz_assumed = tz, False
                ctx.tz_source = f"{fmt_tz(tz)}, stated in {cite}"
            elif re.search(r"(in|on) (each|every) line", low):
                ctx.tz_assumed = False
                ctx.tz_source = f"offset written in each line ({cite})"
            else:
                continue
            return ctx
    return TimeCtx()


def _rows(f: SourceFile) -> list[tuple[int, str, dict | None]]:
    name = f.name.lower()
    if name.endswith(".md"):
        fence = f.fenced()
        if fence:
            return [(i, f.lines[i - 1], None) for i in fence]
        return [(i, f.lines[i - 1], r) for i, r in read_table(f)]
    if name.endswith((".csv", ".tsv")):
        delim = "\t" if name.endswith(".tsv") else ","
        out, header = [], None
        for i, l in enumerate(f.lines, 1):
            if not l.strip() or l.lstrip().startswith("#"):
                continue
            try:
                cells = next(csv.reader(io.StringIO(l), delimiter=delim))
            except (csv.Error, StopIteration):
                continue
            if header is None:
                header = [c.strip().lower() for c in cells]
                continue
            out.append((i, l, {h: (cells[k].strip() if k < len(cells) else "") for k, h in enumerate(header)}))
        return out
    return [(i, l, None) for i, l in enumerate(f.lines, 1) if l.strip() and not l.lstrip().startswith("#")]


def parse_logs(files: dict[str, SourceFile], overrides: dict[str, str] | None = None
               ) -> tuple[list[Event], dict[str, dict]]:
    """Parse every log file. Returns (events sorted by UTC time, per-file notes)."""
    overrides = overrides or {}
    logs = [f for f in files.values() if f.is_log]
    ctxs = {f.path: file_time_ctx(f, files, overrides) for f in logs}
    rows = {f.path: _rows(f) for f in logs}

    ref: list[datetime] = []
    for f in logs:
        for _, l, _r in rows[f.path][:400]:
            p = parse_ts(l, ctxs[f.path])
            if p and p.fmt in ("iso", "apache"):
                ref.append(p.utc)
    ref_date = datetime.fromtimestamp(statistics.median(t.timestamp() for t in ref), UTC) if ref else None

    info: dict[str, dict] = {}
    events: list[Event] = []
    for f in logs:
        ctx = ctxs[f.path]
        notes: list[str] = []
        sample = [l for _, l, _r in rows[f.path]][:200]
        if any(RE_SLASH.search(l) and not RE_APACHE.search(l) for l in sample):
            hint = slash_hint(sample)
            if hint is None and ref_date is not None:
                dists = {}
                for df in (True, False):
                    ctx.dayfirst = df
                    ts = [p.utc for p in (parse_ts(l, ctx) for l in sample) if p]
                    dists[df] = statistics.median(abs((t - ref_date).total_seconds()) for t in ts) if ts else 9e18
                hint = dists[True] <= dists[False]
                notes.append(f"DD/MM vs MM/DD is ambiguous in this file; read as {'day/month' if hint else 'month/day'} "
                             f"because that puts the dates closest to the other logs")
            ctx.dayfirst = True if hint is None else hint
        if any(RE_SYSLOG.search(l) and not RE_ISO.search(l) for l in sample[:20]):
            ctx.year = ref_date.year if ref_date else datetime.now(UTC).year
            notes.append(f"timestamps have no year; {ctx.year} taken from the other logs")
        if ctx.logged_at == "close":
            notes.append(f"lines are written when the session CLOSES ({ctx.logged_at_cite}); session start = "
                         f"logged time - duration")
        elif ctx.logged_at == "start":
            notes.append(f"lines are written when the connection STARTS ({ctx.logged_at_cite}); byte counts may "
                         f"not cover the whole connection")
        parsed, unparsed = 0, []
        for i, l, row in rows[f.path]:
            try:
                ev = _build(f, i, l, row, ctx)
            except Exception:          # one bad line must never stop the run
                ev = None
            if ev is None:
                unparsed.append(i)
                continue
            if ctx.logged_at == "close":
                ev.end = ev.ts
                ev.extra["logged_at_close"] = True
                dur = ev.extra.get("duration_s")
                if dur:
                    ev.ts = ev.ts - timedelta(seconds=dur)
            events.append(ev)
            parsed += 1
        info[f.path] = {"kind": f.kind, "timezone": ctx.tz_source, "tz_assumed": ctx.tz_assumed, "notes": notes,
                        "logged_at": ctx.logged_at, "events": parsed, "unparsed_lines": unparsed[:50]}
    events.sort(key=lambda e: (e.ts, e.file, e.line))
    return events, info
