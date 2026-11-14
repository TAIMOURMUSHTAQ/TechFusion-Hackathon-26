"""Timestamp parsing. Everything is converted to UTC, and every guess is recorded.

Formats handled: ISO 8601 (with Z / offset / none), Apache "10/Nov/2026:02:40:10 +0000",
slash dates "10/11/2026 09:10:02" (day-first or month-first), syslog "Nov 10 09:19:30"
(no year), and Unix epoch seconds or milliseconds.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
MONTHS = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
TZ_ABBR = {"utc": 0, "gmt": 0, "z": 0, "pkt": 5, "ist": 5.5, "gst": 4, "cet": 1, "cest": 2, "bst": 1,
           "est": -5, "edt": -4, "cst": -6, "cdt": -5, "pst": -8, "pdt": -7, "sgt": 8, "jst": 9}

_ABBR = "|".join(sorted((k.upper() for k in TZ_ABBR if len(k) >= 3), key=len, reverse=True))
RE_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:[.,]\d+)?\s?(Z\b|(?:" + _ABBR + r")\b|[+-]\d{2}:?\d{2}\b)?")
RE_APACHE = re.compile(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s([+-]\d{4})")
RE_SLASH = re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s?([AP]M)\b)?", re.I)
RE_SYSLOG = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})\b")
RE_EPOCH = re.compile(r"(?<![\d.:/-])(1[5-9]\d{8})(\d{3})?(?:\.\d+)?(?![\d:/-])")
RE_OFFSET = re.compile(r"(?:UTC|GMT)\s*([+-])\s*(\d{1,2})(?::?(\d{2}))?", re.I)


@dataclass
class TimeCtx:
    """How to read timestamps in one file that do not say everything themselves."""
    tz: timezone = UTC
    tz_source: str = "assumed UTC (no time zone stated anywhere for this file)"
    tz_assumed: bool = True
    logged_at: str = ""            # "close" = the line is written when the session ends
    logged_at_cite: str = ""
    year: int | None = None
    dayfirst: bool = True
    notes: tuple[str, ...] = ()


@dataclass
class Parsed:
    utc: datetime
    raw: str
    explicit_tz: bool
    fmt: str


def tz_from_text(text: str) -> timezone | None:
    """Find a time zone in free text such as 'local time (PKT, UTC+05:00)' or 'written in UTC'."""
    m = RE_OFFSET.search(text)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0)))
    m = re.search(r"(?<![\w])([+-])(\d{2}):?(\d{2})(?![\w])", text)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    for word in re.findall(r"\b[A-Za-z]{3,4}\b", text):
        w = word.lower()
        if w in TZ_ABBR:
            return timezone(timedelta(hours=TZ_ABBR[w]))
    return None


def _offset(tok: str) -> timezone:
    t = tok.strip().upper()
    if t in ("Z", "UTC", "GMT"):
        return UTC
    if t.lower() in TZ_ABBR:
        return timezone(timedelta(hours=TZ_ABBR[t.lower()]))
    sign = 1 if t[0] == "+" else -1
    digits = t[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0)))


def fmt_tz(tz: timezone) -> str:
    off = tz.utcoffset(None) or timedelta(0)
    mins = int(off.total_seconds() // 60)
    sign = "+" if mins >= 0 else "-"
    return f"UTC{sign}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}"


def parse_ts(text: str, ctx: TimeCtx) -> Parsed | None:
    """Parse the first timestamp found in text. Returns None when there is none."""
    best: tuple[int, str, re.Match] | None = None
    for name, rx in (("iso", RE_ISO), ("apache", RE_APACHE), ("slash", RE_SLASH), ("syslog", RE_SYSLOG)):
        m = rx.search(text)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), name, m)
    try:
        if best is None:
            m = RE_EPOCH.search(text[:80])
            if not m:
                return None
            return Parsed(datetime.fromtimestamp(int(m.group(1)), UTC), m.group(0), True, "epoch")
        _, name, m = best
        if name == "iso":
            y, mo, d, h, mi, s, tz = m.groups()
            naive = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0))
            zone = _offset(tz) if tz else ctx.tz
            return Parsed(naive.replace(tzinfo=zone).astimezone(UTC), m.group(0).strip(), bool(tz), "iso")
        if name == "apache":
            d, mon, y, h, mi, s, tz = m.groups()
            naive = datetime(int(y), MONTHS[mon.lower()], int(d), int(h), int(mi), int(s))
            return Parsed(naive.replace(tzinfo=_offset(tz)).astimezone(UTC), m.group(0), True, "apache")
        if name == "slash":
            a, b, y, h, mi, s, ampm = m.groups()
            d, mo = (int(a), int(b)) if ctx.dayfirst else (int(b), int(a))
            hour = int(h)
            if ampm:
                hour = hour % 12 + (12 if ampm.upper() == "PM" else 0)
            naive = datetime(int(y), mo, d, hour, int(mi), int(s or 0))
            tail = text[m.end():m.end() + 12]
            zone = tz_from_text(tail) if re.match(r"\s?(UTC|GMT|[+-]\d{2})", tail) else None
            return Parsed(naive.replace(tzinfo=zone or ctx.tz).astimezone(UTC), m.group(0), zone is not None, "slash")
        mon, d, h, mi, s = m.groups()
        if mon.lower() not in MONTHS:
            return None
        naive = datetime(ctx.year or datetime.now(UTC).year, MONTHS[mon.lower()], int(d), int(h), int(mi), int(s))
        return Parsed(naive.replace(tzinfo=ctx.tz).astimezone(UTC), m.group(0), False, "syslog")
    except (ValueError, KeyError):
        return None


def slash_hint(lines: list[str]) -> bool | None:
    """True = day first, False = month first, None = cannot tell from the values alone."""
    for l in lines:
        m = RE_SLASH.search(l)
        if not m or RE_APACHE.search(l):
            continue
        a, b = int(m.group(1)), int(m.group(2))
        if a > 12:
            return True
        if b > 12:
            return False
    return None


def uses(lines: list[str], rx: re.Pattern) -> bool:
    return any(rx.search(l) for l in lines[:50])


def local(dt: datetime, tz: timezone | None) -> str:
    return dt.astimezone(tz).strftime("%H:%M:%S") if tz else ""


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
