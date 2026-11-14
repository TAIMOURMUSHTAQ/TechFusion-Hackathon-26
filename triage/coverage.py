"""Log-source coverage sheet: declared gaps per log, and log sources that do not exist at all."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .events import Event
from .ingest import SourceFile, find_col, read_table
from .timeparse import UTC, TimeCtx, parse_ts, tz_from_text, iso

HMS = r"(\d{1,2}:\d{2}(?::\d{2})?)"


@dataclass
class DeclaredGap:
    file: str
    start: datetime
    end: datetime
    reason: str
    cite: str

    def text(self) -> str:
        why = f" ({self.reason})" if self.reason else ""
        return f"{self.file} has no data from {iso(self.start)} to {iso(self.end)[11:]} UTC{why} [{self.cite}]"


@dataclass
class MissingSource:
    text: str
    cite: str


@dataclass
class Coverage:
    gaps: list[DeclaredGap] = field(default_factory=list)
    missing: list[MissingSource] = field(default_factory=list)
    rows: dict[str, str] = field(default_factory=dict)       # log path -> cite of its coverage row


def _match_file(name: str, logs: list[SourceFile]) -> SourceFile | None:
    n = name.strip().strip("`").lower()
    if not n:
        return None
    for f in logs:
        if f.name.lower() == n or f.name.lower().endswith(n) or n.endswith(f.name.lower()):
            return f
    return None


def load_coverage(files: dict[str, SourceFile], events: list[Event]) -> Coverage:
    cov = Coverage()
    logs = [f for f in files.values() if f.is_log]
    days = sorted({e.ts.date() for e in events})
    for sf in (f for f in files.values() if f.kind == "coverage"):
        rows = read_table(sf)
        if rows:
            s = rows[0][1]
            c_file = find_col(s, "file", "path", "log")
            c_cov = find_col(s, "coverage", "available", "retention")
            c_tz = find_col(s, "time zone", "timezone", "format")
            c_note = find_col(s, "note", "comment", "remark")
            m = re.search(r"(\d{4}-\d{2}-\d{2})", c_cov or "")
            day = m.group(1) if m else (days[0].isoformat() if days else "")
            for line, r in rows:
                f = _match_file(r.get(c_file, "") if c_file else "", logs)
                if not f:
                    continue
                cite = sf.cite(line)
                cov.rows[f.path] = cite
                text = r.get(c_cov, "") if c_cov else ""
                reason = (r.get(c_note, "") if c_note else "").split(".")[0].strip()
                tz = tz_from_text(text) or tz_from_text(r.get(c_tz, "") if c_tz else "") or UTC
                ctx = TimeCtx(tz=tz)

                def at(hms: str) -> datetime | None:
                    p = parse_ts(f"{day} {hms if hms.count(':') == 2 else hms + ':00'}", ctx)
                    return p.utc if p else None

                m = re.search(rf"except\s+{HMS}\s*(?:to|-|–)\s*{HMS}", text, re.I)
                if m and day:
                    a, b = at(m.group(1)), at(m.group(2))
                    if a and b:
                        cov.gaps.append(DeclaredGap(f.path, a, b, reason, cite))
                    continue
                m = re.search(rf"{HMS}\s*(?:to|-|–)\s*{HMS}[^|]*\bonly\b", text, re.I)
                if m and day:
                    a, b = at(m.group(1)), at(m.group(2))
                    d0 = at("00:00:00")
                    if a and b and d0:
                        if a > d0:
                            cov.gaps.append(DeclaredGap(f.path, d0, a, "outside the covered hours", cite))
                        cov.gaps.append(DeclaredGap(f.path, b, d0 + timedelta(days=1) - timedelta(seconds=1),
                                                    "outside the covered hours", cite))
        listing = False
        for i, l in enumerate(sf.lines, 1):
            low = l.lower()
            if re.search(r"not exist|not collected|not available|missing", low) and not l.strip().startswith(("|", "-", "*")):
                listing = True
                continue
            if listing and l.strip().startswith(("-", "*")):
                cov.missing.append(MissingSource(l.strip().lstrip("-* ").strip(), sf.cite(i)))
            elif listing and l.strip():
                listing = False
    return cov
