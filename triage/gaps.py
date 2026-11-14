"""Missing-data detection. Missing logs are reported, never read as "nothing happened"."""
from __future__ import annotations

import re
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .events import Event
from .ingest import SourceFile
from .timeparse import iso

RE_RESTART = re.compile(r"rsyslogd.*start|syslogd.*restart|journal.*(start|rotat)|log(ging)? (service )?(start|restart)|audit.*(start|resum)", re.I)
RE_FILEREF = re.compile(r"(?<![\w.-])([\w-]+\.(?:log|jsonl|csv|json|evtx))\b")


@dataclass
class Gap:
    file: str
    host: str
    start: datetime
    end: datetime
    expected: str
    before: str
    after: str
    note: str = ""

    @property
    def minutes(self) -> int:
        return int((self.end - self.start).total_seconds() // 60)

    def text(self) -> str:
        return (f"{self.file}: no `{self.expected}` lines from {self.host or 'this source'} between {iso(self.start)} and "
                f"{iso(self.end)[11:]} UTC ({self.minutes} min), although the line normally appears every "
                f"{self.note}. Last line before the gap {self.before}, first line after {self.after}")


def _template(e: Event) -> str:
    body = e.raw.replace(e.raw_ts, " ")
    body = re.sub(r"\[\d+\]", "", body)
    return re.sub(r"\d+", "#", body).strip()[:120]


def find_gaps(events: list[Event]) -> list[Gap]:
    """A stream that repeats on a steady schedule (heartbeat, cron, health check) and suddenly stops is a gap."""
    streams: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for e in events:
        streams[(e.file, e.host, _template(e))].append(e)
    gaps: list[Gap] = []
    for (file, host, tmpl), evs in streams.items():
        if len(evs) < 6:
            continue
        iv = [(b.ts - a.ts).total_seconds() for a, b in zip(evs, evs[1:])]
        med = statistics.median(iv)
        if med <= 0:
            continue
        regular = sum(1 for x in iv if abs(x - med) <= 0.2 * med + 5) / len(iv)
        if regular < 0.6:
            continue
        for a, b, x in zip(evs, evs[1:], iv):
            if x > max(2.5 * med, med + 600):
                restart = [r for r in events if r.file == file and (not host or r.host == host)
                           and a.ts < r.ts <= b.ts and RE_RESTART.search(r.raw)]
                note = f"{int(med // 60)} min" if med >= 60 else f"{int(med)} s"
                g = Gap(file, host, a.ts, b.ts, re.sub(r"\s+", " ", tmpl)[:70], a.cite, b.cite, note)
                if restart:
                    g.note += f"; the logging service started again at {iso(restart[0].ts)} UTC ({restart[0].cite}), " \
                              f"which suggests logging was stopped"
                gaps.append(g)
    return sorted(gaps, key=lambda g: g.start)


def missing_files(files: dict[str, SourceFile]) -> list[tuple[str, str]]:
    """Log files that a policy/runbook says exist, but are not in the dataset."""
    present = {f.name.lower() for f in files.values()}
    out: dict[str, str] = {}
    for f in files.values():
        if f.is_log:
            continue
        for i, l in enumerate(f.lines, 1):
            for name in RE_FILEREF.findall(l):
                if name.lower() not in present and name.lower() not in out:
                    out[name.lower()] = f"{name} is referenced in {f.cite(i)} but is not in the dataset"
    return sorted(out.items())


def coverage(events: list[Event]) -> dict[str, tuple[datetime, datetime]]:
    cov: dict[str, tuple[datetime, datetime]] = {}
    for e in events:
        a, b = cov.get(e.file, (e.ts, e.ts))
        cov[e.file] = (min(a, e.ts), max(b, e.ts))
    return cov
