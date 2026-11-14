"""Reference files: change calendar, severity matrix, runbooks, escalation sheet.

Nothing here is hard-coded to the sample data. Rows are matched by keywords, and when a
file has no matching row the caller is told so (it must then say "cannot be decided from
the files" instead of inventing a value).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .entities import Asset, Resolver
from .events import RE_IP
from .ingest import SourceFile, find_col, read_table
from .timeparse import TimeCtx, UTC, fmt_tz, iso, parse_ts, tz_from_text

# Canonical incident types -> words that identify the matching row / runbook. First two count most.
TYPE_KW = {
    "credential_compromise": ["credential", "compromise", "account", "takeover", "unauthori", "stolen"],
    "brute_force": ["brute", "force", "password", "login", "guess", "failed"],
    "phishing": ["phish", "email", "mail", "spoof"],
    "web_attack": ["web", "application", "sql", "injection", "traversal", "xss", "attack"],
    "data_exfiltration": ["exfil", "data", "leak", "outbound", "transfer", "loss"],
    "port_scan": ["scan", "recon", "sweep", "probe"],
    "malware": ["malware", "ransom", "virus", "infect"],
    "remote_admin": ["remote desktop", "rdp", "privileged", "admin"],
}
TYPE_NAME = {
    "credential_compromise": "Credential compromise", "brute_force": "Brute-force login attempt",
    "phishing": "Phishing email", "web_attack": "Web application attack",
    "data_exfiltration": "Data exfiltration (large transfer)", "port_scan": "Scanning / reconnaissance", "malware": "Malware",
    "remote_admin": "Privileged remote access",
}
_NEG = re.compile(r"no success|unsuccess|not success|block|attempt|fail|no confirm")


def kw_score(label: str, itype: str, variant: str = "") -> int:
    low = label.lower()
    kws = TYPE_KW.get(itype, [])
    score = sum((3 if i < 2 else 1) for i, k in enumerate(kws) if k in low)
    if score and variant:
        neg = bool(_NEG.search(low))
        pos = "success" in low and not neg
        if variant == "successful":
            score += 2 if pos else (-3 if neg else 0)
        elif variant == "blocked":
            score += 2 if neg else (-3 if pos else 0)
    return score


# ------------------------------------------------------------ change calendar
@dataclass
class Change:
    id: str
    title: str
    start: datetime
    end: datetime
    approved: bool
    status: str
    actors: set[str]
    targets: set[str]
    nets: list
    target_text: str
    cite: str
    tz_note: str


@dataclass
class ChangeVerdict:
    covered: bool
    change: Change
    reasons: list[str]


_BAD_STATUS = re.compile(r"reject|cancel|pending|draft|denied|withdrawn|not approved|postpon|not performed|not done|"
                         r"declined|on hold|failed", re.I)
RE_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")


def load_changes(sf: SourceFile, res: Resolver, known_users: set[str], file_tz: TimeCtx) -> list[Change]:
    out: list[Change] = []
    rows = read_table(sf)
    if not rows:
        return out
    s = rows[0][1]
    c_id = find_col(s, "change id", "change_id", "ticket", "ref") or find_col(s, "id")
    c_start = find_col(s, "start", "begin")
    c_end = find_col(s, "end", "finish", "until")
    c_window = find_col(s, "window", "time", "hours")
    c_date = find_col(s, "date", "day")
    c_tz = find_col(s, "timezone", "time zone", "tz")
    c_status = find_col(s, "status", "state", "approval")
    c_title = find_col(s, "title", "summary", "description", "activity")
    actor_cols = [h for h in s if re.search(r"source|scanner|performed|engineer|owner|assignee|request|actor|by$", h)
                  and "approv" not in h]
    target_cols = [h for h in s if re.search(r"target|system|scope|asset|affected|host", h) and h not in actor_cols]
    header_tz = tz_from_text(c_window or "") or tz_from_text(" ".join(sf.lines[:3]))
    default_tz = header_tz or file_tz.tz
    tz_src = "the table header" if header_tz else file_tz.tz_source

    def ents(text: str) -> set[str]:
        nets = set(RE_CIDR.findall(text))
        found = {"net:" + n for n in nets}
        for ip in RE_IP.findall(text):
            if not any(n.startswith(ip + "/") for n in nets):
                found.add("ip:" + ip)
        for a in res.hosts_in(text):
            found.add("asset:" + a.key)
            found |= {"ip:" + ip for ip in a.ips}
        found |= {"user:" + u for u in res.users_in(text, known_users)}
        return found

    for line, r in rows:
        tz = (tz_from_text(r.get(c_tz, "")) if c_tz else None) or default_tz
        ctx = TimeCtx(tz=tz, dayfirst=file_tz.dayfirst)
        ps = pe = None
        if c_start and c_end:
            ps, pe = parse_ts(r.get(c_start, ""), ctx), parse_ts(r.get(c_end, ""), ctx)
        elif c_window:
            m = re.search(r"(\d{1,2}:\d{2})\s*(?:-|–|to)\s*(\d{1,2}:\d{2})", r.get(c_window, ""))
            day = r.get(c_date, "") if c_date else ""
            if m and day:
                ps, pe = parse_ts(f"{day} {m.group(1)}", ctx), parse_ts(f"{day} {m.group(2)}", ctx)
        if not ps or not pe:
            continue
        start, end = ps.utc, pe.utc
        if end < start:
            end += timedelta(days=1)
        status = r.get(c_status, "") if c_status else ""
        actors = set().union(*[ents(r.get(c, "")) for c in actor_cols]) if actor_cols else set()
        ttext = " ".join(r.get(c, "") for c in target_cols)
        targets = ents(ttext) if target_cols else set()
        if not actor_cols and not target_cols:
            actors = ents(" ".join(r.values()))
        nets = [ipaddress.ip_network(t[4:], strict=False) for t in targets if t.startswith("net:")]
        local_win = f"{ps.raw} to {pe.raw}"
        note = f"{local_win} {fmt_tz(tz)} = {iso(start)} to {iso(end)[11:]} UTC (zone from {('the row' if c_tz and r.get(c_tz) else tz_src)})"
        out.append(Change(id=r.get(c_id, "") if c_id else f"row {line}", title=r.get(c_title, "") if c_title else "",
                          start=start, end=end, approved=not _BAD_STATUS.search(status), status=status, actors=actors,
                          targets=targets, nets=nets, target_text=ttext.strip(), cite=sf.cite(line), tz_note=note))
    return out


def _covers(c: Change, a: Asset) -> bool:
    if "asset:" + a.key in c.targets or any("ip:" + ip in c.targets for ip in a.ips):
        return True
    for ip in a.ips:
        try:
            if any(ipaddress.ip_address(ip) in n for n in c.nets):
                return True
        except ValueError:
            pass
    return False


def _who(keys: set[str]) -> str:
    return ", ".join(sorted(k.split(":", 1)[1] for k in keys))


def check_change(changes: list[Change], start: datetime, end: datetime, actors: set[str], targets: list[Asset]
                 ) -> ChangeVerdict | None:
    """Approved only if the same person/tool, a window that contains the activity, the same systems, and approved status."""
    best: ChangeVerdict | None = None
    for c in changes:
        hit = actors & c.actors
        if not hit:
            continue
        reasons = [f"performer {_who(hit)} is named in {c.id} \"{c.title}\" ({c.cite})"]
        ok = True
        if not c.approved:
            ok = False
            reasons.append(f"but its status is \"{c.status}\", so it is not approved activity")
        else:
            reasons.append(f"status \"{c.status}\"")
        if c.start <= start and end <= c.end:
            reasons.append(f"activity {iso(start)} to {iso(end)[11:]} UTC is inside the window {c.tz_note}")
        else:
            ok = False
            reasons.append(f"but activity {iso(start)} to {iso(end)[11:]} UTC is NOT inside the window {c.tz_note}")
        if targets and (c.targets or c.nets):
            outside = [a for a in targets if not _covers(c, a)]
            if outside:
                ok = False
                reasons.append("but these systems are outside its scope (\"" + c.target_text + "\"): "
                               + ", ".join(a.short() for a in outside))
            else:
                reasons.append("every system involved (" + ", ".join(a.short() for a in targets)
                               + f") is in its scope \"{c.target_text}\"")
        v = ChangeVerdict(ok, c, reasons)
        if ok:
            return v
        if best is None or (not best.change.approved and c.approved):
            best = v
    return best


def related_changes(changes: list[Change], start: datetime, end: datetime, actors: set[str], targets: list[Asset]
                    ) -> list[str]:
    """Changes that name the same systems but do NOT explain the activity, and why (so nobody closes it by mistake).
    Only changes naming the system itself count; a whole-subnet change is too broad to be a plausible mix-up."""
    out = []
    for c in changes:
        if actors & c.actors:
            continue
        same = [a for a in targets if "asset:" + a.key in c.targets or any("ip:" + ip in c.targets for ip in a.ips)]
        if not same:
            continue
        why = [f"performer \"{_who(c.actors) or 'not an account or address in the logs'}\" is not the actor here"]
        if not c.approved:
            why.append(f"status \"{c.status}\"")
        if not (c.start <= start and end <= c.end):
            why.append(f"window {c.tz_note} does not contain the activity")
        out.append(f"{c.id} \"{c.title}\" on {', '.join(a.label for a in same)} does not cover it: "
                   + "; ".join(why) + f" ({c.cite})")
    return out


# ------------------------------------------------------------ severity matrix
@dataclass
class SeverityMatrix:
    rows: list[tuple[str, dict[str, str], str]] = field(default_factory=list)   # (label, {criticality: sev}, cite)
    files: list[str] = field(default_factory=list)

    def load(self, sf: SourceFile) -> None:
        rows = read_table(sf)
        if not rows:
            return
        self.files.append(sf.path)
        s = rows[0][1]
        heads = list(s)
        c_crit = find_col(s, "critic", "tier")
        c_sev = find_col(s, "severity", "sev", "priority")
        c_type = find_col(s, "type", "incident", "category", "event") or heads[0]
        if c_crit and c_sev and c_crit != c_type:              # long format: one row per (type, criticality)
            acc: dict[str, tuple[dict[str, str], str]] = {}
            for line, r in rows:
                d, _ = acc.setdefault(r.get(c_type, ""), ({}, sf.cite(line)))
                d[r.get(c_crit, "").lower()] = r.get(c_sev, "")
            self.rows += [(k, v[0], v[1]) for k, v in acc.items()]
            return
        for line, r in rows:                                    # wide format: one column per criticality
            self.rows.append((r.get(c_type, ""), {h: v for h, v in r.items() if h != c_type}, sf.cite(line)))

    def lookup(self, itype: str, variant: str, criticality: str) -> dict:
        """Returns {severity, row, cite, step} or {severity: None, step: why not}."""
        if not self.rows:
            return {"severity": None, "step": "no severity matrix file was found in the dataset"}
        scored = sorted(((kw_score(lbl, itype, variant), lbl, cols, cite) for lbl, cols, cite in self.rows), key=lambda x: -x[0])
        score, label, cols, cite = scored[0]
        if score < 3:
            return {"severity": None, "step": f"the severity matrix has no row for \"{TYPE_NAME.get(itype, itype)}\""}
        crit = (criticality or "").strip().lower()
        if not crit:
            return {"severity": None, "row": label, "cite": cite,
                    "step": f"matrix row \"{label}\" ({cite}) applies, but the asset's criticality is not in the inventory"}
        col = next((h for h in cols if h == crit), None) or next((h for h in cols if crit in h or (h and h in crit)), None)
        if not col or not cols.get(col):
            return {"severity": None, "row": label, "cite": cite,
                    "step": f"matrix row \"{label}\" ({cite}) has no column for criticality \"{criticality}\""}
        return {"severity": cols[col], "row": label, "cite": cite,
                "step": f"matrix row \"{label}\" x column \"{criticality}\" = **{cols[col]}** ({cite})"}


def sev_rank(sev: str | None) -> float:
    """Higher = more serious. SEV1/P1 style: the smaller number is worse. Words: critical > high > medium > low."""
    if not sev:
        return -99
    low = sev.lower()
    for i, w in enumerate(("info", "low", "medium", "high", "critical")):
        if w in low:
            return float(i)
    m = re.search(r"\d+", low)
    return -float(m.group()) if m else -50


# ------------------------------------------------------------------ runbooks
@dataclass
class Runbook:
    id: str
    title: str
    applies: str
    steps: list[tuple[str, str, str]]          # (step number, text, cite)
    file: str


_GENERIC = re.compile(r"^(steps?|procedure|actions?|response|response steps|containment|checklist)$", re.I)
_STEP = re.compile(r"^\s*(?:step\s*)?(\d+)\s*[.):-]\s+(.*\S)", re.I)


def load_runbooks(sf: SourceFile) -> list[Runbook]:
    books: list[Runbook] = []
    cur: Runbook | None = None
    file_id = re.search(r"\brb[-_ ]?\d+", sf.name, re.I)
    for i, l in enumerate(sf.lines, 1):
        s = l.strip()
        h = re.match(r"^#{1,4}\s+(.*)", s)
        if h and not _GENERIC.match(h.group(1).strip().rstrip(":")):
            title = h.group(1).strip()
            m = re.search(r"\b(?:RB|PB)-[A-Z]+-\d+\b|\b(?:RB|PB)[-_ ]?\d+\b", title, re.I)
            cur = Runbook(id=(m.group(0) if m else (file_id.group(0) if file_id and not books else "")).upper().replace("_", "-"),
                          title=re.sub(r"^runbook\s+", "", title, flags=re.I), applies="", steps=[], file=sf.path)
            books.append(cur)
            continue
        if cur is None:
            if not s:
                continue
            cur = Runbook(id=file_id.group(0).upper() if file_id else "", title=s.lstrip("# "), applies="", steps=[], file=sf.path)
            books.append(cur)
            continue
        if re.match(r"^(applies to|scope|incident types?|use (this )?(when|for)|trigger)", s, re.I):
            cur.applies += " " + s
        m = _STEP.match(l)
        if m:
            cur.steps.append((m.group(1), m.group(2), sf.cite(i)))
    for b in books:
        b.id = b.id or sf.name.rsplit(".", 1)[0]
    return [b for b in books if b.steps]


def pick_runbook(books: list[Runbook], itype: str) -> Runbook | None:
    scored = sorted(((kw_score(b.title + " " + b.applies, itype), b) for b in books), key=lambda x: -x[0])
    return scored[0][1] if scored and scored[0][0] >= 3 else None


# ---------------------------------------------------------------- escalation
@dataclass
class Escalation:
    rows: list[tuple[int, dict[str, str], str]] = field(default_factory=list)
    sev_col: str | None = None

    def load(self, sf: SourceFile) -> None:
        for line, r in read_table(sf):
            col = find_col(r, "severity", "sev", "level", "priority")
            if col:
                self.sev_col = self.sev_col or col
                self.rows.append((line, r, sf.cite(line)))

    def for_severity(self, sev: str) -> list[dict]:
        key = re.sub(r"[\s_-]", "", sev.lower())
        out = []
        for _, r, cite in self.rows:
            col = find_col(r, "severity", "sev", "level", "priority")
            cell = re.sub(r"[\s_-]", "", r.get(col, "").lower())
            if cell == key or key in re.split(r"[,/&]|and", cell):
                d = {k: v for k, v in r.items() if k != col and v}
                d["cite"] = cite
                out.append(d)
        return out
