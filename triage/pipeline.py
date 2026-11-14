"""End-to-end triage: files -> events -> findings -> incidents -> report.

Deterministic. The LLM never decides facts; it only answers follow-up questions on top of
this analysis (see triage/qa.py).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .coverage import Coverage, DeclaredGap, MissingSource, load_coverage
from .detect import Claim, Ctx, Finding, cites, run_all
from .entities import Asset, Resolver, crit_rank, is_internal_ip
from .events import Event, RE_IP, file_time_ctx, parse_logs
from .gaps import Gap, find_gaps, missing_files
from .ingest import SourceFile, load_dataset
from .reference import (TYPE_NAME, Escalation, Runbook, SeverityMatrix, check_change, load_changes, load_runbooks,
                        pick_runbook, related_changes, sev_rank)
from .timeparse import iso, tz_from_text


@dataclass
class Incident:
    id: str
    findings: list[Finding]
    severity: str | None = None
    severity_steps: list[str] = field(default_factory=list)
    decisive: list[Asset] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    escalation: list[dict] = field(default_factory=list)
    escalation_note: str = ""
    gaps: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    alerts: list[Event] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return min(f.start for f in self.findings)

    @property
    def end(self) -> datetime:
        return max(f.end for f in self.findings)

    @property
    def title(self) -> str:
        names = []
        for f in sorted(self.findings, key=lambda f: f.start):
            n = TYPE_NAME.get(f.type, f.type)
            if f.type == "phishing" and f.clickers:
                n = "Phishing email (clicked)"
            if f.variant == "suspected":
                n = "Suspected account misuse"
            if n not in names:
                names.append(n)
        return " -> ".join(names)


@dataclass
class Analysis:
    root: str
    files: dict[str, SourceFile]
    file_info: dict[str, dict]
    events: list[Event]
    resolver: Resolver
    findings: list[Finding]
    incidents: list[Incident]
    dismissed: list[Finding]
    gaps: list[Gap]
    coverage: Coverage
    missing: list[tuple[str, str]]
    observations: list[Claim]
    alert_map: list[tuple[Event, Finding | None]]
    company_tz: object
    warnings: list[str]
    report_md: str = ""

    def to_json(self) -> dict:
        def claims(cs: list[Claim]) -> list[dict]:
            return [{"text": c.text, "cites": c.cites} for c in cs]

        def finding(f: Finding) -> dict:
            return {"id": f.id, "type": f.type, "title": f.title, "start_utc": iso(f.start), "end_utc": iso(f.end),
                    "source_ips": f.src_ips, "users": f.users, "assets": [a.label for a in f.targets],
                    "confirmed": claims(f.confirmed), "suspected": claims(f.suspected),
                    "not_enough_evidence": claims(f.unknown), "entity_matching": f.matches,
                    "related_changes": f.related_changes,
                    "change_check": ({"covered": f.change.covered, "change_id": f.change.change.id,
                                      "reasons": f.change.reasons, "cite": f.change.change.cite} if f.change else None)}
        return {
            "dataset": self.root,
            "files": {p: {"kind": f.kind, "lines": len(f.lines), **self.file_info.get(p, {})} for p, f in self.files.items()},
            "event_count": len(self.events),
            "incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "severity_steps": i.severity_steps,
                           "start_utc": iso(i.start), "end_utc": iso(i.end), "findings": [finding(f) for f in i.findings],
                           "actions": i.actions, "escalation": i.escalation, "escalation_note": i.escalation_note,
                           "gaps": i.gaps, "missing_sources": i.missing,
                           "timeline": [_tl(e, self.company_tz) for e in timeline(i)]} for i in self.incidents],
            "closed_as_harmless": [finding(f) for f in self.dismissed],
            "alerts": [{"alert": a.extra.get("alert id") or a.extra.get("alert_id") or a.cite, "utc": iso(a.ts),
                        "description": a.extra.get("description", a.raw), "cite": a.cite,
                        "outcome": _alert_outcome(f, self)} for a, f in self.alert_map],
            "missing_data": [g.text() for g in self.coverage.gaps] + [f"{m.text} [{m.cite}]" for m in self.coverage.missing]
                            + [g.text() for g in self.gaps] + [m for _, m in self.missing],
            "observations": claims(self.observations),
            "warnings": self.warnings,
        }


def _tl(e: Event, tz) -> dict:
    return {"utc": iso(e.ts), "local": e.ts.astimezone(tz).strftime("%H:%M:%S") if tz else "", "original": e.raw_ts,
            "file": e.file, "line": e.line, "cite": e.cite, "event": e.brief(),
            "note": (f"session start; logged at close {iso(e.end)[11:]} UTC" if e.extra.get("logged_at_close")
                     and e.end and e.end != e.ts else "")}


def _alert_outcome(f: Finding | None, an: "Analysis") -> str:
    if f is None:
        return "not linked to any finding"
    if f.dismissed:
        return f"closed as harmless ({f.change.change.id})"
    inc = next((i for i in an.incidents if f in i.findings), None)
    return f"{inc.id} ({inc.severity or 'undecided'}), part {f.id}" if inc else f.id


def timeline(inc_or_f) -> list[Event]:
    fs = inc_or_f.findings if isinstance(inc_or_f, Incident) else [inc_or_f]
    seen, out = set(), []
    extra = list(inc_or_f.alerts) if isinstance(inc_or_f, Incident) else list(inc_or_f.alerts)
    for f in fs:
        for e in f.evidence + f.alerts + extra:
            if e is not None and id(e) not in seen:
                seen.add(id(e)); out.append(e)
        extra = []
    return sorted(out, key=lambda e: (e.ts, e.file, e.line))


# ------------------------------------------------------------- grouping
def correlate(findings: list[Finding]) -> list[list[Finding]]:
    """Findings that share an attacker address, a used account or a VPN address are one incident (rule 4.3)."""
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(findings):
        for j in range(i + 1, len(findings)):
            if a.keys & findings[j].keys:
                parent[find(i)] = find(j)
    groups: dict[int, list[Finding]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(find(i), []).append(f)
    return sorted(groups.values(), key=lambda g: min(f.start for f in g))


def map_alerts(alerts: list[Event], findings: list[Finding], res: Resolver, users: set[str]) -> list[tuple[Event, Finding | None]]:
    out = []
    for a in alerts:
        desc = str(a.extra.get("description") or a.raw)
        toks = {x.lower() for x in RE_IP.findall(desc)} | {u.lower() for u in res.users_in(desc, users)}
        for h in res.hosts_in(desc):
            toks |= {x.lower() for x in (h.hostname, h.tag, *h.ips) if x}
        best, score = None, (0, 0.0)
        for f in findings:
            ov = len(toks & {x.lower() for x in f.ids if x})
            if not ov:
                continue
            if not (f.start - timedelta(minutes=30) <= a.ts <= f.end + timedelta(minutes=30)):
                continue
            d = min(abs((a.ts - f.start).total_seconds()), abs((a.ts - f.end).total_seconds()))
            sc = (ov, -d)
            if sc > score:
                best, score = f, sc
        out.append((a, best))
        if best is not None:
            best.alerts.append(a)
    return out


# ------------------------------------------------------------- severity (rules 4.1 and 4.2)
def assess_severity(inc: Incident, matrix: SeverityMatrix, cx: Ctx) -> None:
    r41, r42 = cx.rule("most critical asset"), cx.rule("several parts")
    best, decisive = None, []
    for f in sorted(inc.findings, key=lambda f: f.start):
        name = f"{f.id} {TYPE_NAME.get(f.type, f.type)}"
        if f.type == "web_attack":
            name += " (success suspected)" if f.variant == "successful" else " (attempts only)"
        if f.variant == "suspected":
            name += " (only suspected, rule 6.2)"
        if f.type == "phishing" and f.clickers:
            rc = cx.rule("click is seen") or cx.rule("click", "credential")
            inc.severity_steps.append(f"{f.id} Phishing: a click was seen for {', '.join(f.clickers)}, which is handled as "
                                      f"credential compromise ({rc}) and scored in that part. What is left here is the "
                                      f"delivered email to the other recipients, with no click seen.")
        if not f.affected:
            inc.severity_steps.append(f"{name}: no asset it reached is in the inventory, so it cannot be scored from the files")
            continue
        ranked = sorted(f.affected, key=lambda x: crit_rank(x[0].criticality), reverse=True)
        top = ranked[0][0]
        listing = "; ".join(f"{a.label} = **{a.criticality or 'not recorded'}** ({a.cite}): {why}" for a, why in ranked)
        step = f"{name}: assets reached - {listing}."
        higher = [(a, w) for a, w in f.touched if crit_rank(a.criticality) > crit_rank(top.criticality)]
        for a, why in higher:
            step += f" Not counted: {a.label} = {a.criticality} ({a.cite}) because {why} (rule 4.1: {r41})."
        r = matrix.lookup(f.type, f.variant, top.criticality)
        step += f" Most critical reached: {top.label} ({top.criticality}) -> {r['step']}"
        for a, _ in higher[:1]:
            r2 = matrix.lookup(f.type, f.variant, a.criticality)
            if r2.get("severity") and r2["severity"] != r.get("severity"):
                step += f" (If {a.label} were counted, this part would be {r2['severity']}.)"
        inc.severity_steps.append(step)
        sev = r.get("severity")
        if sev and (best is None or sev_rank(sev) > sev_rank(best)):
            best, decisive = sev, [top]
        elif sev and sev == best and all(top is not d for d in decisive):
            decisive.append(top)
    inc.severity, inc.decisive = best, decisive
    if best:
        many = len(inc.findings) > 1
        inc.severity_steps.append((f"The incident has {len(inc.findings)} parts; the whole incident gets the highest part "
                                   f"({r42}): " if many else "Incident severity: ") + f"**{best}**")
    else:
        inc.severity_steps.append("Severity cannot be decided from the files (see the steps above)")


# ------------------------------------------------------------- runbook steps
def _assets(inc: Incident) -> list[Asset]:
    out = []
    for f in inc.findings:
        for a, _ in f.affected:
            if all(a is not x for x in out):
                out.append(a)
    return out


def eval_condition(text: str, f: Finding, inc: Incident, cx: Ctx, cov: Coverage) -> tuple[str, str]:
    low = text.lower()
    if not re.search(r"(?<!ask )(?<!see )(?<!check )(?<!know )(?<!verify )\bif\b", low):
        return "", ""
    if "click" in low:
        cl = [u for g in inc.findings if g.type == "phishing" for u in g.clickers]
        return ("met", f"click seen for {', '.join(cl)}") if cl else ("not met", "no click seen in the firewall logs")
    if "phishing" in low and "source" in low:
        ph = [g for g in inc.findings if g.type == "phishing" and set(f.users) & set(g.clickers)]
        if ph:
            return "met (suspected link)", f"{', '.join(ph[0].clickers)} clicked the phishing link before this login ({ph[0].id})"
        return "not met", f"no phishing click by {', '.join(f.users) or 'this account'} is linked to this incident"
    if "data transfer" in low or "large transfer" in low:
        ex = [g for g in inc.findings if g.type == "data_exfiltration"]
        return ("met", f"{ex[0].id}: {ex[0].title}") if ex else ("not met", "no large transfer is seen in this incident")
    if "audit log" in low:
        names = {x.lower() for a in _assets(inc) for x in (a.hostname, a.tag) if x}
        miss = [m for m in cov.missing if "audit" in m.text.lower() and any(n in m.text.lower() for n in names)]
        if miss:
            return "met: they do not exist", f"{miss[0].text} ({miss[0].cite}) -> record that it is unknown which files were read"
        return "check", "the files do not say whether audit logs exist"
    if re.search(r"finance|\bhr\b|customer", low):
        hits = [a for a in _assets(inc) if re.search(r"finance|\bhr\b|customer|payroll", f"{a.type} {a.owner}", re.I)]
        if hits:
            return "met", f"{hits[0].label} is \"{hits[0].type}\" ({hits[0].cite})"
        return "not met", "no affected asset is listed as holding finance, HR or customer data"
    if "approved" in low:
        approved = bool(f.change and f.change.covered)
        cond_ok = (not approved) if "not approved" in low else approved
        src = f.src_ips[0] if f.src_ips else ""
        if cond_ok and "external" in low:
            cond_ok = bool(src) and not is_internal_ip(src)
        if cond_ok and "internal" in low:
            cond_ok = bool(src) and is_internal_ip(src)
        why = (f"approved change {f.change.change.id}" if approved else "no approved change covers it")
        return ("met" if cond_ok else "not met"), why + (f"; source {src} is {'internal' if is_internal_ip(src) else 'external'}" if src else "")
    if "source is internal" in low or "source is external" in low:
        src = f.src_ips[0] if f.src_ips else ""
        want_int = "internal" in low
        ok = bool(src) and is_internal_ip(src) == want_int
        return ("met" if ok else "not met"), f"source {src} is {'internal' if is_internal_ip(src) else 'external'}"
    if "available" in low:
        if "database" in low or "db" in low:
            miss = [m for m in cov.missing if re.search(r"\bdb|database|query", m.text, re.I)]
            if miss:
                return "not met: not available", f"{miss[0].text} ({miss[0].cite})"
        return "check", "availability is not stated in the files"
    return "check", "condition not decided from the files"


def _hint(text: str, f: Finding, inc: Incident, cx: Ctx) -> str:
    low, res = text.lower(), cx.res
    hints = []
    users = [u for u in dict.fromkeys(f.users) if u]
    if "recipient" in low and f.recipients:
        hints.append("recipients: " + ", ".join(f.recipients))
    if ("sender domain" in low or "link domain" in low) and f.sender:
        hints.append(f"sender domain {f.sender.split('@')[-1]}; link domain {', '.join(f.link_domains)}")
    if "link address" in low and f.link_ips:
        hints.append("link address " + ", ".join(f.link_ips) + "; laptops: "
                     + ", ".join(filter(None, (res.user_laptop(u)[0].label if res.user_laptop(u)[0] else "" for u in f.recipients))))
    if re.search(r"phone|call the", low) and users:
        ps = [res.person(u) for u in users]
        hints.append("; ".join(f"{p.name} ({p.username}) {p.phone} [{p.cite}]" for p in ps if p))
    if re.search(r"account|the user\b|user's", low) and users and "laptop" not in low and "phone" not in low:
        hints.append("account: " + ", ".join(users))
    if "laptop" in low and users:
        labs = [res.user_laptop(u) for u in users]
        hints.append("laptop: " + ", ".join(f"{a.label} ({a.tag}, {', '.join(a.ips)})" for a, _ in labs if a))
    if re.search(r"attacker (source )?ip|source ip|attacker ip|ip address", low):
        ext = [ip for g in inc.findings for ip in g.src_ips if ip and not is_internal_ip(ip)
               and g.type in (f.type, "credential_compromise", "web_attack", "port_scan")]
        if ext:
            hints.append("IP: " + ", ".join(dict.fromkeys(ext)))
    if "destination" in low and f.receivers:
        hints.append("destination: " + ", ".join(f.receivers) + (f" (via VPN address {f.lease.ip})" if f.lease else ""))
    if re.search(r"every system|systems? (it )?reached|list every", low):
        hints.append("reached: " + ", ".join(a.label for a in _assets(inc) if a.type and "laptop" not in a.type.lower()))
    if re.search(r"system owner|owner of", low):
        hints.append("owner: " + "; ".join(f"{a.label}: {a.owner}" for a, _ in f.affected if a.owner))
    if re.search(r"unusually large transfer|bytes, the times", low) and f.type == "data_exfiltration":
        hints.append("; ".join(c.text for c in f.confirmed[:2]))
    if "web server log" in low and f.src_ips:
        hints.append(f"{f.src_ips[0]}: {', '.join(cites([e for e in f.evidence if e.category == 'web']))}")
    return " | ".join(h for h in hints if h)


def plan_actions(inc: Incident, books: list[Runbook], cx: Ctx, cov: Coverage) -> None:
    done: set[str] = set()
    for f in sorted(inc.findings, key=lambda f: f.start):
        b = pick_runbook(books, f.type)
        if b is None:
            inc.actions.append({"runbook": None, "for": f"{f.id} {TYPE_NAME.get(f.type, f.type)}",
                                "note": "No runbook in the files covers this type, so no action is recommended for it"})
            continue
        if b.id in done:
            continue
        done.add(b.id)
        steps = []
        if f.variant == "suspected":
            steps.append({"step": "note", "text": "This incident is only suspected: do step 1 first; the other steps are "
                          "needed only if the account owner says the activity was not theirs.", "cite": "", "applies_to": "",
                          "condition": "", "condition_detail": ""})
        for num, text, cite in b.steps:
            status, why = eval_condition(text, f, inc, cx, cov)
            steps.append({"step": f"{b.id} step {num}", "text": text, "cite": cite, "applies_to": _hint(text, f, inc, cx),
                          "condition": status, "condition_detail": why})
        inc.actions.append({"runbook": b.title, "id": b.id, "file": b.file, "for": f"{f.id} {TYPE_NAME.get(f.type, f.type)}",
                            "steps": steps})


def resolve_contacts(inc: Incident, esc: Escalation, cx: Ctx) -> None:
    if not inc.severity:
        return
    for r in esc.for_severity(inc.severity):
        who = next((v for k, v in r.items() if re.search(r"who|notify|name|contact|role", k) and k != "cite"), "")
        lim = next((v for k, v in r.items() if re.search(r"time|limit|within|sla|deadline", k)), "")
        how = next((v for k, v in r.items() if re.search(r"how|channel|method", k)), "")
        item = {"who": who, "limit": lim, "how": how, "cite": r["cite"], "resolved": "", "condition": ""}
        if re.search(r"data owner", who, re.I):
            names = []
            for a in inc.decisive:
                m = re.search(r"data owner:\s*([^,)]+)", a.owner, re.I)
                names.append(f"{m.group(1).strip() if m else a.owner} (data owner of {a.label}, {a.cite})")
            item["resolved"] = "; ".join(names) or "not stated in the inventory"
        elif re.search(r"system owner|owner of the affected", who, re.I):
            item["resolved"] = "; ".join(f"{a.owner} (owner of {a.label}, {a.cite})" for a in inc.decisive) or "not stated"
        m = re.search(r"\bif\b(.*)", how, re.I)
        if m:
            data = [a for a in _assets(inc) if re.search(r"finance|\bhr\b|customer|payroll", f"{a.type} {a.owner}", re.I)]
            item["condition"] = (f"condition met: {data[0].label} is \"{data[0].type}\" ({data[0].cite})" if data
                                 else "condition not shown by the files")
        inc.escalation.append(item)
    rs = cx.rule("time limit starts")
    first = min(inc.alerts, key=lambda a: a.ts) if inc.alerts else None
    inc.escalation_note = (f"Time limits start when the SOC first sees the incident ({rs})" if rs else "") + \
        (f"; the earliest related alert was raised at {iso(first.ts)} UTC "
         f"({first.extra.get('alert id', first.cite)}, {first.cite})" if first else "")


# ------------------------------------------------------------- missing data per incident
def attach_missing(inc: Incident, cov: Coverage, gaps: list[Gap], cx: Ctx, changes: list) -> None:
    for g in cov.gaps:
        hits = [f for f in inc.findings if g.start <= f.end and g.end >= f.start]
        if not hits:
            continue
        lo, hi = max(g.start, inc.start), min(g.end, inc.end)
        extra = ""
        if cx.file_info.get(g.file, {}).get("logged_at") == "close":
            extra = " Because this log is written when a session closes, any session that ended in that window is missing."
        changes_txt = ""
        m = re.search(r"firmware|reboot|maintenance|update|patch", g.reason, re.I)
        if m and changes:
            names = {e.reporter.lower() for e in cx.events if e.file == g.file and e.reporter}
            src = cx.files[g.cite.rsplit(":L", 1)[0]].lines[int(g.cite.rsplit(":L", 1)[1]) - 1].split("|")
            names |= {src[1].strip().lower()} if len(src) > 2 else set()
            named = [c for c in changes if any(n and n in (c.target_text + " " + c.title).lower() for n in names)]
            kws = [k for k in ("firmware", "patch", "update", "reboot", "maintenance") if k in g.reason.lower()]
            alike = [c for c in changes if any(k in (c.title + " " + c.target_text).lower() for k in kws[:1])]
            if not named:
                changes_txt = f" No change-calendar entry covers this device ({', '.join(sorted(n for n in names if n))})"
                if alike:
                    changes_txt += "; the only " + (kws[0] if kws else "similar") + " change, " + ", ".join(
                        f"{c.id} on {c.target_text} (status \"{c.status}\", {c.cite})" for c in alike) + ", is for another system"
                changes_txt += "."
        inc.gaps.append(f"{g.file} has no lines from {iso(g.start)} to {iso(g.end)[11:]} UTC ({g.reason or 'gap'}), "
                        f"which overlaps this incident ({iso(lo)[11:]} to {iso(hi)[11:]} UTC). What happened in that "
                        f"log during the gap is unknown, not absent.{extra}{changes_txt} [{g.cite}]")
    for g in gaps:
        if g.start <= inc.end and g.end >= inc.start:
            inc.gaps.append(g.text())
    names = {x.lower() for f in inc.findings for a in f.targets for x in (a.hostname, a.tag) if x}
    laptops = any("laptop" in a.type.lower() for f in inc.findings for a in f.targets) or \
        any(f.type in ("phishing", "credential_compromise") for f in inc.findings)
    phish = any(f.type == "phishing" for f in inc.findings)
    for m in cov.missing:
        t = m.text.lower()
        if any(n in t for n in names) or (laptops and re.search(r"laptop|endpoint|edr", t)) or \
                (phish and re.search(r"proxy|websites", t)):
            inc.missing.append(f"{m.text} [{m.cite}]")


def _vpn_change_note(changes, inc: Incident) -> list[str]:
    return []


# ------------------------------------------------------------- main entry
def analyse(root: str | Path) -> Analysis:
    root = Path(root)
    files = load_dataset(root)
    warnings: list[str] = []
    overrides: dict[str, str] = {}
    tzf = root / "timezones.json"
    if tzf.exists():
        try:
            overrides = json.loads(tzf.read_text())
        except json.JSONDecodeError:
            warnings.append("timezones.json exists but is not valid JSON; ignored")
    files.pop("timezones.json", None)

    res = Resolver()
    matrix, esc = SeverityMatrix(), Escalation()
    books: list[Runbook] = []
    for f in files.values():
        if f.kind == "inventory":
            res.load_inventory(f)
        elif f.kind == "severity":
            matrix.load(f)
        elif f.kind == "escalation":
            esc.load(f)
        elif f.kind == "runbook":
            books += load_runbooks(f)
    for f in files.values():
        if f.kind == "directory":
            res.load_directory(f)
    for need, ok in (("asset inventory", res.assets), ("severity matrix", matrix.rows), ("runbooks", books),
                     ("escalation sheet", esc.rows)):
        if not ok:
            warnings.append(f"No {need} found in the dataset; the report says where it could not decide")

    events, info = parse_logs(files, overrides)
    if not events:
        warnings.append("No timestamped log lines could be parsed")
    for p, i in info.items():
        if i["tz_assumed"]:
            warnings.append(f"{p}: time zone not stated anywhere, assumed UTC. Add it to timezones.json if that is wrong")
        if i["unparsed_lines"]:
            warnings.append(f"{p}: {len(i['unparsed_lines'])} line(s) had no readable timestamp and were skipped "
                            f"(first: L{i['unparsed_lines'][0]})")
    res.map_log_assets(files)
    res.learn_leases(events)
    company_tz = None
    for f in files.values():
        if f.kind == "policy":
            for l in f.lines:
                if re.search(r"local time", l, re.I):
                    company_tz = tz_from_text(l)
                    if company_tz:
                        break
        if company_tz:
            break

    cov = load_coverage(files, events)
    known_users = {e.user for e in events if e.user} | set(res.people) | {a.user for a in res.assets if a.user}
    changes = []
    for f in files.values():
        if f.kind == "change":
            changes += load_changes(f, res, known_users, file_time_ctx(f, files, overrides))

    cx = Ctx(events, res, files, info)
    findings, observations = run_all(cx)
    real, dismissed = [], []
    for f in findings:
        f.change = check_change(changes, f.start, f.end, f.actors, f.targets)
        if not f.dismissed:
            f.related_changes = related_changes(changes, f.start, f.end, f.actors, [a for a, _ in f.affected])
        (dismissed if f.dismissed else real).append(f)

    # phishing click -> login from the same address
    for p in [f for f in real if f.type == "phishing" and f.link_ips]:
        for c in [f for f in real if f.type == "credential_compromise" and set(f.src_ips) & set(p.link_ips)]:
            ip = sorted(set(c.src_ips) & set(p.link_ips))[0]
            click = next((e for e in p.evidence if e.category == "fw_allow" and e.dst_ip == ip), None)
            login = next((e for e in c.evidence if e.category == "auth_success" and e.src_ip == ip), None)
            c.suspected.append(Claim(f"The phishing click and this login are one attack: {', '.join(p.clickers)}'s laptop "
                                     f"connected to {ip} (the phishing host) and the VPN login came from the same {ip}. "
                                     f"Guess: the password was typed on the phishing page and reused by the attacker",
                                     cites([x for x in (click, login) if x])))
    # recipients of a phishing email whose separate activity began earlier
    for c in [f for f in real if f.variant == "suspected"]:
        for p in [f for f in real if f.type == "phishing"]:
            for u in set(c.users) & set(p.recipients):
                mail = next((e for e in p.evidence if e.category == "email" and e.user == u), None)
                if mail and mail.ts > c.start:
                    c.add(mail)
                    mins = int((mail.ts - c.start).total_seconds() // 60)
                    c.confirmed.append(Claim(f"{u} also received the phishing email at {iso(mail.ts)} UTC, {mins} min AFTER "
                                             f"this VPN session began, so that email cannot have started it", [mail.cite]))

    # a large transfer from a server that a compromised session had just reached
    for x in [f for f in real if f.type == "data_exfiltration"]:
        srcs = [a for a, _ in x.affected]
        for c in [f for f in real if f.type == "credential_compromise" and not (f.keys & x.keys)]:
            hit = [a for a, _ in c.affected if any(a is s_ for s_ in srcs)]
            if hit and c.start <= x.start <= c.end + timedelta(hours=1):
                x.keys |= c.keys
                x.suspected.append(Claim(f"This transfer is part of the {', '.join(c.users)} intrusion ({c.id}): it left "
                                         f"{hit[0].label} at {iso(x.start)} UTC, while the compromised session was on that "
                                         f"server. Guess: the same person caused both", cites(x.evidence[:1] + c.evidence[-1:])))
    alerts = [e for e in events if e.category == "alert"]
    alert_map = map_alerts(alerts, findings, res, known_users)
    gaps = find_gaps(events)
    incidents: list[Incident] = []
    for n, group in enumerate(correlate(real), 1):
        inc = Incident(id=f"INC-{n:02d}", findings=group)
        inc.alerts = [a for f in group for a in f.alerts]
        attach_missing(inc, cov, gaps, cx, changes)
        assess_severity(inc, matrix, cx)
        plan_actions(inc, books, cx, cov)
        resolve_contacts(inc, esc, cx)
        incidents.append(inc)
    incidents.sort(key=lambda i: (-sev_rank(i.severity), i.start))
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{n:02d}"
    for f in dismissed:
        b = pick_runbook(books, f.type)
        if b:
            tmp = Incident(id="", findings=[f])
            f.related_changes = [f"{b.id} step {num}: {t} [{c}]" for num, t, c in b.steps
                                 if re.search(r"change calendar|approved", t, re.I)
                                 and eval_condition(t, f, tmp, cx, cov)[0] in ("", "met")]

    an = Analysis(str(root), files, info, events, res, findings, incidents, dismissed, gaps, cov,
                  missing_files(files), observations, alert_map, company_tz, warnings)
    from .report import render
    an.report_md = render(an)
    return an
