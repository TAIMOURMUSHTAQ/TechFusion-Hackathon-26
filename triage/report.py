"""Render the incident report as Markdown, with the sections required by the security rules (section 7):

Summary; Timeline (UTC, with file and line); Affected assets and accounts; Severity (with steps);
Confirmed; Suspected; Not enough evidence in the logs; Missing log sources; Closed as harmless
(with change ID); Recommended actions (runbook ID and step); People to inform (name and time limit).
"""
from __future__ import annotations

from datetime import datetime, timezone

from .detect import Claim, cites
from .timeparse import fmt_tz, iso

NEE = "Not enough evidence in the logs"


def _c(cs: list[str]) -> str:
    return " [" + "; ".join(cs) + "]" if cs else ""


def _claims(cs: list[Claim]) -> list[str]:
    seen, out = set(), []
    for c in cs:
        if c.text not in seen:
            seen.add(c.text)
            out.append(f"- {c.text}{_c(c.cites)}")
    return out or ["- none"]


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render(an) -> str:
    from .pipeline import timeline
    tz = an.company_tz
    tzn = f" ({fmt_tz(tz).replace('UTC+05:00', 'PKT, UTC+5')})" if tz else ""
    L: list[str] = []
    w = L.append
    w("# Incident Report - Orbit Logistics")
    w("")
    w(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC from `{an.root}` "
      f"({len(an.files)} files, {len(an.events)} timestamped log events). All times are **UTC**"
      + (f"; local time{tzn} in brackets" if tz else "") + ". Every fact cites `file:line`.")
    w("")

    # 1 ------------------------------------------------------------------
    w("## 1. Summary")
    w("")
    w("| Incident | Severity | Window (UTC) | What happened |")
    w("|---|---|---|---|")
    for i in an.incidents:
        w(f"| {i.id} | **{i.severity or 'undecided'}** | {iso(i.start)} to {iso(i.end)[11:]} | "
          + _cell("; ".join(f"{f.id}: {f.title}" for f in i.findings)) + " |")
    for f in an.dismissed:
        w(f"| closed | none | {iso(f.start)} to {iso(f.end)[11:]} | {_cell(f.title)}: approved change {f.change.change.id} |")
    w("")
    if an.alert_map:
        w("**Every IDS alert and where it went**")
        w("")
        w("| Alert | Raised (UTC) | Description | Outcome |")
        w("|---|---|---|---|")
        from .pipeline import _alert_outcome
        for a, f in sorted(an.alert_map, key=lambda x: x[0].ts):
            w(f"| {a.extra.get('alert id', '')} | {iso(a.ts)} | {_cell(a.extra.get('description', a.raw))} | "
              f"{_alert_outcome(f, an)} [{a.cite}] |")
        w("")

    # 2 ------------------------------------------------------------------
    w("## 2. Timeline (UTC, with file and line)")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id} - {inc.title}")
        w("")
        w("| # | Time UTC" + (" (local)" if tz else "") + " | As written in the log | Source | Event |")
        w("|---|---|---|---|---|")
        for n, e in enumerate(timeline(inc), 1):
            loc = f" ({e.ts.astimezone(tz).strftime('%H:%M:%S')})" if tz else ""
            note = (f" _session start; line logged at close {iso(e.end)[11:]}_" if e.extra.get("logged_at_close")
                    and e.end and e.end != e.ts else "")
            w(f"| {n} | {iso(e.ts)}{loc} | `{_cell(e.raw_ts)}` | {e.cite} | {_cell(e.brief())}{note} |")
        w("")

    # 3 ------------------------------------------------------------------
    w("## 3. Affected assets and accounts")
    w("")
    res = an.resolver
    for inc in an.incidents:
        w(f"### {inc.id}")
        w("")
        srcs: dict[str, list[str]] = {}
        for f in sorted(inc.findings, key=lambda f: f.start):
            if f.sender:
                srcs.setdefault(f"email sender {f.sender}", []).append(f.id)
            for ip in f.src_ips:
                d = res.describe_ip(ip, f.start)[0]
                srcs.setdefault(d, []).append(f.id)
        w("- **Source of the suspicious activity:** " + ("; ".join(f"{k} ({', '.join(dict.fromkeys(v))})" for k, v in srcs.items()) or "unknown"))
        users = list(dict.fromkeys(u for f in inc.findings for u in f.users if u))
        for u in users:
            p = res.person(u)
            w(f"- **Account:** {u}" + (f" = {p.name}, {p.role}, {p.email}, laptop tag {p.laptop}, manager {p.manager} [{p.cite}]" if p else ""))
        rows = []
        for f in inc.findings:
            for a, why in f.affected:
                rows.append((a, f"reached ({f.id}): {why}"))
            for a, why in f.touched:
                rows.append((a, f"involved but not counted for severity ({f.id}): {why}"))
        if rows:
            w("")
            w("| Asset | Tag / IP | Type | Owner | Criticality | Role in this incident |")
            w("|---|---|---|---|---|---|")
            for a, why in rows:
                w(f"| {a.label} | {a.tag} / {', '.join(a.ips)} | {_cell(a.type)} | {_cell(a.owner)} | "
                  f"**{a.criticality or 'n/a'}** [{a.cite}] | {_cell(why)} |")
        matches = list(dict.fromkeys(m for f in inc.findings for m in f.matches))
        if matches:
            w("")
            w("How the same thing was matched across files:")
            w("")
            for m in matches:
                w(f"- {m}")
        w("")

    # 4 ------------------------------------------------------------------
    w("## 4. Severity (with steps)")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id}: **{inc.severity or 'cannot be decided from the files'}**")
        w("")
        for n, s in enumerate(inc.severity_steps, 1):
            w(f"{n}. {s}")
        w("")

    # 5-7 ----------------------------------------------------------------
    w("## 5. Confirmed")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id}")
        w("")
        L.extend(_claims([c for f in sorted(inc.findings, key=lambda f: f.start) for c in f.confirmed]))
        w("")
    w("## 6. Suspected")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id}")
        w("")
        sus = [c for f in sorted(inc.findings, key=lambda f: f.start) for c in f.suspected]
        L.extend(_claims(sus))
        w("")
    w(f"## 7. {NEE}")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id}")
        w("")
        unk = [c for f in sorted(inc.findings, key=lambda f: f.start) for c in f.unknown]
        unk += [Claim(g, []) for g in inc.gaps]
        L.extend(_claims(unk))
        w("")
    if an.observations:
        w("### Other checks with no result")
        w("")
        L.extend(_claims(an.observations))
        w("")

    # 8 ------------------------------------------------------------------
    w("## 8. Missing log sources")
    w("")
    cov = an.coverage
    for g in cov.gaps:
        w(f"- {g.text()}")
    for m in cov.missing:
        w(f"- {m.text} [{m.cite}]")
    for g in an.gaps:
        w(f"- {g.text()}")
    for _, m in an.missing:
        w(f"- {m}")
    if not (cov.gaps or cov.missing or an.gaps or an.missing):
        w("- none detected")
    w("")
    for inc in an.incidents:
        if inc.missing:
            w(f"Relevant to {inc.id}: " + "; ".join(inc.missing))
            w("")

    # 9 ------------------------------------------------------------------
    w("## 9. Closed as harmless (with change ID)")
    w("")
    if not an.dismissed:
        w("- none")
    for f in an.dismissed:
        w(f"**{f.change.change.id}: {f.title}** ({iso(f.start)} to {iso(f.end)[11:]} UTC){_c(cites(f.evidence))}")
        w("")
        for r in f.change.reasons:
            w(f"- {r}")
        for r in f.related_changes:
            w(f"- {r}")
        w(f"- Closed as approved activity and not escalated (rule 3.2). Alerts: "
          + (", ".join(f"{a.extra.get('alert id', '')} [{a.cite}]" for a in f.alerts) or "none"))
        w("")
    near = [(i, f) for i in an.incidents for f in i.findings if f.related_changes or (f.change and not f.change.covered)]
    if near:
        w("Checked against the change calendar but **not** closed:")
        w("")
        for i, f in near:
            if f.change and not f.change.covered:
                w(f"- {i.id} {f.id}: " + "; ".join(f.change.reasons))
            for r in f.related_changes:
                w(f"- {i.id} {f.id}: {r}")
        w("")

    # 10 -----------------------------------------------------------------
    w("## 10. Recommended actions (runbook ID and step)")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id}")
        w("")
        for a in inc.actions:
            if not a.get("runbook"):
                w(f"- {a['for']}: {a['note']}")
                continue
            w(f"**{a['runbook']}** (for {a['for']})")
            w("")
            for s in a["steps"]:
                if s["step"] == "note":
                    w(f"- _{s['text']}_")
                    continue
                cond = ""
                if s.get("condition"):
                    cond = f" _Condition {s['condition']}: {s['condition_detail']}._"
                hint = f" -> {s['applies_to']}" if s["applies_to"] else ""
                w(f"- **{s['step']}**: {s['text']}{hint}{cond} [{s['cite']}]")
            w("")

    # 11 -----------------------------------------------------------------
    w("## 11. People to inform (name and time limit)")
    w("")
    for inc in an.incidents:
        w(f"### {inc.id} ({inc.severity or 'severity unknown'})")
        w("")
        if not inc.severity:
            w("- Cannot be decided: severity is unknown, so the escalation sheet cannot be applied.")
        elif not inc.escalation:
            w(f"- The escalation sheet has no row for {inc.severity}.")
        else:
            w("| Who | Name for this incident | Time limit | How | Source |")
            w("|---|---|---|---|---|")
            for r in inc.escalation:
                how = r["how"] + (f" - {r['condition']}" if r["condition"] else "")
                w(f"| {_cell(r['who'])} | {_cell(r['resolved'] or '-')} | **{r['limit']}** | {_cell(how)} | {r['cite']} |")
        if inc.escalation_note:
            w("")
            w(f"_{inc.escalation_note}._")
        w("")

    # appendix -----------------------------------------------------------
    w("## Appendix A: How timestamps were read")
    w("")
    w("| File | Kind | Time zone used | Events | Notes |")
    w("|---|---|---|---|---|")
    for p, i in sorted(an.file_info.items()):
        w(f"| {p} | {i['kind']} | {i['timezone']} | {i['events']} | {_cell('; '.join(i['notes']) or '-')} |")
    w("")
    if an.warnings:
        w("## Appendix B: Analyst notes")
        w("")
        for x in an.warnings:
            w(f"- {x}")
        w("")
    return "\n".join(L)
