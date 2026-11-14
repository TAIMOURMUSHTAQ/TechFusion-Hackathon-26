"""Detection rules. Each returns Findings whose every claim carries file:line citations.

Every statement is filed under exactly one label (security rules, section 2):
  confirmed - a log line or table row shows it directly
  suspected - fits an attack pattern but needs a guess; the guess is written out
  unknown   - "Not enough evidence in the logs"
"""
from __future__ import annotations

import os
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .entities import Asset, Lease, Resolver, crit_rank, is_internal_ip
from .events import Event, RE_IP
from .ingest import SourceFile
from .timeparse import iso

FAIL_THRESHOLD = int(os.getenv("TRIAGE_FAIL_THRESHOLD", "5"))
MFA_FAIL_THRESHOLD = int(os.getenv("TRIAGE_MFA_FAIL_THRESHOLD", "3"))
FAIL_WINDOW = timedelta(minutes=int(os.getenv("TRIAGE_FAIL_WINDOW_MIN", "10")))
SUCCESS_AFTER = timedelta(minutes=30)
SCAN_MIN = int(os.getenv("TRIAGE_SCAN_PORTS", "5"))
SCAN_WINDOW = timedelta(minutes=5)
EXFIL_BYTES = int(os.getenv("TRIAGE_EXFIL_BYTES", str(500 * 1000 * 1000)))
AUTH_PORTS = {"88", "464", "389", "636", "3268", "3269", "53"}     # domain authentication / directory services

WEB_SIGS = {
    "SQL injection": re.compile(r"union[\s+]+select|['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=|sleep\s*\(|waitfor\s+delay|"
                                r"drop\s+table|information_schema|order\s+by\s+\d+\s*--|;\s*(drop|insert|update|delete)\s|"
                                r"=\s*-?\d+'\s*$|=\d+'(\s|$)", re.I),
    "path traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd|boot\.ini", re.I),
    "cross-site scripting": re.compile(r"<script|onerror\s*=|javascript:", re.I),
    "sensitive path probing": re.compile(r"/\.env|/\.git/|wp-login|phpmyadmin|/server-status|backup\.(zip|sql|tar)|^/admin\b", re.I),
}
ATTACK_UA = re.compile(r"sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|probe|scanner", re.I)
RECON_ONLY = {"sensitive path probing", "scanner user agent"}


@dataclass
class Claim:
    text: str
    cites: list[str] = field(default_factory=list)


@dataclass(eq=False)
class Finding:
    type: str
    title: str
    start: datetime
    end: datetime
    variant: str = ""
    id: str = ""
    src_ips: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    actors: set[str] = field(default_factory=set)
    targets: list[Asset] = field(default_factory=list)
    affected: list[tuple[Asset, str]] = field(default_factory=list)   # counted for severity (reached)
    touched: list[tuple[Asset, str]] = field(default_factory=list)    # involved but NOT counted, with the reason
    evidence: list[Event] = field(default_factory=list)
    confirmed: list[Claim] = field(default_factory=list)
    suspected: list[Claim] = field(default_factory=list)
    unknown: list[Claim] = field(default_factory=list)
    matches: list[str] = field(default_factory=list)
    keys: set[str] = field(default_factory=set)      # strong links used to group findings into incidents
    ids: set[str] = field(default_factory=set)       # every name/IP involved (for mapping IDS alerts)
    change: object = None
    related_changes: list[str] = field(default_factory=list)
    lease: Lease | None = None
    clickers: list[str] = field(default_factory=list)
    recipients: list[str] = field(default_factory=list)
    link_ips: list[str] = field(default_factory=list)
    link_domains: list[str] = field(default_factory=list)
    sender: str = ""
    receivers: list[str] = field(default_factory=list)
    alerts: list[Event] = field(default_factory=list)

    @property
    def dismissed(self) -> bool:
        return bool(self.change and self.change.covered)

    def add(self, *evs: Event) -> None:
        for e in evs:
            if e is not None and all(e is not x for x in self.evidence):
                self.evidence.append(e)

    def affect(self, a: Asset | None, why: str) -> None:
        if a and all(a is not x for x, _ in self.affected):
            self.affected.append((a, why))
            self.touched = [(x, w) for x, w in self.touched if x is not a]
        self.target(a)

    def touch(self, a: Asset | None, why: str) -> None:
        if a and all(a is not x for x, _ in self.affected) and all(a is not x for x, _ in self.touched):
            self.touched.append((a, why))
        self.target(a)

    def target(self, a: Asset | None) -> None:
        if a and all(a is not x for x in self.targets):
            self.targets.append(a)
            self.ids |= {x.lower() for x in (a.hostname, a.tag, *a.ips) if x}


@dataclass
class Ctx:
    events: list[Event]
    res: Resolver
    files: dict[str, SourceFile]
    file_info: dict[str, dict]

    def rule(self, *words: str) -> str:
        """Citation of the first reference line (rules, matrix, runbooks, sheets) that contains all the words."""
        ws = [w.lower() for w in words]
        for f in self.files.values():
            if f.is_log:
                continue
            for i, l in enumerate(f.lines, 1):
                low = l.lower()
                if all(w in low for w in ws):
                    return f.cite(i)
        return ""


# ------------------------------------------------------------------ helpers
def cites(events: list[Event]) -> list[str]:
    """Compress citations: consecutive lines of one file become file:L6-L12."""
    by: dict[str, list[int]] = defaultdict(list)
    for e in events:
        if e is not None:
            by[e.file].append(e.line)
    out = []
    for f, ls in by.items():
        ls = sorted(set(ls))
        a = b = ls[0]
        for n in ls[1:] + [None]:
            if n is not None and n == b + 1:
                b = n
                continue
            out.append(f"{f}:L{a}" if a == b else f"{f}:L{a}-L{b}")
            if n is not None:
                a = b = n
    return out


def C(*parts) -> list[str]:
    out: list[str] = []
    for p in parts:
        if not p:
            continue
        if isinstance(p, Event):
            out += cites([p])
        elif isinstance(p, str):
            out.append(p)
        else:
            items = list(p)
            if items and isinstance(items[0], Event):
                out += cites(items)
            else:
                out += [x for x in items if x]
    return list(dict.fromkeys(out))


def span(evs: list[Event]) -> str:
    a, b = min(e.ts for e in evs), max(e.end or e.ts for e in evs)
    return f"at {iso(a)} UTC" if a == b else f"between {iso(a)} and {iso(b)[11:]} UTC"


def human_bytes(n: int) -> str:
    for unit, size in (("GB", 10 ** 9), ("MB", 10 ** 6), ("KB", 10 ** 3)):
        if n >= size:
            return f"{n / size:.2f} {unit}"
    return f"{n} bytes"


def fw_text(res: Resolver, e: Event) -> str:
    dst = res.asset(e.dst_ip)
    d = f"{dst.label} ({e.dst_ip})" if dst else e.dst_ip
    act = "allowed" if e.category == "fw_allow" else "denied"
    b = e.extra.get("bytes", {})
    vol = b.get("bytes_total") or b.get("bytes") or 0
    when = (f"{iso(e.ts)} to {iso(e.end)[11:]} UTC" if e.end and e.end != e.ts else f"{iso(e.ts)} UTC")
    s = f"{e.src_ip} -> {d}:{e.dst_port} {act}, {when}"
    if vol:
        s += f", {vol:,} bytes"
    if e.extra.get("logged_at_close") and e.extra.get("duration_s"):
        s += f" (logged at close {iso(e.end)[11:]}; start = close - {int(e.extra['duration_s'])} s)"
    return s


def note_match(f: Finding, res: Resolver, tok: str) -> None:
    why = res.explain(tok)
    if why and why not in f.matches:
        f.matches.append(why)


def laptop_text(res: Resolver, user: str) -> tuple[str, list[str], Asset | None]:
    a, cs = res.user_laptop(user)
    if not a:
        return "", [], None
    return f"{a.label} ({a.tag}, {', '.join(a.ips)})", cs, a


# ------------------------------------------------------------------ 1. logins
def detect_auth(cx: Ctx) -> list[Finding]:
    ev, res = cx.events, cx.res
    out: list[Finding] = []
    by: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in ev:
        if e.category == "auth_fail" and e.src_ip:
            by[(e.src_ip, e.user)].append(e)
    for (src, user), fails in by.items():
        clusters: list[list[Event]] = [[fails[0]]]
        for e in fails[1:]:
            (clusters[-1].append(e) if e.ts - clusters[-1][-1].ts <= FAIL_WINDOW else clusters.append([e]))
        for cl in clusters:
            mfa = [e for e in cl if "mfa" in (str(e.extra.get("reason", "")) + e.sub).lower()]
            thr = MFA_FAIL_THRESHOLD if len(mfa) * 2 >= len(cl) else FAIL_THRESHOLD
            if len(cl) < thr:
                continue
            ok = [e for e in ev if e.category == "auth_success" and e.src_ip == src
                  and cl[-1].ts <= e.ts <= cl[-1].ts + SUCCESS_AFTER and (not user or e.user == user)]
            f = Finding(type="credential_compromise" if ok else "brute_force", variant="successful" if ok else "blocked",
                        title="", start=cl[0].ts, end=(ok[0].ts if ok else cl[-1].ts), src_ips=[src],
                        users=[user] if user else [])
            f.add(*cl, *ok[:1])
            gw = res.reporter_asset(cl[0])
            reasons = Counter(str(e.extra.get("reason") or "failed") for e in cl)
            geo = cl[0].extra.get("geo")
            f.confirmed.append(Claim(
                f"{len(cl)} failed logins for {user or 'unknown user'} from {src}{f' (geo {geo})' if geo else ''}"
                f"{' at ' + gw.label if gw else ''} {span(cl)}: " + ", ".join(f"{n} x {r}" for r, n in reasons.most_common()),
                cites(cl)))
            if gw:
                note_match(f, res, cl[0].reporter or gw.label)
            if not ok:
                f.title = f"Brute-force login attempt from {src} ({len(cl)} failures, no success)"
                f.confirmed.append(Claim(f"No successful login from {src} appears in the 30 minutes after the last failure", []))
                if gw:
                    f.affect(gw, "target of the failed logins")
                f.keys |= {"ip:" + src} | ({"user:" + user} if user else set())
                f.actors = {"ip:" + src} | ({"user:" + user} if user else set())
                f.ids |= {src, user}
                out.append(f)
                continue
            s = ok[0]
            lease = res.lease_of_event(s)
            f.lease = lease
            title_how = "after " + (f"{len(mfa)} rejected MFA pushes" if mfa else f"{len(cl)} failed logins")
            f.title = f"{res.user_label(user)} logged in from {src}" + (f" ({s.extra['geo']})" if s.extra.get("geo") else "") \
                      + f" {title_how}"
            txt = f"Successful login for {user} from {src}" + (f" (geo {s.extra['geo']})" if s.extra.get("geo") else "") \
                  + f" at {iso(s.ts)} UTC" + (f", MFA {s.extra['mfa']}" if s.extra.get("mfa") else "")
            if lease:
                txt += f"; VPN session {lease.session} was given address {lease.ip}"
            f.confirmed.append(Claim(txt, [s.cite]))
            if gw:
                f.affect(gw, f"VPN session {lease.session if lease else ''} opened at {iso(s.ts)} UTC ({s.cite})".replace("  ", " "))
            # --- rule 6.1: MFA fatigue from a new country
            g = s.extra.get("geo")
            if mfa and g:
                mine = {str(e.extra.get("geo")) for e in ev if e.category == "auth_success" and e.user == user
                        and e is not s and e.extra.get("geo")}
                if mine:
                    new, basis = g not in mine, f"{user}'s other logins in the logs come from {', '.join(sorted(mine))}"
                else:
                    allg = Counter(str(e.extra.get("geo")) for e in ev if e.category == "auth_success" and e.extra.get("geo")
                                   and e.user != user)
                    usual = allg.most_common(1)[0][0] if allg else ""
                    new = bool(usual) and g != usual
                    basis = (f"{user} has no other login with a location in the logs, and every other VPN login "
                             f"comes from {usual}" if len(allg) == 1 else f"most other VPN logins come from {usual}")
                if new:
                    oth = [e for e in ev if e.category == "auth_success" and e.extra.get("geo") and e is not s]
                    f.confirmed.append(Claim(f"The approved login came from {g}, a country not seen for {user} ({basis})",
                                             C(s, oth)))
                    r = cx.rule("mfa", "country")
                    f.suspected.append(Claim(
                        f"{user}'s password is stolen: {len(mfa)} rejected/unanswered MFA pushes followed by an approved "
                        f"push from a new country is the stolen-password sign in rule 6.1. Guess: the attacker already had "
                        f"the password and kept sending pushes until one was approved", C(mfa, s, r)))
                    f.unknown.append(Claim(f"Who approved the final MFA push at {iso(s.ts)} UTC (the real {user} by "
                                           f"mistake, or someone else). The VPN log records only that it was approved", []))
            elif not mfa:
                f.suspected.append(Claim(f"The account {user} is compromised: a correct password was entered from {src} "
                                         f"right after {len(cl)} wrong ones (guess: password guessing, not the real user "
                                         f"mistyping)", C(cl[-1:], s)))
            if lease:
                _follow_session(cx, f, lease, user, src)
            f.keys |= {"ip:" + src, "user:" + user} | ({"ip:" + lease.ip} if lease else set())
            f.actors = {"ip:" + src, "user:" + user} | ({"ip:" + lease.ip} if lease else set())
            f.ids |= {src, user} | ({lease.ip} if lease else set())
            out.append(f)
    return out


def _follow_session(cx: Ctx, f: Finding, lease: Lease, user: str, src: str) -> None:
    ev, res = cx.events, cx.res
    if lease.end_event:
        e = lease.end_event
        f.add(e)
        f.confirmed.append(Claim(f"VPN session {lease.session} of {user} ended at {iso(e.ts)} UTC"
                                 + (f" after {int(e.extra['duration_s'])} s" if e.extra.get("duration_s") else ""), [e.cite]))
        f.end = max(f.end, e.ts)
    f.matches.append(f"`{lease.ip}` = {lease.text()} (address handed out in {lease.cite}"
                     + (f", session end {lease.end_cite}" if lease.end_cite else "") + ")")
    win_s, win_e = lease.start, lease.end
    inside = [e for e in ev if win_s <= e.ts <= win_e and e not in f.evidence and e.category != "alert"
              and (e.src_ip == lease.ip or e.dst_ip == lease.ip)]
    groups: dict[object, dict[str, list[Event]]] = defaultdict(lambda: defaultdict(list))
    for e in inside:
        f.add(e)
        f.end = max(f.end, e.end or e.ts)
        if e.category.startswith("fw_"):
            a = res.asset(e.dst_ip if e.src_ip == lease.ip else e.src_ip)
            groups[a or e.dst_ip]["fw"].append(e)
        elif e.sub == "service_ticket":
            a = res.asset(str(e.extra.get("service", "")))
            groups[a or str(e.extra.get("service"))]["ticket"].append(e)
        elif e.sub in ("logon", "remote_logon"):
            groups[res.target_of(e) or "?"]["logon"].append(e)
        else:
            groups[res.reporter_asset(e) or "?"]["auth"].append(e)
    for a, g in groups.items():
        label = a.label if isinstance(a, Asset) else str(a)
        for t in g["ticket"]:
            spn = str(t.extra.get("service", ""))
            f.confirmed.append(Claim(f"Kerberos service ticket for `{spn}` ({label}) issued to {t.user} for {t.src_ip} "
                                     f"at {iso(t.ts)} UTC", [t.cite]))
            note_match(f, res, spn)
        for t in g["auth"]:
            if t.sub == "tgt":
                f.confirmed.append(Claim(f"Kerberos login (TGT) for {t.user} from {t.src_ip}, workstation "
                                         f"\"{t.extra.get('workstation', '?')}\", at {iso(t.ts)} UTC", [t.cite]))
            elif t.sub in ("password_reset", "password_change"):
                f.confirmed.append(Claim(f"Password of {t.extra.get('target', t.user)} was changed by "
                                         f"{t.extra.get('caller', t.user)} from {t.src_ip} at {iso(t.ts)} UTC "
                                         f"(result {t.extra.get('result', '?')})", [t.cite]))
            else:
                f.confirmed.append(Claim(f"{t.brief()}", [t.cite]))
        if g["fw"]:
            f.confirmed.append(Claim("Internal firewall: " + "; ".join(fw_text(res, e) for e in g["fw"]), cites(g["fw"])))
            note_match(f, res, g["fw"][0].dst_ip)
        if not isinstance(a, Asset):
            continue
        real = [e for e in g["fw"] if e.category == "fw_allow" and e.dst_port not in AUTH_PORTS] + g["logon"]
        if real:
            first = min(real, key=lambda e: e.ts)
            how = "logon" if g["logon"] else f"network session on port {first.dst_port}"
            f.affect(a, f"{how} from {lease.ip} at {iso(first.ts)} UTC ({first.cite})")
            f.unknown.append(Claim(f"What {user} did inside the session on {a.label} (files, queries, commands): only "
                                   f"the network session{' and the Kerberos ticket are' if g['ticket'] else ' is'} logged", []))
        elif g["auth"] or g["fw"]:
            f.touch(a, "only domain authentication reached it (Kerberos ticket requests on port 88 and a password "
                       "change); every domain login sends these to the domain controller, so it is not a login or "
                       "session on that server")
        elif g["ticket"]:
            f.touch(a, "a ticket was requested but no session to it is logged")
    # what happened to the account around and after the session
    pw = [e for e in inside if e.sub in ("password_reset", "password_change")]
    after = [e for e in ev if win_s < e.ts <= win_e + timedelta(hours=1) and e not in f.evidence and e.user == user
             and e.category in ("auth_fail", "auth_success", "email", "other")]
    for e in [x for x in after if x.category == "email"]:
        f.add(e)
        f.confirmed.append(Claim(f"Email \"{e.extra.get('subject', '')}\" from {e.extra.get('sender', '?')} delivered to "
                                 f"{e.extra.get('recipient', user)} at {iso(e.ts)} UTC", [e.cite]))
    bad = [x for x in after if x.category == "auth_fail"]
    if bad:
        f.add(*bad)
        f.end = max(f.end, max(x.ts for x in bad))
        srcs = sorted({x.src_ip for x in bad if x.src_ip})
        lock = [x for x in bad if x.sub == "lockout"]
        fails = [x for x in bad if x.sub != "lockout"]
        txt = f"{len(fails)} failed logons for {user}" + (f" from {', '.join(res.describe_ip(s, x.ts)[0] for s in srcs for x in fails[:1])}" if srcs else "") \
              + (f" {span(fails)}" if fails else "") + (f"; the account was locked out at {iso(lock[0].ts)} UTC" if lock else "")
        f.confirmed.append(Claim(txt, cites(bad)))
        if pw and srcs:
            lap, lc, _ = laptop_text(res, user)
            p = res.person(user)
            f.suspected.append(Claim(
                f"Those failures are the real {p.name if p and p.name else user} typing the old password on "
                f"{lap or srcs[0]} after it was changed at {iso(pw[0].ts)} UTC from the attacker's VPN address "
                f"(guess: the person at {srcs[0]} is the account owner)", C(pw, bad, lc)))
    # rule 6.2: two logins from different places at the same time
    others = [e for e in ev if e.category == "auth_success" and e.user == user and e.src_ip
              and e.src_ip not in (lease.ip, src) and win_s <= e.ts <= win_e]
    if others:
        f.suspected.append(Claim(f"{user} was logged in from {others[0].src_ip} while the VPN session from {src} was "
                                 f"active (rule 6.2: sign of account misuse)", C(others, lease.cite, cx.rule("same user"))))
    else:
        lap, lc, la = laptop_text(res, user)
        if la:
            dh = [l for l in res.leases_of_host(la.hostname) if l.start <= win_e and l.end >= win_s]
            before = [e for e in ev if e.user == user and e.src_ip in la.ips and e.ts < win_s]
            later = [e for e in ev if e.user == user and e.src_ip in la.ips and e.ts > win_e]
            if dh or before or later:
                bits = []
                if dh:
                    bits.append(f"{la.label} held an office address from {iso(dh[0].start)} UTC ({dh[0].cite})")
                if before:
                    bits.append(f"{user} logged in from it at {iso(before[-1].ts)} UTC ({before[-1].cite})")
                if later:
                    bits.append(f"next activity from it at {iso(later[0].ts)} UTC ({later[0].cite})")
                f.unknown.append(Claim(f"Whether {user} was also logged in from the office laptop {lap} during the VPN "
                                       f"session (rule 6.2): " + "; ".join(bits) + f", but no login from it between "
                                       f"{iso(win_s)[11:]} and {iso(win_e)[11:]} UTC is logged", []))


# ------------------------------------------------------------------ 2. phishing
def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def detect_phishing(cx: Ctx) -> list[Finding]:
    ev, res = cx.events, cx.res
    emails = [e for e in ev if e.category == "email"]
    if not emails:
        return []
    doms = Counter(str(e.extra.get("recipient", "")).split("@")[-1].lower() for e in emails if "@" in str(e.extra.get("recipient", "")))
    company = [d for d, _ in doms.most_common(2)]

    def lookalike(dom: str) -> str:
        b = re.sub(r"[^a-z0-9]", "", dom.split(".")[0])
        for c in company:
            cb = re.sub(r"[^a-z0-9]", "", c.split(".")[0])
            if dom != c and (b == cb or _lev(b, cb) <= 2):
                return c
        return ""

    groups: dict[object, list[Event]] = defaultdict(list)
    for e in emails:
        sender = str(e.extra.get("sender", "")).lower()
        verdict = str(e.extra.get("verdict", "")).lower()
        spf = str(e.extra.get("spf", "")).lower()
        look = lookalike(sender.split("@")[-1])
        if re.search(r"suspicious|phish|malicious|spoof|malware", verdict) or (spf == "fail" and (e.extra.get("urls") or look)) \
                or (look and e.extra.get("urls")):
            groups[e.extra.get("msgid") or (sender, e.extra.get("subject"))].append(e)
    out: list[Finding] = []
    for key, evs in groups.items():
        e0 = evs[0]
        sender = str(e0.extra.get("sender", "")).lower()
        sdom = sender.split("@")[-1]
        urls = e0.extra.get("urls") or []
        domains = [str(u).split("//")[-1].split("/")[0].lower() for u in (urls if isinstance(urls, list) else [urls])]
        delivered = [e for e in evs if re.search(r"deliver|allow|accept|pass", str(e.extra.get("action", "")).lower())]
        stopped = [e for e in evs if re.search(r"quarant|block|reject|drop|held", str(e.extra.get("action", "")).lower())]
        f = Finding(type="phishing", title="", start=min(e.ts for e in evs), end=max(e.ts for e in evs), evidence=list(evs),
                    sender=sender, link_domains=domains)
        f.recipients = [res.email_user.get(str(e.extra.get("recipient", "")).lower()) or e.user for e in delivered]
        mid = f"{key} " if isinstance(key, str) else ""
        f.confirmed.append(Claim(f"Message {mid}\"{e0.extra.get('subject', '')}\" from {sender} was delivered to "
                                 f"{len(delivered)} recipient(s) {span(delivered or evs)}: "
                                 + ", ".join(str(e.extra.get("recipient")) for e in delivered), cites(delivered or evs)))
        bits = []
        look = lookalike(sdom)
        if look:
            bits.append(f"sender domain {sdom} imitates {look}")
        bits.append(f"SPF {e0.extra.get('spf', 'n/a')}, DKIM {e0.extra.get('dkim', 'n/a')}")
        if domains:
            bits.append("link host " + ", ".join(domains))
        f.confirmed.append(Claim("; ".join(bits), [e0.cite]))
        sc = e0.extra.get("score")
        r = cx.rule("score", "quarantin")
        if sc and r:
            line = cx.files[r.rsplit(":L", 1)[0]].lines[int(r.rsplit(":L", 1)[1]) - 1]
            m = re.search(r"score\s+(\d+(?:\.\d+)?)", line, re.I)
            if m and float(sc) < float(m.group(1)):
                f.confirmed.append(Claim(f"Its gateway score {sc} is below the {m.group(1)} quarantine threshold, which is "
                                         f"why it was delivered", C(e0, r)))
        for e in stopped:
            f.confirmed.append(Claim(f"The copy to {e.extra.get('recipient')} was {e.extra.get('action')} at {iso(e.ts)} UTC", [e.cite]))
        # where does the link point? (threat intel / any line naming the link domain and an external IP)
        link: dict[str, tuple[str, str]] = {}
        for sf in cx.files.values():
            if sf.kind == "email":
                continue
            for i, l in enumerate(sf.lines, 1):
                for d in domains:
                    if d and d in l.lower():
                        for ip in RE_IP.findall(l):
                            if not is_internal_ip(ip):
                                link.setdefault(ip, (d, sf.cite(i)))
        f.link_ips = sorted(link)
        for ip, (d, c) in link.items():
            f.confirmed.append(Claim(f"{c.split(':L')[0]} says {ip} hosts the link domain {d}", [c]))
        clicked, quiet = [], []
        for e in delivered:
            u = res.email_user.get(str(e.extra.get("recipient", "")).lower()) or e.user
            lap, lc, la = laptop_text(res, u)
            if la:
                p = res.person(u)
                f.matches.append(f"recipient {e.extra.get('recipient')} = {u} in the user directory"
                                 + (f" ({p.cite}), laptop tag {p.laptop}" if p else "")
                                 + f" -> {la.label} = {', '.join(la.ips)} ({la.cite})"
                                 + "".join(f"; DHCP gave {la.label} {l.ip} at {iso(l.start)} UTC ({l.cite})"
                                           for l in res.leases_of_host(la.hostname)[:1]))
            ips = set(la.ips) if la else set()
            ips |= {l.ip for l in res.leases_of_host(la.hostname)} if la else set()
            hits = [x for x in ev if x.category == "fw_allow" and x.src_ip in ips and x.dst_ip in link
                    and x.ts >= e.ts - timedelta(minutes=1)]
            if hits:
                h = hits[0]
                clicked.append(u)
                f.add(h)
                f.end = max(f.end, h.ts)
                mins = int((h.ts - e.ts).total_seconds() // 60)
                f.confirmed.append(Claim(f"{lap} ({u}'s laptop) connected to {h.dst_ip}:{h.dst_port} at {iso(h.ts)} UTC, "
                                         f"{mins} min after the email arrived", C(h, e, lc)))
                f.suspected.append(Claim(f"{u} clicked the link. Guess: that connection to {h.dst_ip} was to the phishing "
                                         f"page {link[h.dst_ip][0]}; no log shows the web address that was opened", C(h, link[h.dst_ip][1])))
                f.unknown.append(Claim(f"Whether {u} typed a password on the phishing page; no web proxy or endpoint log "
                                       f"shows what happened in the browser", []))
                f.touch(la, f"{u} clicked: handled as credential compromise, not as a phishing part")
            else:
                quiet.append(u)
                if la:
                    f.affect(la, f"laptop of recipient {u}, no click seen")
        if quiet:
            labs = [laptop_text(res, u)[0] or u for u in quiet]
            f.confirmed.append(Claim(f"No connection from {', '.join(labs)} to {', '.join(f.link_ips) or 'the link host'} "
                                     f"appears in the firewall logs", []))
            f.unknown.append(Claim(f"Whether {', '.join(quiet)} opened the link some other way (phone, home network); "
                                   f"no web proxy log exists to check", []))
        f.clickers = clicked
        f.users = clicked
        f.title = (f"Phishing email from {sender} to {len(delivered)} recipient(s)"
                   + (f"; click seen: {', '.join(clicked)}" if clicked else "; no click seen"))
        f.src_ips = sorted({str(e.extra.get('sender_ip')) for e in evs if e.extra.get('sender_ip')})
        f.keys |= {"mail:" + sender} | {"ip:" + ip for ip in f.link_ips} | {"user:" + u for u in clicked}
        f.actors = {"ip:" + ip for ip in f.src_ips}
        f.ids |= {sender, sdom, *domains, *f.link_ips, *(u for u in f.recipients if u)}
        out.append(f)
    return out


# ------------------------------------------------------------------ 3. scans
def detect_scans(cx: Ctx, alert_srcs: set[str]) -> list[Finding]:
    ev, res = cx.events, cx.res
    by: dict[str, list[Event]] = defaultdict(list)
    for e in ev:
        if e.category in ("fw_deny", "fw_allow") and e.src_ip and e.dst_ip and e.dst_port:
            by[e.src_ip].append(e)
    out = []
    for src, evs in by.items():
        best: list[Event] = []
        for i, e in enumerate(evs):
            win = [x for x in evs[i:] if x.ts - e.ts <= SCAN_WINDOW]
            if len({(x.dst_ip, x.dst_port) for x in win}) > len({(x.dst_ip, x.dst_port) for x in best}):
                best = win
        combos = {(x.dst_ip, x.dst_port) for x in best}
        if len(combos) < (3 if src in alert_srcs else SCAN_MIN):
            continue
        sdesc, scites = res.describe_ip(src, best[0].ts)
        f = Finding(type="port_scan", title="", start=best[0].ts, end=max(x.end or x.ts for x in best), src_ips=[src])
        f.add(*best)
        per: dict[str, list[Event]] = defaultdict(list)
        for x in best:
            per[x.dst_ip].append(x)
        for dst, xs in per.items():
            a = res.asset(dst)
            den = sorted({x.dst_port for x in xs if x.category == "fw_deny"}, key=lambda p: int(p) if p.isdigit() else 0)
            alw = sorted({x.dst_port for x in xs if x.category == "fw_allow"}, key=lambda p: int(p) if p.isdigit() else 0)
            f.confirmed.append(Claim(f"{src} -> {a.label + ' (' + dst + ')' if a else dst}: "
                                     + (f"denied on port(s) {', '.join(den)}" if den else "")
                                     + ("; " if den and alw else "") + (f"allowed on port(s) {', '.join(alw)}" if alw else "")
                                     + f" {span(xs)}", cites(xs)))
            if a:
                f.affect(a, "scanned host")
                note_match(f, res, dst)
        web = [e for e in ev if e.category == "web" and e.src_ip == src and f.start - SCAN_WINDOW <= e.ts <= f.end + timedelta(minutes=15)]
        if web:
            f.add(*web)
            f.end = max(f.end, max(e.ts for e in web))
            codes = Counter(e.status for e in web)
            wa = res.log_asset.get(web[0].file, (None, ""))
            f.confirmed.append(Claim(f"{len(web)} web request(s) from {src}{' to ' + wa[0].label if wa[0] else ''} {span(web)} for "
                                     + ", ".join(sorted({e.url.split('?')[0] for e in web})) + "; responses "
                                     + ", ".join(f"{n} x HTTP {c}" for c, n in sorted(codes.items()))
                                     + (f"; user agent \"{web[0].extra.get('user_agent')}\"" if web[0].extra.get('user_agent') else ""),
                                     cites(web)))
            if wa[0]:
                f.affect(wa[0], "web server that received the requests")
                f.matches.append(f"{web[0].file} is the access log of {wa[0].label} (file title {wa[1]})")
        logins = [e for e in ev if e.src_ip == src and e.category in ("auth_fail", "auth_success")]
        if not logins and not is_internal_ip(src):
            f.confirmed.append(Claim(f"No login attempt from {src} appears in the VPN or domain controller logs", []))
        if res.asset(src):
            note_match(f, res, src)
        sa = res.asset(src)
        f.title = f"Scan from {sa.label + ' (' + src + ')' if sa else src} against {len(per)} host(s), {len(combos)} host:port pairs"
        f.keys.add("ip:" + src)
        f.actors = {"ip:" + src} | ({"asset:" + res.asset(src).key} if res.asset(src) else set())
        f.ids |= {src}
        out.append(f)
    return out


# ------------------------------------------------------------------ 4. web attacks
def _size(e: Event) -> int:
    v = e.extra.get("bytes", {}).get("size") or e.extra.get("size") or 0
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def detect_web(cx: Ctx, skip: set[str]) -> list[Finding]:
    ev, res = cx.events, cx.res
    by: dict[str, list[tuple[Event, str]]] = defaultdict(list)
    for e in ev:
        if e.category != "web" or e.src_ip in skip:
            continue
        kind = next((n for n, rx in WEB_SIGS.items() if rx.search(e.url)), "")
        if not kind and ATTACK_UA.search(str(e.extra.get("user_agent", ""))):
            kind = "scanner user agent"
        if kind:
            by[e.src_ip].append((e, kind))
    out = []
    for src, hits in by.items():
        evs = [e for e, _ in hits]
        kinds = Counter(k for _, k in hits)
        errs = [e for e in evs if not e.status.startswith("2")]
        base = statistics.median([_size(e) for e in errs]) if errs else 1000
        big = [e for e in evs if e.status.startswith("2") and _size(e) >= max(5 * base, 10000)]
        recon = set(kinds) <= RECON_ONLY and not big
        f = Finding(type="port_scan" if recon else "web_attack", variant="successful" if big else "blocked", title="",
                    start=evs[0].ts, end=evs[-1].ts, src_ips=[src])
        f.add(*evs)
        ua = Counter(str(e.extra.get("user_agent", "")) for e in evs).most_common(1)[0][0]
        kind_txt = ", ".join(f"{n} {k}" for k, n in kinds.most_common())
        codes = Counter(e.status for e in evs)
        wa = res.log_asset.get(evs[0].file, (None, ""))
        target = wa[0]
        f.confirmed.append(Claim(f"{len(evs)} attack-pattern web requests from {src}{' to ' + target.label if target else ''} "
                                 f"{span(evs)} ({kind_txt}); user agent \"{ua}\"", cites(evs)))
        f.confirmed.append(Claim("Responses: " + ", ".join(f"{n} x HTTP {c}" for c, n in sorted(codes.items()))
                                 + (f"; error responses are about {int(base)} bytes" if errs else ""), cites(evs)))
        if target:
            f.matches.append(f"{evs[0].file} is the access log of {target.label} (file title {wa[1]})")
        fw = [x for x in ev if x.category.startswith("fw_") and x.src_ip == src
              and evs[0].ts - timedelta(minutes=2) <= x.ts <= evs[-1].ts + timedelta(minutes=2)]
        for x in fw:
            a = res.asset(x.dst_ip)
            if a and (target is None or a is target):
                target = a
                f.add(x)
                f.confirmed.append(Claim(f"Perimeter firewall: {fw_text(res, x)}", [x.cite]))
                note_match(f, res, x.dst_ip)
        if big:
            b = big[0]
            r = cx.rule("200", "success")
            f.confirmed.append(Claim(f"The request at {iso(b.ts)} UTC `{b.url[:140]}` got HTTP {b.status} with {_size(b):,} "
                                     f"bytes, while the other attack requests got errors of about {int(base)} bytes", [b.cite]))
            f.suspected.append(Claim(f"That request worked and returned data: a large 200 response to an attack request "
                                     f"may mean success{' (' + r + ')' if r else ''}. Guess: the extra {_size(b) - int(base):,} "
                                     f"bytes are database rows, not an ordinary page", C(b, r)))
            f.unknown.append(Claim("Which data was returned, and whether the database was read or changed: the web log keeps "
                                   "only status and size, and no database query log is in the dataset", []))
        elif not recon:
            f.confirmed.append(Claim("None of the attack requests got a success (2xx) response", cites(evs)))
        if recon:
            f.title = f"Web path probing from {src} ({kind_txt})"
        else:
            f.title = f"{'SQL injection' if 'SQL injection' in kinds else 'Web attack'} from {src}" \
                      + (f" against {target.label}" if target else "") + ("; success suspected" if big else "; attempts only")
        if target:
            f.affect(target, "web server that answered the requests")
        else:
            f.unknown.append(Claim(f"Which server received the requests: neither the web log nor the firewall names it", []))
        f.keys.add("ip:" + src)
        f.actors = {"ip:" + src}
        f.ids |= {src}
        out.append(f)
    return out


# ------------------------------------------------------------------ 5. large transfers
def detect_exfil(cx: Ctx) -> list[Finding]:
    ev, res = cx.events, cx.res
    groups: dict[str, list[tuple[Event, str, str, int, Lease | None]]] = defaultdict(list)
    for e in ev:
        b = e.extra.get("bytes") or {}
        if e.category == "fw_allow":
            if b.get("bytes_server_to_client", 0) >= EXFIL_BYTES:
                snd, rcv, n = e.dst_ip, e.src_ip, b["bytes_server_to_client"]
            elif b.get("bytes_client_to_server", 0) >= EXFIL_BYTES:
                snd, rcv, n = e.src_ip, e.dst_ip, b["bytes_client_to_server"]
            elif e.bytes_out >= EXFIL_BYTES:
                snd, rcv, n = e.src_ip, e.dst_ip, e.bytes_out
            else:
                continue
            lease = res.lease_at(rcv, e.ts, "vpn")
            external = not is_internal_ip(rcv) and not res.asset(rcv)
            remote = bool(lease and lease.src_ip and not is_internal_ip(lease.src_ip))
            if not (external or remote) or not (is_internal_ip(snd) or res.asset(snd)):
                continue
            groups[lease.session or lease.ip if lease else rcv].append((e, snd, rcv, n, lease))
        elif e.category == "auth_logout" and b.get("bytes_to_client", 0) >= EXFIL_BYTES:
            lease = res.lease_of_event(e)
            if lease and lease.src_ip and not is_internal_ip(lease.src_ip):
                groups[lease.session or lease.ip].append((e, "", lease.src_ip, b["bytes_to_client"], lease))
    out = []
    for key, items in groups.items():
        lease = next((x[4] for x in items if x[4]), None)
        evs = [x[0] for x in items]
        f = Finding(type="data_exfiltration", title="", start=min(e.ts for e in evs), end=max(e.end or e.ts for e in evs))
        f.add(*evs)
        f.lease = lease
        fw_n = vpn_n = 0
        src_asset = None
        for e, snd, rcv, n, l in items:
            if e.category == "fw_allow":
                a = res.asset(snd)
                src_asset = src_asset or a
                fw_n += n
                f.confirmed.append(Claim(f"{a.label + ' (' + snd + ')' if a else snd} sent {n:,} bytes ({human_bytes(n)}) to "
                                         f"{rcv} on port {e.dst_port}: {fw_text(res, e)}", [e.cite]))
                if a:
                    f.affect(a, f"source of the {human_bytes(n)} transfer ({e.cite})")
                    note_match(f, res, snd)
            else:
                vpn_n += n
                f.confirmed.append(Claim(f"VPN session {l.session} sent {n:,} bytes ({human_bytes(n)}) to the client at "
                                         f"{l.src_ip}{' (' + l.geo + ')' if l.geo else ''} by {iso(e.ts)} UTC", [e.cite]))
        if lease:
            f.matches.append(f"`{lease.ip}` = {lease.text()} (address handed out in {lease.cite}"
                             + (f", session end {lease.end_cite}" if lease.end_cite else "") + ")")
            f.receivers = [lease.src_ip]
            f.users = [lease.holder]
            per = [x for x in ev if x.category == "fw_allow" and x.src_ip == lease.src_ip
                   and 0 <= (lease.start - x.ts).total_seconds() <= 300 and (x.extra.get("bytes") or {}).get("bytes")]
            for x in per[-1:]:
                if cx.file_info.get(x.file, {}).get("logged_at") == "start":
                    f.unknown.append(Claim(f"The perimeter firewall shows only {x.extra['bytes']['bytes']:,} bytes for "
                                           f"{lease.src_ip} -> VPN at {iso(x.ts)} UTC, but it logs when a connection starts, "
                                           f"so that number does not measure the whole VPN session", C(x, cx.rule("connection starts"))))
        else:
            f.receivers = sorted({x[2] for x in items})
        if fw_n and vpn_n:
            f.suspected.append(Claim(f"The {human_bytes(fw_n)} from {src_asset.label if src_asset else 'the server'} is most of "
                                     f"what the VPN session sent to {lease.src_ip} ({human_bytes(vpn_n)}). Guess: the two byte "
                                     f"counts are the same data", cites(evs)))
        total = max(fw_n, vpn_n)
        r = cx.rule("stolen")
        f.suspected.append(Claim(f"This is data exfiltration: a {human_bytes(total)} transfer from a company server to an "
                                 f"address outside the company", cites(evs)))
        f.unknown.append(Claim("Which files or records were in the transfer. The logs show volume and direction only; "
                               "per the rules this is evidence of a transfer, not of which files were read" + (f" ({r})" if r else ""),
                               C(r)))
        dst = f.receivers[0] if f.receivers else "?"
        f.title = f"{human_bytes(total)} moved from {src_asset.label if src_asset else 'internal server'} to {dst}" \
                  + (f" through VPN session {lease.session}" if lease else "")
        f.keys |= {"ip:" + r_ for r_ in f.receivers} | ({"ip:" + lease.ip, "user:" + lease.holder} if lease else set())
        f.actors = set(f.keys)
        f.ids |= set(f.receivers) | ({lease.ip, lease.holder} if lease else set())
        f.src_ips = f.receivers[:]
        out.append(f)
    return out


# ------------------------------------------------------------------ 6. privileged remote access
def detect_remote_admin(cx: Ctx) -> list[Finding]:
    ev, res = cx.events, cx.res
    out = []
    for lo in [e for e in ev if e.sub == "remote_logon"]:
        a = res.target_of(lo)
        if not a or crit_rank(a.criticality) < 2:
            continue
        user, src = lo.user, lo.src_ip
        f = Finding(type="remote_admin", title=f"Remote desktop by {res.user_label(user)} to {a.label} ({a.criticality})",
                    start=lo.ts, end=lo.ts, src_ips=[src], users=[user])
        f.add(lo)
        f.confirmed.append(Claim(f"Remote desktop logon (type 10) by {user} to {a.label} from {src} at {iso(lo.ts)} UTC", [lo.cite]))
        note_match(f, res, str(lo.extra.get("target", "")))
        priv = [e for e in ev if e.sub == "privileged" and e.user == user and abs((e.ts - lo.ts).total_seconds()) <= 120]
        off = next((e for e in ev if e.ts > lo.ts and e.user == user and e.sub == "logoff"), None)
        fw = [e for e in ev if e.category.startswith("fw_") and e.src_ip == src and res.asset(e.dst_ip) is a
              and abs((e.ts - lo.ts).total_seconds()) <= 300]
        for e in priv:
            f.confirmed.append(Claim(f"Special (admin) privileges assigned to {user} at {iso(e.ts)} UTC", [e.cite]))
        if off:
            f.confirmed.append(Claim(f"Logoff of {user} from {a.label} at {iso(off.ts)} UTC", [off.cite]))
            f.end = off.ts
        for e in fw:
            f.confirmed.append(Claim("Internal firewall: " + fw_text(res, e) + " - the same session seen from the network", [e.cite]))
            f.end = max(f.end, e.end or e.ts)
        f.add(*priv, off, *fw)
        lease = res.lease_at(src, lo.ts, "vpn")
        if lease:
            f.lease = lease
            f.add(lease.start_event, lease.end_event)
            f.matches.append(f"`{src}` = {lease.text()} ({lease.cite})")
            f.src_ips.append(lease.src_ip)
        f.affect(a, f"remote desktop logon at {iso(lo.ts)} UTC ({lo.cite})")
        f.actors = {"user:" + user, "ip:" + src} | ({"ip:" + lease.src_ip} if lease else set())
        f.keys = set(f.actors)
        f.ids |= {user, src}
        out.append(f)
    return out


# ------------------------------------------------------------------ 7. rule 6.2 for VPN sessions not already explained
def detect_concurrent(cx: Ctx, findings: list[Finding]) -> tuple[list[Finding], list[Claim]]:
    ev, res = cx.events, cx.res
    used = {id(f.lease) for f in findings if f.lease}
    out, obs = [], []
    r62 = cx.rule("same user", "same time")
    for l in res.leases:
        if l.kind != "vpn" or id(l) in used or not l.src_ip or is_internal_ip(l.src_ip):
            continue
        others = [e for e in ev if e.category == "auth_success" and e.user == l.holder and e.src_ip
                  and e.src_ip not in (l.ip, l.src_ip) and l.start <= e.ts <= l.end]
        lap, lc, la = laptop_text(res, l.holder)
        dh = [d for d in res.leases_of_host(la.hostname) if d.start <= l.end and d.end >= l.start] if la else []
        if others:
            o = others[0]
            od, oc = res.describe_ip(o.src_ip, o.ts)
            f = Finding(type="credential_compromise", variant="suspected", title=f"Possible misuse of {res.user_label(l.holder)}: "
                        f"VPN from {l.src_ip} while logged in at {od.split(' = ')[-1].split(' (')[0]} (rule 6.2)",
                        start=l.start, end=l.end, src_ips=[l.src_ip], users=[l.holder], lease=l)
            f.add(l.start_event, l.end_event, *others, *(d.start_event for d in dh))
            f.confirmed.append(Claim(f"VPN login for {l.holder} from {l.src_ip}{' (' + l.geo + ')' if l.geo else ''} at "
                                     f"{iso(l.start)} UTC, address {l.ip}, session {l.session}", [l.cite]))
            if l.end_event:
                b = (l.end_event.extra.get("bytes") or {}).get("bytes_to_client")
                f.confirmed.append(Claim(f"That session stayed open until {iso(l.end)} UTC" + (f" ({b:,} bytes to the client)" if b else ""),
                                         [l.end_event.cite]))
            f.confirmed.append(Claim(f"Meanwhile {l.holder} logged in from {od} at {iso(o.ts)} UTC"
                                     + (f"; that laptop got its office address at {iso(dh[0].start)} UTC" if dh else ""),
                                     C(o, oc, [d.cite for d in dh])))
            f.suspected.append(Claim(f"The account was used from two places at the same time, which rule 6.2 treats as a sign "
                                     f"of account misuse. Guess: the VPN client at {l.src_ip} and {od.split(' = ')[-1]} in the "
                                     f"office are different devices/people", C(l.cite, o, r62)))
            inner = [e for e in ev if (e.src_ip == l.ip or e.dst_ip == l.ip) and l.start <= e.ts <= l.end]
            if not inner:
                f.unknown.append(Claim(f"Who used the VPN session and what it reached: no internal firewall or domain "
                                       f"controller line from {l.ip} is logged", []))
            gw = res.reporter_asset(l.start_event) if l.start_event else None
            if gw:
                f.affect(gw, f"VPN session {l.session} ({l.cite})")
            f.keys = {"user:" + l.holder, "ip:" + l.src_ip, "ip:" + l.ip}
            f.actors = set(f.keys)
            f.ids |= {l.holder, l.src_ip, l.ip}
            out.append(f)
        elif dh:
            obs.append(Claim(f"Rule 6.2 check for {l.holder}: the laptop {lap} held an office address from {iso(dh[0].start)} UTC "
                             f"while VPN session {l.session} from {l.src_ip} was open ({iso(l.start)} to {iso(l.end)[11:]} UTC), "
                             f"but no login by {l.holder} from the office is logged in that time, so two logins at once "
                             f"cannot be shown", C(l.cite, [d.cite for d in dh])))
    return out, obs


def run_all(cx: Ctx) -> tuple[list[Finding], list[Claim]]:
    alert_srcs = set()
    for e in cx.events:
        if e.category == "alert" and re.search(r"scan|sweep|recon", str(e.extra.get("description", e.raw)), re.I):
            m = re.search(rf"from\s+({RE_IP.pattern})", str(e.extra.get("description", e.raw)))
            if m:
                alert_srcs.add(m.group(1))
    scans = detect_scans(cx, alert_srcs)
    findings = detect_phishing(cx) + detect_auth(cx) + scans + detect_web(cx, {s.src_ips[0] for s in scans}) \
               + detect_exfil(cx) + detect_remote_admin(cx)
    extra, obs = detect_concurrent(cx, findings)
    findings += extra
    findings.sort(key=lambda f: f.start)
    for i, f in enumerate(findings, 1):
        f.id = f"F{i}"
    return findings, obs
