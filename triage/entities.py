"""One machine or person under many names.

Asset inventory (hostname = IP(s) = asset tag, short names, the internal DNS domain), user
directory (username = full name = email = laptop), and address leases (VPN sessions and DHCP)
that tie a temporary IP to a user or laptop for a time window. Every match can be explained
with the lines that prove it.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .events import Event, RE_IP, parse_duration
from .ingest import SourceFile, find_col, read_table
from .timeparse import iso

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]
CRIT_ORDER = ["low", "medium", "high", "critical"]


def is_internal_ip(ip: str) -> bool:
    """RFC 1918 only (ipaddress.is_private would also flag documentation ranges, which are 'external' here)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL)


def crit_rank(c: str) -> int:
    low = (c or "").lower()
    for i in range(len(CRIT_ORDER) - 1, -1, -1):
        if CRIT_ORDER[i] in low:
            return i
    return -1


@dataclass(eq=False)
class Asset:
    tag: str
    hostname: str
    ips: list[str]
    criticality: str
    owner: str
    user: str
    type: str
    cite: str
    row: dict = field(default_factory=dict)

    @property
    def ip(self) -> str:
        return self.ips[0] if self.ips else ""

    @property
    def label(self) -> str:
        return self.hostname or self.tag or self.ip

    @property
    def key(self) -> str:
        return self.tag or self.label

    def short(self) -> str:
        ids = ", ".join(x for x in [self.tag, *self.ips] if x)
        return f"{self.label} ({ids})" if ids else self.label


@dataclass
class Person:
    username: str
    name: str
    email: str
    laptop: str
    phone: str
    manager: str
    role: str
    cite: str


@dataclass(eq=False)
class Lease:
    ip: str
    holder: str                # user (vpn) or hostname (dhcp)
    kind: str                  # vpn | dhcp
    start: datetime
    end: datetime
    cite: str
    src_ip: str = ""
    geo: str = ""
    session: str = ""
    end_cite: str = ""
    start_event: Event | None = None
    end_event: Event | None = None

    def text(self) -> str:
        if self.kind == "vpn":
            g = f", {self.geo}" if self.geo else ""
            s = f" {self.session}" if self.session else ""
            return (f"VPN session{s} of {self.holder} from {self.src_ip}{g}, {iso(self.start)} to "
                    f"{iso(self.end)[11:]} UTC")
        return f"DHCP lease of {self.holder}, from {iso(self.start)} UTC"


class Resolver:
    def __init__(self) -> None:
        self.assets: list[Asset] = []
        self.alias: dict[str, tuple[Asset, str]] = {}
        self.domain = ""
        self.domain_cite = ""
        self.people: dict[str, Person] = {}
        self.email_user: dict[str, str] = {}
        self.name_user: dict[str, str] = {}
        self.user_asset: dict[str, Asset] = {}
        self.leases: list[Lease] = []
        self.log_asset: dict[str, tuple[Asset, str]] = {}
        self.inventory_files: list[str] = []

    # ------------------------------------------------------------ loading
    def _alias(self, tok: str, a: Asset, how: str) -> None:
        t = (tok or "").strip().lower()
        if t and t not in self.alias:
            self.alias[t] = (a, how)

    def load_inventory(self, sf: SourceFile) -> None:
        rows = read_table(sf)
        if rows:
            self.inventory_files.append(sf.path)
            s = rows[0][1]
            c_tag = find_col(s, "asset_tag", "asset tag", "tag", "asset_id", "asset id") or ("id" if "id" in s else None)
            c_host = find_col(s, "hostname", "host", "device", "machine") or ("name" if "name" in s else None)
            c_ip = next((h for h in s if re.search(r"(^|[^a-z])ip([^a-z]|$)|ipaddr|ipv4|address", h)), None)
            c_crit = find_col(s, "critic", "tier", "importance", "priority", "classification")
            c_owner = find_col(s, "owner", "team", "department")
            c_user = find_col(s, "user", "assigned", "account", exclude=("owner",))
            c_type = find_col(s, "type", "role", "function", "description", "purpose")
            for line, r in rows:
                cell = r.get(c_ip, "") if c_ip else ""
                a = Asset(tag=r.get(c_tag, "") if c_tag else "", hostname=r.get(c_host, "") if c_host else "",
                          ips=RE_IP.findall(cell), criticality=r.get(c_crit, "") if c_crit else "",
                          owner=r.get(c_owner, "") if c_owner else "", user=r.get(c_user, "") if c_user else "",
                          type=r.get(c_type, "") if c_type else "", cite=sf.cite(line), row=r)
                if not (a.tag or a.hostname or a.ips):
                    continue
                self.assets.append(a)
                self._alias(a.tag, a, "asset tag column")
                self._alias(a.hostname, a, "hostname column")
                m = re.match(r"^(srv|svr|server|host)[-_](.+)$", a.hostname, re.I)
                if m:
                    self._alias(m.group(2), a, f"hostname without the `{m.group(1)}-` prefix")
                for ip in a.ips:
                    pub = re.search(rf"public\D*{re.escape(ip)}", cell, re.I)
                    self._alias(ip, a, "public address in the IP column" if pub else "IP address column")
                if a.user:
                    self.user_asset[a.user.lower()] = a
        for i, l in enumerate(sf.lines, 1):
            m = re.search(r"\b((?:[a-z0-9-]+\.)*[a-z0-9-]+\.(?:local|lan|corp|internal|intra|ad))\b", l, re.I)
            if m and "domain" in l.lower() and not self.domain:
                self.domain, self.domain_cite = m.group(1).lower(), sf.cite(i)

    def load_directory(self, sf: SourceFile) -> None:
        rows = read_table(sf)
        if not rows:
            return
        s = rows[0][1]
        c_user = find_col(s, "username", "user name", "login", "account", "user id", "userid") or find_col(s, "user")
        c_name = find_col(s, "full name", "display name") or find_col(s, "name", exclude=("user",))
        c_mail = find_col(s, "email", "mail")
        c_tag = find_col(s, "laptop", "device", "asset", "computer", "workstation")
        c_phone = find_col(s, "phone", "mobile")
        c_mgr = find_col(s, "manager")
        c_role = find_col(s, "role", "title", "position", exclude=("manager",))
        for line, r in rows:
            u = (r.get(c_user, "") if c_user else "").strip().lower()
            if not u:
                continue
            p = Person(u, r.get(c_name, "") if c_name else "", (r.get(c_mail, "") if c_mail else "").lower(),
                       r.get(c_tag, "") if c_tag else "", r.get(c_phone, "") if c_phone else "",
                       r.get(c_mgr, "") if c_mgr else "", r.get(c_role, "") if c_role else "", sf.cite(line))
            self.people[u] = p
            if p.email:
                self.email_user[p.email] = u
            if p.name:
                self.name_user[p.name.lower()] = u
        for u, p in self.people.items():
            a = self.asset(p.laptop) if p.laptop else None
            if a:
                self.user_asset.setdefault(u, a)

    def map_log_assets(self, files: dict[str, SourceFile]) -> None:
        """'# Web Server Access Log - SRV-WEB01' -> that file's lines were written by SRV-WEB01."""
        for f in files.values():
            if not f.is_log:
                continue
            for i, l in enumerate(f.lines[:3], 1):
                found = [a for a in self.hosts_in(l, names_only=True)]
                if len(found) == 1:
                    self.log_asset[f.path] = (found[0], f.cite(i))
                    break

    def learn_leases(self, events: list[Event]) -> None:
        for g in events:
            ip = g.extra.get("assigned_ip")
            if not ip or g.category != "auth_success" or not g.user:
                continue
            sess = str(g.extra.get("session", ""))
            lease = Lease(ip, g.user, "vpn", g.ts, g.ts + timedelta(hours=24), g.cite, g.src_ip,
                          str(g.extra.get("geo") or g.extra.get("country") or ""), sess, start_event=g)
            for e in events:
                if e.ts <= g.ts or e is g:
                    continue
                same = (sess and str(e.extra.get("session", "")) == sess) or \
                       (not sess and e.user == g.user and e.file == g.file)
                if e.category == "auth_logout" and same:
                    lease.end, lease.end_cite, lease.end_event = e.ts, e.cite, e
                    break
                if e.extra.get("assigned_ip") == ip:
                    lease.end = e.ts
                    break
            self.leases.append(lease)
        for d in events:
            if d.category != "dhcp":
                continue
            ip = d.src_ip or str(d.extra.get("ip", ""))
            dur = parse_duration(d.extra.get("lease")) or 24 * 3600
            if ip:
                self.leases.append(Lease(ip, d.host, "dhcp", d.ts, d.ts + timedelta(seconds=dur), d.cite, start_event=d))

    # ------------------------------------------------------------ lookups
    def _norm(self, tok: str) -> str:
        t = (tok or "").strip().strip("\"'[](),;|").lower()
        if "\\" in t:
            t = t.rsplit("\\", 1)[-1]
        if "/" in t and not re.fullmatch(r"[\d.]+/\d+", t):
            t = t.rsplit("/", 1)[-1]
        return re.sub(r":\d+$", "", t)

    def lookup(self, tok: str) -> tuple[Asset, str, list[str]] | None:
        raw = (tok or "").strip()
        t = self._norm(raw)
        steps = [f"`{raw}` names host `{t}`"] if t and t != raw.lower() else []
        if t in self.alias:
            a, how = self.alias[t]
            return a, how, steps
        if t and not RE_IP.fullmatch(t) and "." in t:
            short, dom = t.split(".", 1)
            if short in self.alias:
                a, how = self.alias[short]
                note = f"drop the internal domain `{dom}`"
                if self.domain and dom == self.domain:
                    note += f" ({self.domain_cite})"
                return a, how, steps + [note]
        return None

    def asset(self, tok: str) -> Asset | None:
        hit = self.lookup(tok)
        return hit[0] if hit else None

    def explain(self, tok: str) -> str | None:
        hit = self.lookup(tok)
        if not hit:
            return None
        a, how, steps = hit
        names = " = ".join(x for x in (a.hostname, *a.ips, a.tag) if x)
        path = "; ".join(steps + [f"matches the {how}"])
        return f"`{tok}`: {path} of the inventory row {names} ({a.cite})"

    def hosts_in(self, text: str, names_only: bool = False) -> list[Asset]:
        low = text.lower()
        seen: list[Asset] = []
        for tok, (a, _) in self.alias.items():
            if names_only and RE_IP.fullmatch(tok):
                continue
            if a not in seen and len(tok) >= 4 and re.search(rf"(?<![\w.-]){re.escape(tok)}(?![\w-])", low):
                seen.append(a)
        return seen

    def users_in(self, text: str, known: set[str]) -> set[str]:
        low = text.lower()
        out = {u for u in known if u and re.search(rf"(?<![\w.]){re.escape(u)}(?![\w])", low)}
        out |= {u for n, u in self.name_user.items() if n in low}
        return out

    def person(self, user: str) -> Person | None:
        return self.people.get((user or "").lower())

    def user_label(self, user: str) -> str:
        p = self.person(user)
        return f"{user} ({p.name})" if p and p.name else user

    def user_laptop(self, user: str) -> tuple[Asset | None, list[str]]:
        u = (user or "").lower()
        a = self.user_asset.get(u)
        if not a:
            return None, []
        p = self.people.get(u)
        return a, ([p.cite] if p else []) + [a.cite]

    def leases_of_host(self, hostname: str) -> list[Lease]:
        return [l for l in self.leases if l.kind == "dhcp" and l.holder.lower() == (hostname or "").lower()]

    def lease_at(self, ip: str, ts: datetime, kind: str | None = None) -> Lease | None:
        for l in self.leases:
            if l.ip == ip and l.start <= ts <= l.end and (kind is None or l.kind == kind):
                return l
        return None

    def lease_of_event(self, e: Event) -> Lease | None:
        for l in self.leases:
            if l.start_event is e or l.end_event is e:
                return l
        return None

    def describe_ip(self, ip: str, ts: datetime | None = None) -> tuple[str, list[str]]:
        a = self.asset(ip)
        if a:
            extra = f", {a.type}" if a.type else ""
            return f"{ip} = {a.label} ({a.tag}{extra})", [a.cite]
        l = self.lease_at(ip, ts, "vpn") if ts else None
        if l:
            return f"{ip} = {l.text()}", [l.cite]
        l = self.lease_at(ip, ts, "dhcp") if ts else None
        if l:
            return f"{ip} = {l.holder} (DHCP)", [l.cite]
        return ip, []

    def target_of(self, e: Event) -> Asset | None:
        for tok in (e.host, str(e.extra.get("target", "")), e.dst_ip, str(e.extra.get("service", ""))):
            if tok:
                a = self.asset(tok)
                if a:
                    return a
        return None

    def reporter_asset(self, e: Event) -> Asset | None:
        return self.asset(e.reporter) or (self.log_asset.get(e.file, (None, ""))[0])
