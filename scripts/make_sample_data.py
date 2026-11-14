"""Generate the SAMPLE Orbit Logistics dataset in ./data.

This is a synthetic stand-in for the organiser's files so the project runs
end to end. Replace ./data with the real files at kickoff.

Every event is defined once in UTC and then written in the format and time
zone that each system uses, so the "right answer" is known:

  auth.log            syslog, LOCAL time (UTC+05:00), no year
  vpn.log             DD/MM/YYYY, LOCAL time (UTC+05:00)
  web_access.log      Apache combined, explicit +0000
  firewall.csv        ISO 8601, UTC ("Z")
  email_gateway.jsonl ISO 8601 with +05:00 offset
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

UTC = timezone.utc
LOCAL = timezone(timedelta(hours=5))
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "data")


def u(day: int, hh: int, mm: int, ss: int = 0) -> datetime:
    return datetime(2026, 11, day, hh, mm, ss, tzinfo=UTC)


def syslog(t: datetime) -> str:
    l = t.astimezone(LOCAL)
    return f"{l.strftime('%b')} {l.day:>2} {l.strftime('%H:%M:%S')}"


def dmy(t: datetime) -> str:
    return t.astimezone(LOCAL).strftime("%d/%m/%Y %H:%M:%S")


def apache(t: datetime) -> str:
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def isoz(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def isolocal(t: datetime) -> str:
    return t.astimezone(LOCAL).isoformat()


def write(rel: str, text: str) -> None:
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text.rstrip("\n") + "\n", encoding="utf-8")


# --------------------------------------------------------------- auth.log
def auth_log() -> None:
    ev: list[tuple[datetime, str]] = []
    # Approved DB maintenance (CHG-1045): r.khan from jump-01, a few typos first
    for i, s in enumerate([5, 12, 21, 33, 47]):
        ev.append((u(9, 17, 5, s), f"db-prod-01 sshd[41{i}2]: Failed password for r.khan from 10.0.0.40 port 5021{i} ssh2"))
    ev.append((u(9, 17, 7, 30), "db-prod-01 sshd[4190]: Accepted password for r.khan from 10.0.0.40 port 50233 ssh2"))
    ev.append((u(9, 17, 7, 31), "db-prod-01 sshd[4190]: pam_unix(sshd:session): session opened for user r.khan by (uid=0)"))
    ev.append((u(9, 17, 10, 2), "db-prod-01 sudo: r.khan : TTY=pts/0 ; PWD=/home/r.khan ; USER=root ; COMMAND=/usr/bin/systemctl stop postgresql"))
    ev.append((u(9, 17, 41, 15), "db-prod-01 sudo: r.khan : TTY=pts/0 ; PWD=/home/r.khan ; USER=root ; COMMAND=/usr/bin/pg_upgradecluster 15 main"))
    ev.append((u(9, 18, 12, 40), "db-prod-01 sudo: r.khan : TTY=pts/0 ; PWD=/home/r.khan ; USER=root ; COMMAND=/usr/bin/systemctl start postgresql"))
    ev.append((u(9, 18, 20, 3), "db-prod-01 sshd[4190]: pam_unix(sshd:session): session closed for user r.khan"))
    # fs-prod-02 heartbeat every 5 minutes, with a hole 04:21-04:54 UTC
    t = u(10, 3, 30)
    while t <= u(10, 5, 30):
        if not (u(10, 4, 21) <= t <= u(10, 4, 54)):
            ev.append((t, "fs-prod-02 CRON[2201]: (root) CMD (/usr/local/bin/heartbeat.sh)"))
        t += timedelta(minutes=5)
    ev.append((u(10, 4, 54, 40), 'fs-prod-02 rsyslogd: [origin software="rsyslogd" swVersion="8.2102.0"] start'))
    # The intrusion
    ev.append((u(10, 4, 19, 30), "fs-prod-02 sshd[9911]: Accepted password for a.malik from 10.8.0.23 port 51122 ssh2"))
    ev.append((u(10, 4, 19, 31), "fs-prod-02 sshd[9911]: pam_unix(sshd:session): session opened for user a.malik by (uid=0)"))
    for i, s in enumerate([5, 11, 19]):
        ev.append((u(10, 4, 22, s), f"db-prod-01 sshd[77{i}0]: Failed password for a.malik from 10.8.0.23 port 5140{i} ssh2"))
    ev.append((u(10, 5, 2, 10), "fs-prod-02 sshd[9911]: pam_unix(sshd:session): session closed for user a.malik"))
    # db-prod-01 hourly cron
    for h in range(0, 6):
        ev.append((u(10, h, 0, 1), "db-prod-01 CRON[1180]: (postgres) CMD (/usr/local/bin/pg_health.sh)"))
    ev.sort(key=lambda x: x[0])
    write("logs/auth.log", "\n".join(f"{syslog(t)} {m}" for t, m in ev))


# ---------------------------------------------------------------- vpn.log
def vpn_log() -> None:
    ev = [
        (u(9, 3, 58, 12), "event=login_success user=a.malik src=192.0.2.14 assigned_ip=10.8.0.11"),
        (u(9, 4, 30, 44), "event=login_success user=r.khan src=192.0.2.80 assigned_ip=10.8.0.12"),
        (u(9, 12, 5, 9), "event=logout user=a.malik src=192.0.2.14 duration=29217s"),
        (u(9, 13, 1, 50), "event=logout user=r.khan src=192.0.2.80 duration=30666s"),
        (u(10, 3, 55, 3), "event=login_success user=s.ahmed src=192.0.2.61 assigned_ip=10.8.0.14"),
    ]
    for mm, ss in [(10, 2), (10, 48), (11, 37), (12, 30), (13, 22), (14, 41), (15, 40)]:
        ev.append((u(10, 4, mm, ss), "event=login_failed user=a.malik src=203.0.113.77 reason=bad_password"))
    ev.append((u(10, 4, 16, 5), "event=login_success user=a.malik src=203.0.113.77 assigned_ip=10.8.0.23"))
    ev.append((u(10, 5, 3, 0), "event=logout user=a.malik src=203.0.113.77 duration=2815s"))
    ev.sort(key=lambda x: x[0])
    write("logs/vpn.log", "\n".join(f"{dmy(t)} vpn-gw-01 {m}" for t, m in ev))


# --------------------------------------------------------- web_access.log
def web_log() -> None:
    ev: list[tuple[datetime, str, str, int, int, str]] = []
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    normal = ["/", "/portal/login", "/portal/track?id=88213", "/static/app.js", "/portal/rates", "/portal/track?id=90121"]
    ips = ["192.0.2.33", "192.0.2.101", "192.0.2.150", "192.0.2.77"]
    t = u(10, 0, 31, 7)
    for i in range(22):
        ev.append((t, ips[i % 4], f"GET {normal[i % 6]} HTTP/1.1", 200, 1800 + 37 * i, ua))
        t += timedelta(minutes=12, seconds=11)
    # Approved vulnerability scan (CHG-1042) from scan-01
    probes = [
        ("/admin", 404), ("/.env", 403), ("/wp-login.php", 404), ("/portal/track?id=1'%20OR%20'1'='1", 403),
        ("/../../etc/passwd", 403), ("/phpmyadmin/", 404), ("/portal/login?next=<script>alert(1)</script>", 403),
        ("/backup.zip", 404), ("/server-status", 403), ("/portal/track?id=1%20UNION%20SELECT%20NULL--", 403),
        ("/.git/config", 403), ("/api/v1/users", 404), ("/portal/rates", 200), ("/robots.txt", 200),
    ]
    t = u(10, 1, 5, 2)
    for i in range(24):
        path, code = probes[i % len(probes)]
        ev.append((t, "10.0.5.50", f"GET {path} HTTP/1.1", code, 310, "OrbitSec-Scanner/4.2"))
        t += timedelta(seconds=48)
    # Real, unapproved SQL injection attempts from the internet (all blocked)
    sqli = [
        "/portal/track?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/portal/track?id=1%27%20OR%20%271%27=%271",
        "/portal/track?id=1;%20DROP%20TABLE%20shipments--",
        "/portal/track?id=1%27%20AND%20SLEEP(5)--",
    ]
    t = u(10, 2, 40, 10)
    for i in range(8):
        ev.append((t, "198.51.100.23", f"GET {sqli[i % 4]} HTTP/1.1", 403, 199, "sqlmap/1.8.4#stable"))
        t += timedelta(seconds=31)
    ev.sort(key=lambda x: x[0])
    write("logs/web_access.log", "\n".join(
        f'{ip} - - [{apache(t)}] "{req}" {code} {size} "-" "{agent}"' for t, ip, req, code, size, agent in ev))


# ------------------------------------------------------------ firewall.csv
def firewall() -> None:
    rows: list[tuple[datetime, str]] = []
    rows.append((u(9, 20, 0, 4), "allow,10.0.2.30,40112,10.0.2.20,873,tcp,5368709120,20480,INT-BACKUP"))
    for i, port in enumerate([21, 22, 23, 25, 80, 135, 445, 1433, 3306, 3389, 5432, 8080]):
        rows.append((u(10, 1, 2, 5 + 4 * i), f"deny,10.0.5.50,4{4000 + i},10.0.2.30,{port},tcp,0,0,DEFAULT-DENY"))
    rows.append((u(10, 1, 4, 58), "allow,10.0.5.50,44100,10.0.1.10,443,tcp,48211,90122,INT-SCANNER-WEB"))
    for i, (hh, mm) in enumerate([(0, 40), (1, 30), (2, 10), (3, 5), (3, 50), (4, 35), (5, 10)]):
        src = ["10.0.8.43", "10.0.8.98"][i % 2]
        rows.append((u(10, hh, mm, 12), f"allow,{src},5{1000 + i},192.0.2.200,443,tcp,{18000 + 911 * i},{240000 + 1000 * i},OUT-HTTPS-ANY"))
    rows.append((u(10, 2, 40, 9), "allow,198.51.100.23,39811,10.0.1.10,443,tcp,6120,1592,IN-WEB-HTTPS"))
    rows.append((u(10, 4, 10, 1), "allow,203.0.113.77,50211,10.0.0.5,443,tcp,9120,11004,IN-VPN"))
    rows.append((u(10, 4, 19, 29), "allow,10.8.0.23,51122,10.0.2.20,22,tcp,88213,412230,VPN-TO-SERVERS"))
    rows.append((u(10, 4, 22, 4), "allow,10.8.0.23,51400,10.0.2.30,22,tcp,3120,2890,VPN-TO-SERVERS"))
    rows.append((u(10, 4, 52, 11), "allow,10.0.2.20,49822,198.51.100.44,443,tcp,1932735283,402113,OUT-HTTPS-ANY"))
    rows.sort(key=lambda x: x[0])
    head = "timestamp,action,src_ip,src_port,dst_ip,dst_port,protocol,bytes_out,bytes_in,rule"
    write("logs/firewall.csv", head + "\n" + "\n".join(f"{isoz(t)},{r}" for t, r in rows))


# ------------------------------------------------------------- email log
def email_log() -> None:
    dom = "orbitlogistics.example"
    rows = [
        (u(10, 2, 15, 40), "inbound", "billing@freightpartner.example", "192.0.2.210", f"r.khan@{dom}", "Invoice 4471", "pass", "clean", "delivered", []),
        (u(10, 3, 1, 2), "inbound", "noreply@customs-portal.example", "192.0.2.211", f"s.ahmed@{dom}", "Clearance update", "pass", "clean", "delivered", []),
        (u(10, 3, 42, 10), "inbound", "it-support@orbit-logistics-helpdesk.com", "203.0.113.90", f"a.malik@{dom}", "Password expiry notice - action required", "fail", "suspicious", "delivered", ["http://orbit-logistics-helpdesk.com/reset"]),
        (u(10, 3, 42, 12), "inbound", "it-support@orbit-logistics-helpdesk.com", "203.0.113.90", f"s.ahmed@{dom}", "Password expiry notice - action required", "fail", "suspicious", "quarantined", ["http://orbit-logistics-helpdesk.com/reset"]),
        (u(10, 4, 5, 55), "outbound", f"s.ahmed@{dom}", "10.0.0.25", "ops@freightpartner.example", "Re: Manifest 2291", "pass", "clean", "delivered", []),
    ]
    out = []
    for t, d, s, ip, r, subj, spf, verdict, action, urls in rows:
        out.append(json.dumps({"ts": isolocal(t), "direction": d, "sender": s, "sender_ip": ip, "recipient": r,
                               "subject": subj, "spf": spf, "verdict": verdict, "action": action, "urls": urls}))
    write("logs/email_gateway.jsonl", "\n".join(out))


# ------------------------------------------------------------ reference docs
def docs() -> None:
    write("inventory/asset_inventory.csv", """asset_tag,hostname,ip_address,type,owner,primary_user,criticality,location
OL-SRV-0001,web-prod-01,10.0.1.10,Web server (customer portal),IT Operations,,High,DC-1
OL-SRV-0003,mail-gw-01,10.0.0.25,Email gateway,IT Operations,,High,DC-1
OL-SRV-0007,db-prod-01,10.0.2.30,Database server (shipments DB),Data Team,,Critical,DC-1
OL-SRV-0012,fs-prod-02,10.0.2.20,File server (shipping manifests and customer documents),Finance Operations,,Critical,DC-1
OL-SRV-0020,vpn-gw-01,10.0.0.5,VPN gateway,Network Team,,High,DC-1
OL-SRV-0031,scan-01,10.0.5.50,Vulnerability scanner,Security Team,,Low,DC-1
OL-SRV-0040,jump-01,10.0.0.40,Admin jump host,IT Operations,,Medium,DC-1
OL-LAP-0143,lt-amalik,10.0.8.43,Laptop,Ayesha Malik,a.malik,Medium,Karachi office
OL-LAP-0098,lt-rkhan,10.0.8.98,Laptop,Rehan Khan,r.khan,Medium,Karachi office
OL-LAP-0161,lt-sahmed,10.0.8.61,Laptop,Sara Ahmed,s.ahmed,Medium,Lahore office""")

    write("policies/severity_matrix.md", """# Orbit Logistics - Incident Severity Matrix

Severity is chosen from the incident type (row) and the criticality of the most critical
affected asset (column), as recorded in `inventory/asset_inventory.csv`.

| Incident type | Low | Medium | High | Critical |
|---|---|---|---|---|
| Credential compromise (account takeover, successful login) | SEV3 | SEV2 | SEV1 | SEV1 |
| Brute-force attempt (no successful login) | SEV4 | SEV4 | SEV3 | SEV3 |
| Phishing email delivered (no confirmed click) | SEV4 | SEV3 | SEV3 | SEV2 |
| Web application attack - blocked | SEV4 | SEV4 | SEV3 | SEV3 |
| Web application attack - successful | SEV3 | SEV2 | SEV1 | SEV1 |
| Suspected data exfiltration | SEV3 | SEV2 | SEV1 | SEV1 |
| Port scan or reconnaissance | SEV4 | SEV4 | SEV4 | SEV3 |
| Malware infection | SEV3 | SEV2 | SEV1 | SEV1 |

Rules:
1. If more than one incident type applies to the same incident, use the highest severity.
2. Activity covered by an approved entry in `change_calendar.csv` is not an incident and gets no severity.
3. SEV1 is the most serious and SEV4 the least.""")

    write("policies/security_rules.md", """# Orbit Logistics - Security Rules (extract)

## 1. Logging standards
- `auth.log` and `vpn.log` are written in local time (PKT, UTC+05:00). `auth.log` lines carry no year.
- `web_access.log` and `firewall.csv` are written in UTC.
- `email_gateway.jsonl` timestamps carry their own UTC offset.
- File access auditing on fs-prod-02 is shipped to `logs/fs_audit.log`.
- Web proxy click logs are kept in `logs/proxy.log`.

## 2. Accounts and access
- VPN accounts must use multi-factor authentication. Exceptions are recorded by the Network Team.
- Five or more failed logins from one source inside ten minutes must be reviewed.
- Administrative work on production servers is done through jump-01 and must have an approved change.

## 3. Incident handling
- Only actions listed in the approved runbooks may be recommended.
- Analysts must not state that data was stolen unless file audit or DLP evidence shows it.
- Planned scans and approved changes in `change_calendar.csv` must not be escalated.
- Missing logs must be reported, never assumed to mean "nothing happened".""")

    write("change_calendar.csv", """change_id,title,type,start,end,timezone,source,targets,performed_by,approved_by,status
CHG-1042,Monthly authenticated vulnerability scan,Security scan,2026-11-10 06:00,2026-11-10 08:00,UTC+05:00,scan-01,web-prod-01; db-prod-01,Security Team,S. Qureshi,Approved
CHG-1045,PostgreSQL minor version upgrade,Admin maintenance,2026-11-09 22:00,2026-11-09 23:30,UTC+05:00,jump-01,db-prod-01,r.khan,H. Raza,Approved
CHG-1050,Firewall firmware patch,Network maintenance,2026-11-12 23:00,2026-11-13 01:00,UTC+05:00,,vpn-gw-01,Network Team,H. Raza,Approved""")

    write("contacts/escalation_contacts.csv", """severity,notify,role,contact,notify_within,channel,update_frequency
SEV1,Sana Qureshi,CISO,sana.qureshi@orbitlogistics.example / ext 2001,15 minutes,Phone call then email,Every 30 minutes
SEV1,Hamza Raza,IT Director,hamza.raza@orbitlogistics.example / ext 2002,15 minutes,Phone call then email,Every 30 minutes
SEV1,SOC Lead on call,SOC Lead,soc-lead@orbitlogistics.example / ext 2100,Immediately,Phone call,Continuous
SEV2,SOC Lead on call,SOC Lead,soc-lead@orbitlogistics.example / ext 2100,30 minutes,Phone call,Every hour
SEV2,Hamza Raza,IT Director,hamza.raza@orbitlogistics.example / ext 2002,1 hour,Email,Every 2 hours
SEV3,SOC Lead on call,SOC Lead,soc-lead@orbitlogistics.example / ext 2100,4 hours,Ticket and email,Daily
SEV4,SOC queue,SOC Analyst team,soc@orbitlogistics.example,Next business day,Ticket,On closure""")

    write("runbooks/RB-01_credential_compromise.md", """# RB-01: Credential Compromise and Brute Force

Applies to: credential compromise, account takeover, brute-force login attempts, suspicious VPN logins.

## Steps
1. Disable the affected user account in the identity provider.
2. Terminate all active VPN and SSH sessions for the affected account.
3. Block the source IP address at the perimeter firewall.
4. Reset the account password and re-enrol multi-factor authentication.
5. Review every system the account logged in to after the first suspicious login.
6. Preserve the authentication, VPN and firewall logs for the incident window.
7. Notify the account owner and their line manager.""")

    write("runbooks/RB-02_phishing.md", """# RB-02: Phishing Email

Applies to: phishing email, suspicious email, malicious link, spoofed sender.

## Steps
1. Quarantine the email and remove it from every mailbox that received it.
2. Block the sender domain and sender IP address at the email gateway.
3. Block the URLs in the email at the web proxy.
4. Ask each recipient whether they opened the link or entered credentials.
5. If a recipient entered credentials, follow RB-01.""")

    write("runbooks/RB-03_web_application_attack.md", """# RB-03: Web Application Attack

Applies to: web application attack, SQL injection, path traversal, cross-site scripting.

## Steps
1. Confirm from the web server log whether any malicious request received a success response.
2. Block the source IP address at the web application firewall.
3. If any request succeeded, take the affected application offline and follow RB-05.
4. Raise a ticket for the application owner to review the targeted endpoint.""")

    write("runbooks/RB-04_malware.md", """# RB-04: Malware Infection

Applies to: malware infection, ransomware, suspicious process.

## Steps
1. Isolate the affected host from the network.
2. Collect a memory image and the EDR alert details.
3. Re-image the host from the approved baseline.
4. Reset credentials used on the host.""")

    write("runbooks/RB-05_data_exfiltration.md", """# RB-05: Suspected Data Exfiltration

Applies to: suspected data exfiltration, large outbound transfer, data leak.

## Steps
1. Block the external destination IP address at the perimeter firewall.
2. Isolate the source server from outbound internet access.
3. Collect file audit and DLP logs for the source server to find out what was accessed.
4. Do not state that data was stolen until step 3 confirms it.
5. Inform the Data Protection Officer if personal or customer data may be involved.
6. Preserve firewall logs and a disk snapshot of the source server.""")

    write("runbooks/RB-06_port_scan.md", """# RB-06: Port Scan or Reconnaissance

Applies to: port scan, reconnaissance, network sweep.

## Steps
1. Check the change calendar for an approved scan from the same source and window.
2. If the scan is not approved, block the source IP address at the perimeter firewall.
3. Record the scanned hosts and ports in the ticket.""")

    write("README_dataset.md", """# Sample dataset - Orbit Logistics (synthetic)

Generated by `scripts/make_sample_data.py`. It stands in for the organiser's files.
Replace this folder with the real files; no code change is needed for common layouts.""")


if __name__ == "__main__":
    auth_log(); vpn_log(); web_log(); firewall(); email_log(); docs()
    print(f"wrote sample dataset to {OUT}/")
