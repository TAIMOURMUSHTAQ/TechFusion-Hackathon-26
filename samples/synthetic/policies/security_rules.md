# Orbit Logistics - Security Rules (extract)

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
- Missing logs must be reported, never assumed to mean "nothing happened".
