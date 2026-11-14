# Log Source Coverage Sheet

| Source | File | Time zone / format | Coverage on 2026-11-04 | Notes |
|---|---|---|---|---|
| VPN gateway | 11_vpn_auth_log.md | UTC, ISO format with Z | Full day | |
| Domain controller | 12_windows_dc_auth_log.md | UTC (written in each line) | 03:00 to 19:00 UTC only | Nothing before 03:00 UTC or after 19:00 UTC |
| Web server | 13_web_server_log.md | Local time with offset in each line | Full day | |
| Perimeter firewall | 14_firewall_perimeter_log.md | UTC (no zone written) | Full day | Logged when the connection starts. Gateway email quarantine is not part of this device |
| Internal firewall | 15_firewall_internal_log.md | Local time PKT, UTC+5 (no zone written) | Full day except 11:32:00 to 12:28:59 PKT | Device rebooted for a firmware update. Logged when the session closes, not when it starts. Duration is given in seconds |
| Email gateway | 16_email_gateway_log.md | PKT (written in each line) | Full day | Messages with score 8.0 or higher are quarantined |
| IDS | 17_ids_alert_summary.md | UTC | Full day | Summary only |
| DHCP | 19_dhcp_lease_log.md | Local time with offset in each line | Office network only | VPN addresses are not in DHCP |

Log sources that do NOT exist or are NOT collected:
- SRV-FS01 file access (audit) log: agent not installed.
- SRV-DB01 login and query log: not forwarded to the SOC.
- Web proxy log (which websites staff open): no proxy is used.
- Laptop endpoint security (EDR) logs: not collected.
- No logs of any kind are available for dates other than 2026-11-04.
