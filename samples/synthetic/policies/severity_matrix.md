# Orbit Logistics - Incident Severity Matrix

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
3. SEV1 is the most serious and SEV4 the least.
