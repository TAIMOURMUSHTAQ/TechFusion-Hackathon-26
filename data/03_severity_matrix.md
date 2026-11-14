# Severity Matrix

P1 is the most serious, P4 the least. Choose the row by incident type and the column by asset criticality.

| Incident type | Low | Medium | High | Critical |
|---|---|---|---|---|
| Phishing email delivered, no click seen | P4 | P4 | P3 | P3 |
| Credential compromise (account used by an attacker) | P3 | P3 | P2 | P1 |
| Data exfiltration (large transfer, confirmed or suspected) | P3 | P2 | P1 | P1 |
| Web application attack, attempts only | P4 | P3 | P2 | P2 |
| Web application attack, success suspected or confirmed | P3 | P2 | P1 | P1 |
| Unapproved scanning or reconnaissance | P4 | P4 | P3 | P3 |
| Malware on a system | P3 | P2 | P1 | P1 |

Rules:
- A phishing email where a click is seen is handled as credential compromise.
- Approved activity from the change calendar is not an incident and gets no severity.
