# Runbook RB-SCAN-05 - Scanning and Reconnaissance

1. Check the change calendar for an approved scan that matches the source, the target and the time window.
2. If it is approved, close the alert as approved activity. Do not escalate.
3. If it is not approved and the source is external, block the source IP at the perimeter firewall.
4. If the source is internal, find the device owner and contact them.
5. Check which scanned ports answered (allowed) or were refused (denied), and whether any login attempts followed.
6. Watch the source for the next 24 hours.
