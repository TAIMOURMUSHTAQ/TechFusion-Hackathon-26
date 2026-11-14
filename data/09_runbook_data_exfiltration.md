# Runbook RB-EXFIL-04 - Data Exfiltration

1. Find sessions with an unusually large transfer from the source system in the firewall logs. Note the bytes, the times and the destination.
2. Block the destination address of the transfer.
3. Keep the evidence: copy the relevant logs. Do not reboot the source server.
4. Ask the system owner what data the system holds.
5. Check if file-level audit logs exist. If they do not, record that it is unknown which files were read.
6. Inform Legal and Compliance if the system holds finance, HR or customer data.
