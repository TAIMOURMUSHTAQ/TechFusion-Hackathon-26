# RB-05: Suspected Data Exfiltration

Applies to: suspected data exfiltration, large outbound transfer, data leak.

## Steps
1. Block the external destination IP address at the perimeter firewall.
2. Isolate the source server from outbound internet access.
3. Collect file audit and DLP logs for the source server to find out what was accessed.
4. Do not state that data was stolen until step 3 confirms it.
5. Inform the Data Protection Officer if personal or customer data may be involved.
6. Preserve firewall logs and a disk snapshot of the source server.
