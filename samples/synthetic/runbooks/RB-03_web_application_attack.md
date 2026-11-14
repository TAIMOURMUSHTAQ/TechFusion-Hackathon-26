# RB-03: Web Application Attack

Applies to: web application attack, SQL injection, path traversal, cross-site scripting.

## Steps
1. Confirm from the web server log whether any malicious request received a success response.
2. Block the source IP address at the web application firewall.
3. If any request succeeded, take the affected application offline and follow RB-05.
4. Raise a ticket for the application owner to review the targeted endpoint.
