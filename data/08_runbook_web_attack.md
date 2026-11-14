# Runbook RB-WEB-03 - Web Application Attack

1. Find the attacker IP and all its requests in the web server log.
2. Block the attacker IP at the perimeter firewall.
3. Check response codes and response sizes to see if any request succeeded. A normal error is 4xx or 5xx; a large 200 response to an attack request may mean success.
4. Ask the web team to review the code of the attacked page.
5. Check the database server logs for matching queries, if they are available.
6. Check that the SQL injection rule is active on the web server filter.
7. Record all findings in the incident ticket.
