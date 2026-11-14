# Runbook RB-PHISH-01 - Phishing Email

1. Find every recipient of the message in the email gateway log.
2. Remove or quarantine the message from all mailboxes.
3. Block the sender domain and the link domain at the email gateway and the perimeter firewall.
4. For each recipient, check the firewall logs for a connection to the link address, to find who clicked.
5. If a click is found, open RB-CRED-02 for that user.
6. Send a warning notice to all recipients.
7. Record all findings in the incident ticket.
