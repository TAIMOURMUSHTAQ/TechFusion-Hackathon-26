# RB-02: Phishing Email

Applies to: phishing email, suspicious email, malicious link, spoofed sender.

## Steps
1. Quarantine the email and remove it from every mailbox that received it.
2. Block the sender domain and sender IP address at the email gateway.
3. Block the URLs in the email at the web proxy.
4. Ask each recipient whether they opened the link or entered credentials.
5. If a recipient entered credentials, follow RB-01.
