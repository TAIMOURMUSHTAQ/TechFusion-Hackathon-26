# Runbook RB-CRED-02 - Credential Compromise

1. Call the real user on the phone number in the user directory and ask if the login was theirs.
2. Disable the account in the directory and end all active VPN and remote sessions of that account.
3. Block the attacker source IP at the perimeter firewall.
4. Reset the password only after step 2, through the helpdesk with identity checks. Require new MFA enrollment.
5. Review all logins by the account in the last 24 hours and list every system it reached.
6. If phishing was the source, disconnect the user's laptop from the network.
7. For every system reached, check for further activity. If a large data transfer is seen, open RB-EXFIL-04.
8. Keep all logs unchanged as evidence.
