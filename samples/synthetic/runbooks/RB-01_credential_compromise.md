# RB-01: Credential Compromise and Brute Force

Applies to: credential compromise, account takeover, brute-force login attempts, suspicious VPN logins.

## Steps
1. Disable the affected user account in the identity provider.
2. Terminate all active VPN and SSH sessions for the affected account.
3. Block the source IP address at the perimeter firewall.
4. Reset the account password and re-enrol multi-factor authentication.
5. Review every system the account logged in to after the first suspicious login.
6. Preserve the authentication, VPN and firewall logs for the incident window.
7. Notify the account owner and their line manager.
