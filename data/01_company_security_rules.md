# Orbit Logistics - Security Rules (v3.2)

## 1. Time
1.1 Company local time is PKT (UTC+5, no daylight saving). Incident reports must show times in UTC, and may add PKT in brackets.
1.2 Different systems log in different time zones. Check the log source sheet before comparing times.

## 2. Evidence labels
2.1 **Confirmed**: directly shown by a log line or table row. Cite the file and line.
2.2 **Suspected**: fits an attack pattern but needs a guess to link two things together. Say what the guess is.
2.3 **Not enough evidence in the logs**: the logs are silent or missing. Never fill the gap with a guess.
2.4 Never write that data was "stolen" or "leaked" unless a log shows the data moving. A large transfer is evidence of a transfer, not of which files were read.

## 3. Approved changes
3.1 Activity is "approved" only if the change calendar lists the same system, the same person or tool, and a time window that contains the activity.
3.2 Approved activity is not escalated. The report must still say why it was closed and cite the change ID.

## 4. Severity
4.1 Use the severity matrix. Use the most critical asset the attacker actually reached (a confirmed login or session).
4.2 If one incident has several parts, report each part. The whole incident gets the highest severity.
4.3 Separate incidents with no shared evidence are scored separately.

## 5. Actions and contacts
5.1 Recommend only actions found in the runbooks. Cite the runbook ID and step number.
5.2 Inform people only as listed in the escalation sheet, with the time limit for that severity.

## 6. VPN
6.1 Several rejected MFA pushes followed by an approved push from a new country is treated as a sign of a stolen password.
6.2 Two logins by the same user from different places at the same time is a sign of account misuse.

## 7. Incident report format
Every report must have these sections: Summary; Timeline (UTC, with file and line); Affected assets and accounts; Severity (with steps); Confirmed; Suspected; Not enough evidence in the logs; Missing log sources; Closed as harmless (with change ID); Recommended actions (runbook ID and step); People to inform (name and time limit).
