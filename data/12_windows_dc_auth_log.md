# Windows Domain Controller Security Log - SRV-DC01

Raw export. One event per line.

```
2026-11-04 03:58:02 UTC | DC01 | EventID=4768 | Kerberos TGT request | account=ORBIT\amalik | client=10.20.5.14 | workstation=LT-FIN-014 | result=SUCCESS
2026-11-04 04:15:44 UTC | DC01 | EventID=4768 | Kerberos TGT request | account=ORBIT\utariq | client=10.20.7.8 | workstation=LT-WH-021 | result=SUCCESS
2026-11-04 05:55:31 UTC | DC01 | EventID=4768 | Kerberos TGT request | account=ORBIT\amalik | client=10.10.3.45 | workstation=unknown | result=SUCCESS
2026-11-04 05:55:33 UTC | DC01 | EventID=4769 | Kerberos service ticket | account=ORBIT\amalik | service=cifs/FS01.orbit.local | client=10.10.3.45 | result=SUCCESS
2026-11-04 05:58:44 UTC | DC01 | EventID=4769 | Kerberos service ticket | account=ORBIT\amalik | service=MSSQLSvc/DB01.orbit.local:1433 | client=10.10.3.45 | result=SUCCESS
2026-11-04 06:42:17 UTC | DC01 | EventID=4724 | Password reset attempt | target=ORBIT\amalik | caller=ORBIT\amalik | client=10.10.3.45 | result=SUCCESS
2026-11-04 07:31:12 UTC | DC01 | EventID=4625 | Logon failed | account=ORBIT\amalik | client=10.20.5.14 | workstation=LT-FIN-014 | reason=bad_password
2026-11-04 07:31:48 UTC | DC01 | EventID=4625 | Logon failed | account=ORBIT\amalik | client=10.20.5.14 | workstation=LT-FIN-014 | reason=bad_password
2026-11-04 07:32:50 UTC | DC01 | EventID=4740 | Account locked out | account=ORBIT\amalik | caller=LT-FIN-014
2026-11-04 11:20:05 UTC | DC01 | EventID=4768 | Kerberos TGT request | account=ORBIT\sraheel | client=10.20.5.22 | workstation=LT-FIN-022 | result=SUCCESS
2026-11-04 17:31:05 UTC | DC01 | EventID=4624 | Logon type 10 (remote desktop) | account=ORBIT\braza | target=DC01 | client=10.10.3.18 | result=SUCCESS
2026-11-04 17:31:09 UTC | DC01 | EventID=4672 | Special privileges assigned | account=ORBIT\braza
2026-11-04 18:24:12 UTC | DC01 | EventID=4634 | Logoff | account=ORBIT\braza | target=DC01
```
