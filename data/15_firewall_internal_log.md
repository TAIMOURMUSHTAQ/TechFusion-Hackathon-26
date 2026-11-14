# Internal Firewall Log - fw-int01 - 2026-11-04

Raw export. One session per line.

```
2026-11-04 09:15:44 fw-int01 ALLOW tcp 10.20.5.14:51002 -> 10.10.1.20:445 bytes_total=1204551 duration=312s
2026-11-04 09:48:03 fw-int01 ALLOW tcp 10.20.7.8:50214 -> 10.10.2.10:443 bytes_total=88120 duration=14s
2026-11-04 10:55:34 fw-int01 ALLOW tcp 10.10.3.45:49801 -> 10.10.1.5:88 bytes_total=3312 duration=2s
2026-11-04 10:55:41 fw-int01 ALLOW tcp 10.10.3.45:49805 -> 10.10.1.20:445 bytes_total=4096 duration=7s
2026-11-04 10:58:52 fw-int01 ALLOW tcp 10.10.3.45:49830 -> 10.10.1.30:1433 bytes_total=1240 duration=8s
2026-11-04 11:21:19 fw-int01 ALLOW tcp 10.10.3.45:49871 -> 10.10.1.20:445 bytes_total=2426727912 bytes_server_to_client=2411724800 duration=1087s
2026-11-04 11:31:50 fw-int01 ALLOW tcp 10.20.5.22:50990 -> 10.10.1.20:445 bytes_total=220118 duration=40s
2026-11-04 12:29:10 fw-int01 ALLOW tcp 10.20.5.22:51210 -> 10.10.1.20:445 bytes_total=95200 duration=22s
2026-11-04 21:05:20 fw-int01 ALLOW tcp 10.10.9.50:40001 -> 10.10.1.20:445 bytes_total=600 duration=1s
2026-11-04 21:05:21 fw-int01 ALLOW tcp 10.10.9.50:40002 -> 10.10.1.30:1433 bytes_total=480 duration=1s
2026-11-04 21:05:23 fw-int01 ALLOW tcp 10.10.9.50:40003 -> 10.10.1.5:389 bytes_total=520 duration=1s
2026-11-04 21:05:25 fw-int01 ALLOW tcp 10.10.9.50:40004 -> 10.10.2.10:443 bytes_total=700 duration=1s
2026-11-04 21:05:27 fw-int01 DENY tcp 10.10.9.50:40005 -> 10.10.1.20:3389 rule=rdp-restricted
2026-11-04 23:24:12 fw-int01 ALLOW tcp 10.10.3.18:51234 -> 10.10.1.5:3389 bytes_total=912344 duration=3187s
```
