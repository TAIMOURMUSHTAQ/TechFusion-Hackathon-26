# VPN Authentication Log - SRV-VPN01 - 2026-11-04

Raw export from the VPN gateway. One event per line.

```
2026-11-04T02:58:41Z vpn01 auth result=SUCCESS user=utariq src_ip=182.180.44.12 geo=PK assigned_ip=10.10.3.12 session=VS-20411 mfa=push_approved
2026-11-04T03:41:09Z vpn01 auth result=SUCCESS user=braza src_ip=39.40.88.201 geo=PK assigned_ip=10.10.3.18 session=VS-20415 mfa=push_approved
2026-11-04T05:46:58Z vpn01 auth result=FAIL user=amalik src_ip=198.51.100.77 geo=RO reason=mfa_push_denied
2026-11-04T05:47:31Z vpn01 auth result=FAIL user=amalik src_ip=198.51.100.77 geo=RO reason=mfa_push_denied
2026-11-04T05:48:02Z vpn01 auth result=FAIL user=amalik src_ip=198.51.100.77 geo=RO reason=mfa_push_timeout
2026-11-04T05:48:40Z vpn01 auth result=FAIL user=amalik src_ip=198.51.100.77 geo=RO reason=mfa_push_denied
2026-11-04T05:49:12Z vpn01 auth result=SUCCESS user=amalik src_ip=198.51.100.77 geo=RO assigned_ip=10.10.3.45 session=VS-20433 mfa=push_approved
2026-11-04T07:12:44Z vpn01 session_end session=VS-20433 user=amalik duration=5012s bytes_to_client=2418331648 bytes_from_client=9122031
2026-11-04T10:15:20Z vpn01 session_end session=VS-20411 user=utariq duration=26199s bytes_to_client=88120331 bytes_from_client=4120993
2026-11-04T12:30:02Z vpn01 session_end session=VS-20415 user=braza duration=31733s bytes_to_client=140220019 bytes_from_client=22003811
2026-11-04T17:04:22Z vpn01 auth result=SUCCESS user=braza src_ip=39.40.88.201 geo=PK assigned_ip=10.10.3.18 session=VS-20502 mfa=push_approved
2026-11-04T18:40:10Z vpn01 session_end session=VS-20502 user=braza duration=5748s bytes_to_client=9120331 bytes_from_client=3310022
```
