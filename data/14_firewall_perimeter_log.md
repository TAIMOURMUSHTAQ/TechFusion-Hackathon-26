# Perimeter Firewall Log - fw-edge01 - 2026-11-04

Raw export. One connection per line.

```
2026-11-04 03:10:05 fw-edge01 DENY tcp 192.0.2.88:51522 -> 203.0.113.10:22 rule=default-deny
2026-11-04 03:10:07 fw-edge01 DENY tcp 192.0.2.88:51523 -> 203.0.113.10:23 rule=default-deny
2026-11-04 03:10:09 fw-edge01 DENY tcp 192.0.2.88:51524 -> 203.0.113.10:3389 rule=default-deny
2026-11-04 03:10:12 fw-edge01 DENY tcp 192.0.2.88:51525 -> 203.0.113.10:445 rule=default-deny
2026-11-04 03:10:15 fw-edge01 DENY tcp 192.0.2.88:51526 -> 203.0.113.10:8080 rule=default-deny
2026-11-04 03:10:21 fw-edge01 ALLOW tcp 192.0.2.88:51530 -> 203.0.113.10:443 rule=web-public bytes=1850
2026-11-04 03:55:00 fw-edge01 ALLOW tcp 10.20.5.22:50711 -> 142.250.185.46:443 rule=outbound-web bytes=88231
2026-11-04 04:19:40 fw-edge01 ALLOW tcp 10.20.5.14:50833 -> 198.51.100.77:443 rule=outbound-web bytes=18442
2026-11-04 04:20:15 fw-edge01 ALLOW tcp 10.20.7.8:50901 -> 151.101.65.69:443 rule=outbound-web bytes=412
2026-11-04 05:46:50 fw-edge01 ALLOW tcp 198.51.100.77:60021 -> 203.0.113.20:443 rule=vpn-gateway bytes=5120
2026-11-04 05:49:10 fw-edge01 ALLOW tcp 198.51.100.77:60112 -> 203.0.113.20:443 rule=vpn-gateway bytes=9250112
2026-11-04 06:05:10 fw-edge01 ALLOW tcp 192.0.2.150:44120 -> 203.0.113.10:443 rule=web-public bytes=96340
```
