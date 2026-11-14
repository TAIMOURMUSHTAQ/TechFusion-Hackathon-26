# Asset Inventory

| Asset tag | Hostname | Type | IP address | Owner | Criticality |
|---|---|---|---|---|---|
| A-1001 | SRV-DC01 | Domain controller | 10.10.1.5 | IT Infrastructure (Imran Siddiqui) | Critical |
| A-1005 | SRV-FS01 | File server (finance and HR shares) | 10.10.1.20 | Finance (data owner: Saima Noor, Head of Finance) | High |
| A-1007 | SRV-DB01 | Orders database server | 10.10.1.30 | Applications team | High |
| A-1010 | SRV-WEB01 | Public web server | 10.10.2.10 (public 203.0.113.10) | Applications team | Medium |
| A-1012 | SRV-VPN01 | VPN gateway | 10.10.3.2 (public 203.0.113.20) | IT Infrastructure (Imran Siddiqui) | Medium |
| A-1020 | SCAN01 | Vulnerability scanner | 10.10.9.50 | IT Security | Low |
| A-2003 | LT-IT-003 | Laptop | 10.20.9.3 | Bilal Raza | Medium |
| A-2014 | LT-FIN-014 | Laptop | 10.20.5.14 | Ayesha Malik | Medium |
| A-2021 | LT-WH-021 | Laptop | 10.20.7.8 | Usman Tariq | Low |
| A-2022 | LT-FIN-022 | Laptop | 10.20.5.22 | Sadia Raheel | Medium |

Notes:
- VPN clients get a temporary address from the pool 10.10.3.10 to 10.10.3.99. The address for each session is written in the VPN log.
- Domain name of the internal network: orbit.local (for example FS01.orbit.local is SRV-FS01).
