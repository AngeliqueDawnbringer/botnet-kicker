# parser.sh  
### Parser for Fail2ban Logs & Jails

`parser.sh` is a log and jail parser that enriches your **Fail2ban** bans with **ASN (Autonomous System Number)** and **BGP prefix data** from **Team Cymru**.  
It then generates **summaries, blocklists, and actionable recommendations** so you can apply bans at the **ASN** or **prefix** level, not just per-IP.

---

## Features

- Parses Fail2ban jail **status** and **banned IP list**.  
- Enriches IPs with ASN, AS Name, BGP prefix, country, and allocation date via [Team Cymru IP → ASN service](https://team-cymru.com/community-services/ip-asn-mapping/).  
- Generates:
  - `ips_enriched.csv` (per-IP with ASN & prefix info)
  - `asn_summary.csv` (all ASNs, counts)
  - `prefixes.txt` (unique prefixes)
  - `prefixes_annotated.txt` (prefixes with ASN + hit counts)
  - `asn_blocklist.txt` & `asn_blocklist_only.txt`
  - `recommendations.txt` (human-readable next steps)  
- Recommendations include:
  - ASN-level WAF/CDN blocklists
  - Prefix blocklists (`ipset` + `iptables`) with **24h auto-expire**
  - Temporary single-IP drops with **24h auto-expire**
  - Inline annotations:  
    `reason=fail2ban:<jail>`  
    `asn=AS12345 <AS Name>`
- Color-coded console output (using `tput`, safe for terminals).

---

## Requirements

- **Linux / Unix shell**
- **Fail2ban** (`fail2ban-client`)
- **nc (netcat)** *or* `whois` (to query Team Cymru)
- **awk, sed, grep, sort, join** (standard GNU tools)
- **iptables + ipset** (for applying firewall actions)

---

## Usage

```bash
./parser.sh <jail-name> [outdir] [min_prefix_count] [min_asn_count]

sudo ./parser.sh apache-signup-abuse
