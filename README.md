# Botnet Kicker

> Tools to eradicate attackers the hard way.  
> Built around Fail2ban jails, Team Cymru IP → ASN lookups, and aggressive perimeter blocking.

## Disclosure & Warning

These scripts were hacked together during long days of fighting off garbage traffic, brute force attempts, signup abuse, and botnets.  
They take aggressive action against offending IPs, subnets, and entire ASNs if thresholds are met.

Use at your own risk:  
- You will block real networks if thresholds are too low.  
- You might cut off legit traffic (false positives happen).  
- You should review all recommendation files before applying blindly.  
- This repo is not about elegance. It is about results.

In short:  
This is a blunt instrument to kill botnets the hard way.

## Components

### f2b-cymru-ban.sh
- Core parser for Fail2ban jails.  
- Enriches banned IPs via Team Cymru WHOIS service.  
- Produces:
  - list_ips.txt (raw IPs)  
  - list_prefixes.txt (aggregated subnets)  
  - list_asn_prefixes.txt (ASNs with their ranges)  
  - recommendations.txt (human-readable blocklist guidance)  
  - apply_cmds.sh (ready-to-run firewall commands)

Modes:  
- --mode ip → Block individual IPs  
- --mode prefix → Block subnets with many offenders  
- --mode asn → Block entire ASNs meeting thresholds  

Flags:  
- --apply → Immediately apply bans  
- --asn-ban → Enable ASN-wide blocking if:
  - ≥ 10 offending IPs total, and  
  - ≥ 2 distinct ranges, and  
  - ASN not located in Sweden (SE by default exclusion)  

### eradicate-all-attackers.sh
- Wrapper to run f2b-cymru-ban.sh across all active jails.  
- Generates per-jail reports under ./f2b_eradic_run/<jail>/.  
- Runs in modes (ip, prefix, asn) with --apply optional.  
- Provides a run summary at the end.

Example:

    sudo ./eradicate-all-attackers.sh --mode prefix --apply

### f2b-jailstatus-dump.sh
- Dumps fail2ban-client status <jail> into per-jail logs.  
- Default output dir: /var/www/html/log/  
- Creates one file per jail: <jail>.log.  
- Useful for serving live jail status over HTTP.  

Crontab example (run every 5 min, quiet):  

    */5 * * * * root /usr/local/bin/f2b-jailstatus-dump.sh >/dev/null 2>&1

## Usage Workflow

1. Ensure Fail2ban is running with relevant jails (sshd, apache-*, etc).  
2. Run f2b-cymru-ban.sh against one jail for testing.  
3. Review output in recommendations.txt.  
4. Apply bans manually or with --apply.  
5. Automate with eradicate-all-attackers.sh if confident.  
6. (Optional) Serve jail status logs via f2b-jailstatus-dump.sh.

## Requirements
- fail2ban-client  
- ipset + iptables (preferred)  
- or ufw as fallback (not default in current build)  
- awk, sed, curl, bash  

## Example Outputs

Recommendations:

    1) Block high-volume ASNs (>= 5 IPs).
       AS207990 # HR-CUSTOMER (count=500)

    2) Block attack networks by prefix (>= 5 IPs).
       161.123.131.0/24
       154.73.249.0/24

Apply Script:

    ipset create f2b_prefixes hash:net -exist
    ipset add f2b_prefixes 154.73.249.0/24 timeout 86400
    iptables -I INPUT -m set --match-set f2b_prefixes src -j DROP

## License
Do whatever you want.  
Just don’t complain if you shoot yourself in the foot.  

## Author
Angelique Dawnbringer  
https://github.com/AngeliqueDawnbringer
