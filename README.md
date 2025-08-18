# Botnet Kicker

Tools to eradicate attackers the hard way.  
Built around Fail2ban jails, Team Cymru IP → ASN lookups, and aggressive perimeter blocking.

## Disclosure & Warning

These scripts were coded quickly during active defense against botnets and abuse traffic.  
They take aggressive action against offending IPs, subnets, and entire ASNs if thresholds are met.

Use at your own risk:  
- You will block real networks if thresholds are too low.  
- You might cut off legitimate traffic.  
- You should always review recommendation files before applying.  
- This repository is about effectiveness, not elegance.

This is a blunt instrument to stop botnets.

## Components

### f2b-cymru-ban.sh
- Core parser for Fail2ban jails.  
- Enriches banned IPs via Team Cymru WHOIS service.  
- Produces:
  - list_ips.txt (raw IPs)  
  - list_prefixes.txt (aggregated subnets)  
  - list_asn_prefixes.txt (ASNs with their ranges)  
  - recommendations.txt (blocklist guidance)  
  - apply_cmds.sh (firewall commands)

Modes:  
- --mode ip → Block individual IPs  
- --mode prefix → Block subnets with many offenders  
- --mode asn → Block entire ASNs meeting thresholds  

Flags:  
- --apply → Immediately apply bans  
- --asn-ban → Enable ASN-wide blocking if:
  - At least 10 offending IPs total  
  - At least 2 distinct ranges  
  - ASN not located in Sweden (SE excluded by default)  

### eradicate-all-attackers.sh
- Wrapper to run f2b-cymru-ban.sh across all active jails.  
- Generates per-jail reports under ./f2b_eradic_run/<jail>/.  
- Runs in modes (ip, prefix, asn) with optional --apply.  
- Provides a run summary.

Example:

```bash
sudo ./eradicate-all-attackers.sh --mode prefix --apply
```

### f2b-jailstatus-dump.sh
- Dumps fail2ban-client status <jail> into per-jail logs.  
- Default output directory: /var/www/html/log/  
- Creates one file per jail: <jail>.log  
- Useful for serving jail status over HTTP.  

Crontab example (run every 5 minutes):

```bash
*/5 * * * * root /usr/local/bin/f2b-jailstatus-dump.sh >/dev/null 2>&1
```

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
- awk, sed, curl, bash  

## Example Outputs

Recommendations:

```
1) Block high-volume ASNs (>= 5 IPs).
   AS207990 HR-CUSTOMER (count=500)

2) Block attack networks by prefix (>= 5 IPs).
   161.123.131.0/24
   154.73.249.0/24
```

Apply Script:

```bash
ipset create f2b_prefixes hash:net -exist
ipset add f2b_prefixes 154.73.249.0/24 timeout 86400
iptables -I INPUT -m set --match-set f2b_prefixes src -j DROP
```

## Making it Effective

For Fail2ban to produce useful input, you must configure jails and filters.

1. Create a custom jail.local in `/etc/fail2ban/jail.local`. Example:

```ini
[apache-signup-abuse]
enabled  = true
port     = http,https
filter   = apache-signup-abuse
logpath  = /var/log/apache2/access.log
maxretry = 3
bantime  = 3600
```

2. Create a matching filter in `/etc/fail2ban/filter.d/apache-signup-abuse.conf`:

```ini
[Definition]
failregex = ^<HOST> .* "POST /signup
ignoreregex =
```

3. Testing for matches
## Test against Apache
sudo fail2ban-regex /var/log/apache2/access.log /etc/fail2ban/filter.d/anthropic-any.conf

## Test against Nginx
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/anthropic-any.conf

## Enable the jail (optional)
sudo sed -i 's/^enabled\s*=.*/enabled = true/' /etc/fail2ban/jail.local
sudo systemctl restart fail2ban

## Verify
sudo fail2ban-client status anthropic-any

5. Restart Fail2ban:

```bash
sudo systemctl restart fail2ban
```

Once the jail and filter are active, Fail2ban will feed IPs into the jail.  
That becomes the input for `f2b-cymru-ban.sh` and `eradicate-all-attackers.sh`.
