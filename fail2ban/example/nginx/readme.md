# Anthropic Scraper Detection with Nginx

This setup allows you to **classify and handle web traffic** from Anthropic's IP ranges in Nginx.  
It distinguishes between:

1. **Bad** — Requests from Anthropic IPs **without** a proper Anthropic User-Agent.  
2. **Good** — Requests from Anthropic IPs **with** a proper Anthropic User-Agent.  
3. **Spoof** — Requests from non-Anthropic IPs **claiming** to be Anthropic (UA contains "Anthropic").

You can log these separately and optionally serve a quiet message (HTTP 200) to *bad* requests.

---

## 1. Create a ranges include

File: `/etc/nginx/anthropic.ranges`

```
160.79.104.0/23 1;
2607:6bc0::/48  1;
```

This file is generated automatically (see step 4).

---

## 2. Create a conf.d configuration

File: `/etc/nginx/conf.d/anthropic.conf`

```nginx
# --- Identify Anthropic IPs (from include) ---
geo $anthropic_ip {
    default 0;
    include /etc/nginx/anthropic.ranges;
}

# --- UA says "Anthropic"? ---
map $http_user_agent $anthropic_ua {
    default 0;
    ~*anthropic 1;
}

# --- Classification ---
map "$anthropic_ip:$anthropic_ua" $anthropic_bad   { "1:0" 1; default 0; }
map "$anthropic_ip:$anthropic_ua" $anthropic_good  { "1:1" 1; default 0; }
map "$anthropic_ip:$anthropic_ua" $anthropic_spoof { "0:1" 1; default 0; }

# --- Logs ---
log_format anthua '$remote_addr [$time_local] "$request" $status $body_bytes_sent '
                  '"$http_referer" "$http_user_agent"';
access_log /var/log/nginx/anthropic_bad.log   anthua if=$anthropic_bad;
access_log /var/log/nginx/anthropic_good.log  anthua if=$anthropic_good;
access_log /var/log/nginx/anthropic_spoof.log anthua if=$anthropic_spoof;
```

Ensure your `nginx.conf` has:
```
include /etc/nginx/conf.d/*.conf;
```

---

## 3. Apply in server blocks

In any `server { ... }` where you want to return a message for *bad* requests:

```nginx
if ($anthropic_bad) {
    add_header Cache-Control "no-store" always;
    default_type text/plain;
    return 200 "Stop scraping. Identify your client as Anthropic.\n";
}
```

---

## 4. Automate range updates

### From JSON

```bash
jq -r '.ipv4[]?, .ipv6[]? | "\(. ) 1;"' anthropic.json   | sudo tee /etc/nginx/anthropic.ranges >/dev/null
sudo nginx -t && sudo systemctl reload nginx
```

### From bgpq4 (ASN)

```bash
sudo apt-get install -y bgpq4
{ bgpq4 -Ab -l anthropic-v4 AS399358 | awk '/^add anthropic-v4/ {print $3 " 1;"}'
  bgpq4 -6b -l anthropic-v6 AS399358 | awk '/^add anthropic-v6/ {print $3 " 1;"}'; } | sudo tee /etc/nginx/anthropic.ranges >/dev/null
sudo nginx -t && sudo systemctl reload nginx
```

---

## 5. Testing

```bash
# From Anthropic IP without UA
curl -H 'User-Agent:' http://yourhost/ --resolve yourhost:80:160.79.104.10

# From Anthropic IP with UA
curl -H 'User-Agent: Anthropic/1.0' http://yourhost/ --resolve yourhost:80:160.79.104.10

# From non-Anthropic IP with Anthropic UA
curl -H 'User-Agent: Anthropic/1.0' http://yourhost/
```

Check the respective logs:
- `/var/log/nginx/anthropic_bad.log`
- `/var/log/nginx/anthropic_good.log`
- `/var/log/nginx/anthropic_spoof.log`

---

## 6. Notes

- Works with both IPv4 and IPv6.
- You can add rate-limiting on `$anthropic_bad` if desired.
- If you’re behind a proxy/CDN, enable `real_ip_header` so `$remote_addr` is the real client.
