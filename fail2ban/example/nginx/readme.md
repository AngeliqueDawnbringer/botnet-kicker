server {
    # ... your usual config and access_log ...

    # Quiet 200 for Anthropic IPs that don't identify as Anthropic
    if ($anthropic_bad) {
        add_header Cache-Control "no-store" always;
        default_type text/plain;
        return 200 "Stop scraping. Identify your client as Anthropic.\n";
    }

    # ... the rest ...
}
