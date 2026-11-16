# ==============================================================================
# MSuite HoneyPot - MikroTik Firewall Rules (RouterOS v7 & v6)
# ==============================================================================

# OPTION 1: Ultra-fast RAW table drop (RECOMMENDED)
# Raw drops packets in PREROUTING before connection tracking, zero CPU overhead.
/ip firewall raw add chain=prerouting src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot: Nullroute Bots & Scanners"

# OPTION 2: Standard Filter table drop (Alternative)
# /ip firewall filter add chain=input src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot Drop (Input)" place-before=0
# /ip firewall filter add chain=forward src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot Drop (Forward)" place-before=0

# The honeypot uses the HTTP REST API on the www service: http://10.0.0.1:8480/rest.
# Port 8480 is plaintext. Do not enable TLS for it. www-ssl is 4843.
# Port 8728 is the binary api service and is not REST. The reverse proxy owns 443.
