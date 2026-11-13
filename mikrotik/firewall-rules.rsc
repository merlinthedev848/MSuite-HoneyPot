# ==============================================================================
# MSuite HoneyPot - MikroTik Firewall Rules (RouterOS v7 & v6)
# ==============================================================================

# OPTION 1: Ultra-fast RAW table drop (RECOMMENDED)
# Raw drops packets in PREROUTING before connection tracking, zero CPU overhead.
/ip firewall raw add chain=prerouting src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot: Nullroute Bots & Scanners"

# OPTION 2: Standard Filter table drop (Alternative)
# /ip firewall filter add chain=input src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot Drop (Input)" place-before=0
# /ip firewall filter add chain=forward src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot Drop (Forward)" place-before=0

# Ensure REST API (WWW or WWW-SSL) is enabled:
/ip service set www-ssl disabled=no port=443
/ip service set www disabled=no port=80
