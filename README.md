# MSuite-HoneyPot 🍯🛡️

> **Ultra-lightweight Honeypot Server & MikroTik Nullrouter for Proxmox Homelabs**
> Intercepts malicious bot scans, path fuzzers (`.env`, `wp-login`, `/.git`, etc.), and unmapped domain probes from Nginx, automatically blacklisting threat IPs at the MikroTik border router before they ever reach your network again.

---

## 🚀 Architecture Overview

```
                      [ Internet Traffic ]
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │       MikroTik RouterOS              │
            │  /ip firewall raw chain=prerouting   │
            │  [Check src-address-list]            │
            └───────────────┬──────────────────────┘
                   │ Matches?         │ No Match (Allowed)
                   ▼                  ▼
              [ ⛔ DROP ]     [ Proxmox VE / Nginx ]
             (Zero Overhead)          │
                                      ▼
                        ┌──────────────────────────────┐
                        │   Nginx Ingress Reverse Proxy│
                        │   - Legitimate Domain        │ ──► [ Your Web Apps ]
                        │   - Non-matching / 404 / Trap│
                        └──────────────┬───────────────┘
                                       │ Forward Probes
                                       ▼
                        ┌──────────────────────────────┐
                        │     MSuite-HoneyPot          │
                        │  (Alpine LXC / <15MB RAM)    │
                        │   • Real-IP Extraction       │
                        │   • Whitelist Protection     │
                        │   • Deceptive Decoys         │
                        │   • Live Web Dashboard (SSE) │
                        └──────────────┬───────────────┘
                                       │ RouterOS API :8728 (address-list)
                                       ▼
                       [ MikroTik Address-List ]
                       (e.g., MSuite-Blacklist, 7d)
```

---

## ⚡ Single-Command Quick Install

### Method A: Single Command Interactive / Automated Install
Run this single command on your **Proxmox host**, **Alpine LXC**, or **Debian/Ubuntu VM**:

```bash
curl -sSL https://raw.githubusercontent.com/merlinthedev848/MSuite-HoneyPot/main/install.sh | bash
```

> **Proxmox VE Auto-Detection:** If run directly on your Proxmox VE host, the installer will ask if you want it to **automatically provision a dedicated Alpine LXC container** (ID auto-assigned, 128MB RAM, 1GB disk, OpenRC service auto-configured) with **zero manual steps**!

#### Or Non-Interactive (with flags):
```bash
curl -sSL https://raw.githubusercontent.com/merlinthedev848/MSuite-HoneyPot/main/install.sh | bash -s -- \
  --mikrotik 192.168.88.1 \
  --user admin \
  --pass "YourRouterPassword" \
  --list "MSuite-Blacklist" \
  --timeout "7d"
```

---

## 🛡️ Step 1: MikroTik Firewall Rule (Run Once)

The honeypot talks to RouterOS through the **binary `api` service on port 8728** (plaintext on the LAN). It does not use `www` or `www-ssl`, and it does not need ports 80 or 443 on the router. Leave those disabled so Proxmox nginx owns them and the router login page stays unexposed.

Open your MikroTik RouterOS terminal (or WinBox / SSH) and paste this **single line**:

```routeros
/ip firewall raw add chain=prerouting src-address-list=MSuite-Blacklist action=drop comment="MSuite Honeypot: Nullroute Bots & Scanners"
```

> **Why RAW prerouting?** The `raw` table drops packets before connection tracking, which costs essentially **0% CPU** on your MikroTik even during heavy port/HTTP scanning floods.

The `api` service is often disabled. The installer enables it and installs the raw drop rule over SSH (port 22, same username and password) when that login works. If you are configuring the router by hand, enable the API with:

```routeros
/ip service set api disabled=no port=8728
```

`api-ssl` (port 8729) is optional. Set `mikrotik_use_ssl` to `true` and `mikrotik_port` to `8729` only if you want TLS. The default is plaintext `api` on 8728.

---

## 🌐 Step 2: Nginx Routing Configuration

In your Nginx setup on Proxmox, configure your **default server block** to forward all non-matching traffic (bots scanning your raw public IP or arbitrary host headers) to MSuite-HoneyPot:

Create or edit `/etc/nginx/conf.d/00-honeypot-default.conf`:

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;

    server_name _;

    # Default fallback SSL certificates
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    location / {
        proxy_pass http://<HONEYPOT_IP>:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### (Optional) Trap Common Exploits on Existing Sites
To also auto-ban bots that hit valid domains searching for `.env`, `wp-login.php`, or phpMyAdmin, include this inside your domain `server { ... }` blocks:

```nginx
location ~* ^/(\.env|\.git|\.aws|\.docker|wp-login\.php|wp-admin|phpmyadmin|pma|actuator|xmlrpc\.php|boaform|setup\.cgi) {
    proxy_pass http://<HONEYPOT_IP>:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Reload Nginx:
```bash
nginx -t && systemctl reload nginx
```

---

## 📊 Live Web Dashboard

MSuite-HoneyPot includes a built-in, lightweight web UI accessible at:
```
http://<HONEYPOT_IP>:8081
```

- **Live Stream:** Real-time attack telemetry via Server-Sent Events (SSE).
- **Attack Telemetry:** Timestamp, Attacker IP, Method, Probed Path, User-Agent, and Nullroute status.
- **Top Targets:** Overview of most heavily targeted files and top scanning IPs.
- **Manual Control:** Instantly block or unblock any IP in your MikroTik router with one click.
- **RouterOS Health:** Displays live router board model, CPU load, and connection status.

---

## ⚙️ Configuration (`config.json`)

Located at `/etc/msuite-honeypot/config.json`:

```json
{
  "listen_port": 8080,
  "dashboard_port": 8081,
  "mikrotik_enabled": true,
  "mikrotik_host": "192.168.88.1",
  "mikrotik_port": 8728,
  "mikrotik_use_ssl": false,
  "mikrotik_skip_tls": false,
  "mikrotik_user": "admin",
  "mikrotik_password": "YourPassword",
  "mikrotik_list": "MSuite-Blacklist",
  "mikrotik_timeout": "7d",
  "whitelist_subnets": [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]
}
```

> **Safety Whitelist:** RFC1918 private subnets are whitelisted by default, ensuring your internal LAN and Proxmox node IPs can never be accidentally blacklisted.

---

## 🐳 Docker Deployment (Alternative)

```bash
docker run -d \
  --name msuite-honeypot \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 8081:8081 \
  -e MIKROTIK_HOST="192.168.88.1" \
  -e MIKROTIK_PORT="8728" \
  -e MIKROTIK_USE_SSL="false" \
  -e MIKROTIK_USER="admin" \
  -e MIKROTIK_PASS="YourPassword" \
  -e MIKROTIK_LIST="MSuite-Blacklist" \
  -e MIKROTIK_TIMEOUT="7d" \
  ghcr.io/merlinthedev848/msuite-honeypot:latest
```

---

## 📄 License
MIT License. Created by [Chris Kendall (merlinthedev848)](https://github.com/merlinthedev848).
