#!/usr/bin/env bash
# ==============================================================================
# MSuite-HoneyPot: Single-Command Automated Installer
# GitHub: https://github.com/merlinthedev848/MSuite-HoneyPot
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${RED}"
cat << "EOF"
  __  __  _____       _ _         _    _             
 |  \/  |/ ____|     (_) |       | |  | |            
 | \  / | (___  _   _ _| |_ ___  | |__| | ___  _ __  
 | |\/| |\___ \| | | | | __/ _ \ |  __  |/ _ \| '_ \ 
 | |  | |____) | |_| | | ||  __/ | |  | | (_) | |_) |
 |_|  |_|_____/ \__,_|_|\__\___| |_|  |_|\___/| .__/ 
                                              | |    
   Lightweight HoneyPot & MikroTik Nullrouter |_|    
EOF
echo -e "${NC}"

# Default parameters
MIKROTIK_HOST="${MIKROTIK_HOST:-}"
MIKROTIK_PORT="${MIKROTIK_PORT:-443}"
MIKROTIK_USER="${MIKROTIK_USER:-admin}"
MIKROTIK_PASS="${MIKROTIK_PASS:-}"
MIKROTIK_LIST="${MIKROTIK_LIST:-MSuite-Blacklist}"
MIKROTIK_TIMEOUT="${MIKROTIK_TIMEOUT:-7d}"
HONEYPOT_PORT="${HONEYPOT_PORT:-8080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8081}"
REPO_BASE="https://raw.githubusercontent.com/merlinthedev848/MSuite-HoneyPot/main"

# Parse CLI flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --mikrotik|--mt-host) MIKROTIK_HOST="$2"; shift ;;
        --port|--mt-port) MIKROTIK_PORT="$2"; shift ;;
        --user|--mt-user) MIKROTIK_USER="$2"; shift ;;
        --pass|--mt-pass) MIKROTIK_PASS="$2"; shift ;;
        --list|--mt-list) MIKROTIK_LIST="$2"; shift ;;
        --timeout|--mt-timeout) MIKROTIK_TIMEOUT="$2"; shift ;;
        --hp-port) HONEYPOT_PORT="$2"; shift ;;
        --dash-port) DASHBOARD_PORT="$2"; shift ;;
        -h|--help)
            echo "Usage: curl -sSL ... | bash -s -- [OPTIONS]"
            echo "Options:"
            echo "  --mikrotik <IP>    MikroTik router IP"
            echo "  --port <PORT>      MikroTik REST API port (default: 443)"
            echo "  --user <USER>      MikroTik API user (default: admin)"
            echo "  --pass <PASS>      MikroTik API password"
            echo "  --list <NAME>      Firewall address-list name (default: MSuite-Blacklist)"
            echo "  --timeout <TIME>   Ban duration e.g. 7d, 24h, 30d (default: 7d)"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Architecture detection
ARCH=$(uname -m)
case $ARCH in
    x86_64|amd64) BIN_ARCH="linux-amd64" ;;
    aarch64|arm64) BIN_ARCH="linux-arm64" ;;
    *) echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

# Interactive prompt if values missing and terminal is interactive
if [ -t 0 ] && [ -z "$MIKROTIK_HOST" ]; then
    echo -e "${CYAN}--- MikroTik RouterOS Configuration ---${NC}"
    read -rp "Enter MikroTik IP address [e.g. 192.168.88.1]: " MIKROTIK_HOST
    read -rp "Enter MikroTik REST API port [443]: " input_port
    MIKROTIK_PORT="${input_port:-443}"
    read -rp "Enter MikroTik Admin Username [admin]: " input_user
    MIKROTIK_USER="${input_user:-admin}"
    read -s -rp "Enter MikroTik Admin Password: " MIKROTIK_PASS
    echo ""
    read -rp "Enter Address-List Name [MSuite-Blacklist]: " input_list
    MIKROTIK_LIST="${input_list:-MSuite-Blacklist}"
    read -rp "Enter Ban Timeout [7d]: " input_timeout
    MIKROTIK_TIMEOUT="${input_timeout:-7d}"
fi

# Fallback default if still blank
if [ -z "$MIKROTIK_HOST" ]; then
    MIKROTIK_HOST="192.168.88.1"
fi

# Function to check Proxmox VE Host
if command -v pveversion >/dev/null 2>&1 && [ -f /etc/pve/pve-root-ca.pem ]; then
    echo -e "${YELLOW}[*] Proxmox VE Host detected!${NC}"
    echo -e "You can install MSuite-HoneyPot directly on the host (Systemd), or spin up a tiny Alpine LXC container."
    
    if [ -t 0 ]; then
        read -rp "Create a dedicated lightweight Alpine LXC container? (Recommended) [y/N]: " create_lxc
    else
        create_lxc="n"
    fi

    if [[ "$create_lxc" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*] Creating Alpine LXC Container...${NC}"
        CT_ID=$(pvesh get /cluster/nextid)
        
        # Download Alpine template if not present
        STORAGE="local"
        pveam update || true
        TEMPLATE=$(pveam available -section system | grep alpine | tail -n 1 | awk '{print $2}')
        if [ -n "$TEMPLATE" ]; then
            echo -e "${CYAN}[*] Downloading Alpine template: $TEMPLATE...${NC}"
            pveam download $STORAGE "$TEMPLATE" || true
            ARCHIVE_PATH="/var/lib/vz/template/cache/$TEMPLATE"
        else
            ARCHIVE_PATH=$(find /var/lib/vz/template/cache -name "*alpine*" | tail -n 1)
        fi

        if [ -z "$ARCHIVE_PATH" ] || [ ! -f "$ARCHIVE_PATH" ]; then
            echo -e "${YELLOW}[!] Alpine template not found automatically. Falling back to host install.${NC}"
        else
            echo -e "${GREEN}[*] Provisioning LXC Container ID: $CT_ID (RAM: 128MB, Disk: 1GB)...${NC}"
            pct create "$CT_ID" "$ARCHIVE_PATH" \
                --hostname "msuite-honeypot" \
                --cores 1 \
                --memory 128 \
                --swap 128 \
                --net0 name=eth0,bridge=vmbr0,ip=dhcp \
                --start 1 \
                --onboot 1

            sleep 5
            LXC_IP=$(pct exec "$CT_ID" -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

            echo -e "${BLUE}[*] Injecting MSuite-HoneyPot inside Container $CT_ID...${NC}"
            pct exec "$CT_ID" -- apk add --no-cache curl ca-certificates bash tzdata
            pct exec "$CT_ID" -- curl -sSL "${REPO_BASE}/dist/msuite-honeypot-${BIN_ARCH}" -o /usr/local/bin/msuite-honeypot
            pct exec "$CT_ID" -- chmod +x /usr/local/bin/msuite-honeypot

            # Write config inside container
            pct exec "$CT_ID" -- mkdir -p /etc/msuite-honeypot
            cat << EOF | pct exec "$CT_ID" -- tee /etc/msuite-honeypot/config.json > /dev/null
{
  "listen_port": ${HONEYPOT_PORT},
  "dashboard_port": ${DASHBOARD_PORT},
  "mikrotik_enabled": true,
  "mikrotik_host": "${MIKROTIK_HOST}",
  "mikrotik_port": ${MIKROTIK_PORT},
  "mikrotik_use_ssl": true,
  "mikrotik_skip_tls": true,
  "mikrotik_user": "${MIKROTIK_USER}",
  "mikrotik_password": "${MIKROTIK_PASS}",
  "mikrotik_list": "${MIKROTIK_LIST}",
  "mikrotik_timeout": "${MIKROTIK_TIMEOUT}"
}
EOF

            # Setup OpenRC
            pct exec "$CT_ID" -- curl -sSL "${REPO_BASE}/scripts/msuite-honeypot.initd" -o /etc/init.d/msuite-honeypot
            pct exec "$CT_ID" -- chmod +x /etc/init.d/msuite-honeypot
            pct exec "$CT_ID" -- rc-update add msuite-honeypot default
            pct exec "$CT_ID" -- rc-service msuite-honeypot start

            echo -e "${GREEN}===================================================================${NC}"
            echo -e "${GREEN}[✔] MSuite-HoneyPot Alpine LXC Container (ID: $CT_ID) is running!${NC}"
            echo -e "Container IP:    ${CYAN}${LXC_IP:-<check router DHCP>}${NC}"
            echo -e "Web Dashboard:   ${CYAN}http://${LXC_IP:-<CT_IP>}:${DASHBOARD_PORT}${NC}"
            echo -e "Honeypot Ingress:${CYAN}http://${LXC_IP:-<CT_IP>}:${HONEYPOT_PORT}${NC}"
            echo -e "${GREEN}===================================================================${NC}"
            exit 0
        fi
    fi
fi

# Direct System Install (Alpine OpenRC or Debian/Ubuntu Systemd)
echo -e "${BLUE}[*] Installing MSuite-HoneyPot on local system...${NC}"

# Download binary
mkdir -p /usr/local/bin /etc/msuite-honeypot
echo -e "${CYAN}[*] Fetching binary (msuite-honeypot-${BIN_ARCH})...${NC}"
curl -sSL "${REPO_BASE}/dist/msuite-honeypot-${BIN_ARCH}" -o /usr/local/bin/msuite-honeypot || {
    # If downloading prebuilt fails (e.g. repo not yet pushed), check if local binary exists
    if [ -f "./dist/msuite-honeypot-${BIN_ARCH}" ]; then
        cp "./dist/msuite-honeypot-${BIN_ARCH}" /usr/local/bin/msuite-honeypot
    elif [ -f "./msuite-honeypot" ]; then
        cp "./msuite-honeypot" /usr/local/bin/msuite-honeypot
    else
        echo -e "${RED}[!] Failed to fetch binary.${NC}"
        exit 1
    fi
}
chmod +x /usr/local/bin/msuite-honeypot

# Create configuration
cat << EOF > /etc/msuite-honeypot/config.json
{
  "listen_port": ${HONEYPOT_PORT},
  "dashboard_port": ${DASHBOARD_PORT},
  "mikrotik_enabled": true,
  "mikrotik_host": "${MIKROTIK_HOST}",
  "mikrotik_port": ${MIKROTIK_PORT},
  "mikrotik_use_ssl": true,
  "mikrotik_skip_tls": true,
  "mikrotik_user": "${MIKROTIK_USER}",
  "mikrotik_password": "${MIKROTIK_PASS}",
  "mikrotik_list": "${MIKROTIK_LIST}",
  "mikrotik_timeout": "${MIKROTIK_TIMEOUT}"
}
EOF
chmod 600 /etc/msuite-honeypot/config.json

# Init Service setup
if [ -f /etc/alpine-release ]; then
    echo -e "${CYAN}[*] Configuring OpenRC service for Alpine Linux...${NC}"
    curl -sSL "${REPO_BASE}/scripts/msuite-honeypot.initd" -o /etc/init.d/msuite-honeypot || cp ./scripts/msuite-honeypot.initd /etc/init.d/msuite-honeypot
    chmod +x /etc/init.d/msuite-honeypot
    rc-update add msuite-honeypot default
    rc-service msuite-honeypot restart
elif command -v systemctl >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Configuring Systemd service...${NC}"
    curl -sSL "${REPO_BASE}/scripts/msuite-honeypot.service" -o /etc/systemd/system/msuite-honeypot.service || cp ./scripts/msuite-honeypot.service /etc/systemd/system/msuite-honeypot.service
    systemctl daemon-reload
    systemctl enable --now msuite-honeypot
    systemctl restart msuite-honeypot
fi

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo -e "\n${GREEN}===================================================================${NC}"
echo -e "${GREEN}[✔] MSuite-HoneyPot Installed and Running Successfully!${NC}"
echo -e "-------------------------------------------------------------------"
echo -e "Web Dashboard:    ${CYAN}http://${LOCAL_IP}:${DASHBOARD_PORT}${NC}"
echo -e "Honeypot Ingress: ${CYAN}http://${LOCAL_IP}:${HONEYPOT_PORT}${NC}"
echo -e "Target MikroTik:  ${YELLOW}${MIKROTIK_HOST} (List: ${MIKROTIK_LIST})${NC}"
echo -e "-------------------------------------------------------------------"
echo -e "${YELLOW}Step 1: On your MikroTik RouterOS terminal, run this ONE command:${NC}"
echo -e "${CYAN}/ip firewall raw add chain=prerouting src-address-list=${MIKROTIK_LIST} action=drop comment=\"MSuite Honeypot Nullroute\"${NC}"
echo -e ""
echo -e "${YELLOW}Step 2: In your Nginx config (/etc/nginx/conf.d/00-honeypot-default.conf):${NC}"
echo -e "Set your default server block proxy_pass to: ${CYAN}http://${LOCAL_IP}:${HONEYPOT_PORT};${NC}"
echo -e "${GREEN}===================================================================${NC}\n"
