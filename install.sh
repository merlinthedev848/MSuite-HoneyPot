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

# Default parameters. HTTP REST is the RouterOS www service (plaintext).
# On this router www is port 8480. Port 8728 is the binary api, not REST.
# www-ssl is a different listener. Do not enable TLS for 8480.
MIKROTIK_HOST="${MIKROTIK_HOST:-}"
MIKROTIK_PORT="${MIKROTIK_PORT:-8480}"
MIKROTIK_USE_SSL="${MIKROTIK_USE_SSL:-false}"
MIKROTIK_USER="${MIKROTIK_USER:-admin}"
MIKROTIK_PASS="${MIKROTIK_PASS:-}"
MIKROTIK_LIST="${MIKROTIK_LIST:-MSuite-Blacklist}"
MIKROTIK_TIMEOUT="${MIKROTIK_TIMEOUT:-7d}"
HONEYPOT_PORT="${HONEYPOT_PORT:-8080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8081}"
REPO_BASE="https://raw.githubusercontent.com/merlinthedev848/MSuite-HoneyPot/main"
ROUTEROS_CONFIGURED=0

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
            echo "  --port <PORT>      MikroTik www HTTP REST port (default: 8480, plaintext; not binary api 8728)"
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

# www port 8480 is plaintext HTTP. Never turn TLS on for it.
if [ "$MIKROTIK_PORT" = "8480" ]; then
    MIKROTIK_USE_SSL=false
fi

# Interactive prompt if values missing and terminal is interactive
if [ -t 0 ] && [ -z "$MIKROTIK_HOST" ]; then
    echo -e "${CYAN}--- MikroTik RouterOS Configuration ---${NC}"
    read -rp "Enter MikroTik IP address [e.g. 192.168.88.1]: " MIKROTIK_HOST
    read -rp "Enter MikroTik HTTP REST port [${MIKROTIK_PORT}]: " input_port
    MIKROTIK_PORT="${input_port:-$MIKROTIK_PORT}"
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

# The interactive prompt can leave port 8480 with a stale SSL flag. Force HTTP.
if [ "$MIKROTIK_PORT" = "8480" ]; then
    MIKROTIK_USE_SSL=false
fi

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

ros_dquote() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '"%s"' "$s"
}

write_honeypot_config() {
    local host user pass list timeout
    host=$(json_escape "$MIKROTIK_HOST")
    user=$(json_escape "$MIKROTIK_USER")
    pass=$(json_escape "$MIKROTIK_PASS")
    list=$(json_escape "$MIKROTIK_LIST")
    timeout=$(json_escape "$MIKROTIK_TIMEOUT")
    cat << EOF
{
  "listen_port": ${HONEYPOT_PORT},
  "dashboard_port": ${DASHBOARD_PORT},
  "mikrotik_enabled": true,
  "mikrotik_host": "${host}",
  "mikrotik_port": ${MIKROTIK_PORT},
  "mikrotik_use_ssl": ${MIKROTIK_USE_SSL},
  "mikrotik_skip_tls": false,
  "mikrotik_user": "${user}",
  "mikrotik_password": "${pass}",
  "mikrotik_list": "${list}",
  "mikrotik_timeout": "${timeout}"
}
EOF
}

# Install the raw drop rule over SSH (port 22). Do not touch ip services.
# Port 8728 stays the binary api. HTTP REST is the existing www listener.
# A failure here must not abort the honeypot install.
routeros_ssh() {
    local remote_cmd=$1
    local known askpass status out
    known=$(mktemp)
    askpass=$(mktemp)
    cat > "$askpass" << 'EOF'
#!/bin/sh
printf '%s\n' "$MIKROTIK_PASS"
EOF
    chmod 700 "$askpass"

    local -a cmd
    if command -v sshpass >/dev/null 2>&1 && [ -n "$MIKROTIK_PASS" ]; then
        export SSHPASS="$MIKROTIK_PASS"
        cmd=(sshpass -e ssh)
    else
        export MIKROTIK_PASS
        export SSH_ASKPASS="$askpass"
        export SSH_ASKPASS_REQUIRE=force
        export DISPLAY="${DISPLAY:-:0}"
        if setsid -w true >/dev/null 2>&1; then
            cmd=(setsid -w ssh)
        else
            cmd=(ssh)
        fi
    fi
    if command -v timeout >/dev/null 2>&1; then
        cmd=(timeout 20 "${cmd[@]}")
    fi

    local -a opts=(
        -p 22
        -o "UserKnownHostsFile=${known}"
        -o NumberOfPasswordPrompts=1
        -o ConnectTimeout=8
        -o LogLevel=ERROR
    )
    if [ -n "$MIKROTIK_PASS" ]; then
        opts+=(-o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no)
    fi

    run_once() {
        "${cmd[@]}" "${opts[@]}" -o "StrictHostKeyChecking=$1" "${MIKROTIK_USER}@${MIKROTIK_HOST}" "$remote_cmd" </dev/null
    }

    set +e
    out=$(run_once accept-new 2>&1)
    status=$?
    if printf '%s\n' "$out" | grep -qi 'Bad configuration option'; then
        out=$(run_once no 2>&1)
        status=$?
    fi
    set -e
    printf '%s\n' "$out"
    rm -f "$known" "$askpass"
    unset SSHPASS
    return "$status"
}

configure_mikrotik_router() {
    ROUTEROS_CONFIGURED=0
    local list_q comment_q remote output status
    list_q=$(ros_dquote "$MIKROTIK_LIST")
    comment_q=$(ros_dquote "MSuite Honeypot: Nullroute Bots & Scanners")
    remote=":if ([:len [/ip firewall raw find where chain=prerouting src-address-list=${list_q} action=drop]] = 0) do={ /ip firewall raw add chain=prerouting src-address-list=${list_q} action=drop comment=${comment_q} }"

    echo -e "${BLUE}[*] Configuring RouterOS over SSH (${MIKROTIK_HOST}:22): install the raw drop rule if it is missing...${NC}"
    if ! command -v ssh >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ssh client is not installed. The honeypot install will continue.${NC}"
        return 0
    fi

    status=0
    output=$(routeros_ssh "$remote" 2>&1) || status=$?
    if [ "$status" -eq 0 ] && ! printf '%s' "$output" | grep -Eqi 'failure:|syntax error|expected end of command|bad command name|no such item'; then
        ROUTEROS_CONFIGURED=1
        echo -e "${GREEN}[✔] Raw prerouting drop rule is installed. HTTP REST stays on port ${MIKROTIK_PORT}.${NC}"
        return 0
    fi

    echo -e "${YELLOW}[!] Could not configure MikroTik over SSH (${MIKROTIK_HOST}:22). The honeypot install will continue.${NC}"
    if [ -n "$output" ]; then
        printf '%s\n' "$output" | head -n 5 | sed 's/^/    /'
    fi
    return 0
}

print_routeros_followup() {
    if [ "$ROUTEROS_CONFIGURED" = "1" ]; then
        echo -e "RouterOS:        ${GREEN}raw drop rule configured over SSH; REST is http://${MIKROTIK_HOST}:${MIKROTIK_PORT}/rest${NC}"
        return 0
    fi
    echo -e "${YELLOW}Raw drop rule (skip if it already exists):${NC}"
    echo -e "${CYAN}/ip firewall raw add chain=prerouting src-address-list=${MIKROTIK_LIST} action=drop comment=\"MSuite Honeypot: Nullroute Bots & Scanners\"${NC}"
}

configure_mikrotik_router

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
            write_honeypot_config | pct exec "$CT_ID" -- tee /etc/msuite-honeypot/config.json > /dev/null

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
            print_routeros_followup
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
write_honeypot_config > /etc/msuite-honeypot/config.json
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
echo -e "Target MikroTik:  ${YELLOW}${MIKROTIK_HOST}:${MIKROTIK_PORT} (List: ${MIKROTIK_LIST})${NC}"
print_routeros_followup
echo -e "-------------------------------------------------------------------"
echo -e "${YELLOW}In your Nginx config (/etc/nginx/conf.d/00-honeypot-default.conf):${NC}"
echo -e "Set your default server block proxy_pass to: ${CYAN}http://${LOCAL_IP}:${HONEYPOT_PORT};${NC}"
echo -e "${GREEN}===================================================================${NC}\n"
