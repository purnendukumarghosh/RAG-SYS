#!/usr/bin/env bash
# NimbusVPN installer for a fresh cloud VM (Ubuntu 22.04/24.04, Debian 12).
#
#   sudo ./deploy/scripts/install.sh --domain vpn.example.com [--harden]
#
# Options:
#   --domain NAME     DNS name pointing at this server (used for HTTPS and client profiles).
#                     Omit to use <public-ip>.sslip.io, which is handy for testing.
#   --endpoint HOST   Host clients connect to over WireGuard (default: the domain).
#   --harden          Also configure the host firewall (ufw), automatic security updates,
#                     fail2ban and key-only SSH.
#
# Environment:
#   NIMBUS_ADMIN_PASSWORD   Initial admin password (default: randomly generated).
set -euo pipefail

DOMAIN=""
ENDPOINT=""
HARDEN=0
ADMIN_USER="${NIMBUS_ADMIN_USERNAME:-admin}"
WG_PORT="${NIMBUS_WG_PORT:-51820}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CREDENTIALS_FILE=/root/nimbusvpn-initial-admin.txt

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)   DOMAIN="${2:-}"; shift 2 ;;
    --endpoint) ENDPOINT="${2:-}"; shift 2 ;;
    --harden)   HARDEN=1; shift ;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ -f "$REPO_DIR/docker-compose.yml" ]] || die "cannot find docker-compose.yml in $REPO_DIR"
cd "$REPO_DIR"

hostname_re='^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'

# --- 1. Packages ----------------------------------------------------------------------------
log "Installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl git openssl

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine"
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is missing"

# --- 2. Kernel ------------------------------------------------------------------------------
log "Loading the WireGuard kernel module"
if modprobe wireguard 2>/dev/null; then
  echo wireguard > /etc/modules-load.d/nimbusvpn.conf
else
  warn "could not load the wireguard module; the kernel must be 5.6+ or have it built in"
fi

# --- 3. Configuration -----------------------------------------------------------------------
if [[ -z "$DOMAIN" ]]; then
  PUBLIC_IP="$(curl -fsS4 --max-time 10 https://api.ipify.org || true)"
  [[ "$PUBLIC_IP" =~ ^[0-9.]+$ ]] || die "could not detect the public IP; pass --domain"
  DOMAIN="${PUBLIC_IP//./-}.sslip.io"
  warn "no --domain given; using $DOMAIN"
fi
ENDPOINT="${ENDPOINT:-$DOMAIN}"
[[ "$DOMAIN" =~ $hostname_re ]] || die "invalid domain: $DOMAIN"
[[ "$ENDPOINT" =~ $hostname_re ]] || die "invalid endpoint: $ENDPOINT"

GENERATED_PASSWORD=0
if [[ -f .env ]]; then
  log "Keeping the existing .env"
else
  log "Writing .env with fresh secrets"
  SECRET_KEY="$(openssl rand -hex 32)"
  ADMIN_PASSWORD="${NIMBUS_ADMIN_PASSWORD:-}"
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24)"
    GENERATED_PASSWORD=1
  fi
  umask 077
  sed \
    -e "s|^NIMBUS_SECRET_KEY=.*|NIMBUS_SECRET_KEY=${SECRET_KEY}|" \
    -e "s|^NIMBUS_DOMAIN=.*|NIMBUS_DOMAIN=${DOMAIN}|" \
    -e "s|^NIMBUS_PUBLIC_ENDPOINT=.*|NIMBUS_PUBLIC_ENDPOINT=${ENDPOINT}|" \
    -e "s|^NIMBUS_ADMIN_USERNAME=.*|NIMBUS_ADMIN_USERNAME=${ADMIN_USER}|" \
    -e "s|^NIMBUS_ADMIN_PASSWORD=.*|NIMBUS_ADMIN_PASSWORD=${ADMIN_PASSWORD}|" \
    -e "s|^NIMBUS_WG_PORT=.*|NIMBUS_WG_PORT=${WG_PORT}|" \
    .env.example > .env
  chmod 600 .env
  if [[ $GENERATED_PASSWORD -eq 1 ]]; then
    printf 'NimbusVPN initial admin\nurl: https://%s\nusername: %s\npassword: %s\n' \
      "$DOMAIN" "$ADMIN_USER" "$ADMIN_PASSWORD" > "$CREDENTIALS_FILE"
    chmod 600 "$CREDENTIALS_FILE"
  fi
fi

# --- 4. Host hardening (optional) -----------------------------------------------------------
if [[ $HARDEN -eq 1 ]]; then
  log "Hardening the host"
  apt-get install -y -q ufw unattended-upgrades fail2ban

  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 443/udp
  ufw allow "${WG_PORT}/udp"
  ufw --force enable

  dpkg-reconfigure -f noninteractive unattended-upgrades
  systemctl enable --now fail2ban

  # Only switch SSH to key-only logins if a key is actually installed (avoids lock-out).
  if compgen -G "/root/.ssh/authorized_keys" >/dev/null || compgen -G "/home/*/.ssh/authorized_keys" >/dev/null; then
    cat > /etc/ssh/sshd_config.d/99-nimbusvpn.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
X11Forwarding no
EOF
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  else
    warn "no SSH authorized_keys found; leaving SSH password settings unchanged"
  fi
fi

# --- 5. Start -------------------------------------------------------------------------------
log "Building and starting NimbusVPN"
docker compose up -d --build

log "Waiting for the control plane to become healthy"
for _ in $(seq 1 60); do
  status="$(docker inspect -f '{{.State.Health.Status}}' nimbusvpn 2>/dev/null || true)"
  [[ "$status" == "healthy" ]] && break
  sleep 3
done
[[ "${status:-}" == "healthy" ]] || die "nimbusvpn did not become healthy; check: docker compose logs nimbus"

# The admin account exists now; the bootstrap password does not need to stay on disk.
sed -i '/^NIMBUS_ADMIN_PASSWORD=/d' .env

cat <<EOF

  NimbusVPN is running.

  Dashboard:   https://${DOMAIN}
  WireGuard:   ${ENDPOINT}:${WG_PORT}/udp
  Admin user:  ${ADMIN_USER}
EOF
if [[ $GENERATED_PASSWORD -eq 1 ]]; then
  echo "  Password:    saved in ${CREDENTIALS_FILE} (root only)"
fi
cat <<'EOF'

  Next: sign in, change the password, turn on two-factor authentication, then add a device.

EOF
