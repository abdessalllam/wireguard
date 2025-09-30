#!/usr/bin/env bash
# Author: https://github.com/abdessalllam
# Author: https://abdessal.am
#
#       ░███    ░██               ░██                                             ░██ ░██ ░██                            
#      ░██░██   ░██               ░██                                             ░██ ░██ ░██                            
#     ░██  ░██  ░████████   ░████████  ░███████   ░███████   ░███████   ░██████   ░██ ░██ ░██  ░██████   ░█████████████  
#    ░█████████ ░██    ░██ ░██    ░██ ░██    ░██ ░██        ░██              ░██  ░██ ░██ ░██       ░██  ░██   ░██   ░██ 
#    ░██    ░██ ░██    ░██ ░██    ░██ ░█████████  ░███████   ░███████   ░███████  ░██ ░██ ░██  ░███████  ░██   ░██   ░██ 
#    ░██    ░██ ░███   ░██ ░██   ░███ ░██               ░██        ░██ ░██   ░██  ░██ ░██ ░██ ░██   ░██  ░██   ░██   ░██ 
#    ░██    ░██ ░██░█████   ░█████░██  ░███████   ░███████   ░███████   ░█████░██ ░██ ░██ ░██  ░█████░██ ░██   ░██   ░██
#  
# Toggle IPv6-only egress for 1st HOP or Single Hop clients via DNS64 + NAT64 (JOOL) + NAT66
# Modes: enable | disable | status | rollback <backup-dir>
# Assumes: wg-up is the 1st-HOP->2nd-Hop tunnel on this host, Change to suit.
# Backs up iptables, sysctl, and systemd unit on enable.
# Tested on Ubuntu 24.04/22.04, 2nd-Hop must have IPv6 Internet.
# Requires: jool-dkms, jool-tools, iptables-persistent

set -euo pipefail

# Settings (override with env if needed)
IF_WGUP="${IF_WGUP:-wg-up}"
CLIENT_V4_CIDR="${CLIENT_V4_CIDR:-10.66.66.0/24}" # 1st HOP client IPv4 subnet
CLIENT_V6_CIDR="${CLIENT_V6_CIDR:-fd00:66::/64}" # 1st HOP client IPv6 subnet (ULA)
JOOL_INST="${JOOL_INST:-wg64}" # JOOL instance name
POOL6="${POOL6:-64:ff9b::/96}"   # RFC 6052 well-known NAT64 prefix

STATE_DIR="/var/lib/2ndhop-v6only" # persistent state
UNIT_PATH="/etc/systemd/system/jool-${JOOL_INST}.service" # systemd unit path

# Helpers
ts(){ date +%F-%H%M%S; }
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
must_root(){ [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }; }
wan4(){ ip -o route get 1.1.1.1           | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
wan6(){ ip -o route get 2001:4860:4860::8888 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }

persist_rules(){ command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null || true; }

backup_state(){
  local BK="/root/v6only-backup-$(ts)"
  mkdir -p "$BK" "$STATE_DIR"
  iptables-save  > "$BK/iptables.v4"
  ip6tables-save > "$BK/iptables.v6"
  (sysctl -a 2>/dev/null | grep -E '(^net\.ipv4\.ip_forward|^net\.ipv6\.conf\.all\.forwarding|^net\.ipv4\.conf\..*\.rp_filter)') > "$BK/sysctl.snapshot.txt" || true
  tar -C /etc -czf "$BK/sysctl.d.tgz" sysctl.d || true
  [ -f "$UNIT_PATH" ] && cp -a "$UNIT_PATH" "$BK/$(basename "$UNIT_PATH").bak" || true
  echo "$BK"
}

write_state(){
  mkdir -p "$STATE_DIR"
  {
    echo "WAN4=$(wan4)"
    echo "WAN6=$(wan6)"
    echo "IF_WGUP=${IF_WGUP}"
    echo "CLIENT_V4_CIDR=${CLIENT_V4_CIDR}"
    echo "CLIENT_V6_CIDR=${CLIENT_V6_CIDR}"
    echo "JOOL_INST=${JOOL_INST}"
    echo "POOL6=${POOL6}"
  } > "${STATE_DIR}/env"
}

read_state(){
  [ -f "${STATE_DIR}/env" ] && . "${STATE_DIR}/env" || true
}

# Delete any ip6tables nat POSTROUTING MASQUERADE rules for our ULA (even if -o changed)
del_nat66_any(){
  ip6tables -t nat -S POSTROUTING | \
    awk -v ula="${CLIENT_V6_CIDR}" '$0 ~ "-A POSTROUTING" && $0 ~ ula && $0 ~ "MASQUERADE" {print}' | \
    sed 's/^-A /-D /' | while read -r RULE; do ip6tables -t nat $RULE 2>/dev/null || true; done
}

enable_cmd(){
  must_root
  need iptables; need ip6tables
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y jool-dkms jool-tools iptables-persistent >/dev/null

  local BK; BK=$(backup_state); echo "[*] Backup saved: $BK"

  # Verify 2nd Hop has global IPv6 connectivity (needed for DNS64 resolvers & v6 sites)
  if ! ping -c1 -6 2606:4700:4700::1111 >/dev/null 2>&1; then
    echo "[WARN] 2nd-Hop host appears to lack IPv6 Internet reachability. Fix upstream or NAT66 won't help real IPv6."
  fi

  # Forwarding + loose RPF (policy/asymmetric friendly)
  cat >/etc/sysctl.d/91-v6only.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
  sysctl --system >/dev/null

  # Idempotent JOOL unit (iptables-mode). ExecStartPre dash-ignored if absent.
  cat >"$UNIT_PATH" <<EOF
[Unit]
Description=Jool NAT64 instance ${JOOL_INST}
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/modprobe jool
ExecStartPre=-/usr/bin/jool instance remove ${JOOL_INST}
ExecStart=/usr/bin/jool instance add ${JOOL_INST} --iptables --pool6 ${POOL6}
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "jool-${JOOL_INST}.service"

  # JOOL hooks (idempotent): v6 scoped to NAT64 prefix on wg-up; v4 generic for return paths
  ip6tables -t mangle -C PREROUTING -i "${IF_WGUP}" -d "${POOL6}" -j JOOL --instance "${JOOL_INST}" 2>/dev/null || \
  ip6tables -t mangle -A PREROUTING -i "${IF_WGUP}" -d "${POOL6}" -j JOOL --instance "${JOOL_INST}"
  iptables  -t mangle -C PREROUTING -j JOOL --instance "${JOOL_INST}" 2>/dev/null || \
  iptables  -t mangle -A PREROUTING -j JOOL --instance "${JOOL_INST}"

  # IPv6 FORWARD allow between wg-up and WAN6 + NAT66 (ULA -> global v6)
  local W6; W6=$(wan6)
  ip6tables -C FORWARD -i "${IF_WGUP}" -o "$W6" -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "${IF_WGUP}" -o "$W6" -j ACCEPT
  ip6tables -C FORWARD -i "$W6" -o "${IF_WGUP}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    ip6tables -A FORWARD -i "$W6" -o "${IF_WGUP}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  ip6tables -t nat -C POSTROUTING -s "${CLIENT_V6_CIDR}" -o "$W6" -j MASQUERADE 2>/dev/null || \
    ip6tables -t nat -A POSTROUTING -s "${CLIENT_V6_CIDR}" -o "$W6" -j MASQUERADE

  # Block direct IPv4 egress from 1st HOP clients so HEv2 cannot fall back to v4
  local W4; W4=$(wan4)
  iptables -C FORWARD -i "${IF_WGUP}" -o "$W4" -s "${CLIENT_V4_CIDR}" -j REJECT 2>/dev/null || \
    iptables -I FORWARD 1 -i "${IF_WGUP}" -o "$W4" -s "${CLIENT_V4_CIDR}" -j REJECT

  persist_rules
  write_state

  echo
  echo "✅ IPv6-only egress ENABLED."
  echo "   JOOL instance: ${JOOL_INST} (pool6 ${POOL6})"
  echo "   Hooks: ip6tables/iptables mangle PREROUTING → JOOL"
  echo "   NAT66: ${CLIENT_V6_CIDR} → $W6 (MASQUERADE)"
  echo "   IPv4 block: ${CLIENT_V4_CIDR} via ${IF_WGUP} → $W4 (REJECT)"
  echo "   Backup dir: ${BK}"
  echo
  echo "Set client DNS (DNS64): 2606:4700:4700::64, 2606:4700:4700::6400"
}

disable_cmd(){
  must_root
  need iptables; need ip6tables
  read_state

  # Remove JOOL hooks by spec (safe if absent)
  ip6tables -t mangle -D PREROUTING -i "${IF_WGUP}" -d "${POOL6}" -j JOOL --instance "${JOOL_INST}" 2>/dev/null || true
  iptables  -t mangle -D PREROUTING -j JOOL --instance "${JOOL_INST}" 2>/dev/null || true

  # Remove NAT66 & v6 FORWARD rules (by saved WAN6, with robust fallback)
  if [ -n "${WAN6:-}" ]; then
    ip6tables -t nat -D POSTROUTING -s "${CLIENT_V6_CIDR}" -o "$WAN6" -j MASQUERADE 2>/dev/null || true
  fi
  del_nat66_any
  if [ -n "${WAN6:-}" ]; then
    ip6tables -D FORWARD -i "${IF_WGUP}" -o "$WAN6" -j ACCEPT 2>/dev/null || true
    ip6tables -D FORWARD -i "$WAN6" -o "${IF_WGUP}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  fi

  # Remove IPv4 egress block (by saved WAN4; try best-effort if missing)
  if [ -n "${WAN4:-}" ]; then
    iptables -D FORWARD -i "${IF_WGUP}" -o "$WAN4" -s "${CLIENT_V4_CIDR}" -j REJECT 2>/dev/null || true
  fi

  # Stop service, remove instance
  systemctl disable --now "jool-${JOOL_INST}.service" 2>/dev/null || true
  jool instance remove "${JOOL_INST}" 2>/dev/null || true
  modprobe -r jool 2>/dev/null || true

  persist_rules
  echo "✅ IPv6-only egress DISABLED. (Switch clients back to normal DNS if desired.)"
}

status_cmd(){
  echo "== JOOL instance =="; command -v jool >/dev/null 2>&1 && jool instance display || echo "(jool not installed)"
  echo
  echo "== ip6tables mangle PREROUTING =="; ip6tables -t mangle -S PREROUTING | grep JOOL || echo "(none)"
  echo "== iptables  mangle PREROUTING =="; iptables  -t mangle -S PREROUTING | grep JOOL || echo "(none)"
  local W4 W6; W4=$(wan4); W6=$(wan6)
  echo
  echo "== IPv4 egress block =="; iptables -S FORWARD | grep -E " -i ${IF_WGUP} " | grep -E " -o ${W4} " | grep -E "${CLIENT_V4_CIDR}" | grep REJECT || echo "(none)"
  echo "== NAT66 rule(s) =="; ip6tables -t nat -S POSTROUTING | grep -E "${CLIENT_V6_CIDR}.*MASQUERADE" || echo "(none)"
  echo
  systemctl --no-pager --full status "jool-${JOOL_INST}.service" || true
  echo
  echo "DNS64 for clients: 2606:4700:4700::64, 2606:4700:4700::6400"
}

rollback_cmd(){
  must_root
  local BK="${1:-}"; [ -d "$BK" ] || { echo "Usage: $0 rollback /root/v6only-backup-YYYY-MM-DD-HHMMSS"; exit 1; }
  # Stop & remove JOOL
  systemctl disable --now "jool-${JOOL_INST}.service" 2>/dev/null || true
  jool instance remove "${JOOL_INST}" 2>/dev/null || true
  modprobe -r jool 2>/dev/null || true
  # Restore firewall + sysctls
  iptables-restore  < "$BK/iptables.v4"
  ip6tables-restore < "$BK/iptables.v6"
  [ -f "$BK/sysctl.d.tgz" ] && tar -C /etc -xzf "$BK/sysctl.d.tgz"
  sysctl --system >/dev/null
  # Restore unit if backed up
  SVC_BAK="$BK/$(basename "$UNIT_PATH").bak"
  if [ -f "$SVC_BAK" ]; then cp -a "$SVC_BAK" "$UNIT_PATH"; systemctl daemon-reload; fi
  persist_rules
  echo "✅ Rollback complete from: $BK"
}

case "${1:-}" in
  enable)   enable_cmd ;;
  disable)  disable_cmd ;;
  status)   status_cmd ;;
  rollback) shift; rollback_cmd "${1:-}" ;;
  *) echo "Usage: $0 {enable|disable|status|rollback <backup-dir>}"; exit 1 ;;
esac
