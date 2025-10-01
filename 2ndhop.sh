#!/usr/bin/env bash
#   2nd Hop egress-hop toolkit
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
# Commands:
#   apply         - backup + packages + sysctl (ip_forward, rp_filter, UDP conntrack) + NAT + FORWARD + INPUT accept + MSS clamp + peer AllowedIPs sanity
#   test          - show NAT, FORWARD, sysctls
#   rollback DIR  - restore from a printed backup directory
#   help

set -euo pipefail

IF_UP="wg-up"                              # 2nd Hop peer listening for 1st Hop backhaul
CLIENT_V4_CIDR="${CLIENT_V4_CIDR:-10.66.66.0/24}"
CLIENT_V6_CIDR="${CLIENT_V6_CIDR:-fd00:66::/64}"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
must_root(){ [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }; }

backup() {
  local STAMP BK
  STAMP=$(date +%F-%H%M%S)
  BK="/root/wg-backup-2ndhop-${STAMP}" # backup dir
  mkdir -p "$BK"
  cp -a /etc/wireguard "$BK/wireguard"
  iptables-save  > "$BK/iptables.rules.v4"
  ip6tables-save > "$BK/iptables.rules.v6"
  (sysctl -a 2>/dev/null | grep -E '(^net\.ipv4\.ip_forward|^net\.ipv6\.conf\.all\.forwarding|^net\.ipv4\.conf\..*\.rp_filter|^net\.netfilter\.nf_conntrack_udp_timeout(_stream)?)') \
    > "$BK/sysctl.snapshot.txt" || true
  tar -C /etc -czf "$BK/sysctl.d.tgz" sysctl.d || true
  echo "$BK"
}

ensure_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y wireguard wireguard-tools iptables-persistent >/dev/null
}

wan_if() { ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}'; }

nat_forwarding() {
  local WAN LP
  WAN=$(wan_if)

  # Forward wg-up -> WAN and return path with conntrack
  iptables -C FORWARD -i "$IF_UP" -o "$WAN" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$IF_UP" -o "$WAN" -j ACCEPT
  iptables -C FORWARD -i "$WAN" -o "$IF_UP" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$WAN" -o "$IF_UP" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # NAT44 for 1st Hop client pool
  iptables -t nat -C POSTROUTING -s "$CLIENT_V4_CIDR" -o "$WAN" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$CLIENT_V4_CIDR" -o "$WAN" -j MASQUERADE

  # Optional NAT66 (comment this out if you route a real /64 instead)
  ip6tables -t nat -C POSTROUTING -s "$CLIENT_V6_CIDR" -o "$WAN" -j MASQUERADE 2>/dev/null || \
    ip6tables -t nat -A POSTROUTING -s "$CLIENT_V6_CIDR" -o "$WAN" -j MASQUERADE

  # MSS clamps (v4+v6)
  iptables  -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables  -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  ip6tables -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

  # Accept the WireGuard UDP listen port on INPUT if firewall is DROP
  LP=$(grep -E '^\s*ListenPort\s*=' "/etc/wireguard/${IF_UP}.conf" | awk -F'= *' '{print $2}' | head -n1)
  if [ -n "$LP" ]; then
    iptables -C INPUT -p udp --dport "$LP" -j ACCEPT 2>/dev/null || \
      iptables -A INPUT -p udp --dport "$LP" -j ACCEPT
  fi

  # Persist rules
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null || true
}

sysctl_tunables() {
  cat >/etc/sysctl.d/90-wg-core.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
# Loose RPF for policy/asymmetric routing
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
# Conntrack: keep UDP NAT mappings alive between WG keepalives (typical 25s)
net.netfilter.nf_conntrack_udp_timeout=60
net.netfilter.nf_conntrack_udp_timeout_stream=180
EOF
  sysctl --system >/dev/null
}

peer_allowedips_sanity() {
  # Ensure the 1st Hop peer on wg-up authorizes client pools (cryptokey routing)
  local FIRSTHOP_PUB CUR CFG
  CFG="/etc/wireguard/${IF_UP}.conf"

  if [ ! -f "$CFG" ]; then
    echo "[!] $CFG not found — skipping AllowedIPs sanity"
    return 0
  fi

  FIRSTHOP_PUB=$(wg show "$IF_UP" peers | head -n1 || true)
  [ -z "$FIRSTHOP_PUB" ] && { echo "[!] No peers on $IF_UP — skipping AllowedIPs sanity"; return 0; }

  CUR=$(wg show "$IF_UP" allowed-ips | awk '{print $2}' | paste -sd, -)
  if ! echo "$CUR" | grep -q "10.66.66.0/24"; then
    wg set "$IF_UP" peer "$FIRSTHOP_PUB" allowed-ips \
      10.70.0.2/32,fd00:70::2/128,"$CLIENT_V4_CIDR","$CLIENT_V6_CIDR"

    # Persist to disk (first AllowedIPs under the peer)
    sed -i "0,/^AllowedIPs = .*/s|^AllowedIPs = .*|AllowedIPs = 10.70.0.2/32, fd00:70::2/128, ${CLIENT_V4_CIDR}, ${CLIENT_V6_CIDR}|" "$CFG"
  fi
}


apply_cmd() {
  must_root
  need wg; need iptables; need ip6tables
  local BK; BK=$(backup); echo "[*] Backup: $BK"
  ensure_packages
  sysctl_tunables
  nat_forwarding
  peer_allowedips_sanity
  echo "[OK] 2nd Hop apply completed."
}

test_cmd() {
  echo "[*] NAT rules:"; iptables -t nat -S POSTROUTING | grep MASQUERADE || true
  echo "[*] Forward rules:"; iptables -S | grep FORWARD | grep wg-up || true
  echo "[*] INPUT (wg-up listen port):"; iptables -S INPUT | grep udp || true
  echo "[*] Sysctls:"; sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter \
     net.netfilter.nf_conntrack_udp_timeout net.netfilter.nf_conntrack_udp_timeout_stream
}

rollback_cmd() {
  must_root
  local BK="${1:-}"; [ -d "$BK" ] || { echo "Usage: $0 rollback /root/wg-backup-2ndhop-YYYY-MM-DD-HHMMSS"; exit 1; }
  iptables-restore < "$BK/iptables.rules.v4"
  ip6tables-restore < "$BK/iptables.rules.v6"
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null || true
  [ -f "$BK/sysctl.d.tgz" ] && tar -C /etc -xzf "$BK/sysctl.d.tgz"
  sysctl --system >/dev/null
  [ -d "$BK/wireguard" ] && cp -a "$BK/wireguard/." /etc/wireguard/
  wg show "$IF_UP" >/dev/null 2>&1 && wg syncconf "$IF_UP" <(wg-quick strip "$IF_UP") || true
  echo "[OK] 2nd Hop rollback complete."
}

case "${1:-help}" in
  apply) apply_cmd ;;
  test) test_cmd ;;
  rollback) shift; rollback_cmd "${1:-}" ;;
  help|*) echo "Usage: $0 {apply|test|rollback <backup-dir>|help}";;
esac
