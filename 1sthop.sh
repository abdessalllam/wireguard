#!/usr/bin/env bash
#   1st Hop entry-hop toolkit
# Commands:
#   apply         - backup + packages + sysctl + policy routing + firewall + DNS pin (backhaul)
#   add-client    - interactive client generator (auto v4/v6, QR, hot-apply)
#   test          - curl via 1st Hop clients’ source IP (should show 2nd Hop egress IP)
#   rollback DIR  - restore from a printed backup directory
#   help
#
# Assumes two interfaces already exist:
#   wg-up       : 1st Hop -> 2nd Hop backhaul
#   wg-clients  : Devices -> 1st Hop
#
# Verified behaviors:
# - wg-quick DNS= is pushed via resolvconf on up/down (man page).                    
# - Hot reload without dropping peers: wg syncconf <(wg-quick strip IFACE).          
# - When a peer has /0 AllowedIPs, wg-quick uses policy routing (ip rule) not default table clobber. 
# - AllowedIPs is both route-map and ingress allow-list (“cryptokey routing”).       
# - MSS clamp avoids PMTU blackholes; rp_filter=2 avoids strict RPF drops, Cause wireguard is unstable as shit sometimes.        
#
set -euo pipefail

# ---- Tunables ----
IF_UP="wg-up"                      # 1st Hop -> 2nd Hop
IF_CL="wg-clients"                 # Devices -> 1st Hop
CONF_UP="/etc/wireguard/${IF_UP}.conf" 
CONF_CL="/etc/wireguard/${IF_CL}.conf"
CLIENT_DIR="/etc/wireguard/clients"
2NDHOP_TABLE=${2NDHOP_TABLE:-51821}        # policy table used by wg-up for backhaul defaults

DNS_BACKHAUL_V4="1.1.1.1"
DNS_BACKHAUL_V6="2606:4700:4700::1111"
DNS_CLIENTS="9.9.9.9,2620:fe::fe"
CLIENT_MTU=1280

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
must_root(){ [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }; }

backup() {
  local STAMP BK
  STAMP=$(date +%F-%H%M%S)
  BK="/root/wg-backup-1sthop-${STAMP}"
  mkdir -p "$BK"
  cp -a /etc/wireguard "$BK/wireguard"
  iptables-save  > "$BK/iptables.rules.v4"
  ip6tables-save > "$BK/iptables.rules.v6"
  (sysctl -a 2>/dev/null | grep -E '(^net\.ipv4\.conf\..*\.rp_filter|^net\.ipv4\.ip_forward|^net\.ipv6\.conf\.all\.forwarding)') \
    > "$BK/sysctl.snapshot.txt" || true
  tar -C /etc -czf "$BK/sysctl.d.tgz" sysctl.d || true
  echo "$BK"
}

disable_nftables_unit() {
  systemctl is-enabled nftables >/dev/null 2>&1 && systemctl disable --now nftables || true
}

ensure_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y wireguard wireguard-tools iptables-persistent resolvconf qrencode curl >/dev/null
}

parse_pools() {
  local ADDR_LINE V6_IF
  ADDR_LINE=$(grep -E '^\s*Address\s*=' "$CONF_CL" | head -n1 | sed 's/.*=\s*//')
  V4_IF=$(printf '%s' "$ADDR_LINE" | tr ',' '\n' | awk '/\./{print $1}')        # e.g. 10.66.66.1/24
  V6_IF=$(printf '%s' "$ADDR_LINE" | tr ',' '\n' | awk '/:/{print $1}')         # e.g. fd00:66::1/64
  [ -n "${V4_IF:-}" ] && [ -n "${V6_IF:-}" ] || { echo "Could not parse Address= in $CONF_CL"; exit 1; }

  V4_BASE=$(printf '%s' "$V4_IF" | awk -F'[./]' '{printf "%s.%s.%s", $1,$2,$3}')  # 10.66.66
  # Derive clean v6 prefix like "fd00:66::"
  V6_PREFIX=$(printf '%s' "${V6_IF%%/*}" | sed -E 's/::?[0-9A-Fa-f]+$//; s/::$/::/; s/$/::/; s/::+$/::/')
}

listen_port_clients() {
  local LP
  LP=$(grep -E '^\s*ListenPort\s*=' "$CONF_CL" | awk -F'= *' '{print $2}' | head -n1 || true)
  [ -z "$LP" ] && LP=$(wg show "$IF_CL" listen-port || true)
  echo "$LP"
}

public_ipv4() {
  local WAN_IF
  WAN_IF=$(ip -o route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
  ip -o -4 addr show dev "$WAN_IF" | awk '{print $4}' | cut -d/ -f1 | head -n1
}

ensure_backhaul_has_table_and_default_allowedips() {
  # In wg-up.conf ensure Table = 2NDHOP_TABLE under [Interface] (safe insert).
  awk -v tbl="$2NDHOP_TABLE" '
    BEGIN{ins=0}
    /^\[Interface\]/{print; if(!ins){print "Table = " tbl; ins=1; next}}
    {print}
  ' "$CONF_UP" > "${CONF_UP}.new" && mv "${CONF_UP}.new" "$CONF_UP"

  # If wg-up has exactly one [Peer], ensure its AllowedIPs contain 0.0.0.0/0, ::/0
  local peers
  peers=$(grep -c '^\s*\[Peer\]' "$CONF_UP" || true)
  if [ "$peers" = "1" ]; then
    if grep -qE '^\s*AllowedIPs\s*=' "$CONF_UP"; then
      sed -i '0,/^\s*AllowedIPs\s*=.*/s//AllowedIPs = 0.0.0.0\/0, ::\/0/' "$CONF_UP"
    else
      # Append inside the (single) peer
      awk '
        BEGIN{inpeer=0; done=0}
        /^\[Peer\]/{inpeer=1}
        {print}
        inpeer && !done && NF==0 {print "AllowedIPs = 0.0.0.0/0, ::/0"; done=1}
      ' "$CONF_UP" > "${CONF_UP}.tmp" && mv "${CONF_UP}.tmp" "$CONF_UP"
    fi
  else
    echo "[!] Skipped editing AllowedIPs in $CONF_UP because multiple peers are defined; ensure the backhaul peer includes 0.0.0.0/0, ::/0."
  fi
}

policy_routing_apply() {
  # Add rules that send client-source traffic via the wg-up table
  ip rule add from "${V4_BASE}.0/24" lookup "$2NDHOP_TABLE" 2>/dev/null || true
  ip -6 rule add from "${V6_PREFIX%::}/64" lookup "$2NDHOP_TABLE" 2>/dev/null || true
  # Ensure default routes in the 2NDHOP table point to wg-up
  ip route replace table "$2NDHOP_TABLE" default dev "$IF_UP"
  ip -6 route replace table "$2NDHOP_TABLE" ::/0 dev "$IF_UP"
}

dns_pin_backhaul() {
  # wg-quick will push DNS via resolvconf when interface is up (see wg-quick(8))
  if grep -qE '^\s*DNS\s*=' "$CONF_UP"; then
    sed -i "0,/^\s*DNS\s*=.*/s//DNS = ${DNS_BACKHAUL_V4}, ${DNS_BACKHAUL_V6}/" "$CONF_UP"
  else
    awk -v dns="${DNS_BACKHAUL_V4}, ${DNS_BACKHAUL_V6}" '
      BEGIN{done=0}
      {print}
      /^\[Interface\]/ && !done {getline; print "DNS = " dns; print $0; done=1}
    ' "$CONF_UP" > "${CONF_UP}.tmp" && mv "${CONF_UP}.tmp" "$CONF_UP"
  fi
  systemctl is-active --quiet "wg-quick@${IF_UP}" && systemctl restart "wg-quick@${IF_UP}"
}

sysctl_tunables() {
  cat >/etc/sysctl.d/90-wg-core.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
# Loose rp_filter = 2 suits policy/asymmetric routing.
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
  sysctl --system >/dev/null
}

firewall_plumb() {
  local LP
  LP=$(listen_port_clients)
  # Accept WireGuard UDP on 1st Hop’s client port
  iptables -C INPUT -p udp --dport "$LP" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$LP" -j ACCEPT
  # MSS clamps (v4/v6) to avoid PMTU blackholes across the double tunnel
  iptables  -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables  -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  ip6tables -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  # Persist (iptables-persistent)
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null || true
}

wg_hot_reload() { wg syncconf "$1" <(wg-quick strip "$1"); }

# --- Helper: fix any historical bad IPv6 (:: twice) by rebuilding from v4 host octet ---
preclean_bad_v6_allowedips() {
  grep -qE '^AllowedIPs.*::.*::' "$CONF_CL" || return 0
  local TS; TS=$(date +%F-%H%M%S); cp -a "$CONF_CL" "/root/wg-clients.preclean.${TS}.bak"
  awk -v v6pfx="$V6_PREFIX" '
    function trim(s){gsub(/^ +| +$/,"",s);return s}
    BEGIN{inpeer=0}
    {
      if ($0 ~ /^\[Peer\]/){inpeer=1}
      if (inpeer && $0 ~ /^[[:space:]]*AllowedIPs[[:space:]]*=/) {
        split($0, a, "="); ips=trim(a[2]); n=split(ips, arr, /,[[:space:]]*/)
        split(arr[1], v4, "/"); split(v4[1], o, "."); host=o[4]
        arr[2]=v6pfx host "/128"
        printf "AllowedIPs = %s, %s\n", arr[1], arr[2]
        inpeer=0; next
      }
      print
    }' "$CONF_CL" > "${CONF_CL}.new"
  mv "${CONF_CL}.new" "$CONF_CL"
}

used_v4_hosts() {
  {
    wg show "$IF_CL" dump 2>/dev/null | awk -F'\t' 'NR>1{print $4}' | tr ',' '\n' | awk -F'/' '/\./{print $1}'
    grep -E '^[[:space:]]*AllowedIPs' "$CONF_CL" | awk -F'= *' '{print $2}' | tr ',' '\n' | awk -F'/' '/\./{print $1}'
    echo "${V4_BASE}.1"
  } | sed -n "s/^${V4_BASE}\.\([0-9]\+\)$/\1/p" | sort -n | uniq
}
next_v4_host() { local i; for i in $(seq 2 254); do used_v4_hosts | grep -qx "$i" || { echo "$i"; return; }; done; echo "No free IPv4 slots" >&2; exit 1; }

qr_show() { qrencode -t ansiutf8 < "$1"; }

# --- Subcommands ---

apply_cmd() {
  must_root
  need wg; need ip; need iptables; need ip6tables
  [ -f "$CONF_UP" ] && [ -f "$CONF_CL" ] || { echo "Missing $CONF_UP or $CONF_CL"; exit 1; }

  local BK; BK=$(backup); echo "[*] Backup: $BK"
  disable_nftables_unit
  ensure_packages
  parse_pools
  ensure_backhaul_has_table_and_default_allowedips
  sysctl_tunables
  policy_routing_apply
  firewall_plumb
  dns_pin_backhaul
  echo "[OK] 1st Hop apply completed."
  echo "Next: add a client -> $0 add-client"
}

add_client_cmd() {
  parse_pools
  preclean_bad_v6_allowedips

  read -rp "Client name: " NAME
  [ -n "$NAME" ] || { echo "Name required"; exit 1; }
  LC_ALL=C NAME=$(printf '%s' "$NAME" | tr -cs '[:alnum:]._:-' '_')

  local PUB4 LP; PUB4=$(public_ipv4); LP=$(listen_port_clients)
  read -rp "Optional FQDN for Endpoint (Enter to keep ${PUB4}): " EP_HOST
  EP_HOST=${EP_HOST:-$PUB4}

  local host_id CL_V4 CL_V6
  host_id=$(next_v4_host)
  CL_V4="${V4_BASE}.${host_id}/32"
  CL_V6="${V6_PREFIX}${host_id}/128"

  echo; echo "About to add client:"
  echo "  Name     : $NAME"
  echo "  Endpoint : ${EP_HOST}:${LP}"
  echo "  v4 (tun) : $CL_V4"
  echo "  v6 (tun) : $CL_V6"
  read -rp "Proceed? [y/N]: " OK; [[ "$OK" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 1; }

  # Enforce Cloudflare DNS on backhaul (wg-up); restart applies via resolvconf
  dns_pin_backhaul

  install -d -m 0700 "$CLIENT_DIR"
  umask 077
  local PRIV PUB PSK CLIENT_PATH
  PRIV=$(wg genkey); PUB=$(echo "$PRIV" | wg pubkey); PSK=$(wg genpsk)
  CLIENT_PATH="${CLIENT_DIR}/${NAME}.conf"

  cat > "$CLIENT_PATH" <<EOF
[Interface]
PrivateKey = ${PRIV}
Address = ${CL_V4}, ${CL_V6}
DNS = ${DNS_CLIENTS}
MTU = ${CLIENT_MTU}

[Peer]
PublicKey = $(wg show "$IF_CL" public-key)
PresharedKey = ${PSK}
Endpoint = ${EP_HOST}:${LP}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
  chmod 0600 "$CLIENT_PATH"

  {
    echo ""; echo "[Peer]"
    echo "PublicKey = ${PUB}"
    echo "PresharedKey = ${PSK}"
    echo "AllowedIPs = ${CL_V4}, ${CL_V6}"
  } >> "$CONF_CL"

  wg_hot_reload "$IF_CL"
  wg set "$IF_CL" peer "$PUB" preshared-key <(echo "$PSK") allowed-ips "${CL_V4},${CL_V6}"

  echo; echo "✅ Added client '${NAME}'"
  echo "   File: ${CLIENT_PATH}"
  echo; echo "### Scan this QR in the WireGuard app:"; qr_show "$CLIENT_PATH"
}

test_cmd() {
  parse_pools
  local SRC; SRC="${V4_BASE}.1"  # 1st Hop's wg-clients server IP
  echo "[*] curl -4 --interface ${SRC} https://ifconfig.me  (expect 2nd Hop public IP)"
  curl -4 -vv --interface "${SRC}" https://ifconfig.me || true
}

rollback_cmd() {
  must_root
  local BK="${1:-}"; [ -d "$BK" ] || { echo "Usage: $0 rollback /root/wg-backup-1sthop-YYYY-MM-DD-HHMMSS"; exit 1; }
  iptables-restore < "$BK/iptables.rules.v4"
  ip6tables-restore < "$BK/iptables.rules.v6"
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null || true
  [ -f "$BK/sysctl.d.tgz" ] && tar -C /etc -xzf "$BK/sysctl.d.tgz"
  sysctl --system >/dev/null
  [ -d "$BK/wireguard" ] && cp -a "$BK/wireguard/." /etc/wireguard/
  wg show "$IF_UP" >/dev/null 2>&1 && wg_hot_reload "$IF_UP" || true
  wg show "$IF_CL" >/dev/null 2>&1 && wg_hot_reload "$IF_CL" || true
  echo "[OK] 1st Hop rollback complete."
}

case "${1:-help}" in
  apply) apply_cmd ;;
  add-client) add_client_cmd ;;
  test) test_cmd ;;
  rollback) shift; rollback_cmd "${1:-}" ;;
  help|*) echo "Usage: $0 {apply|add-client|test|rollback <backup-dir>|help}";;
esac
