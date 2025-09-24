# Double‑VPN with WireGuard
**1st Hop:** · **2nd Hop: 2nd Hop** · **Optional toggle: `ipv6only`**

This repository sets up a two‑hop WireGuard chain:

- Devices connect to **1st Hop**.
- 1st Hop forwards all client traffic via a backhaul tunnel to **2nd Hop**, which performs Internet egress.
- Optional: **IPv6‑only egress** on 2nd Hop using DNS64+NAT64 (with clean rollback).

Designed for **Ubuntu 24.04** on both servers. Uses **iptables** (with `iptables‑persistent`) and disables `nftables`.

> Script names in this repo are intended to be installed to `/root/` on each server. You can keep them in `scripts/` here and copy them over with `scp`.

---

## Contents

- [Topology](#topology)
- [Prerequisites](#prerequisites)
- [Scripts](#scripts)
  - [1st Hop (`1sthop.sh`)](#1st-hop-1sthopsh)
  - [2nd Hop (`2ndhop.sh`)](#2nd-hop-2ndhopsh)
  - [2nd Hop — IPv6‑only toggle (`ipv6only`)](#ipv6only-toggle-ipv6only)
- [First‑time Bring‑up](#first-time-bring-up)
- [Client Generation & QR](#client-generation--qr)
- [Validation](#validation)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)
- [References](#references)

---

## Topology

```
[ Phone/Laptop ] --(WG)-->  [ 1st Hop ] ==(WG backhaul)==> [ 2nd Hop ] --> Internet
                                   |
                                  Clients: 10.66.66.0/24 (v4), fd00:66::/64 (v6 ULA)
```

- **1st Hop** runs two interfaces: `wg-clients` (terminates devices) and `wg-up` (backhaul to NY). All client routes (`0.0.0.0/0`, `::/0`) are pushed into `wg-up`.
- **2nd Hop** is the egress: NAT44 for client IPv4; NAT66 for client ULA IPv6; optional DNS64+NAT64 when `ipv6only` is enabled.

---

## Prerequisites

On **both** servers:

```bash
sudo systemctl disable --now nftables || true
sudo apt-get update
sudo apt-get install -y wireguard iptables-persistent qrencode
```

Sysctls (forwarding + loose RPF):

```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/90-doublevpn.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
sudo sysctl --system
```

---

## Scripts

Install these on the appropriate hosts (copy from this repo’s `scripts/` directory to the servers’ `/root/`).

- **1st Hop**: [`scripts/1sthop.sh`](scripts/1sthop.sh) → install to `/root/1sthop.sh`
- **2nd Hop**: [`scripts/2ndhop.sh`](scripts/2ndhop.sh) → install to `/root/2ndhop.sh`
- **2nd Hop — IPv6‑only toggle**: [`scripts/ipv6only`](scripts/ipv6only) → install to `/root/ipv6only`

Make executable:
```bash
chmod +x /root/1sthop.sh /root/2ndhop.sh /root/ipv6only
```

### 1st Hop (`1sthop.sh`)

**What it does**
- Creates `wg-clients` (client pool) and `wg-up` (backhaul to NY).
- Forwards all client traffic into `wg-up` (no direct Internet NAT on 1st Hop).
- Includes an **interactive client generator** that emits `.conf` files **and QR codes**, and hot‑loads peers without dropping the interface.

**Defaults**
- Clients: `10.66.66.0/24` (v4), `fd00:66::/64` (v6 ULA).
- Backhaul /30: `10.70.0.0/30`, `fd00:70::/126` (1st Hop `.2`, 2nd Hop `.1`).
- Client DNS (default): **Quad9** (`9.9.9.9`, `2620:fe::fe`).

**Usage (1st Hop)**
```bash
# one‑time
/root/1sthop.sh init

# bring interfaces up
systemctl enable --now wg-quick@wg-up
systemctl enable --now wg-quick@wg-clients

# manage clients
/root/1sthop.sh add-client     # interactive, prints QR
/root/1sthop.sh list
/root/1sthop.sh del-client <name>
```

### 2nd Hop (`2ndhop.sh`)

**What it does**
- Creates `wg-up` (receives backhaul from 1st Hop).
- Enables **NAT44** (clients’ `10.66.66.0/24` → WAN) and matching FORWARD accepts.
- Enables **NAT66** (clients’ `fd00:66::/64` → WAN v6) so IPv6 works for ULAs.
- Adds **TCP MSS clamp** for clean PMTU through tunnels.

**Usage (2nd Hop)**
```bash
# one‑time
/root/2ndhop.sh init

# bring backhaul up
systemctl enable --now wg-quick@wg-up

# sanity
/root/2ndhop.sh status
```

### 2nd Hop — `IPv6 Only` toggle (`/root/ipv6only`)

**Enable** to force IPv6 everywhere while keeping reachability to IPv4‑only sites:
- Installs **Jool**; creates an *iptables‑mode* NAT64 instance with pool `64:ff9b::/96`.
- Adds JOOL hooks (IPv6 on `wg-up` → `64:ff9b::/96`, IPv4 generic for stateful replies).
- Allows IPv6 FORWARD and adds **NAT66** for ULAs (`fd00:66::/64` → WAN v6).
- **Blocks clients’ direct IPv4 egress** (REJECT) so Happy‑Eyeballs can’t fall back.
- Saves firewall/sysctls; drops an idempotent systemd unit; provides clean **disable/rollback**.

**Client DNS while enabled (DNS64)**:
```
DNS = 2606:4700:4700::64, 2606:4700:4700::6400
```
Use DNS64 **only** when NAT64 is enabled. Switch back to normal resolvers when you disable `ipv6only`.

**Commands**
```bash
# enable IPv6‑only egress (prints backup dir)
/root/ipv6only enable

# check
/root/ipv6only status

# disable (reverts to dual‑stack NAT44+NAT66)
/root/ipv6only disable

# full rollback to a printed snapshot
/root/ipv6only rollback /root/v6only-backup-YYYY-MM-DD-HHMMSS
```

---

## First‑time Bring‑up

1) **2nd Hop**
```bash
/root/2ndhop.sh init
systemctl enable --now wg-quick@wg-up
/root/2ndhop.sh status
```

2) **1st Hop**
```bash
/root/1sthop.sh init
systemctl enable --now wg-quick@wg-up
systemctl enable --now wg-quick@wg-clients
```

3) **Add first client on 1st Hop**
```bash
/root/1sthop.sh add-client   # scan the QR on your phone
```

---

## Client Generation & QR

On 1st Hop:
```bash
/root/1sthop.sh add-client    # interactive, prints QR
/root/1sthop.sh list
/root/1sthop.sh del-client <name>
```

The generator reads 1st Hop’s `wg-clients.conf` and backhaul endpoint, assigns addresses, writes the client `.conf`, and hot‑loads the peer via `wg syncconf` without bouncing the interface.

---

## Validation

From **1st Hop**:
```bash
ping -c1 -I 10.70.0.2 10.70.0.1           # reach 2nd Hop over backhaul
curl -4 --interface wg-up https://ifconfig.me
curl -6 --interface wg-up https://ifconfig.co
```

From a **client device** (after importing profile):
- `https://ifconfig.me/` and `https://test-ipv6.com/` should show 2nd Hop egress.
- When `ipv6only` is enabled and client DNS is DNS64, dual‑stack sites should use IPv6; IPv4‑only sites work via DNS64→NAT64.

---

## Maintenance

- **Change ports/endpoints**: edit the `wg-*.conf` files and `systemctl restart wg-quick@name` (or hot‑reload with `wg syncconf <(wg-quick strip ...)`).
- **Add/remove clients**: use 1st Hop’s script; it updates live peers and writes `.conf` + QR.
- **Backups**: `ipv6only` keeps firewall/sysctl snapshots and supports `rollback`.

---

## Troubleshooting

- **DNS64 enabled but no Internet**: clients must use the DNS64 resolvers above *and* 2nd Hop must have NAT64 active (JOOL instance up + PREROUTING hooks).
- **After disabling `ipv6only`, IPv6 disappears**: re‑enable NAT66 on 2nd Hop (the base script does this by default):  
  `ip6tables -t nat -A POSTROUTING -s fd00:66::/64 -o <WANv6> -j MASQUERADE`.
- **Netflix says “using a VPN”**: reputation/CDN policy on the egress IP. Consider split‑tunneling the app, changing exit ASN/provider, or using residential egress.

---

## References

- WireGuard `wg-quick(8)` — routes inferred from `AllowedIPs`, default‑route handling.  
  https://man7.org/linux/man-pages/man8/wg-quick.8.html

- DNS64 for IPv6‑only networks (resolver IPv6 addresses and guidance).  
  https://developers.cloudflare.com/1.1.1.1/infrastructure/ipv6-networks/

- Cloudflare standard resolver addresses (non‑DNS64).  
  https://developers.cloudflare.com/1.1.1.1/ip-addresses/

- NAT64 with Jool — stateful run and instance management (iptables‑mode).  
  https://www.jool.mx/en/run-nat64.html

- RFC 6052 — IPv4‑embedded IPv6 Well‑Known Prefix `64:ff9b::/96`.  
  https://datatracker.ietf.org/doc/html/rfc6052

- RFC 8305 — Happy Eyeballs v2 (why you must block one family to force the other).  
  https://datatracker.ietf.org/doc/html/rfc8305
