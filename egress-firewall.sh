#!/bin/bash
# ptero-egress : filtrage sortant des conteneurs Pterodactyl (table nft dédiée,
# indépendante de Docker/ufw).
#  - bloque Tor et les pools de minage (listes tenues à jour par ptero-guard)
#  - plafonne le débit sortant par conteneur (anti-diffusion massive)
# Usage : egress-firewall.sh apply | refresh | remove | status
set -euo pipefail

TABLE="ptero_egress"
BRIDGE="pterodactyl0"
NET4="172.18.0.0/16"
NET6="fdba:17c8:6c94::/64"
STATE="/var/lib/ptero-guard/state.json"
RATE_KBYTES="${PTERO_EGRESS_RATE_KBYTES:-12500}"   # 12500 ko/s = 100 Mbit/s par conteneur
BURST_KBYTES="${PTERO_EGRESS_BURST_KBYTES:-25000}"

lists() {
  # Sort les éléments nft des 4 sets à partir de state.json
  python3 -I - "$STATE" <<'EOF'
import json, sys, ipaddress
d = json.load(open(sys.argv[1]))
for key, name in (("tor_ips", "tor"), ("pool_ips", "pools")):
    v4, v6 = set(), set()
    for ip in d.get(key, []):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        (v4 if a.version == 4 else v6).add(str(a))
    for fam, s in (("4", v4), ("6", v6)):
        print(f"{name}{fam} " + ",".join(sorted(s)))
EOF
}

fill_sets() {
  local f; f=$(mktemp)
  {
    for s in tor4 tor6 pools4 pools6; do echo "flush set inet $TABLE $s"; done
    lists | while read -r name elems; do
      if [ -n "${elems:-}" ]; then echo "add element inet $TABLE $name { $elems }"; fi
    done
  } > "$f"
  nft -f "$f"
  rm -f "$f"
}

apply() {
  [ -r "$STATE" ] || { echo "state.json introuvable ($STATE)"; exit 1; }
  nft list table inet "$TABLE" >/dev/null 2>&1 && nft delete table inet "$TABLE"
  nft -f - <<EOF
table inet $TABLE {
  set tor4   { type ipv4_addr; }
  set tor6   { type ipv6_addr; }
  set pools4 { type ipv4_addr; }
  set pools6 { type ipv6_addr; }
  set rate4  { type ipv4_addr; flags dynamic; timeout 1m; }
  set rate6  { type ipv6_addr; flags dynamic; timeout 1m; }

  chain forward {
    type filter hook forward priority -5; policy accept;
    iifname "$BRIDGE" ip  daddr @tor4   limit rate 5/minute log prefix "ptero-egress tor: "
    iifname "$BRIDGE" ip  daddr @pools4 limit rate 5/minute log prefix "ptero-egress pool: "
    iifname "$BRIDGE" ip  daddr @tor4   counter drop
    iifname "$BRIDGE" ip6 daddr @tor6   counter drop
    iifname "$BRIDGE" ip  daddr @pools4 counter drop
    iifname "$BRIDGE" ip6 daddr @pools6 counter drop
    iifname "$BRIDGE" jump capped
  }

  chain capped {
    oifname "$BRIDGE" return
    ip  saddr $NET4 ip  daddr != $NET4 update @rate4 { ip  saddr limit rate over $RATE_KBYTES kbytes/second burst $BURST_KBYTES kbytes } counter drop
    ip6 saddr $NET6 ip6 daddr != $NET6 update @rate6 { ip6 saddr limit rate over $RATE_KBYTES kbytes/second burst $BURST_KBYTES kbytes } counter drop
  }
}
EOF
  fill_sets
  status
}

status() {
  nft list table inet "$TABLE" >/dev/null 2>&1 || { echo "table $TABLE absente (filtrage inactif)"; return; }
  for s in tor4 tor6 pools4 pools6; do
    n=$(nft -j list set inet "$TABLE" "$s" | python3 -I -c 'import json,sys;d=json.load(sys.stdin);print(sum(len(x["set"].get("elem",[])) for x in d["nftables"] if "set" in x))')
    echo "$s : $n IP"
  done
  echo "plafond : $RATE_KBYTES ko/s par conteneur (burst $BURST_KBYTES ko)"
  nft list chain inet "$TABLE" forward | grep -o 'counter packets [0-9]* bytes [0-9]*' | sed 's/^/  drop /' || true
  nft list chain inet "$TABLE" capped  | grep -o 'counter packets [0-9]* bytes [0-9]*' | sed 's/^/  plafond /' || true
}

case "${1:-}" in
  apply)   apply ;;
  refresh) nft list table inet "$TABLE" >/dev/null 2>&1 && fill_sets || apply ;;
  remove)  nft list table inet "$TABLE" >/dev/null 2>&1 && nft delete table inet "$TABLE"; echo "filtrage sortant retiré" ;;
  status)  status ;;
  *) echo "usage : $0 apply|refresh|remove|status"; exit 2 ;;
esac
