#!/bin/bash
# Источник: https://github.com/amnezia-vpn/amnezia-client, коммит f0b12257ab5c42730f2dd264fc403aeb98ee1e45
# client/server_scripts/setup_host_firewall.sh — без изменений, кроме sudo (скрипт выполняется
# от root в одноразовом привилегированном контейнере с --net host)
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

#iptables -P FORWARD ACCEPT
iptables -C FORWARD -j DOCKER-USER || iptables -A FORWARD -j DOCKER-USER
iptables -C FORWARD -j DOCKER-ISOLATION-STAGE-1 || iptables -A FORWARD -j DOCKER-ISOLATION-STAGE-1; \
iptables -C FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || iptables -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; \
iptables -C FORWARD -o docker0 -j DOCKER || iptables -A FORWARD -o docker0 -j DOCKER; \
iptables -C FORWARD -i docker0 ! -o docker0 -j ACCEPT || iptables -A FORWARD -i docker0 ! -o docker0 -j ACCEPT; \
iptables -C FORWARD -i docker0 -o docker0 -j ACCEPT || iptables -A FORWARD -i docker0 -o docker0 -j ACCEPT

# Tuning network
# Telegram proxies (mtproxy/telemt/tproxy) each open hundreds of middle-proxy
# connections; the default nf_conntrack_max (often 8192) overflows and new
# connections get dropped, so raise it.
sysctl -w net.netfilter.nf_conntrack_max=262144 2>/dev/null || true; \
sysctl fs.file-max=51200; \
sysctl net.core.rmem_max=67108864; \
sysctl net.core.wmem_max=67108864; \
sysctl net.core.netdev_max_backlog=250000; \
sysctl net.core.somaxconn=4096; \
sysctl net.ipv4.tcp_syncookies=1; \
sysctl net.ipv4.tcp_tw_reuse=1; \
sysctl net.ipv4.tcp_tw_recycle=0; \
sysctl net.ipv4.tcp_fin_timeout=30; \
sysctl net.ipv4.tcp_keepalive_time=1200; \
sysctl net.ipv4.ip_local_port_range="10000 65000"; \
sysctl net.ipv4.tcp_max_syn_backlog=8192; \
sysctl net.ipv4.tcp_max_tw_buckets=5000; \
sysctl net.ipv4.tcp_fastopen=3; \
sysctl net.ipv4.tcp_mem="25600 51200 102400"; \
sysctl net.ipv4.tcp_rmem="4096 87380 67108864"; \
sysctl net.ipv4.tcp_wmem="4096 65536 67108864"; \
sysctl net.ipv4.tcp_mtu_probing=1; \
sysctl net.ipv4.tcp_congestion_control=hybla

# cover CVE-2026-98432
v=$(uname -r); v=${v%%-*}
case $v in
  5.10.*) fix=5.10.272 ;;
  6.1.*)  fix=6.1.190  ;;
  6.6.*)  fix=6.6.159  ;;
  6.12.*) fix=6.12.113 ;;
  6.18.*) fix=6.18.56  ;;
  7.2.*)  fix=7.2.10   ;;
  *)      fix=7.3      ;;
esac

le() { printf '%s\n' "$1" "$2" | sort -V -C; }
if le 4.4 "$v" && ! le "$fix" "$v"; then
  R=(-p tcp -m u32 --u32 "0>>24&0xF=6:15" -j DROP -m comment --comment cve-2026-98432)
  iptables -t raw -C PREROUTING "${R[@]}" 2>/dev/null || iptables -t raw -I PREROUTING "${R[@]}"
fi
