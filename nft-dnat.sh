#!/usr/bin/env bash
# nft-dnat.sh — Dynamic DNAT/NAT manager using nftables (native), IPv4/IPv6, protocol-aware, interactive
# - Uses nft (tables: nat, families ip/ip6) with atomic batch apply (nft -f)
# - Own chains only; hooks: prerouting/postrouting with proper priorities (dstnat/srcnat)
# - Config file compatible with iptables variant: /etc/dnat/conf lines like "8443/all>example.com:443"
# - Protocol selectable: tcp|udp|all
# - Port occupancy checks (menu) using ss
# - Systemd service installer or cron @reboot fallback

set -Eeuo pipefail

BASE_DIR=/etc/dnat
CONF_FILE="$BASE_DIR/conf"
RUNTIME_DIR="$BASE_DIR/runtime"
LOG_TAG="nft-dnat"

# rule files for atomic load
RULES4="$RUNTIME_DIR/nft_rules.ip"
RULES6="$RUNTIME_DIR/nft_rules.ip6"
HASH4="$RUNTIME_DIR/nft_rules.ip.sha256"
HASH6="$RUNTIME_DIR/nft_rules.ip6.sha256"

INTERVAL="${INTERVAL:-60}"
PM_CACHED=""

log(){ echo "[$(date '+%F %T')] [$LOG_TAG] $*"; }
die(){ echo "[$(date '+%F %T')] [$LOG_TAG][ERR] $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1; }

detect_pm() {
  if [[ -n "$PM_CACHED" ]]; then echo "$PM_CACHED"; return; fi
  if   need apt-get;  then PM_CACHED=apt
  elif need dnf;      then PM_CACHED=dnf
  elif need yum;      then PM_CACHED=yum
  elif need zypper;   then PM_CACHED=zypper
  elif need pacman;   then PM_CACHED=pacman
  elif need apk;      then PM_CACHED=apk
  else PM_CACHED=unknown; fi
  echo "$PM_CACHED"
}

pm_install() {
  local pm; pm="$(detect_pm)"
  case "$pm" in
    apt)    export DEBIAN_FRONTEND=noninteractive; apt-get update -qq || true; apt-get install -y -qq "$@" ;;
    dnf)    dnf install -y -q "$@" ;;
    yum)    yum install -y -q "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
    pacman) pacman -Sy --noconfirm "$@" ;;
    apk)    apk add --no-cache "$@" ;;
    *) die "未识别的包管理器，请手动安装：$*";;
  esac
}

ensure_deps() {
  need nft || pm_install nftables || true
  need ip || pm_install iproute2 || pm_install iproute || true
  need ss || true
  need dig || need host || pm_install dnsutils || pm_install bind-utils || true
  need awk || pm_install gawk || pm_install awk || true
  need sed || pm_install sed || true
  need grep || pm_install grep || true
  need sha256sum || pm_install coreutils || pm_install busybox || true
  need nft || die "缺少 nft (nftables)"
}

ensure_dirs(){
  mkdir -p "$BASE_DIR" "$RUNTIME_DIR"
  [[ -f "$CONF_FILE" ]] || : > "$CONF_FILE"
}

# validators
valid_port(){ [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((1<=10#$1 && 10#$1<=65535)); }
is_ipv4(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6(){ [[ "$1" =~ ^([0-9A-Fa-f:]+:+)+[0-9A-Fa-f]+$ ]]; }
valid_proto(){ case "$1" in tcp|udp|all) return 0;; *) return 1;; esac; }
valid_host(){
  is_ipv4 "$1" && return 0
  is_ipv6 "$1" && return 0
  [[ "$1" =~ ^([A-Za-z0-9]([-A-Za-z0-9]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

resolve_a(){
  local h="$1" ip4=""
  if need dig; then ip4="$(dig +time=2 +tries=1 +short A "$h" | grep -E '^[0-9.]+$' | head -n1 || true)"; fi
  [[ -z "$ip4" && $(command -v host) ]] && ip4="$(host -t a "$h" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1 || true)"
  [[ -z "$ip4" && $(command -v getent) ]] && ip4="$(getent ahostsv4 "$h" | awk '{print $1}' | head -n1 || true)"
  echo "$ip4"
}
resolve_aaaa(){
  local h="$1" ip6=""
  if need dig; then ip6="$(dig +time=2 +tries=1 +short AAAA "$h" | head -n1 || true)"; fi
  [[ -z "$ip6" && $(command -v host) ]] && ip6="$(host -t aaaa "$h" 2>/dev/null | awk '{print $NF}' | head -n1 || true)"
  [[ -z "$ip6" && $(command -v getent) ]] && ip6="$(getent ahostsv6 "$h" | awk '{print $1}' | head -n1 || true)"
  echo "$ip6"
}

get_main_ipv4(){
  local ip4
  ip4="$(ip -o -4 addr show | grep -Ev '\s(lo|docker|podman|cni|veth)' \
     | awk '{print $4}' | cut -d/ -f1 \
     | grep -Ev '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' | head -n1 || true)"
  [[ -z "$ip4" ]] && ip4="$(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
  echo "$ip4"
}
get_main_ipv6(){
  ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true
}

enable_forward(){
  if [[ -d /etc/sysctl.d ]]; then
    {
      echo "net.ipv4.ip_forward=1"
      echo "net.ipv6.conf.all.forwarding=1"
    } > /etc/sysctl.d/99-dnat-ipforward.conf
    sysctl --system >/dev/null || true
  else
    sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || true
  fi
}

sha(){ sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
port_in_use_tcp(){ need ss && ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q .; }
port_in_use_udp(){ need ss && ss -lunH "( sport = :$1 )" 2>/dev/null | grep -q .; }

emit_rule_v4(){
  local proto="$1" lp="$2" rip="$3" rp="$4"
  case "$proto" in
    tcp) echo "add rule ip nat prerouting tcp dport $lp dnat to $rip:$rp"
         echo "add rule ip nat postrouting ip daddr $rip tcp dport $rp snat to $LOCAL4" ;;
    udp) echo "add rule ip nat prerouting udp dport $lp dnat to $rip:$rp"
         echo "add rule ip nat postrouting ip daddr $rip udp dport $rp snat to $LOCAL4" ;;
    all) emit_rule_v4 tcp "$lp" "$rip" "$rp"; emit_rule_v4 udp "$lp" "$rip" "$rp" ;;
  esac
}
emit_rule_v6(){
  local proto="$1" lp="$2" rip6="$3" rp="$4"
  case "$proto" in
    tcp) echo "add rule ip6 nat prerouting tcp dport $lp dnat to [$rip6]:$rp"
         echo "add rule ip6 nat postrouting ip6 daddr $rip6 tcp dport $rp snat to $LOCAL6" ;;
    udp) echo "add rule ip6 nat prerouting udp dport $lp dnat to [$rip6]:$rp"
         echo "add rule ip6 nat postrouting ip6 daddr $rip6 udp dport $rp snat to $LOCAL6" ;;
    all) emit_rule_v6 tcp "$lp" "$rip6" "$rp"; emit_rule_v6 udp "$lp" "$rip6" "$rp" ;;
  esac
}

build_rules_v4(){
  local tmp="$RULES4.tmp"
  : > "$tmp"
  {
    echo "flush table ip nat"
    echo "add table ip nat"
    echo "add chain ip nat prerouting { type nat hook prerouting priority dstnat; }"
    echo "add chain ip nat postrouting { type nat hook postrouting priority srcnat; }"
  } >> "$tmp"

  while IFS= read -r raw || [[ -n "$raw" ]]; do
    local line proto lp host rp rip
    line="$(echo "$raw" | tr -d '\r' | sed 's/#.*$//' | xargs || true)"
    [[ -z "$line" ]] && continue
    proto="$(echo "$line" | awk -F'[> /]' '{print $1}' | awk -F'/' '{print $2}')"
    lp="$(echo "$line" | awk -F'[>/: ]' '{print $1}')"
    host="$(echo "$line" | awk -F'[>: ]' '{print $2}' | sed 's|/||g')"
    rp="$(echo "$line" | awk -F'[>: ]' '{print $3}')"
    valid_port "$lp" && valid_port "$rp" || { log "忽略无效端口：$line"; continue; }
    valid_proto "${proto:-all}" || proto="all"
    valid_host "$host" || { log "忽略无效主机：$line"; continue; }
    if is_ipv4 "$host"; then rip="$host"; else rip="$(resolve_a "$host")"; fi
    [[ -z "$rip" ]] && { log "解析失败(IPv4)：$host（跳过）"; continue; }
    emit_rule_v4 "$proto" "$lp" "$rip" "$rp" >> "$tmp"
  done < "$CONF_FILE"

  mv -f "$tmp" "$RULES4"
}

build_rules_v6(){
  local tmp="$RULES6.tmp"
  : > "$tmp"
  {
    echo "flush table ip6 nat"
    echo "add table ip6 nat"
    echo "add chain ip6 nat prerouting { type nat hook prerouting priority dstnat; }"
    echo "add chain ip6 nat postrouting { type nat hook postrouting priority srcnat; }"
  } >> "$tmp"

  while IFS= read -r raw || [[ -n "$raw" ]]; do
    local line proto lp host rp rip6
    line="$(echo "$raw" | tr -d '\r' | sed 's/#.*$//' | xargs || true)"
    [[ -z "$line" ]] && continue
    proto="$(echo "$line" | awk -F'[> /]' '{print $1}' | awk -F'/' '{print $2}')"
    lp="$(echo "$line" | awk -F'[>/: ]' '{print $1}')"
    host="$(echo "$line" | awk -F'[>: ]' '{print $2}' | sed 's|/||g')"
    rp="$(echo "$line" | awk -F'[>: ]' '{print $3}')"
    valid_port "$lp" && valid_port "$rp" || { log "忽略无效端口：$line"; continue; }
    valid_proto "${proto:-all}" || proto="all"
    valid_host "$host" || { log "忽略无效主机：$line"; continue; }
    if is_ipv6 "$host"; then rip6="$host"; else rip6="$(resolve_aaaa "$host")"; fi
    [[ -z "$rip6" ]] && continue
    emit_rule_v6 "$proto" "$lp" "$rip6" "$rp" >> "$tmp"
  done < "$CONF_FILE"

  mv -f "$tmp" "$RULES6"
}

apply_if_changed(){
  LOCAL4="$(get_main_ipv4 || true)"
  LOCAL6="$(get_main_ipv6 || true)"
  local changed=0

  if [[ -n "${LOCAL4:-}" ]]; then
    build_rules_v4
    local nh4 oh4
    nh4="$(sha "$RULES4" || true)"
    oh4="$(cat "$HASH4" 2>/dev/null || true)"
    if [[ "$nh4" != "$oh4" ]]; then
      log "应用 IPv4 nft 规则..."
      nft -f "$RULES4"
      echo "$nh4" > "$HASH4"
      changed=1
    fi
  fi

  if [[ -n "${LOCAL6:-}" ]]; then
    build_rules_v6
    local nh6 oh6
    nh6="$(sha "$RULES6" || true)"
    oh6="$(cat "$HASH6" 2>/dev/null || true)"
    if [[ "$nh6" != "$oh6" ]]; then
      log "应用 IPv6 nft 规则..."
      nft -f "$RULES6"
      echo "$nh6" > "$HASH6"
      changed=1
    fi
  fi

  if [[ "$changed" -eq 0 ]]; then
    log "规则未变更。"
  else
    log "当前表："
    nft list table ip nat   2>/dev/null || true
    nft list table ip6 nat  2>/dev/null || true
  fi
}

cfg_add_line(){ sed -i "/^${1}\\//d" "$CONF_FILE"; echo "${1}/${2}>${3}:${4}" >> "$CONF_FILE"; }
cfg_del_line(){ sed -i "/^${1}\\//d" "$CONF_FILE"; }

cmd_add(){
  local force=0
  if [[ "${1:-}" == "--force" ]]; then force=1; shift; fi
  [[ $# -ne 4 ]] && die "用法: $0 add [--force] <localPort> <proto:tcp|udp|all> <host> <remotePort>"
  local lp="$1" proto="$2" host="$3" rp="$4"
  valid_port "$lp" && valid_port "$rp" && valid_proto "$proto" && valid_host "$host" || die "参数不合法"
  if [[ "$force" -ne 1 ]]; then
    case "$proto" in
      tcp|all) port_in_use_tcp "$lp" && die "TCP 端口 $lp 已被占用。可用 --force 忽略或换端口。";;
    esac
    case "$proto" in
      udp|all) port_in_use_udp "$lp" && die "UDP 端口 $lp 已被占用。可用 --force 忽略或换端口。";;
    esac
  fi
  cfg_add_line "$lp" "$proto" "$host" "$rp"
  log "已添加：$lp/$proto>$host:$rp"
}

cmd_del(){ [[ $# -ne 1 ]] && die "用法: $0 del <localPort>"; valid_port "$1" || die "端口不合法"; cfg_del_line "$1"; log "已删除端口 $1 的规则"; }
cmd_list(){ [[ -s "$CONF_FILE" ]] && awk '{print "规则：", $0}' "$CONF_FILE" || echo "(空)"; }
cmd_apply(){ ensure_deps; ensure_dirs; enable_forward; apply_if_changed; }
cmd_daemon(){ ensure_deps; ensure_dirs; enable_forward; while true; do apply_if_changed || true; sleep "$INTERVAL"; done; }

cmd_menu(){
  ensure_deps; ensure_dirs
  while true; do
    echo
    echo "==== nft DNAT 管理菜单（IPv4/IPv6, 协议可选）===="
    echo "1) 添加/更新 转发规则"
    echo "2) 删除 转发规则"
    echo "3) 列出 所有规则"
    echo "4) 立即应用（原子下发）"
    echo "5) 查看当前 nat 表"
    echo "q) 退出"
    read -rp "请选择: " ans
    case "$ans" in
      1)
        local lp host rp proto opt
        while true; do
          read -rp "本地端口: " lp
          valid_port "$lp" || { echo "端口无效。"; continue; }
          echo "选择协议: 1) tcp  2) udp  3) all"
          read -rp "输入 1/2/3: " opt
          case "$opt" in
            1) proto="tcp";;
            2) proto="udp";;
            3) proto="all";;
            *) echo "选择无效。"; continue;;
          esac
          if [[ "$proto" == "tcp" || "$proto" == "all" ]]; then
            if port_in_use_tcp "$lp"; then
              echo "提示：TCP 端口 $lp 已被占用。"
              read -rp "是否更换端口？(y/n) " yn
              [[ "$yn" =~ ^[Yy]$ ]] && continue
            fi
          fi
          if [[ "$proto" == "udp" || "$proto" == "all" ]]; then
            if port_in_use_udp "$lp"; then
              echo "提示：UDP 端口 $lp 已被占用。"
              read -rp "是否更换端口？(y/n) " yn
              [[ "$yn" =~ ^[Yy]$ ]] && continue
            fi
          fi
          break
        done
        read -rp "目标域名或IP(支持 IPv4/IPv6): " host
        valid_host "$host" || { echo "主机无效。"; continue; }
        read -rp "目标端口: " rp
        valid_port "$rp" || { echo "目标端口无效。"; continue; }
        cfg_add_line "$lp" "$proto" "$host" "$rp"
        echo "已保存：$lp/$proto>$host:$rp"
        ;;
      2)
        read -rp "要删除的本地端口: " lp
        valid_port "$lp" || { echo "端口无效。"; continue; }
        cfg_del_line "$lp"
        echo "已删除本地端口 $lp 的规则"
        ;;
      3) cmd_list ;;
      4) cmd_apply ;;
      5) nft list table ip nat 2>/dev/null || echo "(无 ip nat 表)"; nft list table ip6 nat 2>/dev/null || echo "(无 ip6 nat 表)";;
      q|Q) break ;;
      *) echo "无效选择" ;;
    esac
  done
}

cmd_install_service(){
  ensure_deps; ensure_dirs
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files >/dev/null 2>&1; then
    cat > /etc/systemd/system/nft-dnat.service <<'UNIT'
[Unit]
Description=Dynamic DNAT/NAT updater (nftables, IPv4/IPv6, protocol-aware)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=INTERVAL=60
ExecStart=/usr/local/bin/nft-dnat.sh daemon
Restart=always
RestartSec=15
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
SystemCallFilter=@system-service @network-io
UNIT
    systemctl daemon-reload
    systemctl enable --now nft-dnat.service
    log "已安装并启动 systemd 服务：nft-dnat.service"
  else
    need crontab || pm_install cron cronie cronie-noanacron || true
    ( crontab -l 2>/dev/null | grep -v 'nft-dnat.sh daemon' ; echo "@reboot /usr/local/bin/nft-dnat.sh daemon >> /var/log/nft-dnat.log 2>&1" ) | crontab -
    log "无 systemd，已配置 cron @reboot（日志：/var/log/nft-dnat.log）"
  fi
}

usage(){
  cat <<U
用法：$0 <subcommand>
  add [--force] <localPort> <proto:tcp|udp|all> <host> <remotePort>
  del <localPort>
  list
  apply
  daemon
  menu
  install-service         安装守护（优先 systemd，否则 cron @reboot）
说明：
  - 配置文件：$CONF_FILE ，每行格式：<本地端口>/<协议>><目标主机>:<目标端口>
  - 协议：tcp|udp|all（默认 all）
  - menu 模式会检查端口占用并提示更换；CLI 模式可用 --force 跳过占用检查
U
}

main(){
  case "${1:-}" in
    add) shift; cmd_add "$@";;
    del) shift; cmd_del "$@";;
    list) shift; cmd_list;;
    apply) shift; cmd_apply;;
    daemon) shift; cmd_daemon;;
    menu) shift; cmd_menu;;
    install-service) shift; cmd_install_service;;
    ""|-h|--help) usage;;
    *) die "未知子命令：$1（使用 -h 查看帮助）";;
  esac
}
main "$@"
