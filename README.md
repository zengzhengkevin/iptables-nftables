# Dynamic DNAT/NAT — iptables & nftables (IPv4/IPv6, protocol-aware, interactive)

本包同时提供：
- **`dnat-iptables.sh`**：基于 iptables/ip6tables 的实现（兼容性最好，适合老系统）。  
- **`nft-dnat.sh`**：原生 nftables 实现（现代系统推荐，语法统一，性能更优）。

两者共用同一配置文件：`/etc/dnat/conf`，每行：

```
<本地端口>/<协议>><目标主机>:<目标端口>
```

例：
```
8443/all>example.com:443
60080/tcp>1.2.3.4:80
60053/udp>2001:db8::1:53
```

> 目标主机可为域名、IPv4 或 IPv6。域名将解析 A/AAAA 并分别对 IPv4/IPv6 生成规则；仅当解析到相应族地址时才下发。

## 安装

### iptables 版本
```bash
sudo install -m 0755 dnat-iptables.sh /usr/local/bin/dnat.sh
sudo /usr/local/bin/dnat.sh install-service
```

### nftables 版本
```bash
sudo install -m 0755 nft-dnat.sh /usr/local/bin/nft-dnat.sh
sudo /usr/local/bin/nft-dnat.sh install-service
```

## 使用
两版均支持：
```bash
# 添加/更新（带端口占用检查；CLI 可 --force）
sudo dnat.sh add [--force] <localPort> <proto:tcp|udp|all> <host> <remotePort>

# 删除
sudo dnat.sh del <localPort>

# 查看
dnat.sh list

# 立即应用（原子下发）
sudo dnat.sh apply

# 交互式菜单
sudo dnat.sh menu
```

> nft 版本的命令名如果按上面的安装方式则是 `nft-dnat.sh`。

## 选择建议
- **优先 nftables**（`nft-dnat.sh`）：Debian 11+/12、Ubuntu 20.04+/22.04+、CentOS/Rocky 8/9 等现代系统。  
- **使用 iptables**（`dnat-iptables.sh`）：旧系统或你已有大量 iptables 流程/脚本需要无缝接入。

## 原理要点
- **自有链 / 自有表**：不破坏系统原有规则。
  - iptables: 使用 `DNAT_DYN/SNAT_DYN`（及 v6 对应）并从 PREROUTING/POSTROUTING 跳转。
  - nftables: 创建 `table ip nat`/`table ip6 nat` 并在 hooks `prerouting/postrouting` 注入规则（priority 为 `dstnat/srcnat`）。
- **原子更新**：
  - iptables：`iptables-restore`/`ip6tables-restore`
  - nftables：`nft -f` 批量加载
- **端口占用检查**：借助 `ss` 检测 TCP/UDP 占用；交互式菜单提示更换，CLI 可 `--force` 跳过。

## 卸载
```bash
# iptables 版
sudo systemctl disable --now dnat 2>/dev/null || true
sudo rm -f /etc/systemd/system/dnat.service /usr/local/bin/dnat.sh

# nftables 版
sudo systemctl disable --now nft-dnat 2>/dev/null || true
sudo rm -f /etc/systemd/system/nft-dnat.service /usr/local/bin/nft-dnat.sh

# 通用
( crontab -l 2>/dev/null | grep -v 'dnat.sh daemon' ) | crontab - || true
( crontab -l 2>/dev/null | grep -v 'nft-dnat.sh daemon' ) | crontab - || true
sudo rm -rf /etc/dnat
sudo systemctl daemon-reload 2>/dev/null || true
```

## 许可证
MIT
