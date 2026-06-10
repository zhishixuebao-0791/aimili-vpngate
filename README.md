# AimiliVPN 节点管理系统

Bilingual: [中文](#中文) | [English](#english)

---

<a name="中文"></a>
## 中文

本仓库是 AimiliVPN / aimili-vpngate 的修改版，基于 VPNGate 免费节点构建 OpenVPN 出站连接，并提供 Web UI、HTTP/SOCKS5 本地代理网关、节点测速、收藏、拉黑和自动切换能力。

## 项目来源

- 源项目地址: <https://github.com/baoweise-bot/aimili-vpngate>
- 当前修改版仓库: <https://github.com/zhishixuebao-0791/aimili-vpngate>

本修改版保留源项目的部署脚本、OpenVPN 连接管理、Web 管理界面和本地代理网关能力，并围绕“真实出口延迟排序、低延迟节点保留、收藏/拉黑状态机、固定路由策略”做了定制。

## 一键部署

在全新的 Linux VPS 上以 `root` 用户执行:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

部署完成后，终端会输出 Web 管理后台地址，格式类似:

```text
http://your_vps_ip:8787/随机安全后缀
```

后续可在服务器终端输入 `ml` 打开交互式管理菜单。

## 首次使用

1. 打开部署完成后输出的 Web 管理后台地址。
2. 首次进入后，系统会自动拉取 VPNGate 候选节点并执行一次真实出口延迟测速排序。
3. 测速未完成前，新节点状态会显示“测试中...”动态效果。
4. 测速结束后，仅保留延迟小于等于 `500ms` 的普通可用节点；已收藏节点不会因为后续测速失败被自动清理。
5. 默认路由模式为“固定 IP”，手动切换节点后不会自动漂移到其他节点。

## 本修改版新增/调整功能

- 真实出口延迟测速: 通过当前 OpenVPN + 本地代理出口检测节点实际延迟，不再只看 VPNGate 原始 ping。
- 更新节点逻辑: 点击“更新节点”会拉取新节点，并与旧节点合并后一起测速排序。
- 高延迟触发刷新: 每 30 分钟检测当前已连接节点，只有延迟大于 `500ms` 才触发新一轮拉取、合并、测速、剔除。
- 延迟过滤: 延迟大于 `500ms` 的普通节点会被剔除或标记不可用。
- 默认固定 IP: 默认不自动切换，适合需要稳定出口 IP 的使用场景。
- 自动配置模式: 当前连接延迟过高时，会切换到所有可用节点中延迟最低的节点。
- 固定地区模式: 当前连接延迟过高时，会切换到所选国家/地区、所选 IP 类型中延迟最低的节点。
- 固定收藏菜单模式: 当前连接延迟过高时，只在收藏节点中测速排序并切换到最低延迟收藏节点。
- 收藏菜单: 收藏节点后，即使后续延迟变高或不可用，也不会自动移出收藏，只能用户手动取消收藏。
- 拉黑菜单: 支持持久拉黑 IP、搜索、添加、取消拉黑；被拉黑 IP 即使重新测速通过也保持不可用。
- 拉黑保护: 如果意外连接到拉黑 IP，会立即断开并切换到当前列表中最低延迟的非拉黑可用节点。
- 风险值列: 原第三方纯净度/API 风险过滤逻辑已停用，前端风险值固定显示 `60%`。
- UI 增强: 增加延迟、风险值、物理位置、ASN、运营主体/ISP、网络质量、IP 类型等列。
- 去广告: 已移除右侧 VPS 购买推荐广告。

## 路由模式说明

- 固定 IP: 默认模式。不会因为当前节点不可用而自动切换，但仍会定期测速并刷新候选节点列表。
- 自动配置: 当前已连接节点延迟大于 `500ms` 时，合并新旧节点测速，并切到全局最低延迟可用节点。
- 固定地区: 当前已连接节点延迟大于 `500ms` 时，只在指定国家/地区和 IP 类型范围内选择最低延迟节点。
- 固定收藏菜单: 当前已连接节点延迟大于 `500ms` 时，只在收藏节点中选择最低延迟节点。

## 端口与安全

- Web 管理端口默认是 `8787`，需要在服务器防火墙和云厂商安全组中放行。
- 本地代理端口默认是 `7928`，默认只绑定 `127.0.0.1`，只供 VPS 本机使用，通常不需要也不建议对公网开放。
- 如确实需要让其他设备访问代理端口，请自行评估风险，并通过环境变量调整 `LOCAL_PROXY_HOST` 后重启服务。

常见防火墙命令:

```bash
ufw allow 8787/tcp
```

CentOS / RHEL:

```bash
firewall-cmd --zone=public --add-port=8787/tcp --permanent
firewall-cmd --reload
```

## 更新服务器上的修改版

如果已经通过本仓库部署到 `/opt/aimilivpn`，可在服务器执行:

```bash
cd /opt/aimilivpn
git pull origin main
python3 -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py
systemctl restart aimilivpn.service
systemctl status aimilivpn.service --no-pager
```

如果系统不是 systemd，请使用安装脚本提供的 `ml` 菜单进行服务管理。

## 常见问题

### `Cannot allocate tun` 或 `Cannot open tun/tap dev`

VPS 没有启用 TUN/TAP。请在 VPS 控制面板开启 TUN/TAP，或联系服务商开启。

### Web 管理后台打不开

优先检查:

- 服务是否运行: `systemctl status aimilivpn.service --no-pager`
- 监听端口是否存在: `ss -lntp | grep 8787`
- 服务器防火墙是否放行 `8787/tcp`
- 云厂商安全组是否放行 `8787/tcp`

### 代理端口 `7928` 外部访问不了

这是默认安全策略。`7928` 默认只监听 `127.0.0.1`，用于服务器本机程序通过代理出站。

---

<a name="english"></a>
## English

This repository is a modified version of AimiliVPN / aimili-vpngate.

- Original project: <https://github.com/baoweise-bot/aimili-vpngate>
- Modified version: <https://github.com/zhishixuebao-0791/aimili-vpngate>

## One-Click Installation

Run as `root` on a fresh Linux VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

After installation, open the printed Web UI URL. You can run `ml` on the server to open the CLI management menu.

## Key Differences From The Original Project

- Real egress latency testing through the active OpenVPN/local proxy path.
- First-login automatic benchmark and sorting.
- Manual refresh merges old and new VPNGate candidates, then benchmarks and sorts them together.
- Nodes above `500ms` are marked unavailable or pruned, while favorites are preserved.
- Default route mode is fixed IP.
- Added fixed region and fixed favorites failover logic.
- Added persistent IP blacklist management.
- Added favorite/blacklist UI rules.
- Disabled third-party risk/purity filtering; risk is shown as fixed `60%`.
- Added UI columns for latency, risk, location, ASN, ISP, network quality, and IP type.
- Removed the VPS recommendation ad.

## Ports

- Web UI: `8787`, needs firewall/security-group access.
- Local proxy: `7928`, binds to `127.0.0.1` by default and should not be exposed publicly unless you understand the risk.
