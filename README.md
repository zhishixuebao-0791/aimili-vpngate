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

当前稳定版为 **v1.26.15**：包含IPv6出口能力匹配、OpenVPN服务端证书用途校验，以及conntrack安装调优与回退。详见[更新记录](CHANGELOG.md)。

## 一键部署

在全新的 Linux VPS 上以 `root` 用户执行下面任意一条命令，选择需要的渠道。安装后，`ml update` 只更新该渠道；已有安装不能通过另一条命令串渠道重装。

### 稳定版（v1.26.15）

```bash
AIMILI_CHANNEL=stable bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

### 发行版（v1.26.16）

```bash
AIMILI_CHANNEL=release bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

部署完成后，终端会输出 Web 管理后台地址，格式类似:

```text
http://your_vps_ip:8787/随机安全后缀
```

后续可在服务器终端输入 `ml` 打开交互式管理菜单。

常用终端命令:

```bash
ml status    # 查看状态
ml logs      # 查看实时日志
ml node-log  # 查看节点切换与异常追踪日志
ml update    # 只更新原安装渠道的新版本并重启服务
ml restart   # 重启服务
```

## 首次使用

1. 打开部署完成后输出的 Web 管理后台地址。
2. 首次进入后，系统会自动拉取 VPNGate 候选节点并执行一次真实出口延迟测速排序。
3. 测速未完成前，新节点状态会显示“测试中...”动态效果。
4. 测速结束后，仅保留延迟小于等于当前“延迟筛选阈值”的普通可用节点；默认阈值为 `500ms`，已收藏节点不会因为后续测速失败被自动清理。
5. 默认路由模式为“自动配置”，首次测速排序完成后会立即连接当前批次延迟最低的可用节点。

## 本修改版新增/调整功能

- 真实出口延迟测速: 通过当前 OpenVPN + 本地代理出口检测节点实际延迟，不再只看 VPNGate 原始 ping。
- 首次自动连接: 首次部署或已有缓存但没有活动连接时，会按当前路由模式测速排序，并自动连接符合规则的最低延迟节点。
- 登录触发刷新: 新安装或执行 `ml update` 后，首次进入 Web UI 会触发一次 VPNGate 节点拉取；新旧节点合并后统一测速排序，剔除不可用节点，并按自动配置连接最低延迟节点。
- 更新节点逻辑: 点击“更新节点”会拉取新节点，并与旧节点合并后一起测速排序。
- 终端一键更新: `ml update`只更新原安装渠道，重跑本渠道安装脚本并重启服务。
- 节点活动日志: 新增 `ml node-log` 命令，持续跟踪当前活动节点 IP、节点切换时间、连接失败、巡检超阈值但未切换、后台线程崩溃等信息。
  - 文件路径: `/opt/aimilivpn/vpngate_data/node_activity.log`
  - 主服务日志: `/opt/aimilivpn/vpngate_data/vpngate.log`
  - Web 日志面板 JSON: `/opt/aimilivpn/vpngate_data/logs/YYYY-MM-DD.json`
- 新版本提示: Web UI 登录后会优先检测 GitHub 最新 Release tag，没有 Release 时检测最新 tag；只有仓库发布新 tag 时才提示，不会因为普通 commit 推送而提示。提示每天最多出现一次，文案为“有新的版本发布，可在终端中输入 ml update 命令更新”。
- 高延迟触发刷新: 默认每 30 分钟检测当前已连接节点，只有延迟大于当前阈值才触发新一轮拉取、合并、测速、剔除。
- 可调巡检策略: 在“代理设置”中可选择 5-60 分钟巡检间隔，以及 200-1000ms 延迟筛选阈值；修改后从保存时间重新计时，下次巡检生效。
- 延迟过滤: 延迟大于当前阈值的普通节点会被剔除或标记不可用，默认阈值为 `500ms`。
- 5 秒测速超时: 单个节点测速超过 `5s` 会判定超时，延迟显示 `-1`，普通超时节点会在测速排序后剔除。
- 默认自动配置: 默认会在测速完成后选择最低延迟可用节点，适合首次部署后尽快获得可用出口。
- 旧配置迁移: 如果旧版本保存的是固定 IP 模式但没有锁定具体节点，更新后会自动迁移为自动配置；已经锁定具体节点的固定 IP 配置不会被改动。
- 自动配置模式: 当前连接延迟过高时，会切换到所有可用节点中延迟最低的节点。
- 固定地区模式: 当前连接延迟过高时，会切换到所选国家/地区、所选 IP 类型中延迟最低的节点。
- 固定收藏菜单模式: 当前连接延迟过高时，只在收藏节点中测速排序并切换到最低延迟收藏节点。
- 路由切换即时生效: 在“代理设置”切换自动配置、固定地区、固定 IP 或固定收藏菜单后，会按新模式的节点范围立即测速排序；除固定 IP 外，会切换到该范围内最低延迟可用节点。
- 收藏菜单: 收藏节点后，即使后续延迟变高或不可用，也不会自动移出收藏，只能用户手动取消收藏。
- 拉黑菜单: 支持持久拉黑 IP、搜索、添加、取消拉黑；被拉黑 IP 即使重新测速通过也保持不可用。
- 拉黑保护: 如果意外连接到拉黑 IP，会立即断开并切换到当前列表中最低延迟的非拉黑可用节点。
- 风险值列: 原第三方纯净度/API 风险过滤逻辑已停用，前端风险值固定显示 `60%`。
- UI 增强: 增加延迟、风险值、物理位置、ASN、运营主体/ISP、网络质量、IP 类型等列。
- 去广告: 已移除右侧 VPS 购买推荐广告。

## 路由模式说明

- 自动配置: 默认模式。首次测速、手动更新、模式切换或当前已连接节点延迟大于当前阈值时，会选择全局最低延迟可用节点。
- 固定 IP: 锁定当前手动选择的节点，不会因为当前节点不可用而自动切换，但仍会定期测速并刷新候选节点列表。
- 固定地区: 只在指定国家/地区和 IP 类型范围内测速排序，并选择最低延迟节点。
- 固定收藏菜单: 只在收藏节点中测速排序并选择最低延迟节点；如果收藏节点全部不可用，是否回退到非收藏节点由收藏管理面板选项决定。

### 渠道隔离

- 稳定版只能自动更新到新的稳定版；发行版只能自动更新到新的发行版。首次安装默认稳定版；首次选择发行版可设置 `AIMILI_CHANNEL=release`。已有安装拒绝利用该变量或另一渠道标签串渠道重装。
- 本机渠道记录位于 `vpngate_data/update_channel.json`，代码同时带有 `APP_CHANNEL`。远端 `release_channels.json` 为两渠道分别指定版本，不以全局最大版本号判断渠道。
- 旧ml可能先把源码重置到main；新安装脚本通过ORIG_HEAD/reflog识别更新前的渠道，在生成服务/启动程序前恢复到本渠道目标。若记录不明、清单缺失或目标渠道不符，会停止，能确认旧提交时会恢复旧源码，不静默转到main。
- 本次稳定版使用v1.26.15、发行版使用v1.26.16，因为v1.26.10等旧标签已发布，不可覆盖。渠道由元数据确定，与版本号数字大小无关。
- 本地开发标记`.local_dev`会暂停自动更新/重装，保护当前代码；不会成为绕过渠道校验的入口。
- 未修改已发布旧标签；旧版本未知来源且缺少可识别版本或Git更新记录时，不能保证自动识别，会明确停止。

## 网络调优与回退

安装脚本会自动配置 conntrack：连接表上限至少 `65536`，哈希桶至少 `16384`，已建立 TCP 条目超时最多 `7200` 秒。已有更大容量或更短超时会保留。仅对回环网卡 `lo` 添加双向 NOTRACK；已有规则不会重复添加，支持 systemd 和 OpenRC 开机应用。模块无法加载、参数只读或 raw 表不可用时会明确提示，不会清空防火墙或连接表。

安装前的配置和运行时值保存在 `/var/lib/aimilivpn-network/`。需要回退时执行：

```bash
python3 /opt/aimilivpn/conntrack_tuning.py rollback
```

回退只移除本程序标记的规则，恢复安装前文件及仍保持本程序设置值的运行时参数；遇到安装后被另行修改的配置会停止并提示核对。`ml uninstall` 会先执行该回退。首次安装若要跳过调优，在运行安装脚本前设置 `AIMILI_CONNTRACK_TUNING=0`；该开关不会撤销已经生效的设置。

代理会按 VPNGate 隧道实际能力选择 IPv4/IPv6；没有 IPv6 出口时拒绝 IPv6-only 目标，不会绕到 VPS 直连。OpenVPN 主连接和探测均要求服务端证书用途（`remote-cert-tls server`），保留 CA 验证；不支持该用途校验的节点不能通过探测。

参数参考：[Linux conntrack 文档](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)、[OpenRC 服务指南](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md)、[OpenVPN 手册](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)。

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
ml update
```

也可以手动执行:

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

Choose one command and run it as `root` on a fresh Linux VPS. Later updates stay on the selected channel.

### Stable (v1.26.15)

```bash
AIMILI_CHANNEL=stable bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

### Release (v1.26.16)

```bash
AIMILI_CHANNEL=release bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

After installation, open the printed Web UI URL. You can run `ml` on the server to open the CLI management menu.

Useful commands:

```bash
ml status
ml logs
ml node-log
ml update
ml restart
```

## Key Differences From The Original Project

- Real egress latency testing through the active OpenVPN/local proxy path.
- First-login automatic benchmark, sorting, and connection to the lowest-latency eligible node.
- After a fresh install or `ml update`, the first Web UI login triggers a VPNGate refresh; old and new nodes are benchmarked together, unavailable nodes are pruned, and the lowest-latency node is connected in automatic mode.
- Added `ml update` for pulling the latest GitHub code, rerunning the installer, and restarting the service.
- Added `ml node-log` for tailing persistent node activity logs, including active node IP, switch time, switch failures, threshold stalls, and background thread crashes.
- The Web UI reads the channel manifest and advertises updates only within its own channel.
- Manual refresh merges old and new VPNGate candidates, then benchmarks and sorts them together.
- Nodes above the configured latency threshold are marked unavailable or pruned, while favorites are preserved. The default threshold is `500ms`.
- The active-node health-check interval and latency threshold are configurable in the proxy settings. Defaults are 30 minutes and `500ms`.
- Per-node benchmark timeout is `5s`; timed-out regular nodes are shown as `-1` and pruned after sorting.
- Default route mode is automatic configuration.
- Legacy configs saved as fixed IP without a locked node are migrated to automatic configuration; fixed IP configs with a locked node are preserved.
- Route mode changes immediately trigger scoped benchmarking and, except fixed IP mode, switch to the lowest-latency eligible node.
- Added fixed region and fixed favorites failover logic.
- Added persistent IP blacklist management.
- Added favorite/blacklist UI rules.
- Disabled third-party risk/purity filtering; risk is shown as fixed `60%`.
- Added UI columns for latency, risk, location, ASN, ISP, network quality, and IP type.
- Removed the VPS recommendation ad.

## Ports

- Web UI: `8787`, needs firewall/security-group access.
- Local proxy: `7928`, binds to `127.0.0.1` by default and should not be exposed publicly unless you understand the risk.
