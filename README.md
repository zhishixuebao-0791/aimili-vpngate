# AimiliVPN 节点管理系统

[中文](#中文) · [English](#english) · [一键部署](#一键部署) · [路由模式](#路由模式说明) · [运维工具](ops/README.md) · [更新记录](CHANGELOG.md)

---

<a name="中文"></a>
## 中文

本仓库是 AimiliVPN / aimili-vpngate 的修改版，基于 VPNGate 免费节点构建 OpenVPN 出站连接，并提供 Web UI、HTTP/SOCKS5 本地代理网关、节点测速、收藏、拉黑和自动切换能力。

## 项目来源

- 源项目地址: <https://github.com/baoweise-bot/aimili-vpngate>
- 当前修改版仓库: <https://github.com/zhishixuebao-0791/aimili-vpngate>

本修改版保留源项目的部署脚本、OpenVPN 连接管理、Web 管理界面和本地代理网关能力，并围绕“真实出口延迟排序、低延迟节点保留、收藏/拉黑状态机、固定路由策略”做了定制。

当前提供**稳定版 v1.26.25** 和**发行版 v1.26.26**。首次安装由用户自行选择，后续更新沿用安装时的渠道。

稳定版清理普通失败节点，并在风险检测启用时阻止已确认的高风险节点被自动切入。发行版保留没有延迟结果的失败节点，便于重试。完整版本历史见[更新记录](CHANGELOG.md)。

## 一键部署

在全新的 Linux VPS 上以 `root` 用户执行下面任意一条命令，选择需要的渠道。安装后，`ml update` 只更新该渠道；已有安装不能通过另一条命令串渠道重装。

### 稳定版（v1.26.25）

```bash
AIMILI_CHANNEL=stable bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

### 发行版（v1.26.26）

```bash
AIMILI_CHANNEL=release bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

部署完成后，终端会输出 Web 管理后台端口和路径。配置 API Key 时，可以在本机通过 SSH 转发端口：

```bash
ssh -N -L 8787:127.0.0.1:8787 user@your_vps_ip
```

然后在本机浏览器打开：

```text
http://127.0.0.1:8787/随机安全后缀
```

如果通过 HTTPS 反向代理访问面板，请在服务环境中设置 `AIMILI_UI_HTTPS_PROXIES` 为代理直连后端时使用的 IP，例如 `127.0.0.1`。代理必须覆盖客户端提供的 `X-Forwarded-Proto`，只在入口使用 TLS 时设为 `https`。systemd 安装可在 `/etc/default/aimilivpn` 配置该变量。登录公网 HTTP 面板后可用已保存的 Key 开关风险检测。添加、修改和删除 Key 需要 HTTPS 或 SSH 本地隧道。

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
4. 测速结束后，普通不可用节点和超出延迟阈值的普通节点会被清理，包含延迟显示 `-` 的不可达、拒绝连接和认证失败。默认阈值为 `500ms`。当前连接、固定节点、收藏、拉黑条目与已确认高风险的节点保留供回看。
5. 默认路由模式为“自动配置”，首次测速排序完成后会立即连接当前批次延迟最低的可用节点。

## 本修改版新增/调整功能

- 真实出口延迟测速: 通过当前 OpenVPN + 本地代理出口检测节点实际延迟，不再只看 VPNGate 原始 ping。
- 首次自动连接: 首次部署或已有缓存但没有活动连接时，会按当前路由模式测速排序，并自动连接符合规则的最低延迟节点。
- 登录触发刷新: 新安装或执行 `ml update` 后，首次进入 Web UI 会触发一次 VPNGate 节点拉取。新旧节点合并后测速排序、清理普通不可用节点，再按连接规则选择节点。
- 更新节点逻辑: 点击“更新节点”会拉取新节点，并与旧节点合并后一起测速排序。
- 终端一键更新: `ml update`只更新原安装渠道，重跑本渠道安装脚本并重启服务。
- 节点活动日志: 新增 `ml node-log` 命令，持续跟踪当前活动节点 IP、节点切换时间、连接失败、巡检超阈值但未切换、后台线程崩溃等信息。
  - 文件路径: `/opt/aimilivpn/vpngate_data/node_activity.log`
  - 主服务日志: `/opt/aimilivpn/vpngate_data/vpngate.log`
  - Web 日志面板 JSON: `/opt/aimilivpn/vpngate_data/logs/YYYY-MM-DD.json`
- 新版本提示: Web UI 只提示已安装渠道的新版本，不会因为另一渠道版本更高而提示升级。
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
- 新装默认关闭风险检测，风险值显示“未检测”。旧版已有 Key 且已设置观察或拦截模式，或已有风险查询缓存时，升级会保留启用意图。打开开关后填写 API Key，服务端校验通过至少一个才开始检测。开关打开后可通过“配置API”编辑，清空全部 Key 后保存会关闭开关。ProxyCheck、AbuseIPDB 和 IPQualityScore 各支持最多 5 个 Key，同一服务商的 Key 轮流使用并共用查询预算。拦截模式下，已确认高风险的出口会被排除在自动切换之外，已启用的实例重新校验 Key 时继续使用缓存中的确认记录。环境变量 `AIMILI_RISK_MODE=observe` 可设为只评分观察，`off` 可强制关闭。
- 系统从现有 `PROXYCHECK_API_KEY`、`ABUSEIPDB_API_KEY` 或 `API_Port.txt` 读取密钥，也支持可选的 `IPQS_API_KEY`。每次只查实际出口，后台优先核验活动节点和少量备用。手动测试单个节点也会刷新其出口评分。每个来源每天最多查询 900 次，复用 15 分钟内的有效数据。
- 至少两个有效来源且未达滥用条件时为低风险（10）。滥用信号待复核时为 50 或 70，至少两家来源的滥用证据相互印证且含强信号时为高风险（90 或 100）。证据不足显示未验证。VPN 或机房身份只作参考。
- 拦截模式在停旧隧道前检查候选，并在正式隧道放行前复核实际出口。已确认高风险的记录在接口失败或结果过期时继续生效，直到至少两家有效来源复核为低风险。管理员可在界面确认后手动连接。如果旧连接已停而新出口核验失败，用户会经历中断。
- UI 增强: 增加延迟、风险值、物理位置、ASN、运营主体/ISP、网络质量、IP 类型等列。
- 去广告: 已移除右侧 VPS 购买推荐广告。

## 路由模式说明

- 自动配置: 默认模式。首次测速、手动更新、模式切换或当前已连接节点延迟大于当前阈值时，会选择全局最低延迟可用节点。
- 固定 IP: 锁定当前手动选择的节点，不会因为当前节点不可用而自动切换，但仍会定期测速并刷新候选节点列表。
- 固定地区: 只在指定国家/地区和 IP 类型范围内测速排序，并选择最低延迟节点。
- 固定收藏菜单: 只在收藏节点中测速排序并选择最低延迟节点；如果收藏节点全部不可用，是否回退到非收藏节点由收藏管理面板选项决定。

### 渠道隔离

- 首次安装由用户在上方两条一键部署命令中选择渠道。稳定版只更新到新的稳定版，发行版只更新到新的发行版；重装也保持原渠道。
- 本机渠道记录位于 `vpngate_data/update_channel.json`，代码同时带有 `APP_CHANNEL`。远端 `release_channels.json` 为两渠道分别指定版本，不以全局最大版本号判断渠道。
- 旧ml可能先把源码重置到main；新安装脚本通过ORIG_HEAD/reflog识别更新前的渠道，在生成服务/启动程序前恢复到本渠道目标。若记录不明、清单缺失或目标渠道不符，会停止，能确认旧提交时会恢复旧源码，不静默转到main。
- 当前稳定版为v1.26.25，发行版为v1.26.26；已发布旧标签保持不变。渠道由元数据确定，与版本号数字大小无关。
- 本地开发标记`.local_dev`会暂停自动更新/重装，保护当前代码；不会成为绕过渠道校验的入口。
- 未修改已发布旧标签；旧版本未知来源且缺少可识别版本或Git更新记录时，不能保证自动识别，会明确停止。

## 可选CRL缓存工具

本次程序支持通过`AIMILI_OPENVPN_CAPATH`指定保留原CA信任的CRL目录。`ops/crl_cache.py`及[说明](ops/README.md)提供已验证的独立刷新工具源码；安装器不会自动启用，不会因为升级就强制所有免费出口缺CRL时拒绝连接。服务器端证书用途和CA检查继续保留。

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

### Stable (v1.26.25)

```bash
AIMILI_CHANNEL=stable bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

### Release (v1.26.26)

```bash
AIMILI_CHANNEL=release bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

To enter API keys, use an SSH tunnel (for example, `ssh -N -L 8787:127.0.0.1:8787 user@your_vps_ip`) and open the printed UI path at `http://127.0.0.1:8787`. For an HTTPS reverse proxy, set `AIMILI_UI_HTTPS_PROXIES` to its exact backend IP and configure the proxy to overwrite `X-Forwarded-Proto` based on whether the client connection uses TLS. Signed-in users can toggle risk checks using their saved keys over public HTTP. Adding, editing, and removing keys requires HTTPS or a local SSH tunnel. Run `ml` on the server for the CLI management menu.

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
- `ml update` upgrades within the installed channel, reruns that channel's installer, and restarts the service.
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
- Risk detection is off on fresh installations. An existing installation with legacy keys and an explicit scoring policy or risk-query cache retains its opt-in. Detection starts after the server verifies at least one key. Use the adjacent configuration button to edit keys while the switch is on. Saving with all keys removed turns it off. ProxyCheck, AbuseIPDB, and IPQualityScore each support up to five keys, rotating within a shared provider quota. In enforcement mode, confirmed high-risk exits are excluded from automatic connections, including during revalidation of previously enabled credentials. Set `AIMILI_RISK_MODE=observe` for scoring only or `off` to force the feature off.
- Added UI columns for latency, risk, location, ASN, ISP, network quality, and IP type.
- Removed the VPS recommendation ad.

## Ports

- Web UI: `8787`, needs firewall/security-group access.
- Local proxy: `7928`, binds to `127.0.0.1` by default and should not be exposed publicly unless you understand the risk.
