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

## 版本说明

| 渠道 | 当前版本 | 获取方式 | 说明 |
| --- | --- | --- | --- |
| 稳定版 | **v1.26.8** | 一键部署命令 | 经过线上长期运行验证的版本 |
| 发行版 | **v1.26.13** | `ml update` | 最新功能与修复，已安装用户可主动升级 |

Web 管理界面左上角和 `ml` 管理菜单标题会显示当前运行的版本号。

### 更新日志

- **v1.26.13** / **v1.26.8**（稳定版）：连接前后延迟口径统一
  - 修复连接后延迟检测解析错误：ip.sb 响应体自带换行导致计时解析失败、每次都退回到响应很慢的 api.ipify.org，延迟被虚高约 200ms，并可能误触发延迟巡检切换节点。
  - 连接后延迟改为与节点测速使用同一组目标、同样取最快一次（经本地代理测），连接前后的数值可以直接比较。
  - 节点表格中已连接节点显示真实出口延迟，不再显示 ping VPN 服务器本身的结果；连接时不再额外 ping 服务器，连接更快。
- **v1.26.12** / **v1.26.7**（稳定版）：线上日志排查修复
  - 修复固定地区等模式下当前范围没有可用节点时卡死在无连接状态：没有活动连接时从 5 分钟（`NO_NODE_REFETCH_SECONDS`）起按 2 倍退避（封顶 21 分钟）重新从 VPNGate 拉取节点；连接中途断开并持续空闲约 1 分钟后进入兜底流程。
  - 修复本机代理端口被本服务自己监听时误报"端口被其他进程占用"（ERR_PORT_IN_USE），本机代理网关故障不再拉黑正常节点、不再触发切换；本地端口偶发超时先重试一次，并在提示中保留原始错误。
  - 代理失败日志按同类错误限流（每类 60 秒打印 1 条，附省略条数）；`vpngate.log` 超过 20MB（`LOG_FILE_MAX_BYTES`）自动轮转为 `vpngate.log.1`，`ml` 查看日志改为 `tail -F` 以跟随轮转。
- **v1.26.11**
  - 不可用节点统一清理：除超时（-1）外，其他失败（显示 `-`）也计入连续失败并进入阶梯冷却（30 分钟 / 2 小时 / 6 小时 / 24 小时）；连续失败 4 次或已从 VPNGate 下线的节点自动移出列表，避免死节点无限堆积、拖慢测速。
  - 节点数超过上限时优先丢弃不可用节点，保证新节点能进入列表。
  - 已下线的拉黑节点从列表移除（拉黑 IP 清单本身不受影响）。
  - 切换到固定 IP 模式时锁定当前连接的节点。
  - 后台配置改为原子写入；配置文件读取异常时不再重置账号密码。
  - 连接过程不再覆盖期间其他操作对节点的修改。
- **v1.26.10**：修复固定 IP 模式重启后无法连接、断开连接误杀测速进程、“更新节点”断开健康节点等问题；新增版本号显示与稳定版/发行版双渠道。
- **v1.26.6**：稳定版（0629_bug修复 + 版本号显示）。

## 一键部署

一键部署会安装**稳定版**（当前 `v1.26.8`）。如果服务器上已安装更高的版本（例如通过 `ml update` 升级到了发行版），重新运行一键部署不会降级。

在全新的 Linux VPS 上以 `root` 用户执行:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
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
ml update    # 更新到最新发行版（当前 v1.26.13）并重启服务
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
- 登录触发刷新: 新安装或执行 `ml update` 后，首次进入 Web UI 会触发一次 VPNGate 节点拉取；新旧节点合并后统一测速排序，剔除不可用节点，并按当前路由模式连接符合规则的最低延迟节点（固定 IP 模式不切换）。
- 更新节点逻辑: 点击“更新节点”会拉取新节点，并与旧节点合并后一起测速排序；当前连接节点若测速达标会保留并参与排序，仅在出现更低延迟节点时切换。
- 终端一键更新: 新增 `ml update` 命令，可在服务器终端更新到最新发行版、重跑安装脚本并重启服务。
- 节点活动日志: 新增 `ml node-log` 命令，持续跟踪当前活动节点 IP、节点切换时间、连接失败、巡检超阈值但未切换、后台线程崩溃等信息。
  - 文件路径: `/opt/aimilivpn/vpngate_data/node_activity.log`
  - 主服务日志: `/opt/aimilivpn/vpngate_data/vpngate.log`
  - Web 日志面板 JSON: `/opt/aimilivpn/vpngate_data/logs/YYYY-MM-DD.json`
- 新版本提示: Web UI 登录后会检测 GitHub 仓库中版本号最高的 `vX.Y.Z` 标签（发行版）；只有发布了比当前更新的版本标签时才提示，不会因为普通 commit 推送而提示。提示每天最多出现一次，文案为“有新的版本发布，可在终端中输入 ml update 命令更新”。
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

如果已经通过本仓库部署到 `/opt/aimilivpn`（包括旧版本用户），可在服务器执行:

```bash
ml update
```

`ml update` 会拉取远程版本标签，对比本地版本与最新发行版，确认后切换到最新发行版并重新运行安装脚本、重启服务。旧版本的 `ml` 也可以直接使用该命令完成升级。

如需切换到指定版本（例如从发行版回退到稳定版），可设置环境变量后运行安装脚本:

```bash
AIMILI_DEPLOY_REF=v1.26.8 bash <(curl -fsSL https://raw.githubusercontent.com/zhishixuebao-0791/aimili-vpngate/main/install.sh) zhishixuebao-0791 aimili-vpngate
```

### 发布新版本（维护者）

- **发布新的发行版**:
  1. 修改 `vpngate_manager.py` 中的 `APP_VERSION`，例如 `1.26.11`。
  2. 提交到 `main` 后打同名标签，并与 `main` 一起推送: `git tag -a v1.26.11 -m "v1.26.11" && git push origin main v1.26.11`。
  3. `main` 的最新提交必须始终是最新发行版（旧版 `ml update` 会直接更新到 `main` 的最新提交），未发布的开发改动请放在其他分支。
- **升级稳定版**: 当某个发行版经过充分验证后，把 `install.sh` 中的 `STABLE_TAG` 改为该版本标签（例如 `v1.26.10`），提交并推送 `main`。
- 版本标签格式必须是 `vX.Y.Z`，旧的 `V2026.06.16` 这类日期标签不会被识别为版本。

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

Release channels: the one-click installer deploys the **stable** version (currently `v1.26.8`, pinned by `STABLE_TAG` in `install.sh`); `ml update` upgrades an existing installation (including older versions) to the latest **release** tag (currently `v1.26.13`). Re-running the installer never downgrades a newer installation. The running version is shown at the top-left of the Web UI.

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
- After a fresh install or `ml update`, the first Web UI login triggers a VPNGate refresh; old and new nodes are benchmarked together, unavailable nodes are pruned, and the lowest-latency node eligible under the current routing mode is connected (fixed IP mode does not switch).
- Added `ml update` for upgrading to the latest release tag, rerunning the installer, and restarting the service.
- Added `ml node-log` for tailing persistent node activity logs, including active node IP, switch time, switch failures, threshold stalls, and background thread crashes.
- Web UI checks the latest GitHub Release tag, falling back to the latest tag, and shows an update notice only when a new tag is published; ordinary commits do not trigger the notice.
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
