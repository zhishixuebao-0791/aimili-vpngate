# Ping0 节点纯净度过滤可行性方案

记录日期：2026-06-08

## 目标

为 AimiliVPN 增加节点过滤条件：通过 `https://ping0.cc/` 检测节点 IP 的风控值，只保留风控值小于 20 的节点；风控值大于或等于 20 的节点不进入可用节点池。

## 已读取的 Markdown

- `README.md`

结论：项目是纯 Python 标准库实现的 VPNGate 代理网关，核心能力包括：

- 从官方 VPNGate API 拉取候选 OpenVPN 节点。
- 并发检测节点连通性与延迟。
- Web 管理面板展示节点、状态、日志和代理出口。
- 本地 HTTP/SOCKS5 代理默认监听 `127.0.0.1:7928`。
- 现有过滤能力包括地区、固定 IP、收藏节点、住宅/机房类型等，但没有按 Ping0 风控值硬过滤。

## 当前代码结构判断

主要文件：

- `vpngate_manager.py`
  - `fetch_candidates()`：拉取并解析 VPNGate 官方候选节点。
  - `row_to_node()`：将 VPNGate 行数据转换为项目内部节点字典。
  - `test_multiple_nodes()`：批量测试节点连通性，成功后调用 IP 信息富集。
  - `maintain_valid_nodes()`：节点维护主流程，负责拉取、合并、测试、写入 `nodes.json`，并触发自动连接。
  - `sort_all_nodes()` / `auto_switch_node()`：决定节点展示顺序和自动切换候选。
- `vpn_utils.py`
  - `enrich_ip_info()`：使用 `ip-api.com` 批量补充 ASN、运营商、位置、IP 类型和质量标签。
  - 已有 `ip_cache.json` 缓存模式，可参考用于 Ping0 风控缓存。
- `proxy_server.py`
  - 本地 HTTP/SOCKS5 代理服务，与本次节点过滤关系较弱。

推荐接入点：

1. 在 `row_to_node()` 增加节点字段，例如 `ping0_risk`、`ping0_checked_at`、`ping0_message`。
2. 在 `vpn_utils.py` 新增 Ping0 指定 IP 查询与缓存逻辑。
3. 在 `test_multiple_nodes()` 中，仅对 `probe_status == "available"` 的节点查询 Ping0 风控。
4. 对 `ping0_risk >= 20` 或无法满足策略的节点，更新为不可用或直接从最终写入列表剔除。
5. 在 `maintain_valid_nodes()` 最终统计和自动连接前，确保可用候选只包含 `ping0_risk < 20` 的节点。

## Ping0 接口验证结果

官方页面 `https://ping0.cc/ip/api` 显示：

- 免费接口主要用于获取“当前访问出口 IP”或当前出口 IP 的基础地理信息，例如 `curl ping0.cc/geo`。
- 指定 IP 的详细查询使用：
  - `https://ping0.cc/apiloc/apikey(01234567890123456789012345678901)/ip(111.112.113.114)`
- 指定 IP 查询返回 JSON，包含 `iprisk` 字段。
- 指定 IP 查询是付费接口，页面标注为 `0.1 元/次请求，1w 次起购`。

本地验证：

- 公开 IP 页面可访问，但页面由 Vue/axios 动态渲染，直接抓 HTML 解析风控值不稳定，不建议作为实现基础。
- 使用文档示例 token 调用指定 IP API，返回 `token not found`，说明该路径需要真实 API key。
- FAQ 说明风控值越大风险越高；15 以内为极度纯净，15-25 为纯净。因此项目要求的 `< 20` 属于比 Ping0 默认“纯净”更严格的阈值。

## 可行性结论

可行，但前提是用户提供 Ping0 指定 IP 查询 API key。

原因：

- 目标是筛选 VPNGate 节点 IP，不是检测本机当前出口 IP。
- 免费接口不能批量或任意查询 VPNGate 候选节点的风控值。
- 官方指定 IP API 有明确 JSON 字段 `iprisk`，适合稳定接入。

## 推荐实现方案

### 配置

新增环境变量：

- `PING0_API_KEY`：Ping0 API key；未配置时不启用 Ping0 风控过滤。
- `PING0_RISK_THRESHOLD`：默认 `20`。
- `PING0_CACHE_TTL_SECONDS`：默认 `604800`，即 7 天。
- `PING0_FAIL_POLICY`：建议默认 `mark_unavailable`，含义是查询失败时不把该节点纳入可用池，但不永久拉黑。

### 数据字段

节点字典新增：

- `ping0_risk`: 整数风控值。
- `ping0_checked_at`: 最近检测时间戳。
- `ping0_status`: `ok` / `blocked` / `error` / `not_checked`。
- `ping0_message`: 检测说明或失败原因。

缓存文件建议：

- `vpngate_data/ping0_cache.json`

缓存结构：

```json
{
  "1.2.3.4": {
    "iprisk": 7,
    "checked_at": 1780912800,
    "raw": {
      "ip": "1.2.3.4",
      "isidc": false,
      "isnative": true
    }
  }
}
```

### 流程

推荐流程：

1. `fetch_candidates()` 继续只负责拉取和解析 VPNGate 候选节点。
2. `test_multiple_nodes()` 先执行现有 OpenVPN 可用性检测。
3. 对检测成功的节点调用 Ping0 指定 IP API。
4. `iprisk < 20`：保留为 `probe_status = "available"`。
5. `iprisk >= 20`：将节点标记为不可用或从可用池剔除，`probe_message` 写入 `Ping0 风控值 xx >= 20，已剔除`。
6. 写入 `nodes.json` 前再次过滤，防止高风险节点参与排序、展示和自动连接。
7. `auto_switch_node()` 和固定地区/收藏模式沿用已有候选筛选逻辑，因为高风险节点已不再是 `available`。

### 成本控制

- 不对 VPNGate 原始候选全量查询 Ping0，避免每轮 300 个候选都产生付费请求。
- 只对 OpenVPN 连通性测试成功的节点查询。
- 使用 7 天缓存，同一 IP 在缓存有效期内不重复扣费。
- 可以后续增加每日查询上限，例如 `PING0_DAILY_LIMIT`。

## 当前路径进展记录

突破性进展：

- 已确认项目现有主链路位置：`maintain_valid_nodes()` -> `fetch_candidates()` -> `test_multiple_nodes()` -> `sort_all_nodes()` -> `auto_switch_node()`。
- 已确认 Ping0 官方指定 IP API 返回 `iprisk`，适合做硬过滤字段。
- 已确认免费接口不满足“检测任意 VPNGate 节点 IP”的需求。

走不通或不推荐路径：

- 直接抓取 `https://ping0.cc/ip/<ip>` 页面解析风控值：页面动态渲染，结构容易变化，也可能受广告、脚本、语言和反爬影响，不适合长期稳定运行。
- 使用 `curl ping0.cc/geo`：只能检测当前访问出口 IP，不能检测每个候选节点 IP。

## 下一步计划

1. 等用户确认是否已有 Ping0 API key，以及是否接受通过环境变量 `PING0_API_KEY` 配置。
2. 在 `vpn_utils.py` 实现 `query_ping0_iprisk()` 和缓存读写。
3. 在 `vpngate_manager.py` 增加节点字段与过滤逻辑。
4. 增加日志和 Web 节点字段展示，便于看到剔除原因。
5. 用模拟 Ping0 响应或小样本节点验证：
   - `iprisk = 1` 保留。
   - `iprisk = 19` 保留。
   - `iprisk = 20` 剔除。
   - `iprisk = 21` 剔除。
   - Ping0 查询失败按 `PING0_FAIL_POLICY` 处理。
6. 运行静态语法检查和小范围功能验证，确认不会破坏现有节点维护线程。

## 2026-06-08 补充：无付费 Ping0 API key 时的最合适方案

### 结论

不建议尝试“复刻 Ping0 风控值”作为项目主路径。

原因：

- Ping0 的 `iprisk` 不是单纯由 ASN、机房/住宅、地理位置推导出来的字段。官方 FAQ 说明其风控值来自对扫描、爆破、爬虫、对外攻击、垃圾邮件、C&C 等行为的大数据监测，并结合危险行为次数和频率打分。
- Ping0 对 IP 类型还包含人工 IP 段标注和历史数据。项目本地无法低成本获得同等数据源，因此只能做“近似评分”，不能保证与 Ping0 风控值一致。
- 爬取 `https://ping0.cc/ip/<ip>` 页面绕过付费 API 不适合作为实现路径：页面动态渲染、结构可能变化，也不适合高频自动化查询。

### 免费可行路径

当前项目最适合做“两级免费近似纯净度过滤”：

1. 第一层：保留现有连通性检测。
   - 仍然先跑 OpenVPN 可用性检测。
   - 只有连通成功的节点才进入纯净度评估，避免浪费外部查询额度。

2. 第二层：本地近似纯净度评分。
   - 复用现有 `ip-api.com` 富集结果：`proxy`、`hosting`、`mobile`、ASN、组织、ISP、地理位置。
   - 新增本地规则评分 `purity_score`，范围 0-100，分数越低越干净。
   - 建议初始规则：
     - `ip_type == residential` 或 `mobile`：降低风险。
     - `quality == proxy`：直接高风险。
     - `quality == datacenter` 或 `ip_type == hosting`：增加风险。
     - ASN/组织命中云厂商、IDC、CDN、代理关键词：增加风险。
     - rDNS 或 host name 命中 `vpn`、`proxy`、`server`、`hosting`、`cloud` 等关键词：增加风险。
     - VPNGate 官方 `sessions` 很高：增加共享风险。
     - Ping 延迟极高或测速不稳定：轻微增加风险，但不能作为核心纯净度指标。

3. 第三层：可选免费外部声誉增强。
   - `proxycheck.io`：可免费查代理/VPN/托管类型；无 key 时额度较小，有免费 key 后日额度更高。
   - `AbuseIPDB`：有免费 API key，可查 `abuseConfidenceScore`，适合补充“恶意行为声誉”，但它不等同于 Ping0 风控值。
   - `ip-api.com`：当前项目已经使用，免费端点无需 key，但有 45 请求/分钟限制。

### 推荐实现形态

建议不要把字段命名为 `ping0_risk`，避免误导用户以为这是 Ping0 官方结果。

新增字段建议：

- `purity_score`: 本项目本地计算的近似纯净度风险分。
- `purity_grade`: `clean` / `neutral` / `risky` / `blocked`。
- `purity_reasons`: 命中的规则原因列表。
- `purity_checked_at`: 检测时间。
- `purity_sources`: 使用的数据源，例如 `["ip-api", "local-rules", "proxycheck", "abuseipdb"]`。

过滤策略：

- 当前宽松阈值：`purity_score <= 60` 保留。
- `61 <= purity_score < 85` 标记为中风险，批量校准后通常仍可保留。
- `purity_score >= 85` 标记为高风险；只有硬剔除命中或批量 99% 通过率之外的极少数节点会被标记不可用。

### 对当前项目的最佳方案

最佳方案是“免费本地评分为默认能力，Ping0 付费 API 为可选增强能力”：

1. 默认无需任何付费 key 即可工作。
2. 使用现有 `ip-api.com` 数据和本地规则先实现 `purity_score`。
3. 支持可选配置：
   - `PROXYCHECK_API_KEY`
   - `ABUSEIPDB_API_KEY`
   - `PING0_API_KEY`
4. 如果配置了 `PING0_API_KEY`，则以 Ping0 `iprisk` 作为最高优先级硬过滤。
5. 如果没有 `PING0_API_KEY`，则使用本地近似评分和免费声誉源做过滤，并在 UI/日志中明确显示“本地近似评分，非 Ping0 官方风控值”。

### 下一步计划调整

1. 先实现本地免费纯净度评分 `purity_score`，不依赖付费 Ping0。
2. 增加缓存文件 `purity_cache.json`，避免重复查询和重复计算。
3. 在节点批量测试成功后执行纯净度评分。
4. 默认过滤 `purity_score > 60` 的节点，并通过 `PURITY_MIN_PASS_RATIO=99` 尽量避免错杀纯净节点。
5. 后续再接入可选 Ping0 API，使有 key 的用户获得更准确的官方风控值。

## 2026-06-08 补充：开源项目搜索结论与当前实现

### 开源项目搜索结论

已搜索关键词包括：

- `GitHub open source IP purity score IP risk score proxy VPN detection Python`
- `GitHub IP reputation scoring open source proxy detection Python`
- `开源 IP 纯净度 检测 风控值 GitHub`
- `site:github.com IP reputation score proxy detection Python open source`

发现的相关方向：

- `crowdsecurity/ipdex`：开源 CLI，但核心依赖 CrowdSec CTI API 和 API key。
- `IP2Proxy` 系列库：可以查 VPN、代理、Tor、数据中心等，但需要 IP2Proxy BIN 数据库；免费 Lite 数据可用，精度和字段有限。
- `HakiChecker`、批量 IP reputation lookup 类工具：主要是调用 VirusTotal、AbuseIPDB、IPQualityScore 等第三方 API。
- `proxycheck.io` 相关库：本质是调用 proxycheck.io API；有免费额度，但不是离线开源风控模型。
- 其它代理检查器多偏向可用性、匿名性、延迟检测，不等同于 Ping0 风控或 IP 纯净度。

结论：没有找到适合当前项目直接嵌入、无需外部数据源、能稳定给出类似 Ping0 `iprisk` 的成熟开源实现。当前项目应采用“本地规则评分 + 可选免费声誉 API 增强”的路线。

### 已实现内容

已在 `vpn_utils.py` 增加：

- `PURITY_SCORE_THRESHOLD`，当前默认 `60`，风险值 `<=60%` 通过。
- `PURITY_CACHE_TTL_SECONDS`，默认 7 天。
- `PURITY_ENABLE_PROXYCHECK`，默认关闭，设置为 `1/true/yes/on` 后启用无 key proxycheck.io 查询。
- `PROXYCHECK_API_KEY`，配置后启用 proxycheck.io，免费 key 可提升额度。
- `ABUSEIPDB_API_KEY`，配置后启用 AbuseIPDB。
- `purity_cache.json` 缓存。
- `assess_ip_purity()` 和 `assess_nodes_purity()`。

本地评分已使用：

- 现有 `ip-api.com` 富集后的 `ip_type` 和 `quality`。
- ASN、运营主体、远端主机名关键词。
- VPNGate `sessions` 仅作为轻微共享程度参考。
- 延迟作为弱风险参考。

已在 `vpngate_manager.py` 接入：

- 新节点默认包含 `purity_score`、`purity_grade`、`purity_reasons`、`purity_sources`、`purity_checked_at`。
- 单节点“检测”只测真实出口延迟，不触发纯净度 API。
- 批量节点测试成功后执行纯净度评分。
- `purity_score > PURITY_SCORE_THRESHOLD` 的节点会被标记为 `unavailable`，不会参与自动连接。
- 可用节点排序时会优先选择更低 `purity_score` 的节点。

### 验证结果

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

## 2026-06-10 补充：固定收藏菜单路由与收藏限制

### 调整目标

- 在代理设置的“IP 出站路由模式”中新增“固定收藏菜单”选项。
- 选中后仅在收藏节点范围内进行真实出口延迟测速排序，并切换到延迟最低的收藏节点。
- 固定收藏菜单模式每 30 分钟检查当前活动节点真实出口延迟；如果延迟 `>500ms`，标记当前节点不可用，并重新对收藏节点测速排序后切换最低延迟节点。
- 被手动拉黑的节点不能收藏。
- 被检测或更新节点流程标记为不可用的节点不能收藏。
- 移除页面右侧“VPS购买推荐”浮动入口。

### 已实现

- 新增路由模式 `fixed_favorites`。
- 新增 `refresh_and_switch_fixed_favorites()`：
  - 读取收藏节点 ID。
  - 对当前收藏节点执行 `test_multiple_nodes()` 真实出口测速。
  - 按现有延迟排序规则选择最低延迟可用收藏节点。
  - 当前活动节点已经是最低延迟收藏节点时不重复切换。
- 新增 `fixed_favorites_latency_guard()`：
  - 每 30 分钟运行一次。
  - 仅在 `routing_mode=fixed_favorites`、连接开启、当前节点运行时生效。
  - 延迟 `>500ms` 时标记当前活动节点不可用，并触发收藏节点测速排序切换。
- `background_proxy_checker()` 在固定收藏菜单模式下检测到代理不可用时，会触发固定收藏菜单专用切换路径。
- 保存代理设置或更新路由为固定收藏菜单模式后，会后台触发一次收藏节点测速排序切换。
- 新增收藏清理逻辑：
  - `manual_blacklisted=true` 的节点会从收藏列表清理。
  - `probe_status != available` 的节点会从收藏列表清理。
  - 后端 `/api/toggle_favorite` 拒绝收藏不可用或拉黑节点。
  - 前端不可用/拉黑节点的收藏按钮显示为灰色“不可收藏”并禁用。
- 已移除右侧 `VPS购买推荐` 浮动入口。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

## 2026-06-10 补充：高延迟触发式节点刷新

### 调整目标

- 后台不再定时无条件从 VPNGate 拉取新节点，避免前端列表周期性变成“待检测”。
- 仅当当前已连接节点的真实出口延迟 `>500ms` 时，才触发新一轮节点刷新。
- 刷新时先保留旧节点，再拉取 VPNGate 新节点，把新旧节点合并后一起测速排序。
- 测速未通过的节点剔除，只保留延迟 `<=500ms` 的可用节点。
- 被收藏的节点不因本轮高延迟刷新被剔除。
- 固定 IP 模式下，即使当前节点延迟 `>500ms`，也只刷新、测速、剔除其他失败节点，不自动切换。
- 自动配置、固定地区、固定收藏菜单模式下，延迟 `>500ms` 后会按当前路由模式切换到最低延迟可用节点。

### 已实现

- 新增 `merge_nodes_preserve_old()`：
  - 新旧节点按 `id` 合并。
  - 已存在旧节点时保留旧的检测状态、延迟、ASN、ISP、IP 类型等信息。
- 新增 `prune_failed_nodes()`：
  - 保留 `probe_status=available` 的节点。
  - 保留收藏节点。
  - 固定 IP 模式额外保留当前活动节点。
- 新增 `refresh_test_prune_and_maybe_switch()`：
  - 拉取新节点。
  - 合并旧节点。
  - 对新旧节点统一执行真实出口延迟测速。
  - 非固定 IP 模式下断开高延迟旧活动节点。
  - 剔除未通过节点，按当前路由模式选择最低延迟节点。
  - 固定地区模式继续按当前国家/地区与 IP 类型过滤。
  - 固定收藏菜单模式只在收藏节点中选择最低延迟节点。
- 新增 `active_latency_refresh_guard()`：
  - 每 30 分钟检测当前活动节点真实出口延迟。
  - 适用于 `auto`、`fixed_ip`、`fixed_region`、`favorites`、`fixed_favorites`。
  - 仅当延迟 `>500ms` 时触发刷新。
- `collector_loop()` 改为：
  - 仅在没有任何节点缓存时执行首次拉取。
  - 节点缓存已存在后，不再周期性无条件刷新。
- 默认路由模式改为 `fixed_ip`。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟自动模式：高延迟刷新后剔除失败节点、保留收藏节点，并切换到最低延迟新节点。
- 本地模拟固定 IP 模式：高延迟刷新后不切换、不断开当前节点，并保留当前活动旧节点。

### 2026-06-10 澄清调整

- 收藏规则调整为：
  - 未收藏节点如果当前 `probe_status != available`，前端置灰显示“不可收藏”，后端 `/api/toggle_favorite` 也拒绝新增收藏。
  - 已收藏节点后续即使测速失败或延迟 `>500ms`，也不会被自动取消收藏。
  - 已收藏但不可用的节点仍显示“已收藏”，用户可以手动点击取消收藏。
  - 手动拉黑节点仍会从收藏列表清理。
- 手动点击前端“更新节点”也改为调用 `refresh_test_prune_and_maybe_switch("manual update")`：
  - 拉取 VPNGate 新节点。
  - 新旧节点合并测速排序。
  - 剔除未通过节点，但保留收藏节点；固定 IP 模式额外保留当前活动节点。
  - 是否切换节点继续由当前“IP 出站路由模式”决定。
- 新增前端 `testing` 状态：
  - 新拉入节点在测速完成前写入 `probe_status=testing`。
  - UI 状态栏显示“测试中...”动态点号，直至测速排序完成后更新为最终状态。
- 前端自动轮询不再因为 `state.is_connecting=true` 暂停，后台刷新期间也能及时看到 `testing` 状态变化。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟：不可用的已收藏节点不会被 `cleanup_favorite_node_ids()` 自动清理。
- 本地模拟：手动更新/高延迟刷新中新节点会先写入 `testing` 状态，测速后剔除失败节点并保留收藏节点。

### 2026-06-10 补充：收藏与拉黑状态机对齐

- 收藏取消规则：
  - 已收藏节点后续变为不可用不会被自动取消收藏。
  - 用户手动取消收藏时，如果该节点当前延迟 `>500ms`，会同时从主节点列表移除。
  - 用户手动取消收藏时，如果该节点当前延迟 `<=500ms`，只从收藏列表移除，主节点列表继续保留。
- 拉黑按钮规则：
  - 已收藏节点不能直接在节点行点击拉黑。
  - 必须先取消收藏；如果节点仍保留在主节点列表，才允许点击拉黑。
- 取消拉黑规则：
  - 如果主节点列表中存在该 IP 且延迟 `<=500ms`，取消拉黑后恢复为 `available` 并重新排序。
  - 如果主节点列表中存在该 IP 且延迟 `>500ms` 或无有效延迟，取消拉黑后从主节点列表移除。
  - 如果主节点列表中不存在该 IP，取消拉黑只移除拉黑列表记录，不把该 IP 重新加入主节点列表。
- 拉黑列表规则：
  - 手动添加到拉黑菜单的 IP 会持久保留在 `manual_blacklist.json`。
  - 后续 VPNGate 拉取的新节点如果命中该 IP，会被标记为不可用，且不会作为可用节点保留。
  - 如果任何模式下意外连接到拉黑 IP，后台会立即断开、标记不可用，并从当前已显示节点中切换到最低延迟的非拉黑可用节点；该过程不触发新的测速排序。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟：取消收藏高延迟节点会从主节点列表移除。
- 本地模拟：取消拉黑时按当前延迟恢复或移除主节点。
- 本地模拟：当前活动节点命中拉黑列表时会断开并切换到当前列表最低延迟可用节点。

## 2026-06-10 补充：UI、首次测速与部署说明收尾

### 已实现

- 拉黑菜单与收藏菜单的页面模式对齐：
  - 打开拉黑菜单后，主节点表格只显示当前主列表中命中的拉黑节点。
  - 持久拉黑 IP 仍在拉黑管理面板中统一搜索、添加和取消拉黑。
  - 拉黑页空态文案单独处理，避免误以为普通节点列表为空。
- 首次部署/首次登录体验：
  - 当节点缓存为空时，后台会立即执行一次 VPNGate 拉取、新旧节点合并、真实出口延迟测速与排序。
  - 新拉入节点测速完成前写入 `probe_status=testing`，前端显示“测试中...”动态点号。
- 延迟显示修正：
  - 活动节点连接成功后的延迟改为优先使用本地代理出口检测得到的真实延迟。
  - 活动节点延迟守护线程不再用普通直连 ping 覆盖真实出口延迟。
- 状态机收敛：
  - 旧的固定地区/固定收藏兜底入口改为调用统一的 `refresh_test_prune_and_maybe_switch()`。
  - 自动切换兜底补齐也改为统一的新旧节点合并测速排序流程。
  - 配置接口缺省路由模式统一改为 `fixed_ip`。
- README 更新：
  - 写明源项目地址与当前修改版仓库地址。
  - 更新一键部署命令到当前修改版仓库。
  - 写明修改版与源项目的主要差异。
  - 修正端口安全说明：默认只建议开放 Web 管理端口 `8787`，代理端口 `7928` 默认仅本机使用。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟：首次/手动刷新时新节点会先显示 `testing`，测速完成后保留低延迟节点并按路由模式切换。

### 下一步建议

1. 将当前代码推送到 GitHub 后，在测试 VPS 上执行一键部署命令验证首次安装流程。
2. 部署后确认 `systemctl status aimilivpn.service --no-pager` 为 `active (running)`。
3. 首次打开 Web UI 时观察节点状态是否先显示“测试中...”，随后按延迟从低到高排序。
4. 分别测试收藏、拉黑、取消收藏、取消拉黑，以及固定 IP/自动配置/固定地区/固定收藏菜单四种路由模式。

## 2026-06-11 补充：节点测速 5 秒超时

### 已实现

- 新增 `NODE_PROBE_TIMEOUT_SECONDS`，默认值为 `5`。
- 单个节点测速时，OpenVPN 握手和真实出口 curl 探测共享同一个 5 秒 deadline。
- 超过 5 秒仍未完成的节点直接判定为超时：
  - `probe_status=unavailable`
  - `latency_ms=-1`
  - 前端延迟列显示 `-1`
- 前端排序将 `-1` 视为无效/最慢延迟，不会排到低延迟节点前面。
- 超时节点取消收藏时会被移出主节点列表。
- 进一步对齐：测速排序结束后，`latency_ms=-1` 的超时节点会从主节点列表剔除。
- 收藏管理面板去掉“启用仅用收藏出站”按钮，避免与代理设置中的“固定收藏菜单”重复。
- 收藏管理面板的回退选项语义明确为：只有全部收藏节点不可用时才决定是否回退到当前批次最低延迟的非收藏可用节点。
- 如果关闭收藏回退，全部收藏节点不可用时不切换非收藏节点，并保持当前连接到的不可用节点。
- 收藏管理面板和拉黑IP管理面板增加左上角返回按钮，返回后恢复“全部节点 / 所有国家 / 所有IP类型”的主列表。
- 面板标题调整为“收藏管理面板”和“拉黑IP管理面板”。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟：deadline 已过时，出口测速函数返回 `latency_ms=-1`。
- 本地模拟：`latency_ms=-1` 节点在测速排序后被剔除。
- 本地模拟：固定收藏菜单关闭回退时，全部收藏节点不可用后不切换、不断开，保留当前不可用连接。

## 2026-06-11 补充：路由模式切换立即测速排序

### 已实现

- 新增路由模式切换专用流程 `test_current_routing_scope_and_maybe_switch()`。
- 保存“代理设置 / IP 出站路由模式”后，如果路由模式、固定地区或 IP 类型过滤发生变化，会立即触发后台测速排序。
- 该流程不重新拉取 VPNGate 新节点，只使用当前主节点列表。
- 测速范围按目标路由模式收拢：
  - 自动配置：当前主列表全部节点。
  - 固定地区：当前国家/地区内的节点；如果 IP 类型过滤为住宅 IP 或机房 IP，则进一步只测速该类型节点。
  - 固定收藏菜单：只测速收藏节点。
  - 固定 IP：只测速当前固定节点，不自动切换。
- 排序完成后的切换策略：
  - 自动配置：切换到全部节点中延迟最低的可用节点。
  - 固定地区：切换到目标国家/地区与 IP 类型过滤范围内延迟最低的可用节点。
  - 固定收藏菜单：优先切换到收藏节点中延迟最低的可用节点。
  - 固定收藏菜单下如果全部收藏节点不可用：
    - 收藏回退选项开启时，切换到当前批次中延迟最低的非收藏可用节点。
    - 收藏回退选项关闭时，不切换非收藏节点，保持当前连接。
- `latency_ms=-1` 的节点在测速后会剔除，但如果该节点在收藏列表中则保留。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟：固定地区模式只测速目标国家 + 目标 IP 类型，并切换到该范围最低延迟节点。
- 本地模拟：自动配置模式测速当前全部节点，并切换到全局最低延迟节点。
- 本地模拟：固定收藏菜单只测速收藏节点；收藏全失效且回退开启时，切换到非收藏最低延迟节点。

### 后续建议

1. 在真实 VPS 环境跑一次节点刷新，观察 `vpngate_data/nodes.json` 中的 `purity_score` 和 `probe_message`。
2. 根据误杀情况调节 `PURITY_SCORE_THRESHOLD`，当前默认 `60`；如果漏过明显高风险节点，再逐步收紧。
3. 如果免费本地评分误差较大，再开启 `PURITY_ENABLE_PROXYCHECK=1` 或配置 `PROXYCHECK_API_KEY`。
4. 前端表格可后续单独修复编码问题后展示 `Purity` 列；当前后端 API 已返回评分字段。

## 2026-06-08 补充：免费 API 额度型增强已实现

### API key 来源

本地私密文件：

- `API_Port.txt`

实现策略：

- `API_Port.txt` 已加入 `.gitignore`，避免 key 被误提交。
- 程序启动后会从 `API_Port.txt` 自动解析 proxycheck.io 和 AbuseIPDB key。
- 仍支持环境变量：
  - `PROXYCHECK_API_KEY`
  - `ABUSEIPDB_API_KEY`
  - `API_KEYS_FILE`
- 多个 key 会进入 key 池，每次查询随机打乱 key 顺序。
- 如果一个 key 请求失败或额度用尽，会继续尝试同服务的下一个 key。

### 风控综合逻辑

数据源：

- 本地规则：`ip-api.com` 富集结果、ASN/运营商/主机名关键词、VPNGate session 数、延迟。
- proxycheck.io：检测 `anonymous`、`proxy`、`vpn`、`tor`、`hosting`、`scraper` 和 `confidence`。
- AbuseIPDB：检测 `abuseConfidenceScore`。

硬剔除规则：

- proxycheck.io 命中 `anonymous`、`proxy`、`vpn`、`tor`。
- AbuseIPDB `abuseConfidenceScore >= 50`。
- 缺失 IP。

普通评分规则：

- 本地规则先生成 `purity_raw_score`。
- proxycheck.io `confidence` 和 AbuseIPDB `abuseConfidenceScore` 会提高风险分。
- 最终输出 `purity_score`，当前默认阈值为 `60`。
- `purity_score > 60` 的节点标记为 `unavailable`，不会参与自动连接。

99% 通过率控制：

- 新增 `PURITY_MIN_PASS_RATIO`，当前默认 `99`。
- 批量测试时，如果通过率低于 99%，会在非硬剔除节点中按原始风险分从低到高进行校准。
- 被校准放行的节点会保留 `purity_raw_score`，并在 `purity_reasons` 中记录 `batch pass-floor calibration 99%`。
- 如果硬剔除节点超过 1%，则无法安全保证总通过率达到 99%，因为硬剔除不会被强行放行。

### 已验证

- 解析到 proxycheck.io key 数：2。
- 解析到 AbuseIPDB key 数：2。
- 当前模拟样例 100 个非硬剔除节点中 99 个通过，满足默认 99% 通过率。
- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

## 2026-06-08 补充：刷新筛选与手动检测路径拆分

### 调整目标

- 点击“更新节点”后执行 IP 纯净度筛选，未通过的节点直接标记为不可用。
- 节点列表“操作”栏保留收藏，并显示“检测”按钮。
- 点击“检测”只做延迟测速，不触发 proxycheck.io、AbuseIPDB 或本地纯净度过滤。
- 手动检测时延迟大于 500ms 或检测超时直接标记为不可用。
- 节点 UI 补齐延迟、物理位置、ASN、运营主体/ISP、网络质量、IP 类型。
- 节点按延迟从低到高排序，国家筛选后仍保持延迟升序。

### 已实现

- `test_node_by_id()` 已改为手动检测专用路径：
  - 只调用 `ping_latency_ms()`。
  - `0ms/超时` 标记不可用。
  - `>500ms` 标记不可用。
  - `<=500ms` 标记可用，并补充 IP 信息。
  - 不调用 `assess_nodes_purity()`，不消耗免费声誉 API 额度。
- `test_multiple_nodes()` 仍是后台刷新/批量维护路径：
  - OpenVPN 连通性检测。
  - 延迟 `>500ms` 或超时标记不可用。
  - 可用节点再执行 IP 信息富集和纯净度评分。
- `sort_all_nodes()` 已改为按 `latency_ms` 升序排序。
- 前端 `stableSortNodes()` 已改为按延迟升序排序，并优先使用活动节点的本地代理出口真实延迟。
- 前端表格在 `render()` 中动态补齐列：
  - 状态
  - 延迟
  - IP 地址 : 端口
  - 物理位置
  - ASN
  - 运营主体 / ISP
  - 网络质量
  - IP 类型
  - 操作
- 操作栏现在会显示：
  - 检测
  - 收藏/已收藏
  - 切换/已连接
- 活动节点卡片延迟优先显示 `proxy_latency_ms`，即本地代理出口检测得到的真实延迟。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

## 2026-06-10 补充：手动 IP 拉黑功能

### 调整目标

- 节点操作栏在“检测”和“收藏”之间新增“拉黑”按钮。
- 工具栏“收藏菜单”旁新增“拉黑菜单”。
- 被手动拉黑的 IP 节点始终标记为 `unavailable`。
- 被拉黑节点即使后续点击“检测”或点击“更新节点”测速通过，也不会改回可用。
- 拉黑菜单支持查看、搜索、手动添加 IP、取消拉黑。

### 已实现

- 新增持久化文件 `vpngate_data/manual_blacklist.json`，与原有临时故障黑名单 `blacklist.json` 分离。
- 后端新增接口：
  - `GET /api/manual_blacklist`
  - `POST /api/manual_blacklist_add`
  - `POST /api/manual_blacklist_remove`
- `read_nodes()` 会自动套用手动黑名单，把命中的 IP 标记为：
  - `manual_blacklisted=true`
  - `probe_status=unavailable`
  - `probe_message=Manual blacklist: <ip>`
- 单节点检测、批量更新写回、节点候选抓取、连接入口均会重新套用手动黑名单规则。
- 如果拉黑当前正在连接的活动节点 IP，会立即断开该节点并标记不可用。
- 前端拉黑菜单支持：
  - 输入框
  - 搜索
  - 添加
  - 搜索返回
  - 取消拉黑
- 搜索仅在已拉黑 IP 内执行；未命中时短暂显示红字“没有这个IP”，列表区域为空。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
- 本地模拟添加 `1.2.3.4` 后，对应节点状态变为 `unavailable` 且 `manual_blacklisted=true`。
- 本地模拟取消拉黑后，手动黑名单列表为空。

## 2026-06-09 补充：真实出口延迟测速方案已实现

### 调整目标

- 不新增额外监听端口。
- 点击“检测”时测当前节点建立 OpenVPN 后的真实出口访问延迟，而不是只测节点入口 TCP 延迟。
- 点击“更新节点”批量检测时也使用同一套真实出口测速逻辑。
- 如果被检测节点已经是当前连接节点，直接复用本地代理网关 `127.0.0.1:7928` 做出口检测，避免重复启动 OpenVPN。

### 已实现

- `run_openvpn_until_ready()` 新增 `keep_process` 参数，允许临时测速连接建立成功后短暂保留进程，测速结束再清理。
- 新增 `measure_interface_egress_latency(dev)`：
  - 通过 `curl --interface tunX` 从临时 OpenVPN 网卡发起 HTTP 探测。
  - 为每个测速目标临时添加 `/32` 主机路由到测试网卡，避免 `route-nopull` 下无默认路由导致测速失败。
  - 测速结束后立即删除临时主机路由，不改变服务器默认出口。
  - 使用多个轻量目标取最优响应时间。
  - 返回真实出口延迟、出口 IP、探测目标和错误信息。
- 新增 `active_node_real_latency(node_id)`：
  - 如果节点已经通过 7928 本地代理处于连接状态，则直接调用现有 `check_proxy_health()`。
  - 表格中的检测按钮和批量更新都会复用这个结果。
- 新增 `test_node_real_egress()` 作为统一测速入口：
  - 当前活动节点：复用 7928 代理出口检测。
  - 非活动节点：启动临时 OpenVPN 到独立 `tunX`，通过该接口测速，测速后立刻释放进程和测试网卡编号。
  - `latency_ms <= 0` 或 `latency_ms > 1000` 直接标记为 `unavailable`。
- `test_node_by_id()` 已改为调用 `test_node_real_egress(..., purity_check=False)`，单个检测不触发纯净度 API。
- `test_multiple_nodes()` 已改为调用同一套真实出口测速逻辑，成功节点之后再走批量 IP 富集和纯净度评分。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

### 下一步计划

1. 部署到真实 Linux VPS 后点击单个“检测”，确认表格延迟与 7928 网关出口自检延迟接近。
2. 点击“更新节点”，观察 `nodes.json` 中 `latency_ms`、`probe_message`、`egress_ip` 是否按真实出口测速更新。
3. 如果个别系统上 `curl --interface tunX` 无法出站，再增加临时策略路由兜底，但当前优先保持“不新增端口”的轻量方案。

## 2026-06-09 补充：风险值阈值与评分模型放宽

### 问题记录

对比 `风险值.txt` 中样例后确认，旧模型会把大量 Ping0 显示为 `2% - 11% 极度纯净` 的日本住宅/宽带节点评为 `90% - 100%`，存在明显错杀。

主要原因：

- 默认剔除阈值 `20%` 过严。
- proxycheck.io 的 `vpn/proxy` 命中被当作硬剔除，容易把 VPNGate 入口节点误判为高风险。
- 本地规则对 `host_name` 中的 `vpn`、共享 session 数、普通运营商关键词惩罚过重。

### 已调整

- 默认通过阈值改为 `PURITY_SCORE_THRESHOLD=60`，即风险值 `<=60%` 通过，`>60%` 才剔除。
- 默认批量通过率保障改为 `PURITY_MIN_PASS_RATIO=99`，确保非硬剔除节点中至少 99% 通过。
- `PURITY_CACHE_VERSION` 升级到 `3`，旧的 90%-100% 缓存不会继续生效。
- 本地评分放宽：
  - 住宅/移动 ISP 基本保持低风险。
  - VPNGate session 数只作为轻微参考，不再大幅抬高风险。
  - 不再因为 `host_name` 中出现 `vpn` 直接加重风险。
  - 数据中心、云厂商、托管网络仍会提高风险值。
- proxycheck.io 评分放宽：
  - `vpn/proxy` 命中不再硬剔除，只提高风险分。
  - 只有 `anonymous/tor` 命中才硬剔除。
- AbuseIPDB 评分放宽：
  - 只有 `abuseConfidenceScore >= 90` 才硬剔除。
  - 中等滥用分只提高风险值，由批量 99% 通过率机制决定是否保留。
- UI 风险值颜色阈值同步调整：
  - `<=60%` 显示为低风险通过色。
  - `61%-84%` 显示为中风险。
  - `>=85%` 显示为高风险。

### 验证结果

- 普通住宅 ISP 模拟评分：`9%`。
- 高共享住宅 ISP 模拟评分：`12%`。
- 典型数据中心云厂商模拟评分：`72%`。
- 100 个非硬剔除高风险节点批量校准后：`99` 个通过，`1` 个保留不可用。
- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

### 下一步计划

1. 部署到 VPS 后重新点击“更新节点”，让缓存版本 `3` 重新计算风险值。
2. 抽样对比 Ping0，如果普通住宅节点仍偏高，继续降低本地 `hosting/datacenter/proxycheck confidence` 权重。
3. 如果高风险节点漏过较多，再只针对 AbuseIPDB 高分、Tor/匿名、强数据中心特征提高权重，不恢复大面积硬剔除。

## 2026-06-09 补充：纯净度过滤临时旁路

### 调整原因

当前免费 API + 本地规则的风险值与 Ping0 对比仍不稳定，容易影响节点可用性判断。因此先临时砍掉纯净度过滤逻辑，保留代码注释以便后续恢复或重做。

### 已调整

- 前端 UI “风险值”列固定显示 `60%`。
- 后端节点数据中的风险字段统一写入：
  - `purity_score=60`
  - `purity_raw_score=60`
  - `purity_grade=disabled`
  - `purity_sources=["disabled"]`
- 点击“更新节点”时不再调用 `vpn_utils.assess_nodes_purity()`。
- 单节点“检测”路径不触发任何纯净度计算。
- 批量更新只做真实出口延迟检测和 IP 信息富集。
- 节点排序不再参考 `purity_score`，只按延迟从低到高排序。
- 延迟阈值改为 `500ms`：
  - `0ms/超时` 标记不可用。
  - `>500ms` 标记不可用。
  - `<=500ms` 标记可用。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

### 下一步计划

1. 部署后点击“更新节点”，确认不会再消耗 proxycheck.io / AbuseIPDB 额度。
2. 观察节点列表是否按真实出口延迟升序排列。
3. 如果后续要恢复纯净度功能，优先重新设计为独立参考列，不参与节点可用性剔除。

## 2026-06-09 补充：固定地区模式故障切换增强

### 调整目标

- 当“IP 出站路由模式”为固定地区时，先限定当前锁定国家地区，再继续遵守“IP 出站类型过滤”的所有 IP / 住宅 IP / 机房 IP 选择。
- 当前活动节点超时或代理不可用后，先触发更新节点、真实出口延迟检测和延迟排序。
- 排序完成后，直接切换到当前锁定地区中延迟最低的可用节点。
- 固定地区模式增加每 30 分钟一次的当前活动节点真实出口延迟巡检。
- 如果巡检发现当前活动节点延迟 `>500ms`，则触发更新节点、延迟排序，并切换到该地区延迟最低节点。

### 已实现

- 新增 `filter_routing_candidates()`：
  - 统一处理自动切换候选节点。
  - 固定地区模式先按国家/地区过滤，再按 `routing_ip_type` 过滤。
  - `routing_ip_type=all`：在当前地区所有可用出口 IP 中选延迟最低节点。
  - `routing_ip_type=residential`：在当前地区住宅/移动 IP 中选延迟最低节点。
  - `routing_ip_type=hosting`：在当前地区机房 IP 中选延迟最低节点。
- 新增 `refresh_and_switch_fixed_region()`：
  - 固定地区专用故障切换入口。
  - 等待正在运行的节点更新任务完成；如果没有正在更新，则主动执行 `maintain_valid_nodes(force=False)`。
  - 更新和排序完成后调用 `auto_switch_node()` 切换到最低延迟节点。
- `background_proxy_checker()` 中固定地区模式的代理不可用处理已改为：
  - 标记当前活动节点不可用。
  - 触发固定地区刷新排序切换。
- 新增 `fixed_region_latency_guard()`：
  - 每 30 分钟运行一次。
  - 仅在固定地区模式、连接开启、当前节点正在运行时生效。
  - 使用现有 `check_proxy_health()` 读取 7928 真实出口延迟。
  - 延迟 `>500ms` 时标记当前节点不可用，并触发固定地区刷新排序切换。

### 已验证

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。
