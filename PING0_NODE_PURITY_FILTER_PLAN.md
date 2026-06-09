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

- 默认保守阈值：`purity_score < 20` 保留。
- `20 <= purity_score < 40` 标记为中性，默认不自动连接，但可在 UI 中展示。
- `purity_score >= 40` 剔除或标记不可用。

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
4. 默认过滤 `purity_score >= 20` 的节点，但保留环境变量允许调节阈值。
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

- `PURITY_SCORE_THRESHOLD`，默认 `20`。
- `PURITY_CACHE_TTL_SECONDS`，默认 7 天。
- `PURITY_ENABLE_PROXYCHECK`，默认关闭，设置为 `1/true/yes/on` 后启用无 key proxycheck.io 查询。
- `PROXYCHECK_API_KEY`，配置后启用 proxycheck.io，免费 key 可提升额度。
- `ABUSEIPDB_API_KEY`，配置后启用 AbuseIPDB。
- `purity_cache.json` 缓存。
- `assess_ip_purity()` 和 `assess_nodes_purity()`。

本地评分已使用：

- 现有 `ip-api.com` 富集后的 `ip_type` 和 `quality`。
- ASN、运营主体、主机名、远端主机名关键词。
- VPNGate `sessions` 作为共享程度参考。
- 延迟作为弱风险参考。

已在 `vpngate_manager.py` 接入：

- 新节点默认包含 `purity_score`、`purity_grade`、`purity_reasons`、`purity_sources`、`purity_checked_at`。
- 单节点测试成功后执行纯净度评分。
- 批量节点测试成功后执行纯净度评分。
- `purity_score >= PURITY_SCORE_THRESHOLD` 的节点会被标记为 `unavailable`，不会参与自动连接。
- 可用节点排序时会优先选择更低 `purity_score` 的节点。

### 验证结果

- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

### 后续建议

1. 在真实 VPS 环境跑一次节点刷新，观察 `vpngate_data/nodes.json` 中的 `purity_score` 和 `probe_message`。
2. 根据误杀情况调节 `PURITY_SCORE_THRESHOLD`，例如先用 `30` 观察，再收紧到 `20`。
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
- 最终输出 `purity_score`，默认阈值为 `20`。
- `purity_score >= 20` 的节点标记为 `unavailable`，不会参与自动连接。

60% 通过率控制：

- 新增 `PURITY_MIN_PASS_RATIO`，默认 `60`。
- 批量测试时，如果通过率低于 60%，会在非硬剔除节点中按原始风险分从低到高进行校准。
- 被校准放行的节点会保留 `purity_raw_score`，并在 `purity_reasons` 中记录 `batch pass-floor calibration 60%`。
- 如果硬剔除节点超过 40%，则无法安全保证总通过率达到 60%，因为硬剔除不会被强行放行。

### 已验证

- 解析到 proxycheck.io key 数：2。
- 解析到 AbuseIPDB key 数：2。
- 批量样例 10 个节点中 6 个通过，满足默认 60% 通过率。
- 已运行 `python -m py_compile vpn_utils.py vpngate_manager.py proxy_server.py`，语法检查通过。

## 2026-06-08 补充：刷新筛选与手动检测路径拆分

### 调整目标

- 点击“更新节点”后执行 IP 纯净度筛选，未通过的节点直接标记为不可用。
- 节点列表“操作”栏保留收藏，并显示“检测”按钮。
- 点击“检测”只做延迟测速，不触发 proxycheck.io、AbuseIPDB 或本地纯净度过滤。
- 手动检测时延迟大于 1000ms 或检测超时直接标记为不可用。
- 节点 UI 补齐延迟、物理位置、ASN、运营主体/ISP、网络质量、IP 类型。
- 节点按延迟从低到高排序，国家筛选后仍保持延迟升序。

### 已实现

- `test_node_by_id()` 已改为手动检测专用路径：
  - 只调用 `ping_latency_ms()`。
  - `0ms/超时` 标记不可用。
  - `>1000ms` 标记不可用。
  - `<=1000ms` 标记可用，并补充 IP 信息。
  - 不调用 `assess_nodes_purity()`，不消耗免费声誉 API 额度。
- `test_multiple_nodes()` 仍是后台刷新/批量维护路径：
  - OpenVPN 连通性检测。
  - 延迟 `>1000ms` 或超时标记不可用。
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
