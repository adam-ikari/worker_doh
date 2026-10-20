---
id: stateless-config-model
title: "配置模型：无状态、每请求 URL 参数"
category: decision
status: active
created: "2026-10-18T04:51:05"
updated: "2026-10-20T09:16:16"
---

<!-- compiled_truth -->
DoH worker 的用户级配置完全无状态：配置编码在请求 URL 的 query 参数里（`block` 封禁域、`allow` 白名单例外、`host` 固定应答、`bm` 拦截模式、`up` 上游覆盖、`list` 远程过滤器订阅），由 `src/opts.ts` 统一解析/校验/编码，服务端不保存任何配置。

要点：
- 配置页 `GET /`（`src/page.ts`）只是一个拼参数、生成 DoH URL 供复制的静态表单，不写任何存储；改配置 = 换新 URL 重新粘贴到客户端。表单内容存浏览器 localStorage（纯客户端持久，服务端仍无状态）。
- 参数与 wrangler vars 的部署级配置是**并集**语义：env 规则始终作底，URL 参数叠加其上。这保证无参数请求行为与旧版完全一致。
- `block`/`allow`/`host`/`up`/`list` 五个键、逗号分隔；`host` 用 `域名/目标` 形式：IPv4→A、IPv6→AAAA、目标域名→CNAME（CNAME 对任意查询族优先）；`bm` 覆盖部署级 `BLOCK_MODE`；`/p/<base64url>` 路径形式承载配置（明文域名不暴露），载荷 `?<config>`（query 走 ?dns= 或 POST）或 `<wire-b64>|<config>`。
- **过滤器语法（仿 AdGuard Home，用户确认只取域名级子集）**：`||dom^`、裸域名、`0.0.0.0 dom` / `:: dom`、`*.dom` → 拦截（后缀匹配）；`@@||dom^` → 例外白名单；订阅内 `/pattern/`、`@@/pattern/` → 大小写不敏感正则拦截/例外（pattern ≤128 字符，编译失败跳过；**仅订阅生效**，URL `block=` 仍是纯域名表）；`address=/dom/ip`、hosts `ip dom` → 固定 A/AAAA，`address=/dom/target` → CNAME。跳过并容忍：全正则 `~`、`$` 修饰符 ABP 过滤（如 `$important`）、`##` cosmetic 规则。env `BLOCKLIST_URL` 支持逗号分隔多订阅（各自 6h 刷新）。
- **优先级不变量**：allowed > 固定解析 > blocked > 上游解析。白名单沿标签树向上爬升匹配（域名后缀与 allowRx 正则），`@@||example.com^` 放行其下所有子域的拦截与固定应答（`lookupFixed` 先查 allowed 祖先/allowRx 再查固定表）。固定解析只对查询族出 A/AAAA；某族无记录则该族走上游。
- **拦截应答模式**：默认 NXDOMAIN；`refused`→RCODE 5；`noaddr`→NOERROR 空应答；IP 字面量→按查询族给 A/AAAA（另一族空 NOERROR）。wire 与 JSON 路径语义一致（JSON Status 3/5/0 + 可选 Answer）；wire 拦截应答边缘缓存 60s，固定应答 TTL 300s。
- **上游转发不变量（评审确立）**：`block`/`allow`/`host` 里是用户最隐私的自定义域名，任何转发给第三方上游的请求（wire 和 JSON）只允许携带 DNS 问题本身（name/type/do/edns_client_subnet），配置参数一律不得外泄。`handleJson` 用白名单重建 params，不是复制 searchParams。
- 边缘缓存按配置集分区：有 opts 时 cacheKey 追加规范化参数的 SHA-256 前 8 hex（`optsHash`），`bm` 仅在非空时进入规范串 `m=`（未用该参数时 hash 与旧版一致，零漂移）；实测同域名带/不带参数互不污染；isolate 内 inflight 去重 key 同样带 hash，防止纯请求与过滤请求并发串扰（= 规则绕过）。
- 无鉴权是用户的明确取舍（三问中答"nothing"）。因此任何会让 worker 发外部请求的参数（`up`/`list`）都硬校验：仅 https、禁 IP 字面量（含 IPv6）、禁 localhost 与内网 TLD（.lan/.internal/.local…）、禁自带 query/hash（防参数拼接注入路径）、条目数上限（up≤8、list≤4、block/allow≤200、host≤100）。`list` 正文解析上限 2MB。已知残余：list 用 redirect:follow，重定向目标不经我们的校验（Workers 的 opaqueredirect 不可读，无法手动校验 Location；CF 网络层 IP 策略兜底）。
- `host`/`address=` 目标校验：数字点分但非法 IPv4（如 999.1.1.1）一律拒绝或按拦截处理，不会被误当 CNAME 目标。
- 指定 `up` 的请求不参与 sticky 最快上游选择（每次按给定列表 race），也不复用全局 sticky 结果。
- 已知残余风险：任何人拿到带参 URL 即可看见并复用该配置（隐私域名泄露、开放代理/SSRF 面被缩小但未消除）。若日后要求保密或持久化，方向是 KV 存储 + URL 携带配置 ID（见 timeline）。


## Timeline

- time: 2026-10-18T04:51:05
  kind: decision
  summary: "Created this page: 配置模型：无状态、每请求 URL 参数"
  source: "2026-10-18 与用户的设计问答（配置页面需求）"
  affects: [stateless-config-model]

- time: 2026-10-18T04:51:24
  kind: decision
  summary: "决策落地：配置走 URL 参数、KV/鉴权方案被否决"
  source: "2026-10-18 用户 AskUserQuestion 三问 + 实施验证"
  affects: [stateless-config-model]

- time: 2026-10-18T05:21:15
  kind: decision
  summary: "评审后新增不变量：JSON 上游请求只转发 name/type，配置参数禁止外泄"
  source: "2026-10-18 代码评审（handleJson 泄漏 block/host 到上游）"
  affects: [stateless-config-model]

- time: 2026-10-18T05:58:07
  kind: decision
  summary: Rewrote compiled_truth to the new best understanding
  source: "2026-10-18 订阅域名过滤（仿 AGH）实施"
  affects: [stateless-config-model]

- time: 2026-10-18T05:58:07
  kind: decision
  summary: "订阅过滤对齐 AGH：域名级语法子集（||dom^/*.dom/@@例外/hosts/address=，跳过正则与$修饰符与##），优先级不变量 allowed>hosts>blocked>上游，BLOCKLIST_URL 多源逗号分隔；dev 实测发现并修复 list→env 合并丢 hosts 的缺陷"
  source: "2026-10-18 订阅域名过滤（仿 AGH）实施 + dev 实测"
  affects: [stateless-config-model]

- time: 2026-10-18T06:39:35
  kind: decision
  summary: "地区上游选择=纯部署级 env（UPSTREAM_REGIONS \"码=URL;码=URL\"），刻意不进 URL 参数：地区由 Cloudflare 从客户端 IP 得出（cf.country/cf.continent），非用户配置；匹配优先级 up= > 国家码 > 大洲码 > UPSTREAM_DOH；两位码先按国家解析（NA 兼指纳米比亚与北美）。不变量：每个地区档（bucket cXX/kXX/g）独立 sticky 与边缘缓存分区，未配置时 bucket 为空、缓存 key 与旧版逐字节一致"
  source: "2026-10-18 按地区上游选择实施"
  affects: [stateless-config-model]

- time: 2026-10-18T16:01:02
  kind: decision
  summary: "配置页 UI 重设计为「DoH 控制台」：双主题（prefers-color-scheme + 三态手动切换）、高级规则编辑器（AGH 语法在浏览器端映射为 block/allow/host 参数，服务端零改动、语义不变）、在线测试面板渲染 rcode 徽章/记录表格、平台接入片段 tabs。规则编辑器仅是客户端参数生成器，服务端仍不认识 AGH 原文。"
  source: "src/page.ts 重写 + scripts/test.ts 内联 JS 语法校验"
  affects: [src/page.ts]

- time: 2026-10-20T07:49:06
  kind: decision
  summary: "出站查询防客户端 IP 泄漏（零配置常开）：ECS 前缀截断粗化到 v4 /8、v6 /32（区域保留、精度移除，RFC 7871 低位清零），剥离 Client/Server Cookie、Padding、Client Tag，查询 ID 随机化并在应答回写客户端原 ID；JSON API 的 edns_client_subnet 同样粗化。顺带修复既有 bug：edge cache HIT 曾把首个请求者的响应 ID 发给所有客户端（严格 DoH 客户端会拒收），现统一出口重写。"
  source: src/dnsmsg.ts scrubQuery/randomId/setMsgId/coarseEcsParam
  affects: [src/dnsmsg.ts, src/index.ts]

- time: 2026-10-20T09:15:57
  kind: decision
  summary: "compiled_truth 更新：host 支持 AAAA/CNAME、新增 bm 拦截模式、订阅正则"
  source: "src/opts.ts, src/rules.ts, src/dnsmsg.ts"
  affects: [stateless-config-model]

- time: 2026-10-20T09:16:03
  kind: decision
  summary: "三特性批次：①host=/address= 扩展 IPv6→AAAA 与目标域→CNAME（lookupFixed 按查询族取记录、CNAME 任意族优先、allow 后缀/正则禁用固定解析，非法数字点分不当 CNAME）；②拦截模式 bm= / BLOCK_MODE：nxdomain/refused/noaddr/IP，IP 按族应答另一族空 NOERROR，wire 与 JSON 同语义；③订阅内 /regex/ 与 @@/regex/（i、≤128，仅订阅，block= 仍纯域名表）。优先级保持 allow > 固定 > block > 上游；bm 仅在非空时进 cache hash，保证未用参数时零漂移。"
  source: "src/dnsmsg.ts buildReply answers; src/rules.ts lookupFixed/regex; src/opts.ts bm; dev E2E 18 checks"
  affects: [src/dnsmsg.ts, src/rules.ts, src/opts.ts, src/index.ts, src/page.ts]

- time: 2026-10-20T09:16:16
  kind: note
  summary: "订阅正则的残余风险：pattern 仅限长度 ≤128 的 JS RegExp（i 标志），未做灾难性回溯分析；恶意 list= 订阅可提供 /(a+)+$/ 之类模式，对每个查询名消耗 CPU，目前仅靠 Workers CPU 限额兜底。若要收紧，可做嵌套量词/回溯模式静态拒绝或改用 RE2 子集。"
  source: "三特性实施评审"
  affects: [src/rules.ts]
