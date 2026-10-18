---
id: stateless-config-model
title: "配置模型：无状态、每请求 URL 参数"
category: decision
status: active
created: "2026-10-18T04:51:05"
updated: "2026-10-18T05:21:15"
---

<!-- compiled_truth -->
DoH worker 的用户级配置完全无状态：配置编码在请求 URL 的 query 参数里（`block` 封禁域、`host` 固定 A 应答、`up` 上游覆盖、`list` 远程 blocklist），由 `src/opts.ts` 统一解析/校验/编码，服务端不保存任何配置。

要点：
- 配置页 `GET /`（`src/page.ts`）只是一个拼参数、生成 DoH URL 供复制的静态表单，不写任何存储；改配置 = 换新 URL 重新粘贴到客户端。
- 参数与 wrangler vars 的部署级配置是**并集**语义：env 规则始终作底，URL 参数叠加其上。这保证无参数请求行为与旧版完全一致。
- `block`/`host`/`up`/`list` 四个键、逗号分隔；`host` 用 `域名/IP` 形式；`/p/<base64url>` 路径形式承载配置（明文域名不暴露），载荷 `?<config>`（query 走 ?dns= 或 POST）或 `<wire-b64>|<config>`。
- **上游转发不变量（评审确立）**：`block`/`host` 里是用户最隐私的自定义域名，任何转发给第三方上游的请求（wire 和 JSON）只允许携带 DNS 问题本身（name/type/do/edns_client_subnet），配置参数一律不得外泄。`handleJson` 用白名单重建 params，不是复制 searchParams。
- 边缘缓存按配置集分区：有 opts 时 cacheKey 追加规范化参数的 SHA-256 前 8 hex（`optsHash`），实测同域名带/不带参数互不污染；isolate 内 inflight 去重 key 同样带 hash，防止纯请求与过滤请求并发串扰（= 规则绕过）。
- 无鉴权是用户的明确取舍（三问中答"nothing"）。因此任何会让 worker 发外部请求的参数（`up`/`list`）都硬校验：仅 https、禁 IP 字面量（含 IPv6）、禁 localhost 与内网 TLD（.lan/.internal/.local…）、禁自带 query/hash（防参数拼接注入路径）、条目数上限（up≤8、list≤4、block≤200、host≤100）。`list` 正文解析上限 2MB。已知残余：list 用 redirect:follow，重定向目标不经我们的校验（Workers 的 opaqueredirect 不可读，无法手动校验 Location；CF 网络层 IP 策略兜底）。
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
