---
slug: flow
title: Key flows
role: key flows
updated: "2026-10-18T04:51:58"
---

# Key flows

## 带配置参数的 wire 查询（主路径）

```mermaid
sequenceDiagram
  participant C as 客户端（浏览器 DoH）
  participant W as index.ts
  participant O as opts.ts
  participant R as rules.ts
  participant E as 边缘缓存
  participant U as upstream.ts
  C->>W: GET /dns-query?dns=<b64wire>&block=ads.x&up=https://dns.google/dns-query
  W->>O: parseOpts(searchParams)
  alt 参数非法
    O-->>W: {ok:false} → 400 文本
  end
  W->>R: getRulesFor(env, opts)（env 并集 + list 拉取）
  alt 命中 block / host
    W-->>C: buildReply NXDOMAIN / A（cacheKey 含 optsHash）
  else 未命中
    W->>E: cache.match(key+optsHash)
    alt MISS
      W->>U: resolveWire(query, opts.up 覆盖、不粘滞)
      U-->>W: 最快上游应答
      W->>E: cache.put(clone, max-age=min TTL)
    end
    W-->>C: application/dns-message
  end
```

## 配置页（GET /）

浏览器 `GET /` → `page.ts` 返回内联 HTML；表单输入 block/host/up/list 时前端用 `optsToParams` 同规则拼
`/dns-query?...` 与 `/p/<base64url("?config")>` 两种 URL 供复制；「在线测试」按钮 fetch `/?name=…`（JSON 路径，同样吃配置参数）。服务端无写入、无状态。

## /p/ 路径形式

- `/p/<b64url("?block=…")>` + `?dns=` 或 POST body：配置在路径、查询在别处。
- `/p/<b64url("<wire-b64url>|?config")>`：纯路径请求（`|` 分隔，因 `?`/`&` 会被 URL 层吃掉）。
