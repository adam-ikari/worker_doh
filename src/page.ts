/**
 * The config page served at GET /.
 *
 * It creates nothing on the server: it is a form that builds a per-request
 * DoH URL (params defined in opts.ts) and shows it ready to copy. Everything
 * is inline — no build step, no framework — same register as the old landing.
 */

const CORS = {
	"access-control-allow-origin": "*",
	"access-control-allow-methods": "GET, POST, OPTIONS",
	"access-control-allow-headers": "content-type",
};

export function configPage(url: URL): Response {
	const host = escapeHtml(url.host);	const html = `<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoH 配置页</title>
<style>
 body{font-family:system-ui,"PingFang SC","Microsoft YaHei",sans-serif;max-width:48rem;margin:2.5rem auto;padding:0 1.2rem;line-height:1.65;color:#1c1e21}
 h1{font-size:1.5rem;margin-bottom:.2rem}
 .sub{color:#666;margin-top:0}
 label{display:block;margin:1rem 0 .25rem;font-weight:600}
 small.hint{color:#777;font-weight:400}
 input,textarea{width:100%;box-sizing:border-box;padding:.5rem .6rem;border:1px solid #ccc;border-radius:6px;font:inherit}
 textarea{font-family:ui-monospace,monospace;resize:vertical;min-height:4.5rem}
 .out{background:#f6f8fa;border:1px solid #d8dee4;border-radius:8px;padding:.8rem 1rem;margin:.6rem 0;word-break:break-all;font-family:ui-monospace,monospace;font-size:.86rem}
 button{padding:.4rem .9rem;border:1px solid #bbb;border-radius:6px;background:#fff;cursor:pointer;font:inherit}
 button:hover{background:#f0f2f4}
 .row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
 pre#log{background:#0d1117;color:#c9d1d9;padding:.8rem;border-radius:8px;overflow:auto;font-size:.8rem}
 details{margin:1.2rem 0}
 summary{cursor:pointer;font-weight:600}
 table{border-collapse:collapse;width:100%;font-size:.88rem}
 td,th{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}
 code{background:#f0f2f4;padding:.1rem .35rem;border-radius:4px}
 .warn{background:#fff8e1;border:1px solid #f0d982;border-radius:8px;padding:.7rem 1rem;font-size:.9rem}
</style></head><body>
<h1>DoH 配置页</h1>
<p class="sub">RFC 8484 · 边缘缓存 · 最快上游自动选择 &nbsp;|&nbsp; 端点：<code>https://${host}/dns-query</code></p>

<div class="out"><div class="row"><span id="doh" style="flex:1"></span>
<button data-copy="doh">复制 DoH URL</button></div></div>
<p class="sub" style="font-size:.85rem">把上面的 URL 填进浏览器/系统的「安全 DNS」。改配置 = 生成新 URL、重新粘贴；服务端不保存任何东西。</p>

<label>封禁域名 <small class="hint">逗号分隔，子域一并封禁（block=）</small></label>
<textarea id="block" placeholder="ads.example.com, tracker.example.net"></textarea>

<label>域名固定解析 <small class="hint">每行一条，域名/IP（host=）</small></label>
<textarea id="host" placeholder="router.home/192.168.1.1&#10;nas.home/192.168.1.9"></textarea>

<label>上游 DoH 覆盖 <small class="hint">逗号分隔，仅 https，留空则用服务器默认（up=）</small></label>
<input id="up" placeholder="https://dns.google/dns-query">

<label>订阅 blocklist <small class="hint">逗号分隔 URL，adblock/hosts/dnsmasq 格式（list=）</small></label>
<input id="list" placeholder="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts">

<h2 style="font-size:1.1rem;margin-top:1.6rem">等价 /p/ 形式</h2>
<div class="out"><div class="row"><span id="purl" style="flex:1"></span>
<button data-copy="purl">复制</button></div></div>
<p class="sub" style="font-size:.85rem">配置编码在路径里（<code>/p/&lt;base64url&gt;</code>），URL 更短、不含明文域名。需要纯路径请求时可用
<code>/p/&lt;查询&gt;|&lt;配置&gt;</code>（两段各自 base64url、以 <code>|</code> 分隔）。</p>

<h2 style="font-size:1.1rem">在线测试</h2>
<div class="row">
 <input id="tq" value="example.com" style="flex:2" placeholder="域名">
 <select id="tt" style="flex:0"><option>A</option><option>AAAA</option><option>TXT</option><option>CNAME</option><option>MX</option></select>
 <button id="go">查询</button>
</div>
<pre id="log">—</pre>

<details><summary>使用说明 / 参数含义</summary>
<table>
<tr><th>参数</th><th>作用</th></tr>
<tr><td><code>block</code></td><td>逗号分隔域名，命中返回 NXDOMAIN，后缀匹配（<code>x.com</code> 含子域）</td></tr>
<tr><td><code>host</code></td><td><code>域名/IP</code> 逗号（或换行）分隔，固定 A 应答</td></tr>
<tr><td><code>up</code></td><td>本次请求的上游 DoH 列表（https、最多 8 个），覆盖服务器默认</td></tr>
<tr><td><code>list</code></td><td>远程 blocklist URL（最多 4 个），内容同服务器订阅格式，结果缓存 10 分钟</td></tr>
</table>
<p>客户端接入：浏览器「安全 DNS」直接粘贴 DoH URL；Chrome/Edge 命令行
<code>--custom-profile --dns-over-https-mode=secure --dns-over-https-server="…"</code>；
macOS 描述文件 <code>DNSOverride</code>；Linux 用 <code>doh-proxy</code>/stubby 转发到本端点。</p>
</details>

<div class="warn"><b>注意</b>：配置随 URL 明文传输、无鉴权。任何拿到该 URL 的人即可看到并复用你的
block/host/up/list；请勿在 URL 中使用含有隐私的内部域名。需要隐藏时改用上方 <code>/p/</code> 形式（仅编码，不加密）。</div>

<script>${JS}</script>
</body></html>`;
	return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8", ...CORS } });
}

const JS = String.raw`
const $ = (id) => document.getElementById(id);
function readHosts() {
  return $("host").value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean).join(",");
}
function buildParams() {
  const p = new URLSearchParams();
  const b = $("block").value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean).join(",");
  if (b) p.set("block", b);
  const h = readHosts();
  if (h) p.set("host", h);
  const u = $("up").value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean).join(",");
  if (u) p.set("up", u);
  const l = $("list").value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean).join(",");
  if (l) p.set("list", l);
  return p;
}
function b64url(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x2000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x2000));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function refresh() {
  const p = buildParams();
  const qs = p.toString();
  const origin = location.origin;
  $("doh").textContent = origin + "/dns-query" + (qs ? "?" + qs : "");
  const cfg = b64url(qs ? "?" + qs : "");
  $("purl").textContent = cfg ? origin + "/p/" + cfg : origin + "/dns-query";
}
["block", "host", "up", "list"].forEach(id => $(id).addEventListener("input", refresh));
document.querySelectorAll("[data-copy]").forEach(btn => btn.addEventListener("click", async () => {
  const t = $(btn.dataset.copy).textContent;
  try { await navigator.clipboard.writeText(t); btn.textContent = "已复制"; setTimeout(() => btn.textContent = "复制" + (btn.dataset.copy === "doh" ? " DoH URL" : ""), 1200); }
  catch { prompt("手动复制:", t); }
}));
async function test() {
  const p = buildParams();
  p.set("name", $("tq").value.trim());
  p.set("type", $("tt").value);
  $("log").textContent = "查询中…";
  try {
    const r = await fetch("/?" + p.toString());
    $("log").textContent = r.status + "\n" + JSON.stringify(await r.json(), null, 2);
  } catch (e) { $("log").textContent = "失败: " + e; }
}
$("go").addEventListener("click", test);
$("tq").addEventListener("keydown", e => { if (e.key === "Enter") test(); });
refresh();
`;

function escapeHtml(s: string): string {
	return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
