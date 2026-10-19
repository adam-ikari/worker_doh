/**
 * The config page served at GET /.
 *
 * It creates nothing on the server: it is a form that builds a per-request
 * DoH URL (params defined in opts.ts) and shows it ready to copy. Everything
 * is inline — no build step, no framework. The advanced-rules editor maps
 * AGH-style syntax onto the existing block/allow/host params client-side.
 */

const CORS = {
	"access-control-allow-origin": "*",
	"access-control-allow-methods": "GET, POST, OPTIONS",
	"access-control-allow-headers": "content-type",
};

export function configPage(url: URL): Response {
	const host = escapeHtml(url.host);
	const html = `<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoH 控制台</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1c1e21;--muted:#66707f;--line:#e2e6ea;--accent:#2563eb;--accentsoft:#e8efff;--ok:#0f7b3f;--oksoft:#e1f5e8;--warn:#8a5a00;--warnsoft:#fdf1d3;--err:#b42318;--errsoft:#fbe9e7;--code:#eef1f4;color-scheme:light}
@media (prefers-color-scheme: dark){:root:not([data-theme]){--bg:#0b0f14;--panel:#141a21;--ink:#d8dee6;--muted:#8b96a5;--line:#242e3a;--accent:#6ea8fe;--accentsoft:#1c2a44;--ok:#57d38c;--oksoft:#12341f;--warn:#e0b64c;--warnsoft:#332a10;--err:#f2777a;--errsoft:#3a1616;--code:#1a222c;color-scheme:dark}}
:root[data-theme=dark]{--bg:#0b0f14;--panel:#141a21;--ink:#d8dee6;--muted:#8b96a5;--line:#242e3a;--accent:#6ea8fe;--accentsoft:#1c2a44;--ok:#57d38c;--oksoft:#12341f;--warn:#e0b64c;--warnsoft:#332a10;--err:#f2777a;--errsoft:#3a1616;--code:#1a222c;color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,"PingFang SC","Microsoft YaHei",sans-serif;max-width:64rem;margin:0 auto;padding:1.6rem 1.2rem 3rem;line-height:1.6;color:var(--ink);background:var(--bg)}
header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}
h1{font-size:1.45rem;margin:0}
.sub{color:var(--muted);margin:.15rem 0 0;font-size:.9rem}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:.1rem .35rem;border-radius:4px;font-size:.88em}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem;margin:1rem 0}
.card h2{font-size:.98rem;margin:0 0 .6rem;font-weight:650}
.card h2 small{color:var(--muted);font-weight:400;font-size:.76rem;margin-left:.4rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 .9rem}
.grid .wide{grid-column:1/-1}
@media (max-width:760px){.grid{grid-template-columns:1fr}}
textarea,input,select{width:100%;padding:.5rem .6rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
textarea{font-family:ui-monospace,monospace;font-size:.85rem;resize:vertical;min-height:4.2rem}
textarea:focus,input:focus{outline:2px solid var(--accentsoft);border-color:var(--accent)}
::placeholder{color:var(--muted);opacity:.7}
.row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
button{padding:.38rem .8rem;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);cursor:pointer;font:inherit;font-size:.86rem}
button:hover{border-color:var(--accent);color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{opacity:.9;color:#fff}
.out{position:sticky;top:.6rem;z-index:5;box-shadow:0 6px 18px -12px rgba(0,0,0,.35)}
.out .url{flex:1;min-width:0;overflow-wrap:anywhere;font-size:.86rem}
.chip{font-size:.74rem;color:var(--muted);border:1px solid var(--line);border-radius:99px;padding:.05rem .55rem;white-space:nowrap}
.chip.warnlong{color:var(--warn);border-color:var(--warn);background:var(--warnsoft)}
.hint{color:var(--muted);font-size:.8rem;margin:.55rem 0 0}
.purlrow{font-size:.78rem;color:var(--muted)}
.purlrow .url{overflow-wrap:anywhere}
.tag{display:inline-block;font-size:.72rem;border-radius:5px;padding:.02rem .45rem;margin-right:.45rem;vertical-align:.08rem}
.tag.block{background:var(--errsoft);color:var(--err)}
.tag.allow{background:var(--oksoft);color:var(--ok)}
.tag.host{background:var(--accentsoft);color:var(--accent)}
.tag.skip{background:var(--warnsoft);color:var(--warn)}
.tag.bad{background:var(--errsoft);color:var(--err)}
.tag.comment{background:var(--code);color:var(--muted)}
.rulestat{margin-top:.6rem;font-size:.82rem;max-height:14rem;overflow:auto}
.rulestat .ln{display:block;padding:.14rem 0;border-bottom:1px dashed var(--line);font-family:ui-monospace,monospace;overflow-wrap:anywhere}
.rulestat .ln:last-child{border-bottom:0}
.rulestat .sum{color:var(--muted);font-size:.78rem;margin-bottom:.35rem}
.badge{display:inline-block;font-size:.78rem;font-weight:650;border-radius:99px;padding:.1rem .7rem;margin-right:.5rem}
.badge.ok{background:var(--oksoft);color:var(--ok)}
.badge.err{background:var(--errsoft);color:var(--err)}
.badge.warn{background:var(--warnsoft);color:var(--warn)}
table{border-collapse:collapse;width:100%;font-size:.84rem;margin-top:.5rem}
td,th{border:1px solid var(--line);padding:.32rem .55rem;text-align:left;vertical-align:top}
th{background:var(--code);font-weight:600}
pre.raw{background:var(--code);padding:.7rem;border-radius:8px;overflow:auto;font-size:.78rem}
details{margin:1rem 0}
summary{cursor:pointer;font-weight:600;color:var(--ink)}
.warn{background:var(--warnsoft);border:1px solid var(--warn);border-radius:10px;padding:.7rem 1rem;font-size:.86rem;margin:1rem 0}
.tabs{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:.5rem}
.tabs button.on{background:var(--accent);border-color:var(--accent);color:#fff}
.tabs button.on:hover{color:#fff}
#tres{margin-top:.6rem}
#tres .meta{font-size:.8rem;color:var(--muted)}
.empty{color:var(--muted);font-size:.85rem}
</style></head><body>
<header>
 <div><h1>DoH 控制台</h1>
 <p class="sub">RFC 8484 · 边缘缓存 · 最快上游 / 地区选择 &nbsp;|&nbsp; 端点 <code>https://${host}/dns-query</code></p></div>
 <button id="theme" title="切换配色">◐ 主题 · 系统</button>
</header>

<section class="card out">
 <div class="row"><span id="doh" class="url mono"></span><span id="len" class="chip"></span>
 <button class="primary" data-copy="doh">复制 DoH URL</button></div>
 <div class="row purlrow" style="margin-top:.5rem"><span id="purl" class="url mono"></span>
 <button data-copy="purl">复制 /p/ 形式</button></div>
 <p class="hint">把 URL 填进浏览器/系统的「安全 DNS」。改配置 = 生成新 URL 重新粘贴；服务端不保存任何东西。表单内容自动存浏览器本地。</p>
</section>

<div class="grid">
 <section class="card"><h2>封禁域名 <small>block= · 含子域</small></h2>
 <textarea id="block" placeholder="ads.example.com, tracker.example.net"></textarea></section>

 <section class="card"><h2>例外域名 <small>allow= · 白名单，优先级最高</small></h2>
 <textarea id="allow" placeholder="cdn.example.com&#10;mail.example.net"></textarea></section>

 <section class="card wide"><h2>域名固定解析 <small>host= · 每行 域名/IP</small></h2>
 <textarea id="host" placeholder="router.home/192.168.1.1&#10;nas.home/192.168.1.9"></textarea></section>

 <section class="card"><h2>上游 DoH 覆盖 <small>up= · 仅 https · ≤8 个</small></h2>
 <textarea id="up" placeholder="https://dns.google/dns-query"></textarea></section>

 <section class="card"><h2>订阅过滤器 <small>list= · ≤4 个 · 每行一个 URL</small></h2>
 <textarea id="list" placeholder="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"></textarea></section>

 <section class="card wide"><h2>高级规则 <small>AdGuard 语法 · 在浏览器里映射为 block/allow/host 参数</small></h2>
 <textarea id="rules" placeholder="||ads.example.com^&#10;@@||cdn.example.com^&#10;address=/nas.home/192.168.1.9&#10;0.0.0.0 tracker.example.net" style="min-height:7rem"></textarea>
 <div id="rulestat" class="rulestat"></div></section>
</div>

<section class="card"><h2>在线测试 <small>走 JSON API · 自动带上方当前配置</small></h2>
 <div class="row">
  <input id="tq" value="example.com" style="flex:2" placeholder="域名">
  <select id="tt" style="flex:0"><option>A</option><option>AAAA</option><option>TXT</option><option>CNAME</option><option>MX</option></select>
  <button id="go" class="primary">查询</button>
 </div>
 <div id="tres"><p class="empty">—</p></div>
</section>

<section class="card"><h2>客户端接入片段 <small>使用上方当前 URL</small></h2>
 <div class="tabs" id="tabs"></div>
 <pre class="raw" id="snippet"></pre>
 <div class="row" style="margin-top:.5rem"><button data-copy="snippet">复制片段</button></div>
</section>

<details><summary>使用说明 / 参数含义</summary>
<table>
<tr><th>参数</th><th>作用</th></tr>
<tr><td><code>block</code></td><td>逗号分隔域名，命中返回 NXDOMAIN，后缀匹配（<code>x.com</code> 含子域）</td></tr>
<tr><td><code>allow</code></td><td>白名单例外，优先级高于 block 与 host 固定应答（含父域例外）</td></tr>
<tr><td><code>host</code></td><td><code>域名/IP</code> 逗号（或换行）分隔，固定 A 应答</td></tr>
<tr><td><code>up</code></td><td>本次请求的上游 DoH 列表（https、≤8），覆盖服务器默认与地区规则</td></tr>
<tr><td><code>list</code></td><td>远程过滤器订阅 URL（≤4），语法见下，结果缓存 10 分钟</td></tr>
<tr><td><em>高级规则</em></td><td>仅本页生效的输入助手：逐行解析后并入 block/allow/host 参数，服务端没有对应的新语义</td></tr>
</table>
<p>过滤器订阅 / 高级规则支持的语法（域名级子集，仿 AdGuard Home）：
<code>||域^</code> 拦截、<code>*.域</code> 通配、<code>@@||域^</code> 例外、hosts 文件
<code>0.0.0.0 域</code> / <code>IP 域</code>、dnsmasq <code>address=/域/IP</code>；
正则 <code>~</code>、<code>$</code> 修饰符、<code>##</code> 元素规则自动跳过。
优先级：例外 &gt; 固定解析 &gt; 拦截 &gt; 上游解析。</p>
<p>表单内容保存在<b>本浏览器</b>（localStorage），下次打开自动恢复；服务器依旧无状态。</p>
</details>

<div class="warn"><b>注意</b>：配置随 URL 明文传输、无鉴权。任何拿到该 URL 的人即可看到并复用你的
block/allow/host/up/list；请勿在 URL 中使用含隐私的内部域名。需要隐藏时改用 <code>/p/</code> 形式（仅编码，不加密）。
地区上游（<code>UPSTREAM_REGIONS</code>）由 Cloudflare 依据你的源 IP 判定，属于部署级配置，不在本页设置。</div>

<script>${JS}</script>
</body></html>`;
	return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8", ...CORS } });
}

const JS = String.raw`
var $ = function (id) { return document.getElementById(id); };
var FIELDS = ["block", "allow", "host", "up", "list", "rules"];
var LS = "doh-config-page", LST = "doh-ui-theme";

function splitList(el) {
  return el.value.split(/[\s,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
}
function dedup(arr) {
  var seen = {}, out = [];
  for (var i = 0; i < arr.length; i++) {
    var d = String(arr[i]).toLowerCase();
    if (!seen[d]) { seen[d] = 1; out.push(d); }
  }
  return out;
}
function isIpv4(s) {
  var p = s.split(".");
  return p.length === 4 && p.every(function (x) { return /^\d{1,3}$/.test(x) && +x <= 255; });
}
var DOK = /^[a-z0-9._-]+$/;
function normDom(s) {
  return s.replace(/^\*\./, "").replace(/^\|\|/, "").replace(/\^.*$/, "").toLowerCase().replace(/\.+$/, "");
}

// AGH-syntax subset mapped onto the existing params: {block, allow, hosts, rows}
function parseRules(text) {
  var r = { block: [], allow: [], hosts: [], rows: [] };
  var lines = text.split(/\r?\n|\f/);
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line) continue;
    if (/^[#;!]/.test(line)) { r.rows.push({ k: "comment", t: line }); continue; }
    if (/^(##|#@#|~)/.test(line)) { r.rows.push({ k: "skip", t: "元素/正则规则，DNS 层不支持 — " + line }); continue; }
    if (line.indexOf("@@") === 0) {
      var ad = normDom(line.slice(2).split("$")[0]);
      if (DOK.test(ad)) { r.allow.push(ad); r.rows.push({ k: "allow", t: ad }); }
      else r.rows.push({ k: "bad", t: "无法识别的例外: " + line });
      continue;
    }
    var toks = line.split(/\s+/), first = toks[0];
    if (isIpv4(first)) {
      for (var j = 1; j < toks.length; j++) {
        if (toks[j].charAt(0) === "#") break;
        var hd = toks[j].toLowerCase().replace(/\.+$/, "");
        if (!DOK.test(hd)) { r.rows.push({ k: "bad", t: "非法域名: " + toks[j] }); continue; }
        if (first === "0.0.0.0") { r.block.push(hd); r.rows.push({ k: "block", t: hd }); }
        else { r.hosts.push(hd + "/" + first); r.rows.push({ k: "host", t: hd + " → " + first }); }
      }
      continue;
    }
    var m = line.match(/^address=\/([^/]+)(?:\/([^/]*))?/);
    if (m) {
      var doms = m[1].split("/");
      for (var k = 0; k < doms.length; k++) {
        var dd = normDom(doms[k]);
        if (!dd) continue;
        if (m[2] && m[2] !== "#" && isIpv4(m[2])) { r.hosts.push(dd + "/" + m[2]); r.rows.push({ k: "host", t: dd + " → " + m[2] }); }
        else if (DOK.test(dd)) { r.block.push(dd); r.rows.push({ k: "block", t: dd }); }
        else r.rows.push({ k: "bad", t: "非法域名: " + doms[k] });
      }
      continue;
    }
    if (/^\|\|([a-z0-9._-]+)\^/i.test(line)) { var bd = normDom(line); r.block.push(bd); r.rows.push({ k: "block", t: bd }); continue; }
    if (line.indexOf("$") !== -1 || line.indexOf("/") !== -1) { r.rows.push({ k: "skip", t: "$ 修饰符/路径规则不支持 — " + line }); continue; }
    var pd = normDom(toks[0]);
    if (DOK.test(pd)) { r.block.push(pd); r.rows.push({ k: "block", t: pd }); }
    else r.rows.push({ k: "bad", t: "无法识别的规则: " + line });
  }
  r.block = dedup(r.block); r.allow = dedup(r.allow); r.hosts = dedup(r.hosts);
  return r;
}

function collect() {
  var pr = parseRules($("rules").value);
  var block = dedup(splitList($("block")).concat(pr.block));
  var allow = dedup(splitList($("allow")).concat(pr.allow));
  var hosts = dedup(splitList($("host")).concat(pr.hosts));
  $("rulestat").innerHTML = renderRuleStat(pr);
  var p = new URLSearchParams();
  if (block.length) p.set("block", block.join(","));
  if (allow.length) p.set("allow", allow.join(","));
  if (hosts.length) p.set("host", hosts.join(","));
  var up = splitList($("up"));
  if (up.length) p.set("up", up.join(","));
  var list = splitList($("list"));
  if (list.length) p.set("list", list.join(","));
  return p;
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function renderRuleStat(pr) {
  if (!pr.rows.length) return '<p class="hint">支持：||域^ 拦截 · @@||域^ 例外 · *.域 通配 · 0.0.0.0 域 · IP 域 · address=/域/IP · 裸域名</p>';
  var names = { block: "拦截", allow: "例外", host: "固定", skip: "跳过", bad: "错误", comment: "注释" };
  var inert = pr.rows.filter(function (x) { return x.k === "skip" || x.k === "bad"; }).length;
  var sum = "解析：" + pr.block.length + " 拦截 · " + pr.allow.length + " 例外 · " + pr.hosts.length + " 固定 · " + inert + " 未生效";
  var h = '<p class="sum">' + sum + "</p>";
  for (var i = 0; i < pr.rows.length; i++) {
    var x = pr.rows[i];
    h += '<span class="ln"><span class="tag ' + x.k + '">' + names[x.k] + "</span>" + esc(x.t) + "</span>";
  }
  return h;
}

function b64url(s) {
  var bytes = new TextEncoder().encode(s), bin = "";
  for (var i = 0; i < bytes.length; i += 0x2000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x2000));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

var lastParams = "";
function refresh() {
  var qs = collect().toString();
  lastParams = qs;
  var origin = location.origin;
  var doh = origin + "/dns-query" + (qs ? "?" + qs : "");
  $("doh").textContent = doh;
  var chip = $("len");
  chip.textContent = doh.length + " 字符";
  chip.className = "chip" + (doh.length > 2000 ? " warnlong" : "");
  $("purl").textContent = qs ? origin + "/p/" + b64url("?" + qs) : origin + "/dns-query";
  renderSnippet();
  persist();
}

var saveT = null;
function persist() {
  clearTimeout(saveT);
  saveT = setTimeout(function () {
    var o = {};
    for (var i = 0; i < FIELDS.length; i++) o[FIELDS[i]] = $(FIELDS[i]).value;
    try { localStorage.setItem(LS, JSON.stringify(o)); } catch (e) {}
  }, 300);
}
function restore() {
  try {
    var o = JSON.parse(localStorage.getItem(LS) || "{}");
    for (var i = 0; i < FIELDS.length; i++) if (typeof o[FIELDS[i]] === "string") $(FIELDS[i]).value = o[FIELDS[i]];
  } catch (e) {}
}

var MODES = ["sys", "light", "dark"], MNAME = { sys: "系统", light: "浅色", dark: "深色" };
function applyTheme(mode) {
  if (mode === "sys") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", mode);
  $("theme").textContent = "◐ 主题 · " + MNAME[mode];
  try { localStorage.setItem(LST, mode); } catch (e) {}
}
$("theme").addEventListener("click", function () {
  var cur;
  try { cur = localStorage.getItem(LST) || "sys"; } catch (e) { cur = "sys"; }
  applyTheme(MODES[(MODES.indexOf(cur) + 1) % MODES.length]);
});

var TABS = [
  { name: "浏览器", gen: function (u) { return "设置 → 隐私和安全 → 安全 DNS →\n「使用指定安全 DNS」，填入:\n" + u; } },
  { name: "Chrome/Edge", gen: function (u) { return 'chrome --user-data-dir=<独立配置目录> \\\n  --dns-over-https-mode=secure \\\n  --dns-over-https-server="' + u + '"'; } },
  { name: "macOS 描述文件", gen: function (u) { return "macOS 系统设置不直接支持 DoH，需要配置描述文件：\nPayloadType: com.apple.dnsSettings（加密 DNS 设置，macOS 11+）\nDoH 服务器 URL: " + u + "\n键名以 Apple《配置配置文件参考 · Encrypted DNS Settings》为准。"; } },
  { name: "curl 验证", gen: function (u) { return "curl --doh-url '" + u + "' -sS https://example.com -o /dev/null -w '%{http_code}\\n'"; } }
];
var tabNow = 0;
function renderTabs() {
  var h = "";
  for (var i = 0; i < TABS.length; i++) h += '<button data-tab="' + i + '" class="' + (i === tabNow ? "on" : "") + '">' + TABS[i].name + "</button>";
  $("tabs").innerHTML = h;
}
function renderSnippet() {
  $("snippet").textContent = TABS[tabNow].gen($("doh").textContent);
}
$("tabs").addEventListener("click", function (ev) {
  var b = ev.target.closest("[data-tab]");
  if (!b) return;
  tabNow = +b.getAttribute("data-tab");
  renderTabs();
  renderSnippet();
});

var TN = { 1: "A", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA" };
function rcodeName(s) { return ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN"][s] || ("RCODE " + s); }
async function test() {
  var p = new URLSearchParams(lastParams);
  var name = $("tq").value.trim();
  if (!name) return;
  p.set("name", name);
  p.set("type", $("tt").value);
  $("tres").innerHTML = '<p class="empty">查询中…</p>';
  var t0 = performance.now();
  try {
    var res = await fetch("/?" + p.toString());
    var ms = Math.round(performance.now() - t0);
    var j = await res.json();
    var cls = j.Status === 0 ? "ok" : j.Status === 3 ? "err" : "warn";
    var cached = res.headers.get("cf-cache-status") || "-";
    var h = '<div><span class="badge ' + cls + '">' + rcodeName(j.Status) + "</span>" +
      '<span class="meta">' + esc(name + " / " + $("tt").value) + " · " + ms + "ms · 缓存 " + cached + "</span></div>";
    var rows = (j.Answer || []).map(function (a) {
      return "<tr><td>" + esc(a.name) + "</td><td>" + (TN[a.type] || a.type) + "</td><td>" + (a.TTL != null ? a.TTL + "s" : "") + "</td><td class=\"mono\">" + esc(a.data) + "</td></tr>";
    }).join("");
    if (rows) h += '<table><tr><th>名称</th><th>类型</th><th>TTL</th><th>数据</th></tr>' + rows + "</table>";
    else if (j.Status === 3) h += '<p class="empty">NXDOMAIN — 命中拦截规则或域名不存在</p>';
    else h += '<p class="empty">无应答记录</p>';
    h += '<details style="margin:.5rem 0 0"><summary style="font-size:.8rem">raw JSON</summary><pre class="raw">' + esc(JSON.stringify(j, null, 2)) + "</pre></details>";
    $("tres").innerHTML = h;
  } catch (e) {
    $("tres").innerHTML = '<span class="badge err">请求失败</span><span class="meta">' + esc(String(e)) + "</span>";
  }
}
$("go").addEventListener("click", test);
$("tq").addEventListener("keydown", function (e) { if (e.key === "Enter") test(); });

Array.prototype.forEach.call(document.querySelectorAll("[data-copy]"), function (btn) {
  btn.addEventListener("click", async function () {
    var t = $(btn.getAttribute("data-copy")).textContent;
    try {
      await navigator.clipboard.writeText(t);
      var old = btn.textContent;
      btn.textContent = "已复制";
      setTimeout(function () { btn.textContent = old; }, 1100);
    } catch (e) { prompt("手动复制:", t); }
  });
});

FIELDS.forEach(function (f) { $(f).addEventListener("input", refresh); });
restore();
try { applyTheme(localStorage.getItem(LST) || "sys"); } catch (e) { applyTheme("sys"); }
renderTabs();
refresh();
`;

function escapeHtml(s: string): string {
	return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
