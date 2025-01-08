# HTTP 安全响应头备忘录

## 简介

HTTP 头是一个易于实施且能显著提升 Web 安全的重要机制。正确的 HTTP 响应头可以帮助防止跨站脚本（XSS）、点击劫持、信息泄露等安全漏洞。

在这个备忘录中，我们将回顾所有与安全相关的 HTTP 头、推荐配置，并引用其他复杂头的参考资源。

## 安全头

### X-Frame-Options

`X-Frame-Options` HTTP 响应头可用于指示浏览器是否允许在 `<frame>`、`<iframe>`、`<embed>` 或 `<object>` 中渲染页面。网站可以通过确保其内容不被嵌入到其他站点来避免[点击劫持](https://owasp.org/www-community/attacks/Clickjacking)攻击。

对于支持的浏览器，内容安全策略（CSP）的 frame-ancestors 指令已经废弃了 X-Frame-Options 头（[来源](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)）。

仅当包含该头的 HTTP 响应有可交互内容（如链接、按钮）时，X-Frame-Options 头才有用。如果 HTTP 响应是重定向或返回 JSON 数据的 API，X-Frame-Options 不提供任何安全性。

#### 推荐

如果可能，使用内容安全策略（CSP）的 frame-ancestors 指令。

不允许在框架中显示页面：
> `X-Frame-Options: DENY`

### X-XSS-Protection

HTTP `X-XSS-Protection` 响应头是 Internet Explorer、Chrome 和 Safari 的一个功能，可以在检测到反射型跨站脚本（XSS）攻击时阻止页面加载。

警告：尽管此头可以保护尚不支持 CSP 的旧版 Web 浏览器，但在某些情况下，此头可能在原本安全的网站中创建 XSS 漏洞（[来源](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)）。

#### 推荐

使用禁用内联 JavaScript 的内容安全策略（CSP）。

不设置此头或显式关闭：
> `X-XSS-Protection: 0`

请参阅 [Mozilla X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection) 了解详情。

### X-Content-Type-Options

`X-Content-Type-Options` 响应 HTTP 头由服务器用于指示浏览器应遵循 Content-Type 头中声明的 MIME 类型，而不是猜测。

此头用于阻止浏览器的 [MIME 类型嗅探](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing)，防止将非可执行 MIME 类型转换为可执行 MIME 类型（[MIME 混淆攻击](https://blog.mozilla.org/security/2016/08/26/mitigating-mime-confusion-attacks-in-firefox/)）。

#### 推荐

在整个站点中正确设置 Content-Type 头。

> `X-Content-Type-Options: nosniff`

### Referrer-Policy

`Referrer-Policy` HTTP 头控制应包含多少引用信息（通过 Referer 头发送）。

#### 推荐

自 2014 年以来，浏览器已支持引用策略。如今，现代浏览器的默认行为是不再向同一站点发送所有引用信息（源、路径和查询字符串），而只向其他站点发送源。但是，由于并非所有用户都使用最新浏览器，我们建议通过在所有响应中发送此头来强制执行此行为。

> `Referrer-Policy: strict-origin-when-cross-origin`

- *注意：* 有关配置此头的更多信息，请参见 [Mozilla Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)。

### Content-Type

`Content-Type` 表示头用于指示资源的原始媒体类型（在应用任何内容编码以发送之前）。如果未正确设置，资源（例如图像）可能被解释为 HTML，从而使 XSS 漏洞成为可能。

尽管建议始终正确设置 `Content-Type` 头，但仅当内容旨在由客户端渲染且资源不受信任（由用户提供或修改）时，才会构成漏洞。

#### 推荐

> `Content-Type: text/html; charset=UTF-8`

- *注意：* `charset` 属性对于防止 **HTML** 页面中的 XSS 是必要的
- *注意：* `text/html` 可以是任何可能的 [MIME 类型](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types)

### Set-Cookie

`Set-Cookie` HTTP 响应头用于从服务器向用户代理发送 Cookie，以便用户代理可以在之后将其发送回服务器。要发送多个 Cookie，应在同一响应中发送多个 Set-Cookie 头。

这本身不是安全头，但其安全属性至关重要。

#### 推荐

- 请阅读[会话管理备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)以详细了解 Cookie 配置选项。

### Strict-Transport-Security (HSTS)

HTTP `Strict-Transport-Security` 响应头（通常缩写为 HSTS）允许网站告诉浏览器只能使用 HTTPS 访问，而不是 HTTP。

#### 推荐

> `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

- *注意*：在使用前仔细阅读此头的工作原理。如果 HSTS 头配置错误或 SSL/TLS 证书存在问题，合法用户可能无法访问网站。例如，如果 HSTS 头设置了很长的持续时间，且 SSL/TLS 证书过期或被吊销，合法用户可能在 HSTS 头持续时间到期之前无法访问网站。

请查看 [HTTP 严格传输安全备忘录](HTTP_Strict_Transport_Security_Cheat_Sheet.md)获取更多信息。

### Expect-CT ❌

`Expect-CT` 头允许站点选择加入证书透明度（CT）要求的报告。鉴于主流客户端现在需要 CT 资格，唯一剩余的价值是将此类情况报告给头中指定的 report-uri 值。该头现在不太关注执行，更多地关注检测/报告。

#### 推荐

不要使用它。Mozilla [建议](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT)避免使用，并尽可能从现有代码中删除。

### Content-Security-Policy (CSP)

内容安全策略（CSP）是一种安全功能，用于指定允许在网站或 Web 应用程序上加载的内容来源。这是一个额外的安全层，有助于检测和缓解某些类型的攻击，包括跨站脚本（XSS）和数据注入攻击。这些攻击被用于从数据窃取到网站篡改再到恶意软件分发等各种目的。

- *注意*：此头适用于可以加载和解释脚本和代码的页面，但对于返回不会被渲染的内容的 REST API 响应可能没有意义。

#### 推荐

内容安全策略配置和维护很复杂。有关自定义选项的解释，请阅读[内容安全策略备忘录](Content_Security_Policy_Cheat_Sheet.md)

### Access-Control-Allow-Origin

如果不使用此头，您的站点默认受同源策略（SOP）保护。此头的作用是在特定情况下放宽此控制。

`Access-Control-Allow-Origin` 是一个 CORS（跨源资源共享）头。此头指示相关响应是否可以与来自给定源的请求代码共享。换句话说，如果 siteA 从 siteB 请求资源，siteB 应在其 `Access-Control-Allow-Origin` 头中指示 siteA 是否被允许获取该资源，否则由于同源策略（SOP）将阻止访问。

#### 推荐

如果使用，请设置特定的[源](https://developer.mozilla.org/en-US/docs/Glossary/Origin)而不是 `*`。查看 [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) 了解详情。
> `Access-Control-Allow-Origin: https://yoursite.com`

- *注意*：根据需要，使用 '\*' 可能是必要的。例如，对于应该可从任何源访问的公共 API，可能需要允许 '\*'。

### Cross-Origin-Opener-Policy (COOP)

HTTP `Cross-Origin-Opener-Policy`（COOP）响应头允许您确保顶级文档不与跨源文档共享浏览上下文组。

此头与下面解释的 Cross-Origin-Embedder-Policy（COEP）和 Cross-Origin-Resource-Policy（CORP）一起工作。

这种机制可以防止类似 Spectre 这样的攻击，这些攻击可以跨越同源策略（SOP）为同一浏览上下文组中的资源建立的安全边界。

由于这些头与浏览器高度相关，因此对 REST API 或非浏览器客户端可能没有意义。

#### 建议

将浏览上下文严格限制在同源文档。
> `Cross-Origin-Opener-Policy: same-origin`

### 跨源嵌入策略（Cross-Origin-Embedder-Policy，COEP）

HTTP `跨源嵌入策略`（COEP）响应头阻止文档加载任何未明确授予文档权限的跨源资源（使用 [CORP](#跨源资源策略) 或 CORS）。

- *注意*：启用此策略将阻止未正确配置的跨源资源加载。

#### 建议

文档只能加载来自同源的资源，或明确标记为可从其他源加载的资源。
> `Cross-Origin-Embedder-Policy: require-corp`

- *注意*：您可以通过添加 `crossorigin` 属性为特定资源绕过此限制：
- `<img src="https://thirdparty.com/img.png" crossorigin>`

### 跨源资源策略（Cross-Origin-Resource-Policy，CORP）

`跨源资源策略`（CORP）头允许您控制有权包含资源的源集合。这是对 [Spectre](https://meltdownattack.com/) 等攻击的强大防御，因为它允许浏览器在资源进入攻击者的进程之前阻止响应。

#### 建议

将当前资源加载限制在站点及其子域。
> `Cross-Origin-Resource-Policy: same-site`

### 权限策略（Permissions-Policy，原 Feature-Policy）

权限策略允许您控制哪些源可以使用浏览器功能，无论是在顶级页面还是嵌入的框架中。对于受功能策略控制的每个功能，仅当其源与允许的源列表匹配时，该功能才在当前文档或框架中启用。这意味着您可以配置站点以永不允许摄像头或麦克风被激活。这可以防止注入（例如 XSS）启用摄像头、麦克风或其他浏览器功能。

更多信息：[权限策略](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Permissions-Policy)

#### 建议

设置并禁用站点不需要的所有功能，或仅允许授权域使用：
> `Permissions-Policy: geolocation=(), camera=(), microphone=()`

- *注意*：此示例禁用所有域的地理位置、摄像头和麦克风。

### FLoC（联合学习群组）

FLoC 是 Google 在 2021 年提出的一种向用户群组（"群组"）提供基于兴趣的广告的方法。[电子前沿基金会](https://www.eff.org/deeplinks/2021/03/googles-floc-terrible-idea)、[Mozilla](https://blog.mozilla.org/en/privacy-security/privacy-analysis-of-floc/) 等认为 FLoC 在保护用户隐私方面做得不够。

#### 建议

站点可以通过发送此 HTTP 头声明不希望被包含在用户的群组计算站点列表中。
> Permissions-Policy: interest-cohort=()

### 服务器（Server）

`Server` 头描述了处理请求的源服务器使用的软件——即生成响应的服务器。

这不是安全头，但其使用方式与安全相关。

#### 建议

删除此头或设置非信息性值。
> `Server: webserver`

- *注意*：请记住攻击者有其他方式识别服务器技术。

### X-Powered-By

`X-Powered-By` 头描述了 Web 服务器使用的技术。此信息会使服务器暴露给攻击者。攻击者可以使用此头中的信息更容易地找到漏洞。

#### 建议

删除所有 `X-Powered-By` 头。

- *注意*：请记住攻击者有其他方式识别您的技术栈。

### X-AspNet-Version

提供关于 .NET 版本的信息。

#### 建议

禁用发送此头。在 `web.config` 的 `<system.web>` 节中添加以下行以删除它。

```xml
<httpRuntime enableVersionHeader="false" />
```

- *注意*：请记住攻击者有其他方式识别您的技术栈。

### X-AspNetMvc-Version

提供关于 .NET 版本的信息。

#### 建议

禁用发送此头。要删除 `X-AspNetMvc-Version` 头，在 `Global.asax` 文件中添加以下代码。

```lang-none
MvcHandler.DisableMvcResponseHeader = true;
```

- *注意*：请记住攻击者有其他方式识别您的技术栈。

### X-DNS-Prefetch-Control

`X-DNS-Prefetch-Control` HTTP 响应头控制 DNS 预取，这是浏览器主动执行域名解析的一个功能，包括用户可能选择跟随的链接以及文档引用的项目的 URL，如图像、CSS、JavaScript 等。

#### 建议

浏览器的默认行为是执行 DNS 缓存，这对大多数网站来说是好的。
如果您无法控制网站上的链接，可能希望将值设置为 `off` 以禁用 DNS 预取，避免向这些域泄露信息。

> `X-DNS-Prefetch-Control: off`

- *注意*：不要依赖此功能处理任何生产敏感的事项：它不是标准或完全支持的，且实现可能在浏览器间有所不同。

### 公钥固定（Public-Key-Pins，HPKP）

HTTP `公钥固定`响应头用于将特定的加密公钥与某个 Web 服务器关联，以降低使用伪造证书的中间人攻击风险。

#### 建议

此头已被弃用，不应再使用。

## 在不同技术中添加 HTTP 头

### PHP

下面的示例代码在 PHP 中设置 `X-Frame-Options` 头。

```php
header("X-Frame-Options: DENY");
```

### Apache

以下是 `.htaccess` 示例配置，在 Apache 中设置 `X-Frame-Options` 头。注意，没有 `always` 选项，头将仅针对某些状态码发送，详见 [Apache 文档](https://httpd.apache.org/docs/2.4/mod/mod_headers.html#header)。

```lang-bsh
<IfModule mod_headers.c>
Header always set X-Frame-Options "DENY"
</IfModule>
```

### IIS

在 IIS 中添加以下配置到您的 `Web.config` 以发送 `X-Frame-Options` 头。

```xml
<system.webServer>
...
 <httpProtocol>
   <customHeaders>
     <add name="X-Frame-Options" value="DENY" />
   </customHeaders>
 </httpProtocol>
...
</system.webServer>
```

### HAProxy

在前端、监听或后端配置中添加以下行以发送 `X-Frame-Options` 头。

```lang-none
http-response set-header X-Frame-Options DENY
```

### Nginx

下面是一个示例配置，在 Nginx 中设置 `X-Frame-Options` 头。注意，没有 `always` 选项，头将仅针对某些状态码发送，详见 [Nginx 文档](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header)。

```lang-none
add_header "X-Frame-Options" "DENY" always;
```

### Express

您可以使用 [helmet](https://www.npmjs.com/package/helmet) 在 Express 中设置 HTTP 头。下面的代码是添加 `X-Frame-Options` 头的示例。

```javascript
const helmet = require('helmet');
const app = express();
// 设置 "X-Frame-Options: SAMEORIGIN"
app.use(
 helmet.frameguard({
   action: "sameorigin",
 })
);
```

## 测试安全头部的正确实施

### Mozilla Observatory

[Mozilla Observatory](https://observatory.mozilla.org/) 是一个在线工具，可帮助您检查网站的头部状态。

### SmartScanner

[SmartScanner](https://www.thesmartscanner.com/) 有一个专门的[测试配置文件](https://www.thesmartscanner.com/docs/configuring-security-tests)用于测试 HTTP 头的安全性。
在线工具通常只测试给定地址的主页。但 SmartScanner 会扫描整个网站。因此，您可以确保所有网页都正确设置了 HTTP 头。

## 参考资料

- [Mozilla: X-Frame-Options](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Frame-Options)
- [Mozilla: X-XSS-Protection](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-XSS-Protection)
- [hstspreload.org](https://hstspreload.org/)
- [Mozilla: Strict-Transport-Security](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [Mozilla: Content-Type](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Content-Type)
- [Mozilla: Expect-CT](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Expect-CT)
- [Mozilla: Set-Cookie](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Set-Cookie)
- [content-security-policy.com](https://content-security-policy.com/)
- [Mozilla: Cross-Origin-Opener-Policy](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
- [resourcepolicy.fyi](https://resourcepolicy.fyi/)
- [Mozilla: Cross-Origin-Resource-Policy](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
- [Mozilla: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
- [Mozilla: Server 头](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Server)
- [链接的 OWASP 项目：安全头部项目](https://owasp.org/www-project-secure-headers/)
