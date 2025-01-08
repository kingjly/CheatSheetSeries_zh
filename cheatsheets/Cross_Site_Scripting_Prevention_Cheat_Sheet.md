# 跨站脚本（XSS）防御备忘录

## 引言

本备忘录帮助开发者防范 XSS 漏洞。

跨站脚本（Cross-Site Scripting，XSS）这个术语其实是个误称。最初，这个术语源于早期主要关注跨站数据窃取的攻击方式。此后，这个术语的范围已经扩大到包括基本上任何内容的注入。XSS 攻击是严重的，可能导致账户冒充、监视用户行为、加载外部内容、窃取敏感数据等。

**本速查表包含防止或限制 XSS 影响的技术。由于没有单一技术可以完全解决 XSS，因此需要正确组合防御性技术来预防 XSS。**

## 框架安全

幸运的是，使用现代 Web 框架构建的应用程序具有较少的 XSS 漏洞，因为这些框架引导开发者采用良好的安全实践，并通过使用模板、自动转义等方式帮助缓解 XSS。然而，开发者需要知道，如果框架使用不当，仍然可能出现问题，例如：

- 框架用于直接操作 DOM 的"逃生舱口"
- 在未经过滤的情况下使用 React 的 `dangerouslySetInnerHTML`
- React 无法处理未经专门验证的 `javascript:` 或 `data:` URL
- Angular 的 `bypassSecurityTrustAs*` 函数
- Lit 的 `unsafeHTML` 函数
- Polymer 的 `inner-h-t-m-l` 属性和 `htmlLiteral` 函数
- 模板注入
- 过时的框架插件或组件
- 等等

当使用现代 Web 框架时，你需要了解框架如何防止 XSS 以及存在哪些漏洞。有时你需要在框架提供的保护之外做一些事情，这意味着输出编码和 HTML 净化可能至关重要。OWASP 将为 React、Vue 和 Angular 制作特定框架的速查表。

## XSS 防御理念

为了 XSS 攻击成功，攻击者必须能够在网页中插入和执行恶意内容。因此，Web 应用程序中的所有变量都需要得到保护。确保**所有变量**都经过验证，然后进行转义或净化，这被称为**完美的注入抵抗**。任何未经过此过程的变量都是潜在的弱点。框架使得确保变量正确验证并转义或净化变得容易。

然而，没有框架是完美的，即使是 React 和 Angular 等流行框架中仍然存在安全漏洞。输出编码和 HTML 净化有助于解决这些漏洞。

## 输出编码

当你需要按用户输入的方式安全地显示数据时，建议使用输出编码。变量不应被解释为代码，而应被解释为文本。本节介绍每种输出编码形式、使用场景，以及何时根本不应使用动态变量。

首先，当你希望按用户输入的方式显示数据时，请从框架的默认输出编码保护开始。大多数框架都内置了自动编码和转义函数。

如果你没有使用框架或需要弥补框架中的漏洞，则应使用输出编码库。用户界面中使用的每个变量都应通过输出编码函数。附录中包含了输出编码库列表。

存在许多不同的输出编码方法，因为浏览器以不同方式解析 HTML、JS、URL 和 CSS。使用错误的编码方法可能会引入弱点或损害应用程序的功能。

### HTML 上下文的输出编码

"HTML 上下文"是指在两个基本 HTML 标签（如 `<div>` 或 `<b>`）之间插入变量。例如：

```HTML
<div> $varUnsafe </div>
```

攻击者可能修改渲染为 `$varUnsafe` 的数据。这可能导致攻击被添加到网页中。例如：

```HTML
<div> <script>alert`1`</script> </div> // 示例攻击
```

为了安全地将变量添加到 Web 模板的 HTML 上下文中，请对该变量使用 HTML 实体编码。

以下是特定字符的编码值示例：

如果你使用 JavaScript 写入 HTML，请查看 `.textContent` 属性。它是一个**安全接收器**，将自动进行 HTML 实体编码。

```HTML
&    &amp;
<    &lt;
>    &gt;
"    &quot;
'    &#x27;
```

### HTML 属性上下文的输出编码

"HTML 属性上下文"发生在变量被放置在 HTML 属性值中的情况。你可能希望这样做以更改超链接、隐藏元素、为图像添加替代文本或更改内联 CSS 样式。对于大多数 HTML 属性中的变量，你应该应用 HTML 属性编码。在**安全接收器**部分提供了安全的 HTML 属性列表。

```HTML
<div attr="$varUnsafe">
<div attr="*x" onblur="alert(1)*"> // 示例攻击
```

**使用 `"` 或 `'` 等引号包围变量至关重要。** 引号使得更改变量所在的上下文变得困难，这有助于防止 XSS。引号还显著减少了需要编码的字符集，使应用程序更可靠，编码实现更容易。

如果你使用 JavaScript 写入 HTML 属性，请查看 `.setAttribute` 和 `[attribute]` 方法，因为它们会自动进行 HTML 属性编码。只要属性名是硬编码且无害的（如 `id` 或 `class`），这些都是**安全接收器**。通常，接受 JavaScript 的属性（如 `onClick`）在使用不可信的属性值时**不安全**。

### JavaScript 上下文的输出编码

"JavaScript 上下文"是指将变量放置在内联 JavaScript 中并嵌入 HTML 文档的情况。这种情况在大量使用嵌入网页的自定义 JavaScript 的程序中很常见。

然而，放置变量的唯一"安全"位置是在"带引号的数据值"内。所有其他上下文都是不安全的，你不应在其中放置变量数据。

"带引号的数据值"示例：

```HTML
<script>alert('$varUnsafe')</script>
<script>x='$varUnsafe'</script>
<div onmouseover="'$varUnsafe'"</div>
```

使用 `\xHH` 格式对所有字符进行编码。编码库通常有 `EncodeForJavaScript` 或类似函数来支持此功能。

请查看 [OWASP Java 编码器 JavaScript 编码示例](https://owasp.org/www-project-java-encoder/)，了解需要最少编码的正确 JavaScript 使用示例。

对于 JSON，请验证 `Content-Type` 标头是 `application/json` 而不是 `text/html`，以防止 XSS。

### CSS 上下文的输出编码

"CSS 上下文"是指放置在内联 CSS 中的变量，当开发者希望用户自定义网页外观时很常见。由于 CSS 出奇地强大，它已被用于多种攻击。**变量应该只放置在 CSS 属性值中。其他"CSS 上下文"是不安全的，你不应在其中放置变量数据。**

```HTML
<style> selector { property : $varUnsafe; } </style>
<style> selector { property : "$varUnsafe"; } </style>
<span style="property : $varUnsafe">Oh no</span>
```

如果你使用 JavaScript 更改 CSS 属性，可以使用 `style.property = x`。
这是一个**安全接收器**，将自动对其中的数据进行 CSS 编码。

在将变量插入 CSS 属性时，确保数据经过正确编码和净化以防止注入攻击。避免将变量直接放入选择器或其他 CSS 上下文中。

### URL 上下文的输出编码

"URL 上下文"是指放置在 URL 中的变量。最常见的是，开发者会向 URL 基础添加参数或 URL 片段，然后显示或用于某些操作。对于这些场景，使用 URL 编码。

```HTML
<a href="http://www.owasp.org?test=$varUnsafe">link</a>
```

使用 `%HH` 编码格式对所有字符进行编码。确保任何属性都完全带引号，与 JS 和 CSS 相同。

#### 常见错误

在某些情况下，你会在不同上下文中使用 URL。最常见的是将其添加到 `<a>` 标签的 `href` 或 `src` 属性中。在这些场景中，你应该先进行 URL 编码，然后再进行 HTML 属性编码。

```HTML
url = "https://site.com?data=" + urlencode(parameter)
<a href='attributeEncode(url)'>link</a>
```

如果你使用 JavaScript 构建 URL 查询值，可以使用 `window.encodeURIComponent(x)`。这是一个**安全接收器**，将自动对其中的数据进行 URL 编码。

### 危险上下文

输出编码并非完美。它不会始终防止 XSS。这些位置被称为**危险上下文**。危险上下文包括：

```HTML
<script>直接在脚本中</script>
<!-- 在 HTML 注释中 -->
<style>直接在 CSS 中</style>
<div ToDefineAnAttribute=test />
<ToDefineATag href="/test" />
```

其他需要小心的区域包括：

- 回调函数
- 代码中处理 URL 的地方，如 CSS { background-url : "javascript:alert(xss)"; }
- 所有 JavaScript 事件处理程序（`onclick()`、`onerror()`、`onmouseover()`）
- 不安全的 JS 函数，如 `eval()`、`setInterval()`、`setTimeout()`

不要将变量放入危险上下文，因为即使使用输出编码，也无法完全防止 XSS 攻击。

## HTML 净化

当用户需要编写 HTML 时，开发者可能允许用户在 WYSIWYG 编辑器中更改内容的样式或结构。在这种情况下，输出编码会阻止 XSS，但会破坏应用程序的预期功能。样式将无法呈现。在这些情况下，应使用 HTML 净化。

HTML 净化将从变量中剥离危险的 HTML 并返回安全的 HTML 字符串。OWASP 推荐使用 [DOMPurify](https://github.com/cure53/DOMPurify) 进行 HTML 净化。

```js
let clean = DOMPurify.sanitize(dirty);
```

还有一些需要考虑的事项：

- 如果你净化内容后又对其进行修改，很容易会作废你的安全工作。
- 如果你净化内容后将其发送到库使用，请检查它是否以某种方式改变了该字符串。否则，你的安全工作同样会作废。
- 你必须定期修补 DOMPurify 或其他你使用的 HTML 净化库。浏览器功能在变化，绕过漏洞正在不断被发现。

## 安全接收器

安全专业人士经常从源和接收器的角度来讨论问题。如果你污染了一条河，它会在下游某处流动。计算机安全也是如此。XSS 接收器是网页中放置变量的地方。

幸运的是，许多可以放置变量的接收器是安全的。这是因为这些接收器将变量视为文本，永远不会执行它。尝试重构代码，删除对 innerHTML 等不安全接收器的引用，转而使用 textContent 或 value。

```js
elem.textContent = dangerVariable;
elem.insertAdjacentText(dangerVariable);
elem.className = dangerVariable;
elem.setAttribute(safeName, dangerVariable);
formfield.value = dangerVariable;
document.createTextNode(dangerVariable);
document.createElement(dangerVariable);
elem.innerHTML = DOMPurify.sanitize(dangerVar);
```

**安全的 HTML 属性包括：** `align`, `alink`, `alt`, `bgcolor`, `border`, `cellpadding`, `cellspacing`, `class`, `color`, `cols`, `colspan`, `coords`, `dir`, `face`, `height`, `hspace`, `ismap`, `lang`, `marginheight`, `marginwidth`, `multiple`, `nohref`, `noresize`, `noshade`, `nowrap`, `ref`, `rel`, `rev`, `rows`, `rowspan`, `scrolling`, `shape`, `span`, `summary`, `tabindex`, `title`, `usemap`, `valign`, `value`, `vlink`, `vspace`, `width`。

对于上面未报告的属性，请确保如果提供 JavaScript 代码作为值，它无法被执行。

## 其他控制措施

框架安全保护、输出编码和 HTML 净化将为你的应用程序提供最佳保护。OWASP 在所有情况下都推荐这些方法。

考虑除上述方法外，还采用以下控制措施：

- Cookie 属性 - 这些改变 JavaScript 和浏览器与 Cookie 交互的方式。Cookie 属性试图限制 XSS 攻击的影响，但不能防止恶意内容的执行或解决漏洞的根本原因。
- 内容安全策略（CSP） - 一个阻止加载内容的白名单。实施很容易出错，因此不应成为你的主要防御机制。将 CSP 作为额外的防御层，并查看[此处的速查表](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)。
- Web 应用防火墙（WAF） - 这些会查找已知的攻击字符串并阻止它们。WAF 不可靠，新的绕过技术正在不断被发现。WAF 也不能解决 XSS 漏洞的根本原因。此外，WAF 还会遗漏完全在客户端运行的 XSS 漏洞类别。不建议使用 WAF 来防止 XSS，尤其是基于 DOM 的 XSS。

### XSS 防御规则总结

这些 HTML 片段展示了如何在各种不同上下文中安全地呈现不可信数据。

数据类型：字符串
上下文：HTML 正文
代码：`<span>不可信数据</span>`
示例防御：HTML 实体编码（规则 #1）

数据类型：强
上下文：安全的 HTML 属性
代码：`<input type="text" name="fname" value="不可信数据">`
示例防御：积极的 HTML 实体编码（规则 #2），仅将不可信数据放入安全属性列表（如下所列），严格验证不安全属性，如 background、ID 和 name。

数据类型：字符串
上下文：GET 参数
代码：`<a href="/site/search?value=不可信数据">点击我</a>`
示例防御：URL 编码（规则 #5）。

数据类型：字符串
上下文：不可信 URL 在 SRC 或 HREF 属性中
代码：`<a href="不可信 URL">点击我</a> <iframe src="不可信 URL" />`
示例防御：规范化输入，URL 验证，安全 URL 验证，仅允许 http 和 HTTPS URL（避免使用 JavaScript 协议打开新窗口），属性编码器。

数据类型：字符串
上下文：CSS 值
代码：`HTML <div style="width: 不可信数据;">选择</div>`
示例防御：严格的结构验证（规则 #4），CSS 十六进制编码，良好的 CSS 功能设计。

数据类型：字符串
上下文：JavaScript 变量
代码：`<script>var currentValue='不可信数据';</script> <script>someFunction('不可信数据');</script>`
示例防御：确保 JavaScript 变量带引号，JavaScript 十六进制编码，JavaScript Unicode 编码，避免反斜杠编码（`\"` 或 `\'` 或 `\\`）。

数据类型：HTML
上下文：HTML 正文
代码：`<div>不可信 HTML</div>`
示例防御：HTML 验证（JSoup、AntiSamy、HTML Sanitizer 等）。

数据类型：字符串
上下文：DOM XSS
代码：`<script>document.write("不可信输入: " + document.location.hash );<script/>`
示例防御：[基于 DOM 的 XSS 防御速查表](DOM_based_XSS_Prevention_Cheat_Sheet.md)

### 输出编码规则总结

输出编码的目的（与跨站脚本有关）是将不可信输入转换为安全形式，使输入作为**数据**显示给用户，而不在浏览器中作为**代码**执行。以下图表提供了阻止跨站脚本所需的关键输出编码方法列表。

编码类型：HTML 实体
编码机制：转换 `&` 为 `&amp;`，转换 `<` 为 `&lt;`，转换 `>` 为 `&gt;`，转换 `"` 为 `&quot;`，转换 `'` 为 `&#x27`

编码类型：HTML 属性编码
编码机制：使用 HTML 实体 `&#xHH;` 格式对所有字符进行编码，包括空格，其中 **HH** 表示 Unicode 中字符的十六进制值。例如，`A` 变为 `&#x41`。所有字母数字字符（A 到 Z 的字母，a 到 z 的字母，以及 0 到 9 的数字）保持未编码。

编码类型：URL 编码
编码机制：使用 [W3C 规范](http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1)中指定的标准百分比编码对参数值进行编码。谨慎操作，仅对参数值进行编码，不要对整个 URL 或 URL 的路径片段进行编码。

编码类型：JavaScript 编码
编码机制：使用 Unicode `\uXXXX` 编码格式对所有字符进行编码，其中 **XXXX** 表示十六进制 Unicode 码点。例如，`A` 变为 `\u0041`。所有字母数字字符（A 到 Z 的字母，a 到 z 的字母，以及 0 到 9 的数字）保持未编码。

编码类型：CSS 十六进制编码
编码机制：CSS 编码支持 `\XX` 和 `\XXXXXX` 格式。为确保正确编码，考虑以下选项：(a) 在 CSS 编码后添加空格（CSS 解析器会忽略），或 (b) 使用全六字符 CSS 编码格式，通过零填充值。例如，`A` 变为 `\41`（短格式）或 `\000041`（完整格式）。字母数字字符（A 到 Z 的字母，a 到 z 的字母，以及 0 到 9 的数字）保持未编码。

## 常见反模式：无效的防御方法

防御 XSS 很困难。因此，有些人寻求防止 XSS 的捷径。

我们将研究两种常见的[反模式](https://en.wikipedia.org/wiki/Anti-pattern)，这些反模式经常出现在古老的帖子中，但在 Stack Overflow 等程序员论坛和其他开发者聚集地的关于 XSS 防御的现代帖子中仍被广泛引用。

### 仅依赖内容安全策略（CSP）标头

首先，我们要明确，我们是 CSP 的强烈支持者，前提是正确使用。在 XSS 防御的背景下，CSP 最有效的使用方式是：

- 作为深度防御技术使用。
- 为每个单独的应用程序定制，而不是作为一刀切的企业解决方案部署。

我们反对的是针对整个企业的笼统 CSP 策略。这种方法存在的问题是：

#### 问题1 - 假设浏览器版本对CSP支持相同

通常存在一个隐含的假设，即所有客户浏览器都支持笼统 CSP 策略使用的所有 CSP 构造。更进一步，这种假设往往未明确测试 `User-Agent` 请求标头，以确定是否确实是支持的浏览器类型，并在不支持时拒绝使用网站。为什么？因为大多数企业不想因客户使用不支持某些 CSP Level 2 或 Level 3 构造（用于 XSS 防御）的过时浏览器而将其拒之门外。（统计数据显示，几乎所有浏览器都支持 CSP Level 1 指令，所以除非你担心祖父用他的老旧 Windows 98 笔记本和古老的 Internet Explorer 访问你的网站，否则可以假定 CSP Level 1 支持是可行的。）

#### 问题2 - 支持遗留应用程序的问题

强制的、企业范围的 CSP 响应标头不可避免地会破坏一些 Web 应用程序，尤其是遗留应用程序。这导致业务方抵制应用安全指南，并不可避免地导致应用安全团队发出豁免或安全例外，直到应用代码可以修补。但这些安全例外会在你的 XSS 防御armor中留下裂缝，即使这些裂缝是暂时的，它们仍可能影响你的业务，至少在声誉方面。

### 依赖 HTTP 拦截器

我们观察到的另一种常见反模式是试图在某种拦截器中处理验证和/或输出编码，比如实现 `org.springframework.web.servlet.HandlerInterceptor` 的 Spring 拦截器，或实现 `javax.servlet.Filter` 的 JavaEE servlet 过滤器。虽然这对于非常特定的应用程序可能成功（例如，验证所有要呈现的输入请求只包含字母数字数据），但它违背了 XSS 防御的主要原则 - 在尽可能接近数据呈现的地方执行输出编码。通常，HTTP 请求被检查查询和 POST 参数，但其他可能被呈现的 HTTP 请求标头（如 cookie 数据）未被检查。我们见过的常见方法是调用 `ESAPI.validator().getValidSafeHTML()` 或 `ESAPI.encoder.canonicalize()`，并根据结果重定向到错误页面或调用类似 `ESAPI.encoder().encodeForHTML()` 的方法。除了这种方法常常遗漏被污染的输入（如请求标头或 URI 中的"额外路径信息"）之外，该方法完全忽略了输出编码是完全非上下文的这一事实。例如，servlet 过滤器如何知道输入查询参数将在 HTML 上下文（即 HTML 标签之间）而不是在 JavaScript 上下文（如 `<script>` 标签内或与 JavaScript 事件处理程序属性一起使用）中呈现？它不知道。因为 JavaScript 和 HTML 编码不可互换，你仍然容易遭受 XSS 攻击。

除非你的过滤器或拦截器完全了解你的应用程序，并具体知道应用程序如何为给定请求使用每个参数，否则它无法处理所有可能的边缘情况。我们认为，使用这种方法永远无法成功，因为提供所需的额外上下文的设计太复杂，而且尝试这样做几乎不可避免地会引入其他漏洞（可能其影响远比 XSS 更严重）。

这种天真的方法通常至少存在以下四个问题：

#### 问题1 - 特定上下文的编码对所有 URI 路径不满意

一个问题是不恰当的编码仍可能在应用程序的某些 URI 路径中允许可利用的 XSS。例如，来自 POST 的 'lastname' 表单参数通常显示在 HTML 标签之间，因此 HTML 编码就足够了，但可能存在一两个边缘情况，其中 lastname 实际上是作为 JavaScript 块的一部分呈现，此时 HTML 编码是不够的，因此容易遭受 XSS 攻击。

#### 问题2 - 拦截器方法可能导致由于不正确或双重编码而导致的渲染中断

第二个问题是应用程序可能导致不正确或双重编码。例如，假设在前面的示例中，开发者已对 lastname 的 JavaScript 渲染进行了正确的输出编码。但如果它已经被 HTML 输出编码，当渲染时，一个合法的姓氏如 "O'Hara" 可能会呈现为 "O\&#39;Hara"。

虽然第二种情况严格来说不是安全问题，但如果经常发生，可能导致业务方反对使用过滤器，从而决定禁用过滤器或为某些页面或参数指定例外，这反过来会削弱其提供的任何 XSS 防御。

#### 问题3 - 拦截器对基于 DOM 的 XSS 无效

第三个问题是它对基于 DOM 的 XSS 无效。要做到这一点，需要有一个拦截器或过滤器扫描作为 HTTP 响应一部分的所有 JavaScript 内容，尝试找出被污染的输出并查看它是否容易受到基于 DOM 的 XSS 攻击。这简直是不切实际的。

#### 问题4 - 拦截器对源自应用程序外部的响应数据无效

最后一个问题是拦截器通常对应用程序响应中源自其他内部源（如内部基于 REST 的 Web 服务或内部数据库）的数据视而不见。问题在于，除非应用程序在检索数据时严格验证数据（这通常是应用程序有足够上下文使用白名单方法进行严格数据验证的唯一点），否则该数据应始终被视为被污染。但是，如果你试图在 HTTP 响应端的拦截器（如 Java servlet 过滤器）上对所有被污染的数据进行输出编码或严格的数据验证，那么此时你的应用程序的拦截器将不知道来自这些 REST Web 服务或其他数据库的被污染数据是否存在。通常在响应端拦截器上用于提供 XSS 防御的方法是仅考虑匹配的"输入参数"为被污染，并对其进行输出编码或 HTML 净化，而其他一切都被视为安全。但有时并非如此？虽然经常假设所有内部 Web 服务和所有内部数据库都是"可信的"并可直接使用，但除非你已将其纳入应用程序的深度威胁建模，否则这是一个非常糟糕的假设。

例如，假设你正在开发一个应用程序，用于向客户展示其详细的月度账单。假设你的应用程序正在查询一个外部（非你特定应用程序的一部分）内部数据库或 REST Web 服务，以获取用户的全名、地址等。但该数据源于另一个应用程序，你假设它是"可信的"，但实际上在各种与客户地址相关的字段中有未报告的持续性 XSS 漏洞。此外，假设你公司的客户支持人员可以查看客户的详细账单以协助客户解答账单相关问题。因此，一个阴险的客户决定在地址字段中植入 XSS 炸弹，然后致电客户服务寻求账单帮助。如果这种情况真的发生，试图防止 XSS 的拦截器将完全错过这一点，其结果将远比仅仅弹出显示"1"或"XSS"或"pwn'd"的警告框更糟。

### 总结

最后一点：如果部署拦截器/过滤器作为 XSS 防御是针对 XSS 攻击的有用方法，你不认为它早就会被纳入所有商业 Web 应用防火墙（WAF）中，并成为 OWASP 在本速查表中推荐的方法吗？

## 相关文章

**XSS 攻击速查表：**

以下文章描述了攻击者如何利用不同类型的 XSS 漏洞（本文旨在帮助你避免这些漏洞）：

- OWASP：[XSS 过滤器规避速查表](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)。

**XSS 漏洞描述：**

- OWASP 关于 [XSS](https://owasp.org/www-community/attacks/xss/) 漏洞的文章。

**关于 XSS 漏洞类型的讨论：**

- [跨站脚本的类型](https://owasp.org/www-community/Types_of_Cross-Site_Scripting)。

**如何审查跨站脚本漏洞的代码：**

- [OWASP 代码审查指南](https://owasp.org/www-project-code-review-guide/)中关于[审查跨站脚本漏洞的代码](https://wiki.owasp.org/index.php/Reviewing_Code_for_Cross-site_scripting)的文章。

**如何测试跨站脚本漏洞：**

- [OWASP 测试指南](https://owasp.org/www-project-web-security-testing-guide/)中关于测试跨站脚本漏洞的文章。
- [XSS 实验性最小编码规则](https://wiki.owasp.org/index.php/XSS_Experimental_Minimal_Encoding_Rules)
