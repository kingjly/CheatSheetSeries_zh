# 点击劫持防御备忘录

## 引言

这份备忘录旨在为开发者提供如何防御 [点击劫持](https://owasp.org/www-community/attacks/Clickjacking)（也称为 UI 红色欺骗攻击）的指导。

主要有三种机制可以用来防御这些攻击：

- 使用 [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) 或者 [Content Security Policy (frame-ancestors)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors) HTTP 头来防止浏览器将页面嵌入框架中。
- 使用 [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) 会话 cookie 属性来防止在框架中加载时包含 session cookies。
- 在页面中实现 JavaScript 代码以尝试防止其被嵌入框架（称为“框架破坏器”）。

请注意，这些机制彼此独立，并且尽可能多地实施多种机制可以提供多层次防御。

## 使用 Content Security Policy (CSP) frame-ancestors 指令进行防御

`frame-ancestors` 指令可以在 Content-Security-Policy HTTP 响应头中使用以指示浏览器是否允许将页面嵌入 `<frame>` 或 `<iframe>` 中。站点可以利用这一点来避免点击劫持攻击，确保其内容不会被嵌入其他网站。

`frame-ancestors` 允许站点授权多个域名，使用正常的 Content Security Policy 语义。

### Content-Security-Policy: frame-ancestors 示例

常见的 CSP frame-ancestors 使用场景包括：

- `Content-Security-Policy: frame-ancestors 'none';`
    - 这会阻止任何域嵌入内容。除非有特定需求，否则推荐使用此设置。
- `Content-Security-Policy: frame-ancestors 'self';`
    - 只允许当前站点嵌入内容。
- `Content-Security-Policy: frame-ancestors 'self' *.somesite.com https://myfriend.site.com;`
    - 允许当前站点以及任何来自 `somesite.com` 的页面（使用任意协议），仅允许 `myfriend.site.com` 页面通过 HTTPS 在默认端口上嵌入。

注意，单引号在 `self` 和 `none` 时是必需的，但在其他来源表达式中则不需要出现。

请参阅以下文档以获取更多详细信息和复杂示例：

- <https://w3c.github.io/webappsec-csp/#directive-frame-ancestors>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors>

### 限制

- **X-Frame-Options 具有优先级**：CSP 规范的 [“关系到 X-Frame-Options”部分](https://w3c.github.io/webappsec/specs/content-security-policy/#frame-ancesters-and-frame-options) 中提到：“*如果资源使用包含名为 frame-ancestors 的指令且其处置为“enforce”的策略，则必须忽略 X-Frame-Options 头*”，但 Chrome 40 和 Firefox 35 忽略了 frame-ancestors 指令，而遵循 X-Frame-Options 头。

### 浏览器支持

以下 [浏览器](https://caniuse.com/?search=frame-ancestors) 支持 CSP frame-ancestors。

参考：

- [Mozilla 开发者网络](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors#browser_compatibility)

## 使用 X-Frame-Options 响应头进行防御

`X-Frame-Options` HTTP 响应头可以用来指示浏览器是否允许将页面嵌入 `<frame>` 或 `<iframe>` 中。站点可以通过确保其内容不被嵌入其他网站来避免点击劫持攻击。对于所有包含 HTML 内容的响应设置 X-Frame-Options 头。可能的值为 "DENY"、"SAMEORIGIN" 或 "ALLOW-FROM uri"

### X-Frame-Options 头类型

X-Frame-Options 头有三种可能的值：

- **DENY**，阻止任何域嵌入内容。除非有特定需求，否则推荐使用此设置。
- **SAMEORIGIN**，仅允许当前站点嵌入内容。
- **ALLOW-FROM uri**，允许指定的 'uri' 嵌入此页面。（例如，`ALLOW-FROM http://www.example.com`）。
    - 这是一个过时指令，在现代浏览器中不再生效。请小心依赖 ALLOW-FROM，因为如果浏览器不支持它，则会失效。
    - 其他浏览器支持新的 [CSP frame-ancestors 指令](https://w3c.github.io/webappsec-csp/#directive-frame-ancestors) 代替。一些浏览器同时支持两者。

### 浏览器支持

以下 [浏览器](https://caniuse.com/#search=X-Frame-Options) 支持 X-Frame-Options 头。

参考：

- [Mozilla 开发者网络](https://developer.mozilla.org/en-US/docs/web/http/headers/x-frame-options#browser_compatibility)
- [IETF 草案](http://datatracker.ietf.org/doc/draft-ietf-websec-x-frame-options/)
- [X-Frame-Options 兼容性测试](https://erlend.oftedal.no/blog/tools/xframeoptions/) - 请检查此链接获取 X-Frame-Options 头的最新浏览器支持信息

### 实现

要实现这种保护，您需要为希望防止被点击劫持框架破坏的每个页面添加 `X-Frame-Options` HTTP 响应头。一种方法是手动在每个页面中添加 HTTP 响应头。更简单的方法是在 Web 应用程序防火墙或 Web 应用服务器级别实现一个过滤器，自动为所有页面添加该头。

### 防御常见错误

试图应用 X-Frame-Options 指令的元标签不起作用。例如，`<meta http-equiv="X-Frame-Options" content="deny">` 不会生效。您必须如上所述将 X-FRAME-OPTIONS 指令作为 HTTP 响应头来应用。

### 限制

- **分页策略指定**：需要为每个页面指定策略，这可能会使部署复杂化。例如，在登录时强制执行整个站点的策略可以简化采用。
- **多域网站的问题**：当前实现不允许网站管理员提供允许嵌入页面的域名列表。虽然列出允许的域名可能有风险，但在某些情况下，网站管理员可能别无选择只能使用多个主机名。
- **ALLOW-FROM 浏览器支持**：ALLOW-FROM 选项已过时且在现代浏览器中不再生效。请小心依赖 ALLOW-FROM。如果应用后浏览器不支持它，则将没有任何点击劫持防御措施。
- **多种选项不受支持**：无法允许当前站点和第三方站点嵌入同一响应。浏览器仅承认一个 X-Frame-Options 头以及该头上的单一值。
- **SAMEORIGIN 和 ALLOW-FROM 与嵌套框架不兼容**：在这种情况下，`http://framed.invalid/child` 框不会加载，因为 ALLOW-FROM 应用于顶级浏览上下文，而不应用于立即父级。解决方案是在父框架和子框架中都使用 ALLOW-FROM（但这会阻止子框架加载如果 `//framed.invalid/parent` 页面被用作顶层文档）。

![NestedFrames](../assets/Clickjacking_Defense_Cheat_Sheet_NestedFrames.png)

- **X-Frame-Options 已弃用**：虽然 X-Frame-Options 头由主要浏览器支持，但它已被 CSP Level 2 规范中的 frame-ancestors 指令取代。
- **代理服务器问题**：代理服务器经常添加和删除头。如果 Web 代理剥离了 X-Frame-Options 头，则站点将失去其框架保护。

## 使用 SameSite Cookies 进行防御

SameSite cookie 属性根据 [RFC 6265bis](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7) 主要旨在防范 [跨站请求伪造（CSRF）攻击](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md#samesite-cookie-属性)；然而，它也可以提供防止点击劫持的保护。

具有 `SameSite` 属性为 `strict` 或 `lax` 的 cookie 不会在对 `<iframe>` 中页面发起的请求中包含。这意味着如果会话 cookies 标记为 SameSite，则任何需要用户认证的点击劫持攻击将不会生效，因为该 cookie 将不会发送。有关不同 SameSite 策略下发送哪些类型的请求的文章可以参阅 [Netsparker 博客](https://www.netsparker.com/blog/web-security/same-site-cookie-attribute-prevent-cross-site-request-forgery/)。

此方法已在 [JavaScript.info 网站](https://javascript.info/clickjacking#samesite-cookie-属性) 上讨论过。

### 限制

如果点击劫持攻击不需要用户认证，则该属性将无法提供任何保护。

此外，虽然 `SameSite` 属性在 [大多数现代浏览器中得到支持](https://caniuse.com/#feat=same-site-cookie-attribute)，但仍有一些用户（截至2020年11月约为6%）使用不支持它的浏览器。

此特性的使用应作为多层次防御的一部分，并不应仅依赖于点击劫持防护的唯一保护措施。

## 为遗留浏览器提供最佳防御脚本

一种防御点击劫持的方法是在每个不应该被框架化的页面中包含一个“帧破坏”脚本。以下方法将防止在不支持 X-Frame-Options 头的遗留浏览器中嵌入网页。

在文档的 HEAD 元素中添加如下内容：

首先为 style 元素本身应用一个 ID：

```html
<style id="antiClickjack">
    body{display:none !important;}
</style>
```

然后，通过其 ID 立即删除该样式：

```html
<script type="text/javascript">
    if (self === top) {
        var antiClickjack = document.getElementById("antiClickjack");
        antiClickjack.parentNode.removeChild(antiClickjack);
    } else {
        top.location = self.location;
    }
</script>
```

这样，所有内容都可以放在文档的 HEAD 中，并且您只需要在 API 中使用一个方法/标签。

## window.confirm() 保护

X-Frame-Options 或帧破坏脚本的使用是一种更可靠的方法来防御点击劫持。然而，在必须嵌入框架的内容场景中，则可以使用 window.confirm() 来帮助缓解点击劫持，通过向用户告知即将执行的操作。

调用 window.confirm() 将会显示一个弹出窗口，该窗口无法被框架化。如果 window.confirm() 从具有不同域的 iframe 中发起，则对话框将显示 window.confirm() 起源的域名。在这种情况下，浏览器会显示出对话框的来源以帮助缓解点击劫持攻击。需要注意的是，只有 Internet Explorer 不会在其 window.confirm() 对话框中显示该域名，为了解决这个问题，请确保在对话框的消息中包含关于执行操作类型的上下文信息。例如：

```html
<script type="text/javascript">
   var action_confirm = window.confirm("Are you sure you want to delete your youtube account?")
   if (action_confirm) {
       //... Perform action
   } else {
       //... The user does not want to perform the requested action.`
   }
</script>
```

## 不安全的非工作脚本，请勿使用

考虑以下代码片段，该代码 **不推荐** 用于防御点击劫持：

```html
<script>if (top!=self) top.location.href=self.location.href</script>
```

此简单的防框架脚本尝试通过强制父窗口加载当前框架的 URL 来阻止页面被嵌套到框架或 iframe 中。不幸的是，有多种方法可以绕过此类脚本。以下是一些示例。

### 双重框架

一些反框架技术通过给 `parent.location` 赋值来导航到正确的页面。如果受害页面被单个页面框架，这种方法很有效。然而，如果攻击者将受害者嵌套在另一个框架内的框架中（双重框架），那么访问 `parent.location` 将在所有主流浏览器中触发安全违规，这是由于**后代框架导航策略**。这种安全违规会禁用反制导航操作。

**受害者反框架代码：**

```javascript
if(top.location != self.location) {
    parent.location = self.location;
}
```

**攻击者顶层框架：**

```html
<iframe src="attacker2.html">
```

**攻击者子框架：**

```html
<iframe src="http://www.victim.com">
```

### onBeforeUnload 事件

用户可以手动取消由框架页面提交的任何导航请求。为了利用这一点，框架页面注册了一个 `onBeforeUnload` 处理程序，每当由于导航即将卸载框架页面时，该处理程序就会被调用。处理程序函数返回一个字符串，该字符串将成为向用户显示的提示的一部分。

假设攻击者想要框架 PayPal。他注册了一个卸载处理程序函数，返回字符串"你要退出 PayPal 吗？"。当向用户显示此字符串时，用户很可能会取消导航，从而破坏 PayPal 的反框架尝试。

攻击者通过在顶层页面注册卸载事件来挂载此攻击：

```html
<script>
    window.onbeforeunload = function(){
        return "友好地询问用户";
    }
</script>

<iframe src="http://www.paypal.com">
```

PayPal 的反框架代码将生成一个 `BeforeUnload` 事件，激活我们的函数并提示用户取消导航事件。

### 无内容刷新

虽然前面的攻击需要用户交互，但同样的攻击可以在不提示用户的情况下进行。大多数浏览器（IE7、IE8、Google Chrome 和 Firefox）使攻击者能够在 `onBeforeUnload` 事件处理程序中通过重复提交导航请求到响应"*204 - 无内容*"的站点，自动取消传入的导航请求。

导航到无内容站点实际上是一个空操作，但会刷新请求管道，从而取消原始导航请求。以下是示例代码：

```javascript
var preventbust = 0
window.onbeforeunload = function() { killbust++ }
setInterval( function() {
    if(killbust > 0){
    killbust = 2;
    window.top.location = 'http://nocontent204.com'
    }
}, 1);
```

```html
<iframe src="http://www.victim.com">
```

### 利用 XSS 过滤器

IE8 和 Google Chrome 引入了反射性 XSS 过滤器，以帮助保护网页免受某些类型的 XSS 攻击。Nava 和 Lindsay（在"Blackhat"上）观察到，这些过滤器可用于规避反框架代码。IE8 的 XSS 过滤器通过将给定的请求参数与一组正则表达式进行比较，以查找明显的跨站脚本攻击。使用"诱导的假阳性"，可以使用过滤器禁用选定的脚本。通过匹配请求参数中任何脚本标签的开头，XSS 过滤器将禁用页面中的所有内联脚本，包括反框架脚本。通过匹配外部包含，外部脚本也可以被定位，有效地禁用所有外部脚本。由于加载的 JavaScript 子集仍然是功能性的（内联或外部），且 Cookie 仍然可用，因此此攻击对点击劫持很有效。

**受害者反框架代码：**

```html
<script>
    if(top != self) {
        top.location = self.location;
    }
</script>
```

**攻击者：**

```html
<iframe src="http://www.victim.com/?v=<script>if''>
```

XSS 过滤器将匹配参数 `<script>if` 到受害者反框架脚本的开头，因此将禁用受害者页面中的所有内联脚本，包括反框架脚本。Google Chrome 可用的 XSSAuditor 过滤器支持相同的漏洞。

### 覆盖 top.location

几种现代浏览器将位置变量视为跨所有上下文的特殊不可变属性。然而，在 IE7 和 Safari 4.0.4 中情况并非如此，位置变量可以被重新定义。

**IE7**：一旦框架页面重新定义位置，子框架中试图读取 `top.location` 的任何反框架代码都将通过尝试读取另一个域中的局部变量而触发安全违规。同样，任何通过分配 `top.location` 进行导航的尝试都将失败。

**受害者反框架代码：**

```javascript
if(top.location != self.location) {
    top.location = self.location;
}
```

**攻击者：**

```html
<script>var location = "clobbered";</script>
<iframe src="http://www.victim.com"></iframe>
```

**Safari 4.0.4：**

我们观察到，尽管在大多数情况下位置保持不可变，但当通过 `defineSetter`（通过窗口）定义自定义位置设置器时，对象位置将变为未定义。

框架页面简单地执行：

```html
<script>
    window.defineSetter("location", function(){});
</script>
```

现在，任何读取或导航顶层框架位置的尝试都将失败。

### 受限区域

大多数反框架依赖于框架页面中的 JavaScript 来检测框架并脱离框架。如果在子框架上下文中禁用了 JavaScript，反框架代码将不会运行。不幸的是，有几种方法可以限制子框架中的 JavaScript：

**在 IE 8 中：**

```html
<iframe src="http://www.victim.com" security="restricted"></iframe>
```

**在 Chrome 中：**

```html
<iframe src="http://www.victim.com" sandbox></iframe>
```

**Firefox 和 IE：**

在父页面中激活 [designMode](https://developer.mozilla.org/en-US/docs/Web/API/Document/designMode)：

```javascript
document.designMode = "on";
```
