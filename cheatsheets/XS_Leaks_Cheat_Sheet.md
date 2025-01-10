# 跨站点泄露备忘录

## 引言

本文描述了针对跨站点泄露漏洞（XS Leaks）的攻击和防御示例。由于该漏洞基于现代网络浏览器的核心机制，也被称为浏览器侧信道攻击。XS-Leaks 攻击试图利用站点间跨站通信中看似微不足道的信息交换。攻击者可以通过这些信息推断出关于受害者用户账户的预设问题的答案。请查看以下示例：

- 用户当前是否已登录？
- 用户 ID 是否为 1337？
- 用户是否为管理员？
- 用户的联系人列表中是否有特定邮箱地址的人？

基于这类问题，攻击者可能尝试推断答案，具体取决于应用程序的上下文。在大多数情况下，答案将以二进制形式呈现（是或否）。此漏洞的影响很大程度上取决于应用程序的风险配置。尽管如此，XS Leaks 可能对用户隐私和匿名性构成真正的威胁。

## 攻击向量

![XS Leaks 攻击向量](../assets/XS_Attack_Vector.png)

- 整个攻击发生在受害者的浏览器端 - 就像 XSS 攻击一样
- 在某些情况下，受害者必须在攻击者的站点上停留更长时间，攻击才能成功。

## 同源策略（SOP）

在描述攻击之前，了解浏览器中最关键的安全机制之一 - 同源策略很重要。几个关键方面：

- 如果两个 URL 的**协议**、**端口**和**主机**相同，则被视为**同源**
- 任何源都可以向另一个源发送请求，但由于同源策略，它们无法直接读取响应
- 同源策略可以通过[跨域资源共享（CORS）](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)放宽。

| 源 A                   | 源 B                      | 是否同源？                    |
| -------------         | -------------             | -------------                  |
| `https://example.com` | `http://sub.example.com`  | 否，主机不同                   |
| `https://example.com` | `https://example.com:443` | 是！源 A 中的隐式端口          |

尽管同源策略原则上保护我们不能访问跨源通信中的信息，但基于残留数据的 XS-Leaks 攻击仍可推断某些信息。

## SameSite Cookies

Cookie 的 SameSite 属性告诉浏览器是否应在来自其他站点的请求中包含该 Cookie。SameSite 属性有以下值：

- `None` - Cookie 将附加到来自另一个站点的请求，但必须通过安全的 HTTPS 通道发送
- `Lax` - 如果请求方法是 GET 且请求是顶级导航（即导航更改浏览器地址栏），则 Cookie 将附加到来自另一个页面的请求
- `Strict` - Cookie 永远不会从另一个站点发送

值得一提的是，在基于 Chromium 的浏览器中，默认情况下未设置 SameSite 属性的 Cookie 被视为 Lax。

SameSite Cookie 是针对某些类型的 XS Leaks 和 [CSRF 攻击](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)的强大**深度防御**机制，可以显著减少攻击面，但可能无法完全切断（参见，例如，[基于窗口的 XS Leak](https://soheilkhodayari.github.io/same-site-wiki/docs/attacks/xs-leaks.html)攻击，如[帧计数](https://xsleaks.dev/docs/attacks/frame-counting/)和[导航](https://xsleaks.dev/docs/attacks/navigations/)）。

### 我们如何知道两个站点是 SameSite？

![XS Leaks eTLD 解释](../assets/XS_Leaks_eTLD.png)

在 SameSite 属性的上下文中，我们将站点视为 TLD（顶级域）和它之前的域名的组合。例如：

| 完整 URL                                      | 站点（eTLD+1）             |
| --------------------------------------------  | ------------------------  |
| `https://example.com:443/data?query=test`     | `example.com`             |

为什么我们讨论 eTLD+1 而不是简单的 TLD+1？这是因为像 `.github.io` 或 `.eu.org` 这样的域名。这些部分不够原子，无法很好地比较。因此，创建了一个"有效"TLD（eTLDs）列表，可以在[此处](https://publicsuffix.org/list/public_suffix_list.dat)找到。

具有相同 eTLD+1 的站点被视为 SameSite，示例：

| 源 A                   | 源 B                    | 是否 SameSite？             |
| ---------------------- | ----------------------- | -------------------------- |
| `https://example.com`  | `http://example.com`    | 是，方案无关紧要             |
| `https://evil.net`     | `https://example.com`   | 否，不同的 eTLD+1            |
| `https://sub.example.com` | `https://data.example.com` | 是，子域无关紧要           |

有关 SameSite 的更多信息，请参阅优秀文章[理解"同站点"](https://web.dev/same-site-same-origin/)。

## 使用元素 ID 属性的攻击

DOM 中的元素可以有一个在文档中唯一的 ID 属性。例如：

```html
<button id="pro">专业账户</button>
```

如果我们在 URL 后附加哈希值，浏览器将自动聚焦到具有给定 ID 的元素，例如 `https://example.com#pro`。更重要的是，JavaScript [焦点事件](https://developer.mozilla.org/en-US/docs/Web/API/Element/focus_event)会被触发。攻击者可能尝试在自己控制的页面中使用特定源嵌入应用程序的 iframe：

![XS-Leaks-ID](../assets/XS_Leaks_ID.png)

然后在主文档中为[模糊事件](https://developer.mozilla.org/en-US/docs/Web/API/Element/blur_event)（焦点的反面）添加监听器。当受害者访问攻击者的站点时，模糊事件被触发。攻击者将能够推断出受害者拥有专业账户。

### 防御

#### 框架保护

如果您不需要其他源在框架中嵌入您的应用程序，可以考虑使用以下两种机制之一：

- **内容安全策略框架祖先**指令。[阅读有关语法的更多信息](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src)。
- **X-Frame-Options** - 主要用于支持旧浏览器。

有效设置框架保护可以有效阻止在攻击者控制的源中嵌入您的应用程序，并防止其他攻击，如[点击劫持](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)。

#### 获取元数据（Sec-Fetch-Dest）

Sec-Fetch-Dest 标头为我们提供了关于请求最终目标的信息。该标头由浏览器自动包含，是获取元数据标准中的标头之一。

使用 Sec-Fetch-Dest，您可以构建有效的资源隔离策略，例如：

```javascript
app.get('/', (req, res) => {
    if (req.get('Sec-Fetch-Dest') === 'iframe') {
        return res.sendStatus(403);
    }
    res.send({
        message: '你好！'
    });
});
```

![XS Leaks Sec-Fetch-Dest](../assets/XS_Leaks_Sec_Fetch_Dest.png)

如果要使用获取元数据标准的标头，请确保您的用户浏览器支持此标准（您可以在[此处](https://caniuse.com/?search=sec-fetch)检查）。另外，考虑在代码中使用适当的回退，以防请求中未包含 Sec-Fetch-* 标头。

## 基于错误事件的攻击

从其他源嵌入资源通常是允许的。例如，您可以在页面上嵌入来自另一个源的图像或脚本。但是，由于同源策略，不允许读取跨源资源。

当浏览器发送资源请求时，服务器处理请求并决定响应（例如 200 OK 或 404 NOT FOUND）。浏览器接收 HTTP 响应，并基于此触发适当的 JavaScript 事件（onload 或 onerror）。

通过这种方式，我们可以尝试加载资源，并根据响应状态推断它们在已登录受害者的上下文中是否存在。让我们看看以下情况：

- `GET /api/user/1234` - 200 OK - 当前登录用户是 1234，因为我们成功加载了资源（触发了 [onload](https://developer.mozilla.org/en-US/docs/Web/API/GlobalEventHandlers/onload) 事件）
- `GET /api/user/1235` - 401 未授权 - 1235 不是当前登录用户的 ID（将触发 [onerror](https://developer.mozilla.org/en-US/docs/Web/API/GlobalEventHandlers/onerror) 事件）

基于上述示例，攻击者可以在其控制的源上使用 JavaScript 通过简单的循环枚举所有值来猜测受害者的 ID。

```javascript
function checkId(id) {
    const script = document.createElement('script');
    script.src = `https://example.com/api/users/${id}`;
    script.onload = () => {
        console.log(`登录用户 ID: ${id}`);
    };
    document.body.appendChild(script);
}

// 生成数组 [0, 1, ..., 40]
const ids = Array(41)
    .fill()
    .map((_, i) => i + 0);

for (const id of ids) {
    checkId(id);
}
```

请注意，攻击者在这里并不关心读取响应正文，即使由于浏览器中的坚固隔离机制（如[跨源资源阻止](https://www.chromium.org/Home/chromium-security/corb-for-developers)），它也无法读取。它所需要的只是 `onload` 事件触发时收到的成功信息。

### 防御

#### 子资源保护

在某些情况下，可以实施特殊唯一令牌机制来保护敏感端点。

```
/api/users/1234?token=be930b8cfb5011eb9a030242ac130003
```

- 令牌应该长且唯一
- 后端必须正确验证请求中传递的令牌

尽管相当有效，但该解决方案在正确实施时会产生显著的开销。

#### 获取元数据（Sec-Fetch-Site）

此标头指定请求的发送来源，它具有以下值：

- `cross-site`
- `same-origin`
- `same-site`
- `none` - 用户直接访问页面

与 Sec-Fetch-Dest 类似，此标头由浏览器自动附加到每个请求，是获取元数据标准的一部分。使用示例：

```javascript
app.get('/api/users/:id', authorization, (req, res) => {
    if (req.get('Sec-Fetch-Site') === 'cross-site') {
        return res.sendStatus(403);
    }

    // ... 更多代码

    return res.send({ id: 1234, name: '约翰', role: '管理员' });
});
```

#### 跨源资源策略（CORP）

如果服务器返回带有适当值的此标头，浏览器将不会在另一个应用程序中加载来自我们站点或源的资源（甚至是静态图像）。可能的值：

- `same-site`
- `same-origin`
- `cross-origin`

阅读有关 CORP 的更多信息[请点击此处](https://resourcepolicy.fyi/)。

## postMessage 通信攻击

有时在受控情况下，尽管有同源策略，我们仍希望在不同源之间交换信息。我们可以使用 postMessage 机制。请看下面的示例：

```javascript
// 源：http://example.com
const site = new URLSearchParams(window.location.search).get('site'); // https://evil.com
const popup = window.open(site);
popup.postMessage('秘密消息！', '*');

// 源：https://evil.com
window.addEventListener('message', e => {
    alert(e.data) // 秘密消息！ - 泄露
});
```

### 防御

#### 指定严格的目标源

为避免如上所示的情况（攻击者设法获取窗口引用以接收消息），请始终在 postMessage 中指定确切的 `targetOrigin`。将通配符 `*` 传递给 `targetOrigin` 会导致任何源都能接收消息。

```javascript
// 源：http://example.com
const site = new URLSearchParams(window.location.search).get('site'); // https://evil.com
const popup = window.open(site);
popup.postMessage('秘密消息！', 'https://sub.example.com');

// 源：https://evil.com
window.addEventListener('message', e => {
    alert(e.data) // 无数据！
});
```

## 帧计数攻击

窗口中已加载帧的数量信息可能成为信息泄露的来源。以加载搜索结果到框架的应用程序为例，如果结果为空，则框架不会出现。

![XS-Leaks-Frame-Counting](../assets/XS_Leaks_Frame_Counting.png)

攻击者可以通过计算 `window.frames` 对象中的帧数来获取窗口中已加载帧的数量信息。

最终，攻击者可以获取电子邮件列表，并在简单的循环中打开后续窗口并计算帧数。如果打开窗口中的帧数等于 1，则该电子邮件存在于受害者使用的应用程序的客户端数据库中。

### 防御

#### 跨源打开策略（COOP）

设置此标头将阻止跨源文档在同一浏览上下文组中打开。此解决方案确保打开另一个文档的文档 A 将无法访问 `window` 对象。可能的值：

- `unsafe-none`
- `same-origin-allow-popups`
- `same-origin`

如果服务器返回 `same-origin` COOP 标头，攻击将失败：

```javascript
const win = window.open('https://example.com/admin/customers?search=john%40example.com');
console.log(win.frames.length) // 无法读取 'length' 属性为 null
```

## 使用浏览器缓存的攻击

浏览器缓存有助于显著减少页面重新访问时的加载时间。然而，它也可能造成信息泄露风险。如果攻击者能够在加载后检测资源是否从缓存加载，他将能够据此得出一些结论。

原理很简单，从缓存内存加载的资源将比从服务器加载快得多。

![XS Leaks 缓存攻击](../assets/XS_Leaks_Cache_Attack.png)

攻击者可以在其站点上嵌入一个仅对具有管理员角色的用户可访问的资源。然后，使用 JavaScript 读取特定资源的加载时间，并基于此信息推断资源是否在缓存中。

```javascript
    // 超过此阈值时，我们认为资源是从服务器加载的
    // const THRESHOLD = ...

    const adminImagePerfEntry = window.performance
        .getEntries()
        .filter((entry) => entry.name.endsWith('admin.svg'));

    if (adminImagePerfEntry.duration < THRESHOLD) {
        console.log('图像从缓存加载！')
    }
```

### 防御

#### 图像的不可预测令牌

当用户希望资源仍然被缓存，而攻击者无法了解到这一点时，此技术是准确的。

```
/avatars/admin.svg?token=be930b8cfb5011eb9a030242ac130003
```

- 令牌在每个用户的上下文中应该是唯一的
- 如果攻击者无法猜测此令牌，它将无法检测资源是否从缓存加载

#### 使用 Cache-Control 标头

如果您接受与每次用户访问站点时必须从服务器重新加载资源相关的性能下降，可以禁用缓存机制。要禁用要保护的资源的缓存，请设置响应标头 `Cache-Control: no-store`。

## 快速建议

- 如果您的应用程序使用 Cookie，请确保设置适当的 [SameSite 属性](#samesite-cookies)。
- 考虑是否真的希望允许在框架中嵌入您的应用程序。如果不希望，请考虑使用[框架保护](#框架保护)部分中描述的机制。
- 要加强应用程序与其他源之间的隔离，请使用[跨源资源策略](#跨源资源策略corp)和[跨源打开策略](#跨源打开策略coop)标头，并设置适当的值。
- 使用获取元数据中可用的标头构建您自己的资源隔离策略。

## 参考文献

### XS Leaks

- [XS Leaks Wiki](https://xsleaks.dev/)
- [XS Leaks 攻击与防御](https://www.appsecmonkey.com/blog/xs-leaks)

### 获取元数据

- [获取元数据和隔离策略](https://www.appsecmonkey.com/blog/fetch-metadata)
- [使用获取元数据保护您的资源免受攻击](https://web.dev/fetch-metadata/)

### 框架保护

- [使用策略防止框架](https://pragmaticwebsecurity.com/articles/securitypolicies/preventing-framing-with-policies.html)
- [CSP 'frame-ancestors' 策略](https://content-security-policy.com/frame-ancestors/)

### SameSite

- [SameSite Cookie 详解](https://web.dev/samesite-cookies-explained/)
- [SameSite Cookie 配方](https://web.dev/samesite-cookie-recipes/)

### COOP 和 CORP 标头

- [使您的站点"跨源隔离"](https://web.dev/coop-coep/)
- [MDN Web 文档关于 CORP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_%28CORP%29)
