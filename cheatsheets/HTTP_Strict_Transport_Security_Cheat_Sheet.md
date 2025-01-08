# HTTP 严格传输安全备忘录

## 简介

HTTP [严格传输安全](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Strict-Transport-Security)（也称为 **HSTS**）是一种通过特殊响应头由 Web 应用程序选择性开启的安全增强机制。当支持的浏览器接收到此头后，将阻止对指定域名的任何 HTTP 通信，并强制所有通信通过 HTTPS 进行。它还可以防止浏览器上的 HTTPS 点击提示。

该规范已于 2012 年底由 IETF 发布为 [RFC 6797](http://tools.ietf.org/html/rfc6797)（HTTP 严格传输安全（HSTS））。

## 威胁

HSTS 解决了以下威胁：

- 用户收藏夹或手动输入 `http://example.com`，并可能遭受中间人攻击
    - HSTS 自动将目标域名的 HTTP 请求重定向到 HTTPS
- Web 应用程序本应完全使用 HTTPS，但inadvertently包含 HTTP 链接或通过 HTTP 提供内容
    - HSTS 自动将目标域名的 HTTP 请求重定向到 HTTPS
- 中间人攻击者试图使用无效证书拦截受害者用户的流量，并希望用户接受错误的证书
    - HSTS 不允许用户覆盖无效证书消息

## 示例

简单示例，使用较长的 max-age（1年 = 31536000 秒）。此示例存在风险，因为缺少 `includeSubDomains`：

`Strict-Transport-Security: max-age=31536000`

如果所有当前和未来的子域都将使用 HTTPS，则此示例很有用。这是一个更安全的选项，但会阻止仅能通过 HTTP 提供的某些页面：

`Strict-Transport-Security: max-age=31536000; includeSubDomains`

如果所有当前和未来的子域都将使用 HTTPS，则此示例很有用。在此示例中，我们在初始部署期间设置了非常短的 max-age：

`Strict-Transport-Security: max-age=86400; includeSubDomains`

**推荐：**

- 如果站点所有者希望将其域名包含在由 Chrome 维护的 [HSTS 预加载列表](https://hstspreload.org)（并被 Firefox 和 Safari 使用）中，则使用以下头：
- 从您的站点发送 `preload` 指令可能会产生**永久性后果**，如果您需要切换回 HTTP，可能会阻止用户访问您的站点及其所有子域。在发送带有 `preload` 的头之前，请仔细阅读 [预加载移除](https://hstspreload.org/#removal) 的详细信息。

`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

`preload` 标志表示站点所有者同意将其域名预加载。站点所有者仍需提交域名到列表中。

## 问题

站点所有者可以使用 HSTS 在没有 Cookie 的情况下识别用户。这可能导致严重的隐私泄露。更多详情请查看[此处](http://www.leviathansecurity.com/blog/the-double-edged-sword-of-hsts-persistence-and-privacy)。

Cookie 可以从子域被篡改，因此省略 `includeSubDomains` 选项会允许广泛的与 Cookie 相关的攻击，而 HSTS 通过要求子域有效证书可以防止这些攻击。确保在所有 Cookie 上设置 `secure` 标志也可以防止部分（但非全部）此类攻击。

## 浏览器支持

截至 2019 年 9 月，HSTS 已被[所有现代浏览器](https://caniuse.com/#feat=stricttransportsecurity)支持，唯一值得注意的例外是 Opera Mini。

## 参考资料

- [Chromium 项目/HSTS](https://www.chromium.org/hsts/)
- [OWASP TLS 保护备忘录](Transport_Layer_Security_Cheat_Sheet.md)
- [sslstrip](https://github.com/moxie0/sslstrip)
- [AppSecTutorial 系列 - 第 4 集](https://www.youtube.com/watch?v=zEV3HOuM_Vw)
- [用于检测 HSTS 配置的 Nmap NSE 脚本](https://github.com/icarot/NSE_scripts/blob/master/http-hsts-verify.nse)
