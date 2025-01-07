# 跨站请求伪造（CSRF）防御备忘录

## 引言

[跨站请求伪造（CSRF）](https://owasp.org/www-community/attacks/csrf)攻击发生在恶意网站、电子邮件、博客、即时消息或程序诱使经过身份验证的用户的网络浏览器在受信任站点上执行非预期操作时。如果目标用户已通过目标站点的身份验证，未受保护的目标站点无法区分合法授权请求和伪造的经过身份验证的请求。

由于浏览器请求自动包含所有 Cookie（包括会话 Cookie），除非使用适当的授权，否则此攻击将起作用，这意味着目标站点的挑战-响应机制无法验证请求者的身份和权限。实际上，CSRF 攻击使目标系统通过受害者的浏览器执行攻击者指定的功能，而受害者并不知情（通常直到未经授权的操作已经完成）。

然而，成功的 CSRF 攻击只能利用易受攻击应用程序公开的功能和用户的权限。根据用户的凭据，攻击者可以转账、更改密码、进行未经授权的购买、提升目标账户的权限，或执行用户被允许的任何操作。

简而言之，应遵循以下原则来防御 CSRF：

**重要：请记住跨站脚本（XSS）可以击败所有 CSRF 缓解技术！**

- **请参阅 OWASP [XSS 防御速查表](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)，了解如何防止 XSS 漏洞的详细指导。**
- **首先，检查您的框架是否具有[内置 CSRF 保护](#使用内置或现有的-csrf-实现进行-csrf-保护)并使用它**
- **如果框架没有内置 CSRF 保护，请在所有状态改变的请求（在站点上导致操作的请求）中添加 [CSRF 令牌](#基于令牌的缓解)并在后端验证它们**
- **有状态软件应使用[同步器令牌模式](#同步器令牌模式)**
- **无状态软件应使用[双重提交 Cookie](#使用双重提交-cookie-模式的替代方案)**
- **如果 API 驱动的站点无法使用 `<form>` 标签，请考虑[使用自定义请求头](#为-ajaxapi-使用自定义请求头)**
- **从[纵深防御缓解](#纵深防御技术)部分实施至少一种缓解措施**
- **[SameSite Cookie 属性](#samesite-cookie-属性)可用于会话 Cookie**，但要小心不要为特定域设置 Cookie。此操作会引入安全漏洞，因为该域的所有子域将共享 Cookie，如果子域有 CNAME 指向不受控制的域，这尤其成问题。
- **对于高度敏感的操作，考虑实施[基于用户交互的保护](#基于用户交互的-csrf-防御)**
- **考虑[使用标准头验证源](#使用标准头验证源)**
- **不要对状态改变的操作使用 GET 请求。**
- **如果出于任何原因这样做，请防范这些资源的 CSRF**

## 基于令牌的缓解

[同步器令牌模式](#同步器令牌模式)是最流行和推荐的 CSRF 缓解方法之一。

### 使用内置或现有的 CSRF 实现进行 CSRF 保护

由于许多框架都内置了同步器令牌防御，在构建自定义令牌生成系统之前，请先查明您的框架是否默认提供 CSRF 保护。例如，.NET 可以使用[内置保护](https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-2.1)为易受 CSRF 攻击的资源添加令牌。如果选择使用此保护，.NET 会让您负责正确配置（如密钥管理和令牌管理）。

### 同步器令牌模式

CSRF 令牌应在服务器端生成，并且每个用户会话或每个请求只生成一次。由于攻击者利用被盗令牌的时间范围对于每次请求的令牌来说是最小的，因此它们比每会话令牌更安全。然而，使用每次请求的令牌可能会引起可用性问题。

例如，浏览器的"返回"按钮功能可能会受到每次请求令牌的阻碍，因为前一个页面可能包含不再有效的令牌。在这种情况下，与前一个页面的交互将在服务器端导致 CSRF 误报安全事件。如果在初始令牌生成后发生每会话令牌实现，则该值将存储在会话中，并用于每个后续请求，直到会话过期。

当客户端发出请求时，服务器端组件必须验证该请求中令牌的存在和有效性，并将其与用户会话中找到的令牌进行比较。如果在请求中未找到该令牌，或提供的值与用户会话中的值不匹配，则应拒绝该请求。还应考虑记录事件作为正在进行的潜在 CSRF 攻击的额外操作。

CSRF 令牌应该：

- 对每个用户会话唯一
- 保密
- 不可预测（由[安全方法](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#rule---use-cryptographically-secure-pseudo-random-number-generators-csprng)生成的大型随机值）

CSRF 令牌可以防止 CSRF，因为没有 CSRF 令牌，攻击者无法创建对后端服务器的有效请求。

#### 同步模式中的 CSRF 令牌传输

CSRF 令牌可以作为响应有效载荷的一部分传输给客户端，如 HTML 或 JSON 响应，然后可以通过表单提交中的隐藏字段或通过 AJAX 请求作为自定义头值或 JSON 有效载荷的一部分传回服务器。在同步模式下，不应在 Cookie 中传输 CSRF 令牌。CSRF 令牌不得泄露在服务器日志或 URL 中。GET 请求可能在多个位置泄露 CSRF 令牌，如浏览器历史记录、日志文件、记录 HTTP 请求第一行的网络实用程序以及如果受保护站点链接到外部站点时的 Referer 头。

例如：

```html
<form action="/transfer.do" method="post">
<input type="hidden" name="CSRFToken" value="OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==">
[...]
</form>
```

由于带有自定义头的请求自动受同源策略约束，通过 JavaScript 在自定义 HTTP 请求头中插入 CSRF 令牌比在隐藏字段表单参数中添加 CSRF 令牌更安全。

### 替代方案：使用双重提交 Cookie 模式

如果在服务器上维护 CSRF 令牌的状态存在问题，您可以使用一种称为双重提交 Cookie 模式的替代技术。这种技术易于实现且无状态。有不同的方法来实现这种技术，其中最常用的变体是"朴素"模式。

#### 签名双重提交 Cookie（推荐）

双重提交 Cookie 模式最安全的实现是"签名双重提交 Cookie"，它使用仅服务器知道的秘密密钥。这确保攻击者无法在受害者的经过身份验证的会话中创建和注入自己已知的 CSRF 令牌。系统的令牌应通过哈希或加密进行保护。

我们强烈建议使用基于哈希的消息认证（HMAC）算法，因为它比加密和解密 Cookie 的计算强度更低。您还应将 CSRF 令牌与用户的当前会话绑定，以进一步增强安全性。

##### 使用 HMAC CSRF 令牌

要生成 HMAC CSRF 令牌（使用会话相关的用户值），系统必须具备：

- **一个随每次登录会话变化的会话相关值**。此值应仅在用户整个经过身份验证的会话期间有效。避免使用静态值，如用户的电子邮件或 ID，因为它们不安全（[1](https://stackoverflow.com/a/8656417) | [2](https://stackoverflow.com/a/30539335) | [3](https://security.stackexchange.com/a/22936)）。值得注意的是，过于频繁地更新 CSRF 令牌（如每次请求）是一种误解，认为这会增加实质性安全性，而实际上会损害用户体验（[1](https://security.stackexchange.com/a/22936)）。例如，您可以选择以下一种或组合的会话相关值：
    - 服务器端会话 ID（例如 [PHP](https://www.php.net/manual/en/function.session-start.php) 或 [ASP.NET](<https://learn.microsoft.com/en-us/previous-versions/aspnet/ms178581(v=vs.100)>)）。此值永远不应离开服务器或在 CSRF 令牌中以明文存在。
    - JWT 中每次创建时变化的随机值（如 UUID）。
- **一个秘密的加密密钥**。不要与朴素实现中的随机值混淆。此值用于生成 HMAC 哈希。理想情况下，按照[加密存储页面](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-storage)中讨论的方式存储此密钥。
- **用于防止冲突的随机值**。生成一个随机值（最好是密码学随机值），以确保同一秒内的连续调用不会产生相同的哈希（[1](https://github.com/data-govt-nz/ckanext-security/issues/23#issuecomment-479752531)）。

**是否应在 CSRF 令牌中包含时间戳以设置过期时间？**

包含时间戳以指定 CSRF 令牌过期时间是一种常见的误解。CSRF 令牌不是访问令牌。它们用于在整个会话期间验证请求的真实性，使用会话信息。新会话应生成新令牌（[1](https://stackoverflow.com/a/30539335)）。

##### HMAC CSRF 令牌实现的伪代码

下面是一个伪代码示例，演示了上述实现步骤：

```code
// 收集值
secret = readEnvironmentVariable("CSRF_SECRET") // HMAC 秘密密钥
sessionID = session.sessionID // 当前经过身份验证的用户会话
randomValue = cryptographic.randomValue() // 密码学随机值

// 创建 CSRF 令牌
message = sessionID.length + "!" + sessionID + "!" + randomValue.length + "!" + randomValue // HMAC 消息有效载荷
hmac = hmac("SHA256", secret, message) // 生成 HMAC 哈希
csrfToken = hmac + "." + randomValue // 将 `randomValue` 添加到 HMAC 哈希以创建最终的 CSRF 令牌。避免使用 `message`，因为它包含明文的 sessionID，服务器已单独存储

// 在 Cookie 中存储 CSRF 令牌
response.setCookie("csrf_token=" + csrfToken + "; Secure") // 设置 Cookie，不使用 HttpOnly 标志
```

### 朴素双重提交 Cookie 模式（不推荐）

"朴素双重提交 Cookie"方法是一种可扩展且易于实现的技术，它使用密码学强随机值作为 Cookie 和请求参数（甚至在用户身份验证之前）。然后服务器验证 Cookie 值和请求值是否匹配。站点必须要求用户的每个事务请求都包含这个随机值作为隐藏表单值或请求头中。如果服务器端值匹配，则接受为合法请求；如果不匹配，则拒绝请求。

由于攻击者无法在跨站请求期间访问 Cookie 值，因此他们无法在隐藏表单值或作为请求参数/头中包含匹配的值。

尽管朴素双重提交 Cookie 方法是对抗 CSRF 的良好初步步骤，但它仍然容易受到某些攻击。[这个资源](https://owasp.org/www-chapter-london/assets/slides/David_Johansson-Double_Defeat_of_Double-Submit_Cookie.pdf)提供了更多关于一些漏洞的信息。因此，我们强烈建议使用"签名双重提交 Cookie"模式。

## 禁止简单请求

当使用 `<form>` 标签提交数据时，它会发送浏览器不会指定为"需要预检"的["简单"请求](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests)。这些"简单"请求引入了 CSRF 风险，因为浏览器允许它们被发送到任何源。如果您的应用程序在客户端的任何位置使用 `<form>` 标签提交数据，您仍需要使用本文档中描述的替代方法（如令牌）进行保护。

> **注意：**
如果浏览器漏洞允许自定义 HTTP 头，或者不对非简单内容类型强制执行预检，可能会危及您的安全。尽管可能性很低，但在威胁模型中考虑这一点是谨慎的。实施 CSRF 令牌可以增加额外的防御层，并给开发人员更多控制应用程序安全性的能力。

### 禁止简单内容类型

对于被视为简单的请求，它必须具有以下内容类型之一 - `application/x-www-form-urlencoded`、`multipart/form-data` 或 `text/plain`。许多现代 Web 应用程序使用 JSON API，因此自然需要 CORS，但它们可能接受 `text/plain`，这将容易受到 CSRF 攻击。因此，服务器或 API 禁止这些简单内容类型是一种简单的缓解方法。

### 为 AJAX/API 使用自定义请求头

同步器令牌和双重提交 Cookie 都用于防止表单数据伪造，但它们的实现可能很棘手并且会降低可用性。许多现代 Web 应用程序不使用 `<form>` 标签提交数据。对于 AJAX 或 API 端点来说，一种用户友好且特别适合的防御是使用**自定义请求头**。这种方法不需要令牌。

在这种模式中，客户端将自定义头附加到需要 CSRF 保护的请求。头可以是任意键值对，只要不与现有头冲突。

```
X-YOURSITE-CSRF-PROTECTION=1
```

处理请求时，API 检查此头的存在。如果头不存在，后端将请求拒绝为潜在伪造。这种方法有几个优点：

- 不需要更改用户界面
- 不引入服务器状态来跟踪令牌

这种防御依赖于 CORS 预检机制，它发送 `OPTIONS` 请求以验证与目标服务器的 CORS 合规性。所有现代浏览器都将带有自定义头的请求指定为"需要预检"。当 API 验证自定义头存在时，您就知道如果请求来自浏览器，它必须已经预检。

#### 自定义头和 CORS

默认情况下，Cookie 不会在跨源请求（CORS）上设置。要在 API 上启用 Cookie，您将设置 `Access-Control-Allow-Credentials=true`。如果允许凭据，浏览器将拒绝包含 `Access-Control-Allow-Origin=*` 的任何响应。要允许 CORS 请求但防止 CSRF，您需要确保服务器仅允许通过 `Access-Control-Allow-Origin` 头明确控制的少数选定源。来自允许域的任何跨源请求都将能够设置自定义头。

例如，您可以配置后端以允许来自 `http://www.yoursite.com` 和 `http://mobile.yoursite.com` 的带 Cookie 的 CORS，以便唯一可能的预检响应是：

```
Access-Control-Allow-Origin=http://mobile.yoursite.com
Access-Control-Allow-Credentials=true
```

或

```
Access-Control-Allow-Origin=http://www.yoursite.com
Access-Control-Allow-Credentials=true
```

一个不太安全的配置是配置后端服务器使用正则表达式允许来自站点所有子域的 CORS。如果攻击者能够[接管子域](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)（在云服务中并不罕见），您的 CORS 配置将允许他们绕过同源策略并伪造带有自定义头的请求。

## 处理客户端 CSRF 攻击（重要）

[客户端 CSRF](https://soheilkhodayari.github.io/same-site-wiki/docs/attacks/csrf.html#client-side-csrf) 是 CSRF 攻击的一种新变体，攻击者通过操纵程序的输入参数，诱使客户端 JavaScript 代码向易受攻击的目标站点发送伪造的 HTTP 请求。当 JavaScript 程序使用攻击者控制的输入（如 URL）生成异步 HTTP 请求时，就会发生客户端 CSRF。

**注意：** 这些 CSRF 变体特别重要，因为它们可以绕过一些常见的反 CSRF 对策，如[基于令牌的缓解](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#token-based-mitigation)和 [SameSite Cookie](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute)。例如，当使用[同步器令牌](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)或[自定义 HTTP 请求头](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers)时，JavaScript 程序将在异步请求中包含它们。此外，Web 浏览器将在 JavaScript 程序发起的同站点请求上下文中包含 Cookie，从而规避 [SameSite Cookie 策略](https://soheilkhodayari.github.io/same-site-wiki/docs/policies/overview.html)。

**客户端 CSRF 与经典 CSRF：** 在经典 CSRF 模型中，服务器端程序是最脆弱的组件，因为它无法区分传入的经过身份验证的请求是否是**有意**执行的，这也称为混淆代理问题。在客户端 CSR 模型中，最脆弱的组件是客户端 JavaScript 程序，因为攻击者可以通过操纵请求端点和/或其参数来生成任意异步请求。客户端 CSRF 是由于输入验证问题，并重新引入了混淆代理缺陷，即服务器端将再次无法区分请求是否是有意执行的。

有关客户端 CSRF 漏洞的更多信息，请参阅这篇[论文](https://www.usenix.org/system/files/sec21-khodayari.pdf)的第 2 和第 5 节，[SameSite wiki](https://soheilkhodayari.github.io/same-site-wiki)的 [CSRF 章节](https://soheilkhodayari.github.io/same-site-wiki/docs/attacks/csrf.html)，以及 [Meta 漏洞赏金计划](https://www.facebook.com/whitehat)的[这篇文章](https://www.facebook.com/notes/facebook-bug-bounty/client-side-csrf/2056804174333798/)。

### 客户端 CSRF 示例

以下代码片段展示了一个简单的客户端 CSRF 漏洞示例。

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");
    function ajaxLoad(){
        // 处理 URL 哈希片段
        let hash_fragment = window.location.hash.slice(1);

        // 哈希片段应该符合格式：/^(get|post);(.*)$/
        // 例如：https://site.com/index/#post;/profile
        if(hash_fragment.length > 0 && hash_fragment.indexOf(';') > 0 ){

            let params = hash_fragment.match(/^(get|post);(.*)$/);
            if(params && params.length){
                let request_method = params[1];
                let request_endpoint = params[3];

                fetch(request_endpoint, {
                    method: request_method,
                    headers: {
                        'XSRF-TOKEN': csrf_token,
                        // [...]
                    },
                    // [...]
                }).then(response => { /* [...] */ });
            }
        }
    }
    // 在页面加载时触发异步请求
    window.onload = ajaxLoad();
 </script>
```

**漏洞：** 在这个代码片段中，程序在页面加载时调用 `ajaxLoad()` 函数，该函数负责加载各种网页元素。该函数读取 [URL 哈希片段](https://developer.mozilla.org/en-US/docs/Web/API/Location/hash)的值（第 4 行），并从中提取两条信息（即请求方法和端点）以生成异步 HTTP 请求（第 11-13 行）。漏洞发生在第 15-22 行，当 JavaScript 程序使用 URL 片段获取异步 HTTP 请求的服务器端端点（第 15 行）和请求方法时。然而，这两个输入都可以被 Web 攻击者控制，他们可以选择自己想要的值，并制作包含攻击有效载荷的恶意 URL。

**攻击：** 通常，攻击者通过（例如钓鱼邮件等）元素与受害者共享恶意 URL，因为恶意 URL 看起来来自诚实、信誉良好（但易受攻击）的网站，用户经常点击它。或者，攻击者可以创建攻击页面来滥用浏览器 API（例如 [`window.open()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/open) API）并诱使目标页面的易受攻击的 JavaScript 发送 HTTP 请求，这与经典 CSRF 攻击的攻击模型非常相似。

更多客户端 CSRF 示例，请参见 [Meta 漏洞赏金计划](https://www.facebook.com/whitehat)的[这篇文章](https://www.facebook.com/notes/facebook-bug-bounty/client-side-csrf/2056804174333798/)和这篇 USENIX Security [论文](https://www.usenix.org/system/files/sec21-khodayari.pdf)。

### 客户端 CSRF 缓解技术

**独立请求：** 当无法通过攻击者可控制的输入（如 [URL](https://developer.mozilla.org/en-US/docs/Web/API/Window/location)、[窗口名称](https://developer.mozilla.org/en-US/docs/Web/API/Window/name)、[文档引用](https://developer.mozilla.org/en-US/docs/Web/API/Document/referrer)和 [postMessages](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)等）生成异步请求时，可以防止客户端 CSRF。

**输入验证：** 根据上下文和功能，完全隔离输入和请求参数可能并非总是可能。在这些情况下，必须实施输入验证检查。这些检查应严格评估请求参数值的格式和选择，并决定它们是否只能用于非状态更改操作（例如，仅允许 GET 请求和以预定义前缀开头的端点）。

**预定义请求数据：** 另一种缓解技术是在 JavaScript 代码中存储预定义的安全请求数据列表（例如，端点、请求方法和其他参数的组合，可以安全重放）。然后程序可以使用 URL 片段中的开关参数来决定每个 JavaScript 函数应使用列表的哪个条目。

## 深度防御技术

### SameSite（Cookie 属性）

SameSite 是一个 Cookie 属性（类似于 HTTPOnly、Secure 等），旨在缓解 CSRF 攻击。它在 [RFC6265bis](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7) 中定义。此属性帮助浏览器决定是否在跨站请求中发送 Cookie。此属性的可能值为 `Lax`、`Strict` 或 `None`。

Strict 值将阻止浏览器在所有跨站浏览上下文中向目标站点发送 Cookie，即使是跟随常规链接也是如此。例如，如果类似 GitHub 的网站使用 Strict 值，已登录的 GitHub 用户尝试跟随在公司讨论论坛或电子邮件中发布的私有 GitHub 项目的链接，用户将无法访问该项目，因为 GitHub 不会收到会话 Cookie。由于银行网站不允许从外部站点链接任何交易页面，因此 Strict 标志最适合银行。

如果网站希望在用户从外部链接到达后保持用户的登录会话，SameSite 的默认 Lax 值在安全性和可用性之间提供了合理的平衡。如果上述 GitHub 场景使用 Lax 值，会话 Cookie 将在从外部网站跟随常规链接时被允许，同时阻止 POST 等容易受到 CSRF 攻击的请求方法。在 Lax 模式下允许的跨站请求只有顶级导航，并使用[安全](https://tools.ietf.org/html/rfc7231#section-4.2.1)的 HTTP 方法。

有关 `SameSite` 值的更多详细信息，请查看 [rfc](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02) 中的[这一节](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1)。

使用此属性的 Cookie 示例：

```text
Set-Cookie: JSESSIONID=xxxxx; SameSite=Strict
Set-Cookie: JSESSIONID=xxxxx; SameSite=Lax
```

所有桌面浏览器和几乎所有移动浏览器现在都支持 `SameSite` 属性。要跟踪实施它的浏览器并了解属性的使用方式，请参考以下[服务](https://caniuse.com/#feat=same-site-cookie-attribute)。请注意，Chrome 已[宣布](https://blog.chromium.org/2019/10/developers-get-ready-for-new.html)他们将从 Chrome 80（预计在 2020 年 2 月）开始默认将 Cookie 标记为 `SameSite=Lax`，Firefox 和 Edge 也计划跟进。此外，对于标记为 `SameSite=None` 的 Cookie，将需要 `Secure` 标志。

需要注意的是，这个属性应作为额外的"深度防御"概念来实施。该属性通过支持它的浏览器保护用户，并且如[本节](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1)中提到的，它包含两种绕过方式。这个属性不应替代 CSRF 令牌。相反，它应该与该令牌共存，以更强大的方式保护用户。

### 使用标准头验证源

这种缓解方法有两个步骤，两者都检查 HTTP 请求头的值：

1. 确定请求的来源（源源头）。可以通过 Origin 或 Referer 头完成。
2. 确定请求的目标源（目标源）。

在服务器端，我们验证它们是否匹配。如果匹配，我们接受请求为合法（意味着是同源请求），如果不匹配，我们丢弃请求（意味着请求源自跨域）。对这些头的可靠性源于它们不能以编程方式更改，因为它们属于[禁止头](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name)列表，这意味着只有浏览器可以设置它们。

#### 识别源源头（通过 Origin/Referer 头）

##### 检查 Origin 头

如果存在 Origin 头，验证其值是否匹配目标源。与 Referer 不同，Origin 头将出现在源自 HTTPS URL 的 HTTP 请求中。

##### 如果 Origin 头不存在，则检查 Referer 头

如果 Origin 头不存在，验证 Referer 头中的主机名是否匹配目标源。这种 CSRF 缓解方法也常用于未经身份验证的请求，例如在建立会话状态之前发出的请求，这需要跟踪同步令牌。

在这两种情况下，确保目标源检查是严格的。例如，如果您的站点是 `example.org`，请确保 `example.org.attacker.com` 无法通过您的源检查（即，通过源后的尾随 / 匹配以确保匹配整个源）。

如果这些头都不存在，您可以接受或阻止请求。我们建议**阻止**。或者，您可能想记录所有此类实例，监控其用例/行为，然后仅在获得足够信心后开始阻止请求。

#### 识别目标源

通常，确定目标源并不总是容易的。您并不总是能够简单地从请求中的 URL 获取目标源（即其主机名和端口 `#`），因为应用程序服务器经常位于一个或多个代理之后。这意味着原始 URL 可能与应用程序服务器实际接收的 URL 不同。但是，如果您的应用程序服务器直接被用户访问，那么使用 URL 中的源是可以的。

如果您位于代理之后，有几个选项可以考虑。

- **配置应用程序以简单地知道其目标源：** 由于这是您的应用程序，您可以找到其目标源并在某些服务器配置条目中设置该值。这将是最安全的方法，因为它在服务器端定义，所以是可信的值。但是，如果您的应用程序部署在多个地方（如开发、测试、QA、生产，可能还有多个生产实例），这可能难以维护。为每个情况设置正确的值可能很困难，但如果您可以通过某种中央配置并为实例提供获取值的能力，那就太好了！（**注意：**确保集中配置存储是安全的，因为您的 CSRF 防御的主要部分取决于它。）
- **使用 Host 头值：** 如果您希望应用程序找到自己的目标，而不必为每个部署实例配置，我们建议使用 Host 系列头。Host 头旨在包含请求的目标源。但是，如果您的应用程序服务器位于代理之后，Host 头值很可能被代理更改为代理后面 URL 的目标源，这与原始 URL 不同。这个修改后的 Host 头源将与原始 Origin 或 Referer 头中的源源头不匹配。
- **使用 X-Forwarded-Host 头值：** 为避免代理更改主机头的可能性，您可以使用另一个名为 X-Forwarded-Host 的头来包含代理收到的原始 Host 头值。大多数代理会在 X-Forwarded-Host 头中传递原始 Host 头值。因此，X-Forwarded-Host 中的值很可能是您需要与 Origin 或 Referer 头中的源源头比较的目标源值。

当请求中存在源或引用头时，使用此头值进行缓解将正常工作。尽管这些头大多数时候都包含在内，但有一些用例不包含这些头（大多数是出于保护用户隐私/调整浏览器生态系统的正当理由）。

**X-Forward-Host 未使用的用例：**

- 在[跨源 302 重定向](https://stackoverflow.com/questions/22397072/are-there-any-browsers-that-set-the-origin-header-to-null-for-privacy-sensitiv)后，由于可能被视为不应发送到其他源的敏感信息，重定向请求中不包含 Origin。
- 在某些[隐私上下文](https://wiki.mozilla.org/Security/Origin#Privacy-Sensitive_Contexts)中，Origin 设置为"null"。例如，请参见[此处](https://www.google.com/search?q=origin+header+sent+null+value+site%3Astackoverflow.com&oq=origin+header+sent+null+value+site%3Astackoverflow.com)。
- Origin 头包含在所有跨源请求中，但对于同源请求，在大多数浏览器中仅在 POST/DELETE/PUT 中包含 **注意：** 尽管不理想，但许多开发人员使用 GET 请求执行状态更改操作。
- Referer 头也不例外。有多个用例省略了引用头（[1](https://stackoverflow.com/questions/6880659/in-what-cases-will-http-referer-be-empty)，[2](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer)，[3](https://en.wikipedia.org/wiki/HTTP_referer#Referer_hiding)，[4](https://seclab.stanford.edu/websec/csrf/csrf.pdf) 和 [5](https://www.google.com/search?q=referrer+header+sent+null+value+site:stackoverflow.com)）。负载均衡器、代理和嵌入式网络设备也以记录隐私为由众所周知地剥离引用头。

通常，很小一部分流量（[1-2%](http://homakov.blogspot.com/2012/04/playing-with-referer-origin-disquscom.html)）属于上述类别，没有企业希望丢失这些流量。在互联网上广泛使用的一种技术是，如果 Origin/引用头与您配置的域名列表"或"空值匹配，则接受请求（[示例在此](http://homakov.blogspot.com/2012/04/playing-with-referer-origin-disquscom.html)。空值是为了涵盖上述未发送这些头的边缘情况）。请注意，攻击者可以利用这一点，但人们倾向于将其作为深度防御措施，因为部署它只需很少的工作。

#### 使用带有主机前缀的 Cookie 识别源

虽然前面提到的 `SameSite` 和 `Secure` 属性限制了已设置 Cookie 的发送，`HttpOnly` 限制了对已设置 Cookie 的读取，但攻击者仍可能尝试注入或覆盖otherwise安全的 Cookie（参见[会话固定攻击](http://www.acrossecurity.com/papers/session_fixation.pdf)）。对于带有 CSRF 令牌的 Cookie 使用 `Cookie 前缀` 可以扩展针对此类攻击的安全保护。如果 Cookie 具有 `__Host-` 前缀，例如 `Set-Cookie: __Host-token=RANDOM; path=/; Secure`，则每个 Cookie：

- 不能从另一个子域（over）写入
- 不能有 `Domain` 属性
- 必须具有 `/` 路径
- 必须标记为 Secure（即不能通过未加密的 HTTP 发送）

除了 `__Host-` 前缀外，浏览器供应商还支持较弱的 `__Secure-` 前缀。它放宽了域覆盖的限制，即它们：

- 可以有 `Domain` 属性
- 可以被子域覆盖
- 可以有除 `/` 之外的 `Path`

如果经过身份验证的用户需要访问不同的（子）域，这种放宽的变体可以作为"域锁定" `__Host-` 前缀的替代。在所有其他情况下，建议除了 `SameSite` 属性外还使用 `__Host-` 前缀。

截至 2020 年 7 月，[所有主要浏览器都支持 Cookie 前缀](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Browser_compatibility)。

有关 Cookie 前缀的更多信息，请参见 [Mozilla 开发者网络](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)和 [IETF 草案](https://tools.ietf.org/html/draft-west-cookie-prefixes-05)。

### 基于用户交互的 CSRF 防御

虽然这里引用的所有技术都不需要用户交互，但有时涉及用户参与事务以防止未经授权的操作（通过 CSRF 或其他方式伪造）会更容易或更合适。以下是一些可以作为强大 CSRF 防御的技术示例（如果正确实施）。

- 重新认证机制
- 一次性令牌

不要使用 CAPTCHA，因为它专门设计用于防止机器人。在某些 CAPTCHA 实现中，从不同的用户会话获取人机交互/存在的证明是可能的。尽管这使 CSRF 漏洞利用更加复杂，但它并不能防止 CSRF。

虽然这些是非常强大的 CSRF 防御，但可能会对用户体验产生重大影响。因此，它们通常仅用于安全关键操作（如更改密码、资金转账等），并与本速查表中讨论的其他防御措施一起使用。

## 登录表单中可能的 CSRF 漏洞

大多数开发人员倾向于忽略登录表单上的 CSRF 漏洞，因为他们假设 CSRF 在用户尚未通过身份验证的阶段不适用，但这种假设并不总是正确。即使在用户未经身份验证的情况下，登录表单仍可能发生 CSRF 漏洞，但影响和风险是不同的。

例如，如果攻击者使用 CSRF 在购物网站上假冒目标受害者的已验证身份，使用攻击者的账户，然后受害者输入其信用卡信息，攻击者可能能够使用受害者存储的卡详细信息购买商品。有关登录 CSRF 和其他风险的更多信息，请参见[此论文](https://seclab.stanford.edu/websec/csrf/csrf.pdf)的第 3 节。

通过创建预会话（用户通过身份验证之前的会话）并在登录表单中包含令牌，可以缓解登录 CSRF。您可以使用上面提到的任何技术生成令牌。请记住，预会话不能在用户通过身份验证后转换为真实会话 - 应销毁会话并创建新会话，以避免[会话固定攻击](http://www.acrossecurity.com/papers/session_fixation.pdf)。这种技术在[《Robust Defenses for Cross-Site Request Forgery》第 4.1 节](https://seclab.stanford.edu/websec/csrf/csrf.pdf)中有描述。登录 CSRF 还可以通过在 AJAX 请求中包含自定义请求头来缓解，如[上文](#employing-custom-request-headers-for-ajaxapi)所述。

#### AngularJS

AngularJS 允许为 HTTP 操作设置默认头。更多文档可以在 AngularJS 的 [$httpProvider](https://docs.angularjs.org/api/ng/provider/$httpProvider#defaults) 文档中找到。

```html
<script>
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    var app = angular.module("app", []);

    app.config(['$httpProvider', function ($httpProvider) {
        $httpProvider.defaults.headers.post["anti-csrf-token"] = csrf_token;
        $httpProvider.defaults.headers.put["anti-csrf-token"] = csrf_token;
        $httpProvider.defaults.headers.patch["anti-csrf-token"] = csrf_token;
        // AngularJS 默认不为 DELETE 和 TRACE 方法创建对象，必须手动创建。
        $httpProvider.defaults.headers.delete = {
            "Content-Type" : "application/json;charset=utf-8",
            "anti-csrf-token" : csrf_token
        };
        $httpProvider.defaults.headers.trace = {
            "Content-Type" : "application/json;charset=utf-8",
            "anti-csrf-token" : csrf_token
        };
      }]);
 </script>
```

此代码片段已在 AngularJS 版本 1.7.7 上测试。

#### Axios

[Axios](https://github.com/axios/axios) 允许我们为 POST、PUT、DELETE 和 PATCH 操作设置默认头。

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    axios.defaults.headers.post['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.put['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.delete['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.patch['anti-csrf-token'] = csrf_token;

    // Axios 默认不为 TRACE 方法创建对象，必须手动创建。
    axios.defaults.headers.trace = {}
    axios.defaults.headers.trace['anti-csrf-token'] = csrf_token
</script>
```

此代码片段已在 Axios 版本 0.18.0 上测试。

#### JQuery

JQuery 提供了一个名为 `$.ajaxSetup()` 的 API，可用于向 AJAX 请求添加 `anti-csrf-token` 头。`$.ajaxSetup()` 的 API 文档可以在此处找到。下面定义的函数 `csrfSafeMethod()` 将过滤出安全的 HTTP 方法，并仅对不安全的 HTTP 方法添加头。

通过采用以下代码片段，您可以配置 jQuery 自动将令牌添加到所有请求头。这为基于 AJAX 的应用程序提供了简单方便的 CSRF 保护：

```html
<script type="text/javascript">
    var csrf_token = $('meta[name="csrf-token"]').attr('content');

    function csrfSafeMethod(method) {
        // 这些 HTTP 方法不需要 CSRF 保护
        return (/^(GET|HEAD|OPTIONS)$/.test(method));
    }

    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("anti-csrf-token", csrf_token);
            }
        }
    });
</script>
```

此代码片段已在 jQuery 版本 3.3.1 上测试。

## 相关速查表中的参考文献

### CSRF

- [OWASP 跨站请求伪造（CSRF）](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger Web 安全学院](https://portswigger.net/web-security/csrf)
- [Mozilla Web 安全速查表](https://infosec.mozilla.org/guidelines/web_security#csrf-prevention)
- [常见 CSRF 预防误解](https://medium.com/keylogged/common-csrf-prevention-misconceptions-67fd026d94a8)
- [跨站请求伪造的强健防御](https://seclab.stanford.edu/websec/csrf/csrf.pdf)
- 对于 Java：OWASP [CSRF Guard](https://owasp.org/www-project-csrfguard/) 或 [Spring Security](https://docs.spring.io/spring-security/site/docs/5.5.x-SNAPSHOT/reference/html5/#csrf)
- 对于 PHP 和 Apache：[CSRFProtector 项目](https://github.com/OWASP/www-project-csrfprotector)
- 对于 AngularJS: [Cross-Site Request Forgery (XSRF) Protection](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection)
