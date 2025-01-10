# REST 安全备忘录

## 介绍

[REST](http://en.wikipedia.org/wiki/Representational_state_transfer)（或**RE**presentational **S**tate **T**ransfer）是一种架构风格，最初在 [Roy Fielding](https://en.wikipedia.org/wiki/Roy_Fielding) 的博士论文《[架构风格与基于网络的软件架构设计](https://www.ics.uci.edu/~fielding/pubs/dissertation/top.htm)》中首次描述。

它是在 Fielding 编写 HTTP/1.1 和 URI 规范时演进的，并已被证明非常适合开发分布式超媒体应用。虽然 REST 更广泛适用，但它最常用于通过 HTTP 与服务通信。

REST 中信息的关键抽象是资源。REST API 资源由 URI 标识，通常是 HTTP URL。REST 组件使用连接器通过表示来捕获资源的当前或预期状态并传输该表示，从而对资源执行操作。

主要连接器类型是客户端和服务器，次要连接器包括缓存、解析器和隧道。

REST API 是无状态的。有状态的 API 不遵循 REST 架构风格。REST 首字母缩写中的"状态"指的是 API 访问的资源的状态，而不是调用 API 的会话状态。尽管构建有状态 API 可能有充分的理由，但重要的是要认识到管理会话是复杂且难以安全地进行的。

有状态服务不在本备忘录的讨论范围内：*从客户端向后端传递状态，同时使服务在技术上无状态，是一种反模式，应该避免，因为它容易遭受重放和模仿攻击。*

为了使用 REST API 实现流程，通常会创建、读取、更新和删除资源。例如，电子商务网站可能提供创建空购物车、向购物车添加商品和结账的方法。每个 REST 调用都是无状态的，端点应检查调用者是否有权执行请求的操作。

REST 应用的另一个关键特征是使用标准 HTTP 动词和错误代码，以消除不同服务之间不必要的变化。

REST 应用的另一个关键特征是使用 [HATEOAS 或超媒体作为应用状态引擎](https://en.wikipedia.org/wiki/HATEOAS)。这为 REST 应用提供了自文档的特性，使开发者更容易在没有先验知识的情况下与 REST 服务交互。

## HTTPS

安全的 REST 服务必须仅提供 HTTPS 端点。这保护传输中的身份验证凭据，例如密码、API 密钥或 JSON Web 令牌。它还允许客户端验证服务并保证传输数据的完整性。

有关更多信息，请参见[传输层安全备忘录](Transport_Layer_Security_Cheat_Sheet.md)。

考虑使用双向认证的客户端证书为高权限 Web 服务提供额外保护。

## 访问控制

非公开的 REST 服务必须在每个 API 端点执行访问控制。单体应用中的 Web 服务通过用户身份验证、授权逻辑和会话管理来实现这一点。对于遵循 RESTful 风格的多个微服务组成的现代架构来说，这有几个缺点。

- 为了最小化延迟并减少服务间耦合，访问控制决策应由 REST 端点本地做出
- 用户身份验证应集中在身份提供者（IdP）中，由其颁发访问令牌

## JWT

似乎正在趋向使用 [JSON Web 令牌](https://tools.ietf.org/html/rfc7519)（JWT）作为安全令牌的格式。JWT 是包含可用于访问控制决策的一组声明的 JSON 数据结构。可以使用加密签名或消息认证码（MAC）来保护 JWT 的完整性。

- 确保 JWT 通过签名或 MAC 进行完整性保护。不允许不安全的 JWT：`{"alg":"none"}`。
    - 参见[此处](https://tools.ietf.org/html/rfc7519#section-6.1)
- 通常，签名应优先于 MAC 用于 JWT 的完整性保护。

如果使用 MAC 进行完整性保护，每个能够验证 JWT 的服务也可以使用相同的密钥创建新的 JWT。这意味着使用相同密钥的所有服务必须相互信任。这的另一个后果是任何服务的泄露也会危及所有共享相同密钥的其他服务。参见[此处](https://tools.ietf.org/html/rfc7515#section-10.5)了解更多信息。

依赖方或令牌消费者通过验证其完整性和包含的声明来验证 JWT。

- 依赖方必须根据自身配置或硬编码逻辑验证 JWT 的完整性。不得依赖 JWT 头部信息选择验证算法。参见[此处](https://www.chosenplaintext.ca/2015/03/31/jwt-algorithm-confusion.html)和[此处](https://www.youtube.com/watch?v=bW5pS4e_MX8>)

一些声明已被标准化，并且应出现在用于访问控制的 JWT 中。至少应验证以下标准声明：

- `iss`（发行者）- 这是可信的发行者吗？是否是签名密钥的预期所有者？
- `aud`（受众）- 依赖方是否在此 JWT 的目标受众中？
- `exp`（过期时间）- 当前时间是否在此令牌有效期结束之前？
- `nbf`（不早于时间）- 当前时间是否在此令牌有效期开始之后？

由于 JWT 包含经过身份验证的实体（用户等）的详细信息，可能会出现 JWT 与用户会话当前状态不一致的情况，例如，如果由于显式注销或空闲超时而提前终止会话。当发生显式会话终止事件时，应将任何相关 JWT 的摘要或哈希提交到 API 的拒绝列表，这将使该 JWT 在令牌到期之前对任何请求无效。有关更多详细信息，请参见 [Java JSON Web 令牌备忘录](JSON_Web_Token_for_Java_Cheat_Sheet.md#token-explicit-revocation-by-the-user)。

## API 密钥

没有访问控制的公共 REST 服务有被滥用的风险，可能导致带宽或计算周期的过度账单。API 密钥可用于缓解此风险。组织也经常使用它们来实现 API 商业化；与其阻止高频调用，不如根据购买的访问计划授予客户访问权限。

API 密钥可以减少拒绝服务攻击的影响。然而，当它们颁发给第三方客户端时，相对容易被泄露。

- 要求每个对受保护端点的请求都使用 API 密钥。
- 如果请求来得太快，返回 `429 请求过多` HTTP 响应代码。
- 如果客户端违反使用协议，撤销 API 密钥。
- 不要仅依赖 API 密钥来保护敏感、关键或高价值资源。

## 限制 HTTP 方法

- 应用被允许的 HTTP 方法的白名单，例如 `GET`、`POST`、`PUT`。
- 拒绝所有不匹配白名单的请求，并返回 HTTP 响应代码 `405 不允许的方法`。
- 确保调用者有权对资源集合、操作和记录使用传入的 HTTP 方法。

特别是在 Java EE 中，正确实现这一点可能很困难。参见[使用 HTTP 动词篡改绕过 Web 身份验证和授权](../assets/REST_Security_Cheat_Sheet_Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf)以了解这种常见的错误配置。

## 输入验证

- 不要信任输入参数/对象。
- 验证输入：长度/范围/格式和类型。
- 通过在 API 参数中使用强类型（如数字、布尔值、日期、时间或固定数据范围）来实现隐式输入验证。
- 使用正则表达式约束字符串输入。
- 拒绝意外/非法内容。
- 使用特定语言的验证/净化库或框架。
- 定义适当的请求大小限制，并使用 HTTP 响应状态 413 拒绝超过限制的请求。
- 考虑记录输入验证失败。假设每秒执行数百次输入验证失败的人意图不轨。
- 查看输入验证备忘录以获得全面解释。
- 使用安全解析器解析传入消息。如果使用 XML，请确保使用不易受 [XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing) 等攻击的解析器。

## 验证内容类型

REST 请求或响应体应与请求头中的预期内容类型匹配。否则，可能导致消费者/生产者端的误解，并引发代码注入/执行。

- 在您的 API 中记录所有支持的内容类型。

### 验证请求内容类型

- 对包含意外或缺失内容类型请求头的请求，使用 HTTP 响应状态 `406 不可接受` 或 `415 不支持的媒体类型` 进行拒绝。对于 `Content-Length: 0` 的请求，`Content-type` 请求头是可选的。
- 对于 XML 内容类型，确保适当的 XML 解析器强化，参见 [XXE 备忘录](XML_External_Entity_Prevention_Cheat_Sheet.md)。
- 通过显式定义内容类型来避免意外暴露非预期的内容类型，例如 [Jersey](https://jersey.github.io/)（Java）`@consumes("application/json"); @produces("application/json")`。这可以避免 [XXE 攻击](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing)向量。

### 发送安全的响应内容类型

REST 服务通常允许多种响应类型（例如 `application/xml` 或 `application/json`），客户端通过请求中的 Accept 请求头指定首选响应类型顺序。

- **不要** 简单地将 `Accept` 请求头复制到响应的 `Content-type` 请求头。
- 如果 `Accept` 请求头未明确包含可接受的类型之一，则拒绝请求（理想情况下返回 `406 不可接受` 响应）。

在响应中包含脚本代码（例如 JavaScript）的服务必须特别小心，防御请求头注入攻击。

- 确保在响应中发送与正文内容匹配的预期内容类型请求头，例如 `application/json`，而不是 `application/javascript`。

## 管理端点

- 避免通过互联网暴露管理端点。
- 如果管理端点必须通过互联网访问，请确保用户必须使用强身份验证机制，例如多因素认证。
- 通过不同的 HTTP 端口或主机（最好在不同的网卡和受限子网上）公开管理端点。
- 通过防火墙规则或访问控制列表限制对这些端点的访问。

## 错误处理

- 响应通用错误消息 - 避免不必要地泄露失败的详细信息。
- 不要向客户端传递技术细节（例如调用堆栈或其他内部提示）。

## 审计日志

- 在安全相关事件之前和之后写入审计日志。
- 考虑记录令牌验证错误以检测攻击。
- 通过预先净化日志数据来防范日志注入攻击。

## 安全请求头

有许多[安全相关请求头](https://owasp.org/www-project-secure-headers/)可以在 HTTP 响应中返回，以指示浏览器以特定方式行动。然而，这些请求头中的一些旨在与 HTML 响应一起使用，因此对不返回 HTML 的 API 可能几乎没有或没有安全益处。

所有 API 响应都应包含以下请求头：

| 请求头 | 基本原理 |
|--------|----------|
| `Cache-Control: no-store` | 用于指导浏览器缓存。提供 `no-store` 表示任何类型的缓存（私有或共享）都不应存储包含该请求头的响应。浏览器每次调用 API 时都必须发出新请求以获取最新响应。此请求头防止敏感信息被缓存或存储。 |
| `Content-Security-Policy: frame-ancestors 'none'` | 用于指定响应是否可以在 `<frame>`、`<iframe>`、`<embed>` 或 `<object>` 元素中框定。对于 API 响应，没有必要在这些元素中框定。提供 `frame-ancestors 'none'` 可防止任何域框定 API 调用返回的响应。此请求头防止[拖放](https://www.w3.org/Security/wiki/Clickjacking_Threats#Drag_and_drop_attacks)式点击劫持攻击。 |
| `Content-Type` | 用于指定响应的内容类型。必须根据 API 调用返回的内容类型进行指定。如果未指定或指定不正确，浏览器可能会尝试猜测响应的内容类型。这可能导致 MIME 嗅探攻击。如果 API 响应是 JSON，一个常见的内容类型值是 `application/json`。 |
| `Strict-Transport-Security` | 指示浏览器应仅使用 HTTPS 访问域，并且任何未来尝试使用 HTTP 访问都应自动转换为 HTTPS。此请求头确保 API 调用通过 HTTPS 进行，并防止欺骗证书。 |
| `X-Content-Type-Options: nosniff` | 指示浏览器始终使用 `Content-Type` 请求头中声明的 MIME 类型，而不是尝试根据文件内容确定 MIME 类型。此请求头的 `nosniff` 值可防止浏览器执行 MIME 嗅探，并不当地将响应解释为 HTML。 |
| `X-Frame-Options: DENY` | 用于指定响应是否可以在 `<frame>`、`<iframe>`、`<embed>` 或 `<object>` 元素中框定。对于 API 响应，没有必要在这些元素中框定。提供 `DENY` 可防止任何域框定 API 调用返回的响应。此请求头的 `DENY` 值可防止[拖放](https://www.w3.org/Security/wiki/Clickjacking_Threats#Drag_and_drop_attacks)式点击劫持攻击。 |

下面的请求头仅在响应呈现为 HTML 时才提供额外的安全性。因此，如果 API **永远不会** 在响应中返回 HTML，则这些请求头可能不是必需的。但是，如果对请求头的功能或 API 返回（或将来可能返回）的信息类型存在任何不确定性，则建议将它们作为深度防御方法的一部分包括在内。

| 请求头 | 示例 | 基本原理 |
|--------|-------|----------|
| Content-Security-Policy | `Content-Security-Policy: default-src 'none'` | CSP 功能的大部分仅影响呈现为 HTML 的页面。 |
| Permissions-Policy | `Permissions-Policy: accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()` | 此请求头以前名为 Feature-Policy。当浏览器遵守此请求头时，用于通过指令控制浏览器功能。该示例通过对多个[指令名称](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy#directives)使用空白名单来禁用功能。应用此请求头时，请验证指令是最新的并且符合您的需求。请查看[这篇文章](https://developer.chrome.com/en/docs/privacy-sandbox/permissions-policy)以详细解释如何控制浏览器功能。 |
| Referrer-Policy | `Referrer-Policy: no-referrer` | 非 HTML 响应不应触发额外的请求。 |

## 跨域资源共享（CORS）

跨域资源共享（CORS）是一个 W3C 标准，用于灵活指定允许哪些跨域请求。通过提供适当的 CORS 请求头，您的 REST API 向浏览器发出信号，表明允许哪些域（即源）对 REST 服务进行 JavaScript 调用。

- 如果不支持/预期跨域调用，则禁用 CORS 请求头。
- 在设置跨域调用的源时，尽可能具体，同时又尽可能通用。

## HTTP 请求中的敏感信息

RESTful Web 服务应谨慎防止泄露凭据。密码、安全令牌和 API 密钥不应出现在 URL 中，因为这可能被 Web 服务器日志捕获，使它们本质上具有价值。

- 在 `POST`/`PUT` 请求中，敏感数据应在请求体或请求头中传输。
- 在 `GET` 请求中，敏感数据应在 HTTP 请求头中传输。

**正确：**

`https://example.com/resourceCollection/[ID]/action`

`https://twitter.com/vanderaj/lists`

**错误：**

`https://example.com/controller/123/action?apiKey=a53f435643de32`，因为 apiKey 在 URL 中。

## HTTP 返回码

HTTP 定义了[状态码](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)。在设计 REST API 时，不要仅使用 `200` 表示成功或 `404` 表示错误。始终对响应使用语义上恰当的状态码。

以下是与安全相关的 REST API **状态码**的非详尽选择。使用它以确保返回正确的代码。

| 代码 | 消息 | 描述 |
|------|------|------|
| 200 | 成功 | 对成功的 REST API 操作的响应。HTTP 方法可以是 GET、POST、PUT、PATCH 或 DELETE。 |
| 201 | 已创建 | 请求已完成并创建资源。创建的资源的 URI 在 Location 请求头中返回。 |
| 202 | 已接受 | 请求已接受处理，但处理尚未完成。 |
| 301 | 永久重定向 | 永久重定向。 |
| 304 | 未修改 | 与缓存相关的响应，当客户端拥有与服务器相同的资源副本时返回。 |
| 307 | 临时重定向 | 资源的临时重定向。 |
| 400 | 错误请求 | 请求格式错误，例如消息体格式错误。 |
| 401 | 未授权 | 提供了错误或无效的身份验证 ID/密码。 |
| 403 | 禁止 | 当身份验证成功但经过身份验证的用户没有请求资源的权限时使用。 |
| 404 | 未找到 | 请求不存在的资源时。 |
| 405 | 方法不可接受 | 对意外 HTTP 方法的错误。例如，REST API 预期 HTTP GET，但使用了 HTTP PUT。 |
| 406 | 不可接受 | 客户端在 Accept 请求头中提供的内容类型不受服务器 API 支持。 |
| 413 | 负载过大 | 用于表示请求大小超过给定限制，例如关于文件上传。 |
| 415 | 不支持的媒体类型 | REST 服务不支持请求的内容类型。 |
| 429 | 请求过多 | 当可能检测到 DOS 攻击或由于速率限制而拒绝请求时使用。 |
| 500 | 内部服务器错误 | 意外情况阻止服务器完成请求。请注意，响应不应泄露帮助攻击者的内部信息，例如详细的错误消息或堆栈跟踪。 |
| 501 | 未实现 | REST 服务尚未实现请求的操作。 |
| 503 | 服务不可用 | REST 服务暂时无法处理请求。用于通知客户端应稍后重试。 |

有关 REST API 中 HTTP 返回码使用的更多信息，可以在[此处](https://www.restapitutorial.com/httpstatuscodes.html)和[此处](https://restfulapi.net/http-status-codes)找到。
