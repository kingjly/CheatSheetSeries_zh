# 传输层安全备忘录

## 引言

本备忘录提供了使用传输层安全（TLS）为应用程序实施传输层保护的指导。它主要关注如何使用 TLS 保护通过 HTTPS 连接到 Web 应用程序的客户端，尽管大部分指导也适用于 TLS 的其他用途。当正确实施时，TLS 可以提供几个安全优势：

- **机密性**：防止攻击者读取流量内容。
- **完整性**：防止流量被修改，如攻击者重放针对服务器的请求。
- **[认证](Authentication_Cheat_Sheet.md)**：使客户端能够确认他们连接到合法服务器。请注意，除非使用[客户端证书](#客户端证书和双向-tls)，否则不会验证客户端的身份。

### SSL 与 TLS

安全套接字层（SSL）是最初用于为 HTTP 流量提供加密的协议，以 HTTPS 的形式存在。公开发布的 SSL 版本有两个 - 版本 2 和 3。这两个版本都有严重的加密弱点，不应再使用。

出于[各种原因](http://tim.dierks.org/2014/05/security-standards-and-name-changes-in.html)，协议的下一个版本（实际上是 SSL 3.1）被命名为传输层安全（TLS）1.0 版本。随后发布了 TLS 1.1、1.2 和 1.3 版本。

术语"SSL"、"SSL/TLS"和"TLS"经常互换使用，在许多情况下，"SSL"被用来指更现代的 TLS 协议。本备忘录将使用"TLS"一词，除非特指旧版协议。

## 服务器配置

### 仅支持强协议

通用 Web 应用程序应默认使用 **TLS 1.3**（如有必要，支持 TLS 1.2），并禁用所有其他协议。

在特定且罕见的情况下，如果 Web 服务器需要支持依赖过时和不安全浏览器（如 Internet Explorer 10）的旧客户端，可能唯一的选择是激活 TLS 1.0。然而，由于安全隐患，这种方法应谨慎使用，通常不建议。另外，应启用["TLS_FALLBACK_SCSV"扩展](https://tools.ietf.org/html/rfc7507)以防止针对新客户端的降级攻击。

请注意，PCI DSS [禁止使用 TLS 1.0 等旧版协议](https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf)。

### 仅支持强加密算法

TLS 支持大量不同的加密算法（或加密套件），提供不同级别的安全性。在可能的情况下，应仅启用 GCM 加密算法。但是，如果需要支持旧客户端，则可能需要其他加密算法。至少，应始终禁用以下类型的加密算法：

- 空加密算法
- 匿名加密算法
- 出口加密算法

Mozilla 基金会提供了一个[易于使用的安全配置生成器](https://ssl-config.mozilla.org/)，适用于 Web、数据库和邮件服务器。该工具允许站点管理员选择他们正在使用的软件，并获得针对各种浏览器版本和服务器软件平衡安全性和兼容性的配置文件。

### 设置适当的迪菲-赫尔曼群组

早于 TLS 1.3 的协议版本中，用于临时迪菲-赫尔曼密钥交换（由加密套件名称中的"DHE"或"EDH"字符串表示）的迪菲-赫尔曼参数生成存在实际问题。例如，客户端对服务器参数的选择没有发言权，只能无条件接受或拒绝，而随机参数生成常常导致拒绝服务攻击（CVE-2022-40735、CVE-2002-20001）。

TLS 1.3 通过 `supported_groups` 扩展将迪菲-赫尔曼群组参数限制为已知群组。可用的迪菲-赫尔曼群组是 `ffdhe2048`、`ffdhe3072`、`ffdhe4096`、`ffdhe6144`、`ffdhe8192`，如 [RFC7919](https://www.rfc-editor.org/rfc/rfc7919) 中指定。

默认情况下，openssl 3.0 启用所有上述群组。要修改它们，请确保在 `openssl.cnf` 中存在正确的迪菲-赫尔曼群组参数。例如：

```text
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_module
[ssl_module]
system_default = tls_system_default
[tls_system_default]
Groups = x25519:prime256v1:x448:ffdhe2048:ffdhe3072
```

Apache 配置将如下所示：

```text
SSLOpenSSLConfCmd Groups x25519:secp256r1:ffdhe3072
```

NGINX 上的相同配置如下：

```text
ssl_ecdh_curve x25519:secp256r1:ffdhe3072;
```

对于 TLS 1.2 或更早版本，建议不要设置迪菲-赫尔曼参数。

### 禁用压缩

应禁用 TLS 压缩，以防止一个昵称为 [CRIME](https://threatpost.com/crime-attack-uses-compression-ratio-tls-requests-side-channel-hijack-secure-sessions-091312/77006/) 的漏洞，该漏洞可能允许攻击者恢复会话 Cookie 等敏感信息。

### 修补加密库

除了 SSL 和 TLS 协议中的漏洞外，SSL 和 TLS 库中还存在大量历史漏洞，[心脏出血](http://heartbleed.com)是最著名的。因此，重要的是确保这些库保持最新的安全补丁。

### 测试服务器配置

服务器加固后，应测试配置。[OWASP 测试指南中关于 SSL/TLS 测试的章节](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)包含更多测试信息。

有许多在线工具可用于快速验证服务器配置，包括：

- [SSL Labs 服务器测试](https://www.ssllabs.com/ssltest)
- [CryptCheck](https://cryptcheck.fr/)
- [Hardenize](https://www.hardenize.com/)
- [ImmuniWeb](https://www.immuniweb.com/ssl/)
- [Mozilla Observatory](https://observatory.mozilla.org)
- [Scanigma](https://scanigma.com)
- [Stellastra](https://stellastra.com/tls-cipher-suite-check)
- [OWASP PurpleTeam](https://purpleteam-labs.com/) `云`

此外，还有一些离线工具可供使用：

- [O-Saft - OWASP SSL 高级取证工具](https://wiki.owasp.org/index.php/O-Saft)
- [CipherScan](https://github.com/mozilla/cipherscan)
- [CryptoLyzer](https://gitlab.com/coroner/cryptolyzer)
- [SSLScan - 快速 SSL 扫描器](https://github.com/rbsec/sslscan)
- [SSLyze](https://github.com/nabla-c0d3/sslyze)
- [testssl.sh - 测试任何 TLS/SSL 加密](https://testssl.sh)
- [tls-scan](https://github.com/prbinu/tls-scan)
- [OWASP PurpleTeam](https://purpleteam-labs.com/) `本地`

## 应用

### 对所有页面使用 TLS

TLS 应该用于所有页面，而不仅仅是被认为敏感的页面，如登录页面。如果有任何页面未强制使用 TLS，这可能会给攻击者提供窃听敏感信息（如会话令牌）的机会，或者向响应中注入恶意 JavaScript 以对用户执行其他攻击。

对于面向公众的应用程序，可以让 Web 服务器在端口 80 上监听未加密的 HTTP 连接，然后立即使用永久重定向（HTTP 301）重定向它们，以便为手动输入域名的用户提供更好的体验。然后，应使用 [HTTP 严格传输安全（HSTS）](#使用-http-严格传输安全)标头来防止他们在将来通过 HTTP 访问站点。

仅限 API 的端点应完全禁用 HTTP 并仅支持加密连接。如果不可能，API 端点应拒绝通过未加密的 HTTP 连接发出的请求，而不是重定向它们。

### 不要混合 TLS 和非 TLS 内容

在 TLS 上可用的页面不应包含通过未加密 HTTP 加载的任何资源（如 JavaScript 或 CSS）文件。这些未加密的资源可能允许攻击者窃听会话 Cookie 或将恶意代码注入页面。现代浏览器还将阻止尝试将未加密 HTTP 上的活动内容加载到安全页面中。

### 使用"安全"Cookie 标志

所有 Cookie 都应标记为"[Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)"属性，该属性指示浏览器仅通过加密的 HTTPS 连接发送它们，以防止它们被从未加密的 HTTP 连接中窃听。即使网站不在 HTTP（端口 80）上侦听，这也很重要，因为执行主动中间人攻击的攻击者可能在端口 80 上向用户呈现伪造的 Web 服务器以窃取他们的 Cookie。

### 防止敏感数据缓存

尽管 TLS 在传输过程中提供数据保护，但一旦数据到达请求系统，就不再提供任何保护。因此，这些信息可能存储在用户浏览器的缓存中，或被配置为执行 TLS 解密的任何拦截代理存储。

当敏感数据在响应中返回时，应使用 HTTP 标头指示浏览器和任何代理服务器不要缓存信息，以防止其被存储或返回给其他用户。可以通过在响应中设置以下 HTTP 标头来实现：

```text
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

### 使用 HTTP 严格传输安全

HTTP 严格传输安全（HSTS）指示用户的浏览器始终通过 HTTPS 请求站点，并防止用户绕过证书警告。有关实施 HSTS 的更多信息，请参见 [HTTP 严格传输安全备忘录](HTTP_Strict_Transport_Security_Cheat_Sheet.md)。

### 客户端证书和双向 TLS

在典型的 TLS 配置中，服务器上的证书允许客户端验证服务器的身份并在它们之间提供加密连接。然而，这种方法存在两个主要弱点：

- 服务器缺乏验证客户端身份的机制。
- 攻击者获取域的有效证书后可以拦截连接。这种拦截通常被企业用于通过在其客户端系统上安装受信任的 CA 证书来检查 TLS 流量。

客户端证书，作为双向 TLS（mTLS）的核心，解决了这些问题。在 mTLS 中，客户端和服务器都使用 TLS 相互认证。客户端通过自己的证书向服务器证明自己的身份。这不仅实现了客户端的强身份验证，还防止中间方解密 TLS 流量，即使他们在客户端系统上有受信任的 CA 证书。

挑战和考虑因素

由于以下几个挑战，客户端证书很少在公共系统中使用：

- 颁发和管理客户端证书涉及大量管理开销。
- 非技术用户可能会发现安装客户端证书很困难。
- 组织的 TLS 解密实践可能导致客户端证书认证（mTLS 的关键组件）失败。

尽管存在这些挑战，但对于高价值的应用程序或 API，特别是用户技术水平较高或属于同一组织的情况下，仍应考虑使用客户端证书和 mTLS。

### 公钥固定

公钥固定可用于提供保证，即服务器的证书不仅有效且受信任，而且与服务器预期的证书相匹配。这为攻击者提供了保护，即使攻击者能够通过以下方式获取有效证书：

- 利用验证过程中的弱点
- 破坏受信任的证书颁发机构
- 获得客户端的管理访问权限

公钥固定最初是在 HTTP 公钥固定（HPKP）标准中添加到浏览器中。然而，由于存在许多问题，它随后被弃用，不再被推荐或[被现代浏览器支持](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins)。

尽管如此，公钥固定仍可为移动应用程序、厚客户端和服务器间通信提供安全优势。这在[固定备忘录](Pinning_Cheat_Sheet.md)中有更详细的讨论。

## 相关文章

- OWASP - [测试弱 TLS](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)
- OWASP - [应用安全验证标准（ASVS）- 通信安全验证要求（V9）](https://github.com/OWASP/ASVS/blob/v4.0.1/4.0/en/0x17-V9-Communications.md)
- Mozilla - [Mozilla 推荐配置](https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations)
- NIST - [SP 800-52 第 2 版 传输层安全（TLS）实施的选择、配置和使用指南](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- NIST - [NIST SP 800-57 密钥管理建议，第 5 版](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- NIST - [SP 800-95 安全 Web 服务指南](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-95.pdf)
- IETF - [RFC 5280 互联网 X.509 公钥基础设施证书和证书吊销列表（CRL）配置文件](https://tools.ietf.org/html/rfc5280)
- IETF - [RFC 2246 传输层安全（TLS）协议版本 1.0（1999年1月）](https://tools.ietf.org/html/rfc2246)
- IETF - [RFC 4346 传输层安全（TLS）协议版本 1.1（2006年4月）](https://tools.ietf.org/html/rfc4346)
- IETF - [RFC 5246 传输层安全（TLS）协议版本 1.2（2008年8月）](https://tools.ietf.org/html/rfc5246)
- Bettercrypto - [应用加密硬化：最常见服务的安全加密设置方法](https://bettercrypto.org)
