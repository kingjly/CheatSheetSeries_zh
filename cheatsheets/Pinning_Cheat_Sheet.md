# Pinning 备忘单

## 简介

Pinning 备忘单是一份技术指南，旨在实现证书和公钥 Pinning（绑定）。该指南基于 Jeffrey Walton 在弗吉尼亚分会的演讲 [Securing Wireless Channels in the Mobile Space](https://wiki.owasp.org/images/8/8f/Securing-Wireless-Channels-in-the-Mobile-Space.ppt) 中的内容，提供了清晰、简单、可操作的指导，帮助在恶意环境中保护通信通道安全，防止信任机制被滥用。

## 问题是什么？

用户、开发者和应用程序期望通信通道是安全的，但某些通道可能无法满足这一期望。基于众所周知的协议（如 SSL 和 TLS）构建的通道可能会因证书信任机制被滥用而受到中间人攻击（MITM）的威胁。恶意攻击通常有两种形式：

1. 攻击者从受信任的证书颁发机构（CA）获取了伪造的数字证书，冒充受害者网站；
2. 攻击者将危险的 CA 注入到客户端的信任存储中。

在第二种情况下，攻击者如果能更新信任存储，就可能更改移动应用的行为，从而绕过 Pinning 机制。

正如 [Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) 所述，由于证书颁发机构和浏览器社区多年来的安全改进，这一问题的规模已非常小。

## 什么是 Pinning？

Pinning 是将主机与其*预期的* X509 证书或公钥关联的过程。一旦主机的证书或公钥被知晓或记录下来，就会将其与主机"绑定"。如果有多个证书或公钥是可接受的，那么程序会保存一个 *pinset*（取自 [Jon Larimer 和 Kenny Root 在 Google I/O 的演讲](https://www.youtube.com/watch?v=RPJENzweI-A)）。在这种情况下，声明的凭据必须匹配 pinset 中的某个元素。

### 何时添加 Pin

主机或服务的证书或公钥可以在开发时添加，也可以在首次遇到证书或公钥时添加（这种方式通常称为"首次信任"（Trust On First Use，TOFU）），或者通过未绑定的通道实时添加和更新。首选方式是开发时添加，因为通过*带外*预加载证书或公钥通常意味着攻击者无法篡改 Pin。

请注意，这里的"何时"是指在时间点上何时添加 Pin。而第一个问题应该是："我是否应该 Pin？"答案可能是从不。

### 何时执行 Pinning

几乎没有情况需要考虑 Pinning。鉴于安全性的进步，宕机的风险几乎总是大于安全风险。如果考虑 Pinning，您应该阅读 [Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) 并完全理解威胁模型。

### 何时不应该 Pin？

- 如果您不能同时控制连接的客户端和服务器端，不要 Pin。
- 如果您无法安全地更新 pinset，不要 Pin。
- 如果更新 pinset 会造成干扰，例如需要重新部署应用程序，可能不要 Pin。（一个可能的例外是，您可以控制应用程序的重新部署，例如在公司内部强制更新。）
- 如果证书密钥对在投入使用前无法预测，不要 Pin。
- 如果不是原生移动应用程序，不要 Pin。

### 何时应用例外

如果您所在的组织作为数据泄漏防护（DLP）策略的一部分实施"出口过滤"（egress filtering），您可能会遇到*拦截代理*。我们喜欢将这些称为**"好的坏角色"**（与**"坏的坏角色"**相对），因为两者都破坏了端到端的安全性，我们无法区分它们。在这种情况下，**不要**主动允许列入白名单的拦截代理，因为这会破坏您的安全目标。在风险接受部门的指示下，将拦截代理的公钥添加到您的 pinset 中。

### 如何执行 Pinning

Pinning 的核心思想是重用现有的协议和基础设施，但以更严格的方式使用它们。为了重用，程序在建立安全连接时会继续执行传统操作。

为了强化通道，程序可以利用库、框架或平台提供的 `OnConnect` 回调。在回调中，程序通过验证远程主机的证书或公钥来确认其身份。请参阅下面的[一些示例](#examples-of-pinning)。

### 应该 Pin 什么？

为了决定应该 Pin 什么，可以按照以下步骤操作：

1. 决定是否要 Pin 根 CA、中间 CA 或叶子证书：

   - Pin **根 CA** 通常不推荐，因为它会大大增加风险，因为这意味着也信任其所有的中间 CA。
   - Pin 特定的**颁发或中间 CA**可以降低风险，但应用程序也会信任该 CA 或子 CA 签发的其他证书，而不仅仅是为您的应用程序设计的证书。
   - Pin **叶子证书**是推荐的做法，但必须包括备份（例如中间 CA 或包含替代项的 pinset）。这可以确保应用程序仅信任其设计连接的远程主机，同时为故障转移或证书轮换提供弹性。

   例如，应用程序 Pin 远程端点的叶子证书，但包括中间 CA 的备份 Pin。这增加了信任更多证书颁发机构的风险，但减少了因证书问题导致应用程序无法工作的可能性。如果叶子证书有任何问题，应用程序可以回退到中间 CA，直到您发布应用程序更新。

2. 选择是否 Pin **整个证书**或仅 Pin **公钥**。

3. 如果选择公钥，您还有两个额外的选项：

   - Pin `subjectPublicKeyInfo`。
   - Pin 某种具体类型，例如 `RSAPublicKey` 或 `DSAPublicKey`。

这三个选项将在下文中详细解释。建议 Pin `subjectPublicKeyInfo`，因为它包含公钥参数（例如 RSA 公钥的 `{e,n}`）**以及**上下文信息（如算法和 OID）。上下文信息有助于在某些情况下保持清晰，右图显示了可用的附加信息。

#### 证书

证书是最容易 Pin 的。您可以通过带外方式获取网站的证书，例如让 IT 部门通过电子邮件发送公司证书，使用 `openssl s_client` 检索证书等。在运行时，您可以通过回调检索网站或服务器的证书。在回调中，将检索到的证书与程序中嵌入的证书进行比较。如果比较失败，则方法或函数应失败，并在客户端记录日志并提醒最终用户。如果您的威胁模型需要 Pinning，请理解用户会忽略任何警告，因此不要给用户提供跳过 Pin 的选项。

**优点：**

- 在某些语言（如 Cocoa/CocoaTouch 和 OpenSSL）中，可能比其他方法更容易实现。

**缺点：**

- 如果站点定期轮换证书，则需要定期更新应用程序。如果您无法控制证书何时投入使用，Pinning 将导致宕机。

#### 公钥

公钥 Pinning 更加灵活，但由于需要额外步骤从证书中提取公钥，会稍微复杂一些。与证书类似，程序会将提取的公钥与嵌入的公钥副本进行比较。考虑到现今大多数证书只有 90 天有效期，使用公钥 Pinning 可以使 pinset 更新的时间线更长，因为您可以 Pin 一个尚未签发证书的密钥。

**优点：**

- 可以访问公钥参数（例如 RSA 公钥的 `{e,n}`）和上下文信息，如算法和 OID。
- 比证书 Pinning 更加灵活。Pin 可以在证书签发之前很久就计算出来，如果策略允许，可以使用相同的密钥续签证书以避免破坏 Pinning。后者是一种糟糕的密钥管理实践，只应在紧急情况下使用。

**缺点：**

- 处理密钥（相比证书）可能更加困难，因为必须从证书中提取密钥。在 Java 和 .Net 中提取是一个小小的不便，但在 iOS 的 Cocoa/CocoaTouch 框架和 OpenSSL 中则相当不便。
- 一些服务提供商在续期时会生成新密钥，使得预缓存变得不可能。

#### 哈希

虽然上述三种选择使用 DER 编码，使用信息的哈希值也是可以接受的。事实上，最初的示例程序是使用摘要的证书和公钥编写的。这些示例被更改，以允许程序员使用 `dumpasn1` 和其他 ASN.1 解码器检查对象。

**优点：**

- 使用方便。摘要证书指纹通常作为许多库的原生 API 可用。
- 哈希值小且长度固定。

**缺点：**

- 无法访问公钥参数和上下文信息（如算法和 OID），这在某些使用场景中可能是必需的。
- 如果站点定期轮换证书，则应用程序需要定期更新。如果您无法控制证书何时投入使用，Pinning 将导致宕机。

## Pinning 示例

本节讨论 Android Java、iOS、.Net 和 OpenSSL 中的证书和公钥 Pinning。为简洁起见，代码已被省略，但突出了各平台的关键点。

### Android

自 Android N 起，实现 Pinning 的首选方式是利用 Android 的[网络安全配置](https://developer.android.com/training/articles/security-config.html)功能，该功能允许应用在安全的声明性配置文件中自定义网络安全设置，无需修改应用代码。

要启用 Pinning，可以使用 [`<pin-set>` 配置设置](https://developer.android.com/training/articles/security-config.html#CertificatePinning)。

或者，您可以使用 OkHTTP 的 Pinning 方法以编程方式设置特定的 Pin，详见 [OWASP 移动安全测试指南（MSTG）](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#network-libraries-and-webviews)和 [OKHttp 文档](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html)。

Android 文档在[未知 CA 实现文档](https://developer.android.com/training/articles/security-ssl.html#UnknownCa)中提供了如何在应用代码中自定义 SSL 验证的示例（以实现 Pinning）。但是，应避免从头开始实现 Pinning 验证，因为实现错误极有可能导致严重的漏洞。

最后，如果要验证 Pinning 是否成功，请遵循 OWASP 移动安全测试指南（MSTG）中的[网络通信测试简介](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04f-Testing-Network-Communication.md#testing-network-communication)和[Android 特定网络测试](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md)章节。

### iOS

Apple 建议通过在 `Info.plist` 文件的 [App Transport Security 设置](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)中指定 CA 公钥来进行 Pinning。更多详情请参见文章["身份 Pinning：如何为您的应用配置服务器证书"](https://developer.apple.com/news/?id=g9ejcf8y)。

[TrustKit](https://github.com/datatheorem/TrustKit)是一个适用于 iOS 和 macOS 的开源 SSL Pinning 库。它提供了易于使用的 Pinning API，并已在许多应用中部署。

否则，关于如何在 iOS 上自定义 SSL 验证以实现 Pinning 的更多详情，请参见 [HTTPS 服务器信任评估](https://developer.apple.com/library/content/technotes/tn2232/_index.html)技术说明。但是，应避免从头开始实现 Pinning 验证，因为实现错误极有可能导致严重的漏洞。

最后，如果要验证 Pinning 是否成功，请遵循 OWASP 移动安全测试指南（MSTG）中的[网络通信测试简介](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04f-Testing-Network-Communication.md#testing-network-communication)和 [iOS 特定网络测试](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06g-Testing-Network-Communication.md)章节。

### .Net

.Net Pinning 可以通过使用 [`ServicePointManager`](https://docs.microsoft.com/en-us/dotnet/api/system.net.servicepointmanager?view=netframework-4.7.2) 来实现。示例可以在 [OWASP MSTG](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#xamarin-applications) 中找到。

下载 [.Net 示例程序](../assets/Pinning_Cheat_Sheet_Certificate_DotNetSample.zip)。

### OpenSSL

OpenSSL 中的 Pinning 可以在两个地方发生。第一个是用户提供的 `verify_callback`。第二个是通过 `SSL_get_peer_certificate` 在连接建立后。这两种方法都允许您访问对等方的证书。

尽管 OpenSSL 执行 X509 检查，但您必须在出错时终止连接并关闭套接字。根据设计，未提供证书的服务器将导致带有 **NULL** 证书的 `X509_V_OK`。要检查常规验证的结果：

1. 必须调用 `SSL_get_verify_result` 并验证返回代码是 `X509_V_OK`；
2. 必须调用 `SSL_get_peer_certificate` 并验证证书是 **非 NULL**。

下载：[OpenSSL 示例程序](../assets/Pinning_Cheat_Sheet_Certificate_OpenSSLSample.zip)。

### Electron

[electron-ssl-pinning](https://github.com/dialogs/electron-ssl-pinning)是一个用于基于 [Electron](https://electronjs.org) 的应用程序的开源 SSL Pinning 库。它提供了易于使用的 Pinning API，并提供了基于所需主机获取配置的工具。

否则，您可以使用 [ses.setCertificateVerifyProc(proc)](https://electronjs.org/docs/api/session#sessetcertificateverifyprocproc) 自行验证证书。

## 参考文献

- OWASP [注入理论](https://owasp.org/www-community/Injection_Theory)
- OWASP [数据验证](https://wiki.owasp.org/index.php/Data_Validation)
- OWASP [传输层安全备忘单](Transport_Layer_Security_Cheat_Sheet.md)
- OWASP [移动安全测试指南](https://github.com/OWASP/owasp-mstg)
- IETF [RFC 1421 (PEM 编码)](http://www.ietf.org/rfc/rfc1421.txt)
- IETF [RFC 4648 (Base16、Base32 和 Base64 编码)](http://www.ietf.org/rfc/rfc4648.txt)
- IETF [RFC 5280 (Internet X.509, PKIX)](http://www.ietf.org/rfc/rfc5280.txt)
- IETF [RFC 3279 (PKI, X509 算法和 CRL 配置文件)](http://www.ietf.org/rfc/rfc3279.txt)
- IETF [RFC 4055 (PKI, X509 附加算法和 CRL 配置文件)](http://www.ietf.org/rfc/rfc4055.txt)
- IETF [RFC 2246 (TLS 1.0)](http://www.ietf.org/rfc/rfc2246.txt)
- IETF [RFC 4346 (TLS 1.1)](http://www.ietf.org/rfc/rfc4346.txt)
- IETF [RFC 5246 (TLS 1.2)](http://www.ietf.org/rfc/rfc5246.txt)
- IETF [PKCS #1: RSA 密码学规范 版本 2.2](https://tools.ietf.org/html/rfc8017)
