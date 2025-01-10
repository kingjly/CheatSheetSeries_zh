# Web 服务安全备忘录

## 引言

本文旨在提供保护 Web 服务和防止 Web 服务相关攻击的指导。

请注意，由于不同框架的实现差异，本备忘录保持在较高层面。

## 传输保密性

传输保密性防止对 Web 服务通信的窃听和中间人攻击。

**规则**：所有包含敏感功能、经过身份验证的会话或传输敏感数据的 Web 服务通信，必须使用配置良好的 [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 进行加密。即使消息本身已加密，也建议这样做，因为 [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 提供了众多超出流量保密性的好处，包括完整性保护、重放防御和服务器身份验证。有关如何正确执行此操作的更多信息，请参见[传输层安全备忘录](Transport_Layer_Security_Cheat_Sheet.md)。

## 服务器身份验证

**规则**：必须使用 TLS 向服务消费者验证服务提供者的身份。服务消费者应验证服务器证书是由可信提供者颁发的、未过期、未被吊销、与服务域名匹配，并且服务器已通过私钥（通过正确签名某些内容或成功解密使用相关公钥加密的内容）证明其身份。

## 用户身份验证

用户身份验证验证试图连接到服务的用户或系统的身份。这种身份验证通常是 Web 服务容器的功能。

**规则**：如果使用基本身份验证，必须通过 [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 进行，但不建议使用基本身份验证，因为它会在 HTTP 标头中以明文（base64 编码）形式泄露秘密。

**规则**：使用[双向 TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 的客户端证书身份验证是一种推荐的身份验证方式。请参见：[身份验证备忘录](Authentication_Cheat_Sheet.md)。

## 传输编码

[SOAP](https://en.wikipedia.org/wiki/SOAP) 编码样式旨在在软件对象之间以 XML 格式移动数据。

**规则**：在客户端和服务器之间强制执行相同的编码样式。

## 消息完整性

这是针对静态数据。传输中数据的完整性可以通过 [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 轻松提供。

使用[公钥密码学](https://en.wikipedia.org/wiki/Public-key_cryptography)时，加密确实保证了保密性，但由于接收者的公钥是公开的，它不保证完整性。出于同样的原因，加密也不确保发送者的身份。

**规则**：对于 XML 数据，使用 XML 数字签名，通过发送者的私钥提供消息完整性。接收者可以使用发送者的数字证书（公钥）验证此签名。

## 消息保密性

必须使用强加密算法和足够的密钥长度来加密需要保密的数据元素，以阻止暴力破解。

**规则**：包含敏感数据的消息必须使用强加密算法加密。这可以是传输加密或消息加密。

**规则**：接收后必须保持加密的包含敏感数据的消息，必须使用强数据加密，而不仅仅是传输加密。

## 授权

Web 服务需要像 Web 应用程序授权用户一样授权 Web 服务客户端。Web 服务需要确保 Web 服务客户端有权对请求的数据执行特定操作（粗粒度）。

**规则**：Web 服务应授权其客户端是否有权访问相关方法。在身份验证挑战之后，Web 服务应检查请求实体的权限，是否有权访问请求的资源。这应在每个请求上进行，并为敏感资源（如密码更改、主要联系人详细信息，如电子邮件、物理地址、支付或交付说明）添加挑战-响应授权机制。

**规则**：确保对 Web 服务应用程序中的管理和管理功能的访问仅限于 Web 服务管理员。理想情况下，任何管理功能都应位于与这些功能管理的 Web 服务完全分离的应用程序中，从而完全将普通用户与这些敏感功能隔离。

## 架构验证

架构验证强制执行架构定义的约束和语法。

**规则**：Web 服务必须根据其关联的 XML 架构定义（[XSD](https://www.w3schools.com/xml/schema_intro.asp)）验证 [SOAP](https://en.wikipedia.org/wiki/SOAP) 负载。

**规则**：为 [SOAP](https://en.wikipedia.org/wiki/SOAP) Web 服务定义的 [XSD](https://www.w3schools.com/xml/schema_intro.asp) 至少应定义传入和传出 Web 服务的每个参数的最大长度和字符集。

**规则**：为 [SOAP](https://en.wikipedia.org/wiki/SOAP) Web 服务定义的 [XSD](https://www.w3schools.com/xml/schema_intro.asp) 应为所有固定格式参数（如邮政编码、电话号码、列表值等）定义强（理想情况下是允许列表）验证模式。

## 内容验证

**规则**：与任何 Web 应用程序一样，Web 服务需要在使用输入之前验证输入。XML 输入的内容验证应包括：

- 验证畸形 XML 实体。
- 验证 [XML 炸弹攻击](https://en.wikipedia.org/wiki/Billion_laughs_attack)。
- 使用强允许列表验证输入。
- 防范[外部实体攻击](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing)。

## 输出编码

Web 服务需要确保发送给客户端的输出被编码为数据，而不是脚本。当 Web 服务客户端直接或间接使用 AJAX 对象渲染 HTML 页面时，这一点变得尤为重要。

**规则**：所有输出编码规则均遵循[跨站脚本防护备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)。

## 病毒防护

[SOAP](https://en.wikipedia.org/wiki/SOAP) 提供将文件和文档附加到 [SOAP](https://en.wikipedia.org/wiki/SOAP) 消息的能力。这为黑客提供了将病毒和恶意软件附加到这些 [SOAP](https://en.wikipedia.org/wiki/SOAP) 消息的机会。

**规则**：确保安装病毒扫描技术，并最好是内联的，以便在保存到磁盘之前检查文件和附件。

**规则**：确保病毒扫描技术定期更新最新的病毒定义/规则。

## 消息大小

与 Web 应用程序一样，Web 服务可能成为 DOS 攻击的目标，方法是自动向 Web 服务发送数千个大尺寸的 [SOAP](https://en.wikipedia.org/wiki/SOAP) 消息。这可能会使应用程序瘫痪，无法响应合法消息，或完全使其瘫痪。

**规则**：[SOAP](https://en.wikipedia.org/wiki/SOAP) 消息大小应限制在适当的大小限制内。更大的大小限制（或完全没有限制）会增加成功 DoS 攻击的几率。

## 可用性

### 资源限制

在正常运行期间，Web 服务需要计算能力，如 CPU 周期和内存。由于故障或受到攻击，Web 服务可能需要过多资源，使主机系统不稳定。

**规则**：根据预期服务速率限制 Web 服务可以使用的 CPU 周期数，以保持系统稳定。

**规则**：限制 Web 服务可以使用的内存量，以避免系统内存耗尽。在某些情况下，主机系统可能开始终止进程以释放内存。

**规则**：限制同时打开的文件数、网络连接数和启动的进程数。

### 消息吞吐量

吞吐量表示在特定时间内服务的 Web 服务请求数。

**规则**：配置应针对最大消息吞吐量进行优化，以避免陷入类似 DoS 的情况。

### XML 拒绝服务保护

XML 拒绝服务可能是针对 Web 服务最严重的攻击。因此，Web 服务必须提供以下验证：

**规则**：防范递归负载。

**规则**：防范超大负载。

**规则**：防范 [XML 实体扩展](https://www.ws-attacks.org/XML_Entity_Expansion)。

**规则**：验证过长的元素名称。如果使用基于 [SOAP](https://en.wikipedia.org/wiki/SOAP) 的 Web 服务，这些元素名称是 [SOAP](https://en.wikipedia.org/wiki/SOAP) 动作。

这种保护应由 XML 解析器/架构验证器提供。要验证，请构建测试用例，确保解析器能抵抗这些类型的攻击。

## 端点安全配置文件

**规则**：Web 服务必须至少符合 [Web 服务互操作性（WS-I）](https://en.wikipedia.org/wiki/Web_Services_Interoperability) 基本配置文件。
