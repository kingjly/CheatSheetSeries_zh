
# SAML 安全备忘录

## 引言

**安全断言标记语言**（[SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)）是一个用于交换授权和认证信息的开放标准。*基于重定向/POST绑定的Web浏览器SAML/SSO配置文件*是最常见的SSO实现之一。本备忘录将主要关注这种配置文件。

## 验证消息的机密性和完整性

[TLS 1.2](Transport_Layer_Security_Cheat_Sheet.md)是在传输层保证消息机密性和完整性的最常见解决方案。有关更多信息，请参考[SAML安全性（第4.2.1节）](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)。这一步将有助于应对以下攻击：

- 窃听 7.1.1.1
- 用户认证信息盗取 7.1.1.2
- 持有者令牌盗取 7.1.1.3
- 消息删除 7.1.1.6
- 消息篡改 7.1.1.7
- 中间人攻击 7.1.1.8

使用经过认证的密钥进行数字签名是保证消息完整性和认证的最常见解决方案。有关更多信息，请参考[SAML安全性（第4.3节）](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)。这一步将有助于应对以下攻击：

- 中间人攻击 6.4.2
- 伪造断言 6.4.3
- 消息篡改 7.1.1.7

可以使用XMLEnc对断言进行加密，以防止传输后敏感属性被泄露。有关更多信息，请参考[SAML安全性（第4.2.2节）](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)。这一步将有助于应对以下攻击：

- 用户认证信息盗取 7.1.1.2

## 验证协议使用

这是安全漏洞的常见区域 - 请参考[Google SSO漏洞](https://www.kb.cert.org/vuls/id/612636/)作为真实案例。他们的SSO配置文件容易遭受来自恶意SP（服务提供者）的中间人攻击。

Web浏览器配置文件最容易受到来自可信合作伙伴的攻击。这个特定的安全缺陷是因为SAML响应未包含安全消息交换所需的所有必要数据元素。遵循[SAML配置文件](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)中关于AuthnRequest（4.1.4.1）和Response（4.1.4.2）的使用要求将有助于应对这种攻击。

*AVANTSSAR*团队建议以下数据元素应该是必需的：

- **AuthnRequest(ID, SP)：** `AuthnRequest`必须包含`ID`和`SP`。其中`ID`是唯一标识请求的字符串，`SP`标识发起请求的`服务提供者`。此外，请求的`ID`属性必须在响应中返回（`InResponseTo="<requestId>"`）。`InResponseTo`有助于保证来自可信IdP的响应的真实性。这是导致Google SSO存在漏洞的缺失属性之一。
- **Response(ID, SP, IdP, {AA} K -1/IdP)：** 响应必须包含所有这些元素。其中`ID`是唯一标识响应的字符串。`SP`标识响应的接收者。`IdP`标识授权响应的身份提供者。`{AA} K -1/IdP`是使用`IdP`的私钥进行数字签名的断言。
- **AuthAssert(ID, C, IdP, SP)：** 响应中必须存在一个认证断言。它必须包含一个`ID`、一个客户端`(C)`、一个身份提供者`(IdP)`和一个服务提供者`(SP)`标识符。

### 验证签名

2012年描述了SAML实现中由于XML签名包装攻击导致的漏洞，详见[论破解SAML：成为你想成为的任何人](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf)。

针对这一问题，提出了以下建议（[防止XML签名包装攻击的安全SAML验证](https://arxiv.org/pdf/1401.7483v1.pdf)）：

- 在将XML文档用于任何安全相关目的之前，始终执行模式验证：
    - 始终使用本地的、可信的模式副本进行验证。
    - 绝不允许从第三方位置自动下载模式。
    - 如果可能，检查模式并执行模式强化，以禁用可能的通配符类型或宽松的处理语句。
- 安全地验证数字签名：
    - 如果只期望一个签名密钥，使用`StaticKeySelector`。直接从身份提供者获取密钥，将其存储在本地文件中，并忽略文档中的任何`KeyInfo`元素。
    - 如果期望多个签名密钥，使用`X509KeySelector`（JKS变体）。直接从身份提供者获取这些密钥，将其存储在本地JKS中，并忽略文档中的任何`KeyInfo`元素。
    - 如果期望处理异构签名文档（来自多个身份提供者的多个证书，多级验证路径），则基于PKIX和可信根证书实现完整的信任建立模型。
- 避免签名包装攻击。
    - 在没有事先验证的情况下，切勿使用`getElementsByTagName`选择XML文档中的安全相关元素。
    - 除非使用强化的模式进行验证，否则始终使用绝对XPath表达式选择元素。

## 验证协议处理规则

由于需要断言的步骤众多，这是另一个常见的安全漏洞区域。

处理SAML响应是一个昂贵的操作，但所有步骤都必须经过验证：

- 验证AuthnRequest处理规则。参考[SAML核心](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)（3.4.1.4）中的所有AuthnRequest处理规则。这一步将有助于应对以下攻击：
    - 中间人攻击（6.4.2）
- 验证Response处理规则。参考[SAML配置文件](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)（4.1.4.3）中的所有Response处理规则。这一步将有助于应对以下攻击：
    - 断言被盗（6.4.1）
    - 中间人攻击（6.4.2）
    - 伪造断言（6.4.3）
    - 浏览器状态暴露（6.4.4）

## 验证绑定实现

- 对于HTTP重定向绑定，请参考[SAML绑定](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)（3.4）。要查看编码示例，您可以参考[Google的参考实现](https://developers.google.com/google-apps/sso/saml_reference_implementation_web)中的RequestUtil.java。
- 对于HTTP POST绑定，请参考[SAML绑定](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)（3.5）。缓存注意事项也非常重要。如果SAML协议消息被缓存，它随后可能被用于断言被盗（6.4.1）或重放（6.4.5）攻击。

## 验证安全对策

重新审视[SAML安全性](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)文档中存在的每个安全威胁，并确保为您特定的实现应用了适当的对策。

应考虑的额外对策包括：

- 在适当时使用IP过滤。例如，如果Google为每个可信合作伙伴提供单独的端点并为每个端点设置IP过滤，这种对策本可以防止Google最初的安全缺陷。这一步将有助于应对以下攻击：
    - 断言被盗（6.4.1）
    - 中间人攻击（6.4.2）
- 使用短生命周期的SAML响应。这一步将有助于应对以下攻击：
    - 断言被盗（6.4.1）
    - 浏览器状态暴露（6.4.4）
- 在SAML响应中使用一次性（OneTimeUse）。这一步将有助于应对以下攻击：
    - 浏览器状态暴露（6.4.4）
    - 重放攻击（6.4.5）

需要架构图？[SAML技术概述](https://www.oasis-open.org/committees/download.php/11511/

## 未经请求的响应（即IdP发起的SSO）的服务提供者注意事项

从设计上讲，未经请求的响应由于缺乏[跨站请求伪造（CSRF）](https://owasp.org/www-community/attacks/csrf)保护，本质上是[不安全的](https://www.identityserver.com/articles/the-dangers-of-saml-idp-initiated-sso)。然而，由于SAML 1.1的向后兼容性特性，许多系统仍然支持这种方式。一般的安全建议是不支持这种认证类型，但如果必须启用，除了前面提到的所有步骤外，还应采取以下步骤来保护此流程：

- 遵循[SAML配置文件（第4.1.5节）](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)中提到的验证流程。这一步将有助于应对以下攻击：
    - 重放攻击（6.1.2）
    - 消息插入（6.1.3）
- 如果`RelayState`参数的约定是一个URL，确保验证该URL并将其明确列入白名单。这一步将有助于应对以下攻击：
    - [开放重定向](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- 在响应或断言级别实施适当的重放检测。这将有助于应对以下攻击：
    - 重放攻击（6.1.2）

## 身份提供者和服务提供者注意事项

SAML协议很少成为首选攻击向量，尽管制定安全备忘录以确保其健壮性很重要。各种端点更容易成为攻击目标，因此SAML令牌的生成方式和使用方式在实践中都非常重要。

### 身份提供者（IdP）注意事项

- 验证X.509证书的算法兼容性、加密强度和导出限制
- 验证生成SAML令牌的强认证选项
- IdP验证（哪个IdP铸造令牌）
- 尽可能使用/信任根CA
- 同步到公共互联网时间源
- 为身份验证定义保证级别
- 相比个人可识别信息（如社保号等），更倾向使用非对称标识符进行身份断言
- 对每个单独的断言或整个响应元素进行签名

### 服务提供者（SP）注意事项

- 验证用户的会话状态
- 在使用SAML令牌时，设置授权上下文的粒度级别（是使用组、角色还是属性）
- 确保每个断言或整个响应元素都经过签名
- [验证签名](#验证签名)
- 验证是否由授权的IdP签名
- 根据证书吊销列表（CRL）/在线证书状态协议（OCSP）验证IdP证书的到期和吊销情况
- 验证`NotBefore`和`NotOnorAfter`
- 验证接收者属性
- 定义SAML注销的标准
- 仅通过安全传输交换断言
- 定义会话管理标准
- 尽可能验证从SAML票据断言获得的用户身份

## 输入验证

仅仅因为SAML是安全协议，并不意味着可以忽略输入验证。

- 确保所有SAML提供者/消费者执行适当的[输入验证](Input_Validation_Cheat_Sheet.md)。

## 密码学

依赖密码学算法的解决方案需要跟踪密码分析的最新进展。

- 确保链中的所有SAML元素使用[强加密](Cryptographic_Storage_Cheat_Sheet.md#algorithms)
- 考虑废弃对[不安全的XMLEnc算法](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-1_5)的支持
