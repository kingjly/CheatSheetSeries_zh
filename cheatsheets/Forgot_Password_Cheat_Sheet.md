# 忘记密码备忘录

## 引言

为了实现适当的用户管理系统，系统集成了**忘记密码**服务，允许用户请求密码重置。

尽管这个功能看起来直接且易于实现，但它是常见的漏洞源之一，例如著名的[用户枚举攻击](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html)。

以下简短指南可用作保护忘记密码服务的快速参考：

- **对于存在和不存在的账户返回一致的消息。**
- **确保用户响应消息的时间是统一的。**
- **使用侧信道通知重置密码的方法。**
- **对于最简单和最快的实现，使用 [URL 令牌](#url-令牌)。**
- **确保生成的令牌或代码：**
    - **使用加密安全算法随机生成。**
    - **足够长以防止暴力破解攻击。**
    - **安全存储。**
    - **单次使用并在适当时间后过期。**
- **在出示有效令牌之前，不要对账户进行任何更改，例如锁定账户**

本备忘录专注于重置用户密码。关于重置多因素认证（MFA）的指导，请参见[多因素认证备忘录](Multifactor_Authentication_Cheat_Sheet.md#resetting-mfa)中的相关部分。

## 忘记密码服务

密码重置过程可以分为两个主要步骤，详细内容如下节所述。

### 忘记密码请求

当用户使用忘记密码服务并输入用户名或电子邮件时，应遵循以下步骤实现安全流程：

- 对于存在和不存在的账户返回一致的消息。
- 确保响应在一致的时间内返回，以防止攻击者枚举哪些账户存在。这可以通过使用异步调用或确保遵循相同的逻辑来实现，而不是使用快速退出方法。
- 实施针对过多自动提交的保护，如基于每个账户的速率限制、要求 CAPTCHA 或其他控制。否则，攻击者可能每小时对给定账户发起数千次密码重置请求，使用户的接收系统（如电子邮件收件箱或短信）充满无用请求。
- 采用常规安全措施，如 [SQL 注入防护方法](SQL_Injection_Prevention_Cheat_Sheet.md)和[输入验证](Input_Validation_Cheat_Sheet.md)。

### 用户重置密码

一旦用户通过提供令牌（通过电子邮件发送）或代码（通过短信或其他机制发送）证明了自己的身份，他们应将密码重置为新的安全密码。为了保护这一步骤，应采取以下措施：

- 用户应通过两次输入确认他们设置的密码。
- 确保制定安全的密码策略，并与应用程序的其他部分保持一致。
- 按照[安全实践](Password_Storage_Cheat_Sheet.md)更新和存储密码。
- 发送电子邮件通知用户密码已重置（不要在电子邮件中发送密码！）。
- 设置新密码后，用户应通过常规机制登录。不要自动登录用户，因为这会增加身份验证和会话处理代码的复杂性，并增加引入漏洞的可能性。
- 询问用户是否要使所有现有会话失效，或自动使会话失效。

## 方法

为了允许用户请求密码重置，您需要有某种方式识别用户，或通过侧信道与他们联系。

可以通过以下任何方法实现：

- [URL 令牌](#url-令牌)
- [PIN](#pin)
- [离线方法](#离线方法)
- [安全问题](#安全问题)

这些方法可以一起使用，以提供更高程度的保证用户确实是他们声称的身份。无论如何，您必须确保用户始终有办法恢复他们的账户，即使这意味着联系支持团队并向工作人员证明身份。

### 一般安全实践

对重置标识符（令牌、代码、PIN 等）采用良好的安全实践至关重要。某些点不适用于[离线方法](#离线方法)，如生命周期限制。所有令牌和代码应：

- 使用[加密安全随机数生成器](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation)生成。
    - 也可以使用 JSON Web 令牌（JWTs）代替随机令牌，尽管这可能引入额外的漏洞，如 [JSON Web 令牌备忘录](JSON_Web_Token_for_Java_Cheat_Sheet.md)中讨论的那些。
- 足够长以防止暴力破解攻击。
- 在数据库中链接到单个用户。
- 使用后失效。
- 按照[密码存储备忘录](Password_Storage_Cheat_Sheet.md)中讨论的方式安全存储。

### URL 令牌

URL 令牌通过 URL 查询字符串传递，通常通过电子邮件发送给用户。基本流程概述如下：

1. 为用户生成令牌并将其附加到 URL 查询字符串中。
2. 通过电子邮件将此令牌发送给用户。
   - 创建重置 URL 时不要依赖 [Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) 标头，以避免 [Host 标头注入](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)攻击。URL 应该是硬编码的，或者应该针对可信域名列表进行验证。
   - 确保 URL 使用 HTTPS。
3. 用户收到电子邮件，并浏览带有附加令牌的 URL。
   - 确保重置密码页面添加 [Referrer 策略](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)标签，值为 `noreferrer`，以避免[引用者泄露](https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage)。
   - 实施适当的保护，防止用户在 URL 中暴力破解令牌，如速率限制。
4. 如果需要，执行任何额外的验证步骤，如要求用户回答[安全问题](#安全问题)。
5. 让用户创建并确认新密码。确保应用在应用程序其他地方使用的相同密码策略。

*注意：* URL 令牌可以通过从令牌创建受限会话来遵循与 [PIN](#pin) 相同的行为。决策应基于开发人员的需求和专业知识。

### PIN

PIN 是通过侧信道（如短信）发送给用户的数字（6 到 12 位）。

1. 生成 PIN。
2. 通过短信或其他机制将其发送给用户。
   - 用空格分隔 PIN 使用户更容易阅读和输入。
3. 用户在密码重置页面输入 PIN 和用户名。
4. 从该 PIN 创建仅允许用户重置密码的有限会话。
5. 让用户创建并确认新密码。确保应用在应用程序其他地方使用的相同密码策略。

### 离线方法

离线方法与其他方法的不同之处在于允许用户在不从后端请求特殊标识符（如令牌或 PIN）的情况下重置密码。然而，后端仍需进行身份验证，以确保请求是合法的。离线方法在注册时或用户希望配置时提供特定标识符。

这些标识符应以安全方式离线存储（例如密码管理器），后端应正确遵循[一般安全实践](#一般安全实践)。一些实现基于[硬件 OTP 令牌](Multifactor_Authentication_Cheat_Sheet.md#hardware-otp-tokens)、[证书](Multifactor_Authentication_Cheat_Sheet.md#certificates)，或可在企业内部使用的任何其他实现。这些超出了本备忘录的范围。

如果账户启用了 MFA，并且您正在寻找 MFA 恢复，可以在相应的[多因素认证备忘录](Multifactor_Authentication_Cheat_Sheet.md#resetting-mfa)中找到不同的方法。

### 安全问题

由于安全问题的答案经常容易被猜测或被攻击者获取，因此不应将其作为重置密码的唯一机制。然而，当与本备忘录中讨论的其他方法结合使用时，它们可以提供额外的安全层。如果使用，请确保选择[安全问题备忘录](Choosing_and_Using_Security_Questions_Cheat_Sheet.md)中讨论的安全问题。

## 账户锁定

不应因忘记密码攻击而锁定账户，因为这可能被用于拒绝访问已知用户名的用户。有关账户锁定的更多详细信息，请参见[身份验证备忘录](Authentication_Cheat_Sheet.md)。
