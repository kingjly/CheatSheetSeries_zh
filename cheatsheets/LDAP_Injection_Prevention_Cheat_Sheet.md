# LDAP 注入防护备忘录

## 引言

轻量级目录访问协议（LDAP）允许应用程序远程执行搜索和修改目录记录等操作。LDAP 注入源于不充分的输入净化和验证，使恶意用户能够使用目录服务获取受限信息。关于 LDAP 的更多信息，请访问 [轻量级目录访问协议（LDAP）](https://www.redhat.com/en/topics/security/what-is-ldap-authentication)。

LDAP 注入是一种利用基于用户输入构建 LDAP 语句的 Web 应用程序的攻击方式。当应用程序未能正确净化用户输入时，可以通过类似于 [SQL 注入](https://owasp.org/www-community/attacks/SQL_Injection) 的技术修改 LDAP 语句。

本备忘录旨在为防止应用程序中的 LDAP 注入缺陷提供清晰、简单、可操作的指导。由于以下两个因素，LDAP 注入攻击很常见：

1. 缺乏更安全的参数化 LDAP 查询接口
2. 广泛使用 LDAP 对系统进行用户身份验证

LDAP 注入攻击可能导致未经授权的查询获得权限，并修改 LDAP 树中的内容。

主要防御措施：

- 使用正确的 LDAP 编码函数转义所有变量
- 使用自动转义的框架

额外防御措施：

- 最小权限
- 允许列表输入验证

## 主要防御措施

### 防御选项 1：使用正确的 LDAP 编码函数转义所有变量

#### 可分辨名称（DN）转义

LDAP 存储名称的主要方式是基于 DN（可分辨名称）。可以将其视为唯一标识符。这些有时用于访问资源，如用户名。

DN 可能看起来像这样：

`cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu`

或

`uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com`

可以使用白名单来限制输入为有效字符。必须从白名单中排除的字符和字符序列（包括 Java 命名和目录接口（JNDI）元字符和 LDAP 特殊字符）列在以下列表中。

[详尽列表](https://ldapwiki.com/wiki/Wiki.jsp?page=DN%20Escape%20Values)如下：`\ # + < > , ; " =` 以及开头或结尾的空格。

一些在可分辨名称中允许且不需要转义的"特殊"字符包括：

```text
* ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '
```

#### 搜索过滤器转义

每个 DN 指向恰好 1 个条目，可以将其视为类似于关系数据库管理系统中的一行。对于每个条目，将有 1 个或多个属性，类似于关系数据库管理系统的列。如果您有兴趣通过 LDAP 搜索具有特定属性的用户，可以使用搜索过滤器。

在搜索过滤器中，您可以使用标准布尔逻辑获取匹配任意约束的用户列表。搜索过滤器以波兰表示法（即前缀表示法）编写。

示例：

```text
(&(ou=Physics)(|
(manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu)
))
```

在应用程序代码中构建 LDAP 查询时，必须转义添加到任何 LDAP 查询中的任何不可信数据。LDAP 转义有两种形式：LDAP 搜索编码和 LDAP DN（可分辨名称）编码。正确的转义取决于您是为搜索过滤器净化输入，还是使用 DN 作为类似用户名的凭据来访问某些资源。

搜索过滤器中允许且必须转义的一些"特殊"字符包括：

```text
* ( ) \ NUL
```

有关搜索过滤器转义的更多信息，请访问 [RFC4515](https://datatracker.ietf.org/doc/html/rfc4515#section-3)。

#### 安全的 Java 转义示例

以下解决方案使用白名单来净化用户输入，以便过滤器字符串仅包含有效字符。在此代码中，userSN 只能包含字母和空格，而密码只能包含字母数字字符：

```java
// String userSN = "Sherlock Holmes"; // 有效
// String userPassword = "secret2"; // 有效
// ... LDAPInjection.searchRecord() 开始 ...
sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
String base = "dc=example,dc=com";

if (!userSN.matches("[\\w\\s]*") || !userPassword.matches("[\\w]*")) {
 throw new IllegalArgumentException("无效输入");
}

String filter = "(&(sn = " + userSN + ")(userPassword=" + userPassword + "))";
// ... LDAPInjection.searchRecord() 剩余部分 ... 
```

当数据库字段（如密码）必须包含特殊字符时，确保以净化形式将真实数据存储在数据库中，并且在验证或比较之前对任何用户输入进行规范化至关重要。在没有全面的规范化和基于白名单的例程的情况下，不鼓励使用 JNDI 和 LDAP 中具有特殊含义的字符。特殊字符必须在添加到将针对其验证输入的白名单表达式之前转换为净化的安全值。同样，用户输入的规范化应在验证步骤之前进行（来源：[防止 LDAP 注入](https://wiki.sei.cmu.edu/confluence/spaces/flyingpdf/pdfpageexport.action?pageId=88487534)）。

欲了解更多信息，请访问 [OWASP ESAPI Java 编码器项目，其中包括 encodeForLDAP(String) 和 encodeForDN(String)](https://owasp.org/www-project-java-encoder/)。

#### 安全的 C Sharp .NET 待办示例

[.NET AntiXSS](https://blogs.msdn.microsoft.com/securitytools/2010/09/30/antixss-4-0-released/)（现在是编码器类）具有 LDAP 编码函数，包括 `Encoder.LdapFilterEncode(string)`、`Encoder.LdapDistinguishedNameEncode(string)` 和 `Encoder.LdapDistinguishedNameEncode(string, bool, bool)`。

`Encoder.LdapFilterEncode` 根据 [RFC4515](https://tools.ietf.org/search/rfc4515) 对输入进行编码，不安全的值被转换为 `\XX`，其中 `XX` 是不安全字符的表示。

`Encoder.LdapDistinguishedNameEncode` 根据 [RFC2253](https://tools.ietf.org/html/rfc2253) 对输入进行编码，不安全的字符被转换为 `#XX`，其中 `XX` 是不安全字符的表示，逗号、加号、引号、斜杠、小于号和大于号使用斜杠表示法（`\X`）转义。此外，输入字符串开头的空格或井号（`#`）以及字符串末尾的空格都会使用 `\` 转义。

还提供了 `LdapDistinguishedNameEncode(string, bool, bool)`，以便您可以关闭初始或最终字符转义规则，例如，如果您要将转义的可分辨名称片段连接到完整可分辨名称的中间位置。

### 防御选项 2：使用自动防护 LDAP 注入的框架

#### 安全的 .NET 示例

我们建议在 DotNet 中使用 [LINQ to LDAP](https://www.nuget.org/packages/LinqToLdap/)（对于 .NET Framework 4.5 或更低版本[直到更新](https://github.com/madhatter22/LinqToLdap/issues/31)）。它在构建 LDAP 查询时提供自动 LDAP 编码。
请查看项目存储库中的 [自述文件](https://github.com/madhatter22/LinqToLdap/blob/master/README.md)。

## 额外防御措施

除了采用两种主要防御措施之外，我们还建议采用所有这些额外防御措施，以提供深度防御。这些额外的防御措施是：

- **最小权限**
- **允许列表输入验证**

### 最小权限

为了最大限度地减少成功的 LDAP 注入攻击的潜在损害，您应该最小化环境中 LDAP 绑定帐户的分配权限。

### 启用绑定身份验证

如果 LDAP 协议配置了绑定身份验证，攻击者将无法执行 LDAP 注入攻击，因为对用户传递的有效凭据进行了验证和授权检查。
攻击者仍可通过匿名连接或利用未经身份验证的绑定来绕过绑定身份验证：匿名绑定（LDAP）和未经身份验证的绑定（LDAP）。

### 允许列表输入验证

输入验证可用于在将输入传递给 LDAP 查询之前检测未经授权的输入。欲了解更多信息，请参见 [输入验证速查表](Input_Validation_Cheat_Sheet.md)。

## 相关文章

- OWASP 关于 [LDAP 注入](https://owasp.org/www-community/attacks/LDAP_Injection) 漏洞的文章。
- [OWASP 测试指南](https://owasp.org/www-project-web-security-testing-guide/)关于如何[测试 LDAP 注入](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection.html)漏洞的文章。
