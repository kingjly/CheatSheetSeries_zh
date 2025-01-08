# 注入防御备忘录

## 简介

本文旨在为防范应用程序中整个类别的注入缺陷提供清晰、简单且可操作的指导。不幸的是，注入攻击，尤其是 [SQL 注入](https://owasp.org/www-community/attacks/SQL_Injection)，非常普遍。

应用程序的可访问性是防护和预防注入缺陷的重要因素。在企业/公司中，只有少数应用程序是内部开发的，而大多数应用程序来自外部源。开源应用程序至少提供了修复问题的机会，但闭源应用程序需要采用不同的方法来处理注入缺陷。

当应用程序将不可信数据发送给解释器时，就会发生注入缺陷。注入缺陷尤其在遗留代码中很普遍，常见于 SQL 查询、LDAP 查询、XPath 查询、操作系统命令、程序参数等。检查代码时，注入缺陷很容易发现，但通过测试则更加困难。扫描器和模糊测试工具可以帮助攻击者找到这些缺陷。

根据可访问性的不同，必须采取不同的操作来修复这些缺陷。最好的方法是直接在源代码中修复问题，甚至重新设计应用程序的某些部分。但如果源代码不可用，或者仅修复遗留软件在经济上不可行，那么虚拟补丁是唯一有意义的选择。

## 应用程序类型

通常可以在公司内看到三类应用程序。这三种类型有助于确定为防范/修复注入缺陷需要采取的行动。

### A1：新应用程序

处于设计阶段或早期开发阶段的新 Web 应用程序。

### A2：生产型开源应用程序

已投入生产的应用程序，可以轻松调整。模型-视图-控制器（MVC）类型的应用程序就是具有易访问应用程序架构的一个例子。

### A3：生产型闭源应用程序

无法或难以修改的生产应用程序。

## 注入形式

存在针对不同技术的多种注入形式，包括 SQL 查询、LDAP 查询、XPath 查询和操作系统命令。

### 查询语言

最著名的注入形式是 SQL 注入，攻击者可以修改现有的数据库查询。更多信息请参见 [SQL 注入防御备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)。

但 LDAP、SOAP、XPath 和基于 REST 的查询也可能容易受到注入攻击，允许数据检索或绕过控制。

#### SQL 注入

SQL 注入攻击包括通过数据输入或从客户端（浏览器）传输到 Web 应用程序的部分或完整 SQL 查询的"注入"。

成功的 SQL 注入攻击可以：
- 读取数据库中的敏感数据
- 修改数据库数据（插入/更新/删除）
- 在数据库上执行管理操作（如关闭 DBMS）
- 恢复 DBMS 文件系统上存在的给定文件的内容
- 向文件系统写入文件
- 在某些情况下，向操作系统发出命令

SQL 注入攻击是一种注入攻击，通过将 SQL 命令注入数据平面输入以影响预定义 SQL 命令的执行。

SQL 注入攻击可分为以下三类：

- **带内（Inband）：** 使用与注入 SQL 代码相同的通道提取数据。这是最直接的攻击类型，检索到的数据直接显示在应用程序网页上。
- **带外（Out-of-band）：** 使用不同的通道检索数据（例如，生成并发送包含查询结果的电子邮件）。
- **推理或盲注（Inferential or Blind）：** 没有实际的数据传输，但测试者通过发送特定请求并观察数据库服务器的结果行为来重建信息。

##### 如何测试问题

###### 代码审查期间

请检查是否未使用预编译语句进行数据库查询。

如果正在进行动态语句，请检查数据是否在用作语句的一部分之前进行了净化。

审核员应始终查找 SQL Server 存储过程中 sp_execute、execute 或 exec 的使用。对于其他供应商，需要类似的审核指南。

###### 自动利用

下面的大多数情况和技术都可以使用某些工具以自动方式执行。在本文中，测试者可以找到有关使用 [SQLMap](https://wiki.owasp.org/index.php/Automated_Audit_using_SQLMap) 进行自动审核的信息。

同样，静态代码分析数据流规则可以检测未净化的用户控制输入是否可以更改 SQL 查询。

###### 存储过程注入

在存储过程中使用动态 SQL 时，应用程序必须正确净化用户输入以消除代码注入风险。如果未净化，用户可能输入恶意 SQL 并在存储过程中执行。

###### 时间延迟利用技术

当测试者遇到盲 SQL 注入情况（对操作结果一无所知）时，时间延迟利用技术非常有用。该技术包括发送注入的查询，如果条件为真，测试者可以监控服务器响应所需的时间。如果有延迟，测试者可以假设条件查询的结果为真。这种利用技术可能因数据库管理系统（DBMS）而异（请检查 DBMS 特定部分）。

```text
http://www.example.com/product.php?id=10 AND IF(version() like '5%', sleep(10), 'false'))--
```

在此示例中，测试者正在检查 MySQL 版本是否为 5.x，通过使服务器延迟 10 秒来响应。测试者可以增加延迟时间并监控响应。测试者也不需要等待响应。有时他们可以设置非常高的值（例如 100）并在几秒后取消请求。

###### 带外利用技术

当测试者遇到盲 SQL 注入情况（对操作结果一无所知）时，这种技术非常有用。该技术包括使用 DBMS 函数执行带外连接，并将注入查询的结果作为对测试者服务器的请求的一部分传递。与基于错误的技术一样，每个 DBMS 都有自己的函数。请检查特定 DBMS 部分。

##### 补救措施

###### 防御选项 1：预编译语句（参数化查询）

预编译语句确保攻击者即使插入 SQL 命令也无法更改查询的意图。在下面的安全示例中，如果攻击者输入用户 ID `tom' or '1'='1`，参数化查询将不会易受攻击，而是会查找完全匹配整个字符串 `tom' or '1'='1` 的用户名。

###### 防御选项 2：存储过程

预编译语句和存储过程的区别在于存储过程的 SQL 代码在数据库本身中定义和存储，然后从应用程序调用。

这两种技术在防止 SQL 注入方面具有相同的有效性，因此贵组织应选择最适合自身的方法。存储过程并非总是对 SQL 注入免疫。但是，某些标准存储过程编程构造在安全实施时对防止 SQL 注入具有与使用参数化查询相同的效果，这对于大多数存储过程语言来说是常态。

*注意：*"安全实施"意味着存储过程不包含任何不安全的动态 SQL 生成。

###### 防御选项 3：白名单输入验证

SQL 查询的某些部分不适合使用绑定变量，例如表名、列名和排序顺序指示符（ASC 或 DESC）。在这种情况下，输入验证或查询重新设计是最合适的防御。对于表名或列名，理想情况下这些值来自代码，而不是用户参数。

但如果使用用户参数值来区分表名和列名，则应将参数值映射到合法/预期的表或列名，以确保未验证的用户输入不会出现在查询中。请注意，这是设计不当的症状，如果时间允许，应考虑完全重写。

###### 防御选项 4：转义所有用户提供的输入

仅在上述方法都不可行时，才应使用此技术。输入验证可能是更好的选择，因为与其他防御相比，这种方法很脆弱，我们无法保证它在所有情况下都能防止 SQL 注入。

这种技术是在将用户输入放入查询之前对其进行转义。通常仅建议在实施输入验证不具成本效益时对遗留代码进行改造。

##### 示例代码 - Java

###### 安全的 Java 预编译语句示例

以下代码示例使用 `PreparedStatement`（Java 的参数化查询实现）执行相同的数据库查询。

```java
// 这里确实应该进行验证
String custname = request.getParameter("customerName");
// 执行输入验证以检测攻击
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

我们展示了 Java 的示例，但实际上几乎所有其他语言，包括 Cold Fusion 和 Classic ASP，都支持参数化查询接口。

###### 安全的 Java 存储过程示例

以下代码示例使用 `CallableStatement`（Java 的存储过程接口实现）执行相同的数据库查询。`sp_getAccountBalance` 存储过程必须预先在数据库中定义，并实现与上面定义的查询相同的功能。

```java
// 这里确实应该进行验证
String custname = request.getParameter("customerName");
try {
 CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
 cs.setString(1, custname);
 ResultSet results = cs.executeQuery();
 // 结果集处理...
} catch (SQLException se) {
 // 日志记录和错误处理...
}
```

#### LDAP 注入

LDAP 注入是一种利用基于用户输入构建 LDAP 语句的 Web 应用程序的攻击。当应用程序未能正确净化用户输入时，可以使用类似于 [SQL 注入](https://owasp.org/www-community/attacks/SQL_Injection) 的技术修改 LDAP 语句。LDAP 注入攻击可能导致未经授权的查询获得权限，并修改 LDAP 树中的内容。有关 LDAP 注入攻击的更多信息，请访问 [LDAP 注入](https://owasp.org/www-community/attacks/LDAP_Injection)。

[LDAP 注入](https://owasp.org/www-community/attacks/LDAP_Injection)攻击很常见，原因有两个：

1. 缺乏更安全的参数化 LDAP 查询接口
2. 广泛使用 LDAP 对系统用户进行身份验证

##### 如何测试问题

###### 代码审查期间

请检查 LDAP 查询是否转义特殊字符，请参见[此处](LDAP_Injection_Prevention_Cheat_Sheet.md#defense-option-1-escape-all-variables-using-the-right-ldap-encoding-function)。

###### 自动利用

像 OWASP [ZAP](https://www.zaproxy.org/) 这样的工具的扫描器模块有检测 LDAP 注入问题的模块。

##### 补救措施

###### 使用正确的 LDAP 编码函数转义所有变量

LDAP 存储名称的主要方式是基于 DN（[可分辨名称](https://ldapwiki.com/wiki/Distinguished%20Names)）。可以将其视为唯一标识符。这些有时用于访问资源，如用户名。

DN 可能看起来像这样：

```text
cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu
```

或

```text
uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com
```

在 DN 中有一些被视为特殊字符的字符。详尽的列表如下：`\ # + < > , ; " =` 以及前导或尾随空格

每个 DN 都指向恰好 1 个条目，可以将其视为类似于关系数据库管理系统（RDBMS）中的行。对于每个条目，将有 1 个或多个属性，类似于 RDBMS 列。如果您有兴趣在 LDAP 中搜索具有某些属性的用户，可以使用搜索过滤器。在搜索过滤器中，您可以使用标准布尔逻辑获取匹配任意约束的用户列表。搜索过滤器以波兰表示法（又称前缀表示法）编写。

示例：

```text
(&(ou=Physics)(| (manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu) ))
```

在应用程序代码中构建 LDAP 查询时，必须转义添加到任何 LDAP 查询的任何不可信数据。LDAP 转义有两种形式：LDAP 搜索编码和 LDAP DN（可分辨名称）编码。正确的转义取决于您是为搜索过滤器净化输入，还是使用 DN 作为类似用户名的凭据来访问某些资源。

##### 示例代码 - Java

###### 安全的 Java LDAP 转义示例

```java
public String escapeDN (String name) {
 //来自 RFC 2253 和 JNDI 的 / 字符
 final char[] META_CHARS = {'+', '"', '<', '>', ';', '/'};
 String escapedStr = new String(name);
 //反斜杠是 Java 和 LDAP 的转义字符，
 //所以先转义它
 escapedStr = escapedStr.replaceAll("\\\\\\\\","\\\\\\\\");
 //位置字符 - 参见 RFC 2253
 escapedStr = escapedStr.replaceAll("\^#","\\\\\\\\#");
 escapedStr = escapedStr.replaceAll("\^ | $","\\\\\\\\ ");
 for (int i=0 ; i < META_CHARS.length ; i++) {
        escapedStr = escapedStr.replaceAll("\\\\" +
                     META_CHARS[i],"\\\\\\\\" + META_CHARS[i]);
 }
 return escapedStr;
}
```

注意，反斜杠字符是 Java 字符串文字和正则表达式转义字符。

```java
public String escapeSearchFilter (String filter) {
 //来自 RFC 2254
 String escapedStr = new String(filter);
 escapedStr = escapedStr.replaceAll("\\\\\\\\","\\\\\\\\5c");
 escapedStr = escapedStr.replaceAll("\\\\\*","\\\\\\\\2a");
 escapedStr = escapedStr.replaceAll("\\\\(","\\\\\\\\28");
 escapedStr = escapedStr.replaceAll("\\\\)","\\\\\\\\29");
 escapedStr = escapedStr.replaceAll("\\\\" +
               Character.toString('\\u0000'), "\\\\\\\\00");
 return escapedStr;
}
```

#### XPath 注入

待办事项

### 脚本语言

Web 应用程序中使用的所有脚本语言都有一种 `eval` 调用，它在运行时接收代码并执行。如果使用未经验证和未转义的用户输入代码构建，则可能发生代码注入，这允许攻击者颠覆应用程序逻辑并最终获得本地访问权限。

每次使用脚本语言时，"高级"脚本语言的实际实现都是使用像 C 这样的"低级"语言完成的。如果脚本语言的数据处理代码存在缺陷，则可以部署 '[空字节注入](http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection)' 攻击向量以访问内存中的其他区域，从而导致成功攻击。

### 操作系统命令

操作系统命令注入是通过 Web 界面执行 Web 服务器上的操作系统命令的技术。用户通过 Web 界面提供操作系统命令以执行操作系统命令。

任何未经正确净化的 Web 界面都容易受到此漏洞的攻击。有了执行操作系统命令的能力，用户可以上传恶意程序甚至获取密码。在设计和开发应用程序时强调安全性，可以防止操作系统命令注入。

#### 如何测试问题

##### 代码审查期间

检查是否调用了任何命令执行方法，并且未经验证的用户输入被用作该命令的数据。

除此之外，在 URL 查询参数末尾附加分号，后跟操作系统命令，将执行该命令。`%3B` 是 URL 编码，解码为分号。这是因为 `;` 被解释为命令分隔符。

示例：`http://sensitive/something.php?dir=%3Bcat%20/etc/passwd`

如果应用程序使用 `/etc/passwd` 文件的输出响应，则表明攻击已成功。许多 Web 应用程序扫描器可用于测试此攻击，因为它们注入命令注入的变体并测试响应。

同样，静态代码分析工具检查不可信用户输入到 Web 应用程序的数据流，并检查数据是否输入到执行用户输入作为命令的危险方法中。

#### 补救措施

如果认为无法避免使用用户提供的系统命令调用，则应在软件中使用以下两层防御以防止攻击：

1. **参数化** - 如果可用，请使用自动强制数据和命令分离的结构化机制。这些机制可以帮助提供相关的引用和编码。
2. **输入验证** - 命令及其相关参数的值都应进行验证。对于实际命令及其参数，有不同程度的验证：
    - 对于使用的**命令**，必须根据允许的命令列表进行验证。
    - 对于这些命令的**参数**，应使用以下选项进行验证：
        - 正面或白名单输入验证 - 明确定义允许的参数
        - 白名单正则表达式 - 明确定义允许的好字符列表和字符串的最大长度。确保 `& | ; $ > < \ \ !` 和空格不是正则表达式的一部分。例如，以下正则表达式仅允许小写字母和数字，不包含元字符。长度也被限制为 3-10 个字符：

`^[a-z0-9]{3,10}$`

#### 示例代码 - Java

##### 不正确的使用

```java
ProcessBuilder b = new ProcessBuilder("C:\DoStuff.exe -arg1 -arg2");
```

在此示例中，命令和参数作为一个字符串传递，很容易操纵该表达式并注入恶意字符串。

##### 正确的使用

以下是启动具有修改后的工作目录的进程的示例。命令和每个参数都单独传递。这使得验证每个术语变得容易，并降低插入恶意字符串的风险。

```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");
Map<String, String> env = pb.environment();
pb.directory(new File("TrustedDir"));
Process p = pb.start();
```

### 网络协议

Web 应用程序经常与网络守护进程（如 SMTP、IMAP、FTP）通信，用户输入成为通信流的一部分。在这里，可以注入命令序列以滥用已建立的会话。

## 注入防御规则

### 规则 \#1（执行适当的输入验证）

执行适当的输入验证。建议使用正面或白名单输入验证以及适当的规范化，但**并非完全防御**，因为许多应用程序需要在其输入中使用特殊字符。

### 规则 \#2（使用安全的 API）

首选方案是使用完全避免使用解释器或提供参数化接口的安全 API。请注意那些参数化的 API，如存储过程，尽管看似安全，但仍可能在底层引入注入。

### 规则 \#3（上下文转义用户数据）

如果没有可用的参数化 API，则应仔细使用该解释器的特定转义语法转义特殊字符。

## 其他注入备忘录

[SQL 注入防御备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)

[操作系统命令注入防御备忘录](OS_Command_Injection_Defense_Cheat_Sheet.md)

[LDAP 注入防御备忘录](LDAP_Injection_Prevention_Cheat_Sheet.md)

[Java 注入防御备忘录](Injection_Prevention_in_Java_Cheat_Sheet.md)
