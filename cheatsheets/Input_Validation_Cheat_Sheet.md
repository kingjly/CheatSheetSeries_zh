# 输入验证备忘录

## 引言

本文旨在为在应用程序中提供输入验证安全功能提供清晰、简单且可操作的指导。

## 输入验证的目标

输入验证的目的是确保只有格式正确的数据进入信息系统的工作流，防止格式错误的数据持久化到数据库并触发各种下游组件的故障。输入验证应尽可能早地在数据流中进行，最好是在从外部方接收数据时立即进行。

来自所有潜在不可信来源的数据都应接受输入验证，不仅包括面向互联网的 Web 客户端，还包括通过外网从[供应商、合作伙伴、供应商或监管机构](https://badcyber.com/several-polish-banks-hacked-information-stolen-by-unknown-attackers/)传输的后端数据源，每个数据源本身可能已被入侵并开始发送格式错误的数据。

输入验证不应作为防范[跨站脚本（XSS）](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)、[SQL 注入](SQL_Injection_Prevention_Cheat_Sheet.md)和其他在相应[备忘录](https://cheatsheetseries.owasp.org/)中涵盖的攻击的*主要*方法，但如果正确实施，可以显著有助于减少其影响。

## 输入验证策略

输入验证应在语法和语义两个层面应用：

- **语法**验证应强制执行结构化字段的正确语法（例如社会保险号、日期、货币符号）。
- **语义**验证应强制执行特定业务上下文中的值的正确性（例如开始日期在结束日期之前，价格在预期范围内）。

建议尽可能早地在处理用户（攻击者）请求时防止攻击。输入验证可用于在应用程序处理输入之前检测未经授权的输入。

## 实施输入验证

可以使用任何允许有效执行语法和语义正确性的编程技术来实施输入验证，例如：

- Web 应用程序框架中原生可用的数据类型验证器（如 [Django 验证器](https://docs.djangoproject.com/en/1.11/ref/validators/)、[Apache Commons 验证器](https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/package-summary.html#doc.Usage.validator) 等）。
- 针对 JSON 和 XML 格式输入的 [JSON Schema](http://json-schema.org/) 和 [XML Schema (XSD)](https://www.w3schools.com/xml/schema_intro.asp) 验证。
- 类型转换（例如 Java 中的 `Integer.parseInt()`，Python 中的 `int()`）并进行严格的异常处理
- 数字参数和日期的最小和最大值范围检查，字符串的最小和最大长度检查。
- 小型字符串参数集的允许值数组（例如星期几）。
- 正则表达式用于任何其他覆盖整个输入字符串 `(^...$)` 且**不**使用"任意字符"通配符（如 `.` 或 `\S`）的结构化数据。
- 黑名单已知的危险模式可以作为额外的防御层，但它应该补充而不是替代白名单，以帮助捕获一些常见的攻击或模式，而不依赖于它作为主要验证方法。

### 白名单 vs 黑名单

使用黑名单验证以尝试检测可能危险的字符和模式（如撇号 `'`、字符串 `1=1` 或 `<script>` 标签）是一个常见的错误，但这是一种极其脆弱的方法，攻击者可以轻松绕过此类过滤器。

此外，这种过滤器经常阻止合法输入，如 `O'Brian`，其中 `'` 字符是完全合法的。有关 XSS 过滤器规避的更多信息，请参见[此维基页面](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)。

虽然黑名单可以作为额外的防御层来捕获一些常见的恶意模式，但不应将其视为主要方法。白名单仍然是防范潜在有害输入的更强大和安全的方法。

对于用户提供的所有输入字段，白名单验证都是适当的。白名单验证涉及精确定义什么是被授权的，根据定义，其他所有内容都是未经授权的。

如果是结构良好的数据，如日期、社会保险号、邮政编码、电子邮件地址等，开发人员应该能够定义一个非常强大的验证模式，通常基于正则表达式。

如果输入字段来自固定的选项集，如下拉列表或单选按钮，则输入需要与最初提供给用户的值完全匹配。

### 验证自由格式 Unicode 文本

自由格式文本，尤其是包含 Unicode 字符的文本，由于需要允许相对较大的字符空间而被认为难以验证。

自由格式文本输入突出了上下文感知输出编码的重要性，并清楚地表明输入验证**不是**防范跨站脚本的主要防护措施。如果用户希望在其评论字段中键入撇号 `'` 或小于号 `<`，他们可能有完全合法的理由，应用程序的工作是在数据的整个生命周期中正确处理它。

自由格式文本输入的主要输入验证方法应该是：

- **规范化：** 确保使用规范编码，并且没有无效字符。
- **字符类别白名单：** Unicode 允许列出诸如"十进制数字"或"字母"等类别，不仅涵盖拉丁字母，还涵盖全球使用的各种其他脚本（例如阿拉伯文、西里尔文、CJK 表意文字等）。
- **单个字符白名单：** 如果允许名称中使用字母和表意文字，并且还想允许爱尔兰名字中的撇号 `'`，但不想允许整个标点类别。

参考文献：

- [Python 中自由格式 Unicode 文本的输入验证](https://web.archive.org/web/20170717174432/https://ipsec.pl/python/2017/input-validation-free-form-unicode-text-python.html/)
- [UAX 31：Unicode 标识符和模式语法](https://unicode.org/reports/tr31/)
- [UAX 15：Unicode 规范化形式](https://www.unicode.org/reports/tr15/)
- [UAX 24：Unicode 脚本属性](https://unicode.org/reports/tr24/)

### 正则表达式（Regex）

开发正则表达式可能很复杂，这远远超出了本备忘录的范围。

互联网上有很多关于如何编写正则表达式的资源，包括这个[网站](https://www.regular-expressions.info/)和 [OWASP 验证正则表达式仓库](https://owasp.org/www-community/OWASP_Validation_Regex_Repository)。

在设计正则表达式时，要注意[正则表达式拒绝服务（ReDoS）攻击](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)。这些攻击会导致使用设计不当的正则表达式的程序运行非常缓慢，并长时间占用 CPU 资源。

总之，输入验证应：

- 至少应用于所有输入数据。
- 定义要接受的字符集。
- 为数据定义最小和最大长度（例如 `{1,25}`）。

## 白名单正则表达式示例

验证美国邮政编码（5 位数字，可选 -4）

```text
^\d{5}(-\d{4})?$
```

验证下拉菜单中的美国州选择

```text
^(AA|AE|AP|AL|AK|AS|AZ|AR|CA|CO|CT|DE|DC|FM|FL|GA|GU|
HI|ID|IL|IN|IA|KS|KY|LA|ME|MH|MD|MA|MI|MN|MS|MO|MT|NE|
NV|NH|NJ|NM|NY|NC|ND|MP|OH|OK|OR|PW|PA|PR|RI|SC|SD|TN|
TX|UT|VT|VI|VA|WA|WV|WI|WY)$
```

**Java 正则表达式使用示例：**

使用正则表达式验证"zip"参数的示例。

```java
private static final Pattern zipPattern = Pattern.compile("^\d{5}(-\d{4})?$");

public void doPost( HttpServletRequest request, HttpServletResponse response) {
  try {
      String zipCode = request.getParameter( "zip" );
      if ( !zipPattern.matcher( zipCode ).matches() ) {
          throw new YourValidationException( "Improper zipcode format." );
      }
      // 在验证后执行你想做的操作..
  } catch(YourValidationException e ) {
      response.sendError( response.SC_BAD_REQUEST, e.getMessage() );
  }
}
```

一些白名单验证器也已在各种开源包中预定义，您可以利用这些包。例如：

- [Apache Commons 验证器](http://commons.apache.org/proper/commons-validator/)

## 客户端 vs 服务器端验证

输入验证**必须**在应用程序的任何函数处理数据之前在服务器端实施，因为攻击者可以通过禁用 JavaScript 或使用 Web 代理来绕过客户端基于 JavaScript 的输入验证。推荐的方法是同时实施客户端 JavaScript 验证（用于用户体验）和服务器端验证（用于安全性），充分利用各自的优势。

## 验证富文本用户内容

验证用户提交的富文本内容非常困难。更多信息，请参见 XSS 备忘录中的[使用专门设计的库净化 HTML 标记](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)。

## 防范 XSS 和内容安全策略

必须对所有受控用户数据进行编码，以防止恶意数据执行（例如 XSS）。例如，`<script>` 将返回为 `&lt;script&gt;`

编码类型特定于插入用户控制数据的页面上下文。例如，对于放置在 HTML 正文中的数据，HTML 实体编码是合适的。但是，放置在脚本中的用户数据需要 JavaScript 特定的输出编码。

有关 XSS 防范的详细信息，请参见：[OWASP XSS 防范备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)

## 文件上传验证

许多网站允许用户上传文件，如个人资料图片等。本节帮助安全地提供此功能。

请查看[文件上传备忘录](File_Upload_Cheat_Sheet.md)。

### 上传验证

- 使用输入验证确保上传的文件名使用预期的扩展名类型。
- 确保上传的文件不大于定义的最大文件大小。
- 如果网站支持 ZIP 文件上传，请在解压文件前进行验证检查。检查包括目标路径、压缩级别、估计解压大小。

### 上传存储

- 使用新文件名在操作系统上存储文件。不要对此文件名或临时文件名使用任何用户控制的文本。
- 上传到 Web 时，建议重命名存储的文件。例如，上传的文件名是 *test.JPG*，将其重命名为 *JAI1287uaisdjhf.JPG*，使用随机文件名。这样做是为了防止直接文件访问和绕过过滤器的模糊文件名风险，如 `test.jpg;.asp` 或 `/../../../../../test.jpg`。
- 应分析上传的文件是否包含恶意内容（反恶意软件、静态分析等）。
- 文件路径不应由客户端指定，而是由服务器端决定。

### 公开提供上传内容

- 确保上传的图像使用正确的内容类型（例如 image/jpeg, application/x-xpinstall）

### 注意特定文件类型

上传功能应使用白名单方法，仅允许特定文件类型和扩展名。但是，需要注意以下文件类型，如果允许，可能导致安全漏洞：

- **crossdomain.xml** / **clientaccesspolicy.xml**：允许 Flash、Java 和 Silverlight 中的跨域数据加载。如果在有身份验证的站点上允许，可能导致跨域数据盗取和 CSRF 攻击。最好是禁止名为"crossdomain.xml"或"clientaccesspolicy.xml"的文件。
- **.htaccess** 和 **.htpasswd**：提供基于目录的服务器配置选项，不应允许。请参见 [HTACCESS 文档](http://en.wikipedia.org/wiki/Htaccess)。
- 建议不允许 Web 可执行脚本文件，如 `aspx, asp, css, swf, xhtml, rhtml, shtml, jsp, js, pl, php, cgi`。

### 图像上传验证

- 使用图像重写库验证图像有效性并去除多余内容。
- 根据图像处理检测到的内容类型，将存储图像的扩展名设置为有效的图像扩展名（例如，不要仅信任上传的标头）。
- 确保检测到的图像内容类型在已定义的图像类型列表中（jpg, png 等）

## 电子邮件地址验证

### 语法验证

电子邮件地址的格式由 [RFC 5321](https://tools.ietf.org/html/rfc5321#section-4.1.2) 定义，比大多数人意识到的要复杂得多。例如，以下都被视为有效的电子邮件地址：

- `"><script>alert(1);</script>"@example.org`
- `user+subaddress@example.org`
- `user@[IPv6:2001:db8::1]`
- `" "@example.org`

使用正则表达式正确解析电子邮件地址的有效性非常复杂，尽管有许多[关于正则表达式的公开文档](https://datatracker.ietf.org/doc/html/draft-seantek-mail-regexen-03#rfc.section.3)。

最大的警告是，尽管 RFC 定义了电子邮件地址的非常灵活的格式，但大多数现实世界的实现（如邮件服务器）使用更受限制的地址格式，这意味着它们将拒绝*技术上*有效的地址。尽管这些地址在技术上是正确的，但如果应用程序无法实际向它们发送电子邮件，它们就没有什么用处。

因此，验证电子邮件地址的最佳方法是执行一些基本的初步验证，然后将地址传递给邮件服务器并捕获异常（如果被拒绝）。这意味着应用程序可以确信其邮件服务器可以向其接受的任何地址发送电子邮件。初步验证可以简单到：

- 电子邮件地址包含两个部分，用 `@` 符号分隔。
- 电子邮件地址不包含危险字符（如反引号、单引号或双引号，或空字节）。
    - 具体哪些字符是危险的，取决于地址将如何使用（回显在页面上、插入数据库等）。
- 域名部分仅包含字母、数字、连字符（`-`）和句点（`.`）。
- 电子邮件地址长度合理：
    - 本地部分（`@` 之前）不应超过 63 个字符。
    - 总长度不应超过 254 个字符。

### 语义验证

语义验证是为了确定电子邮件地址是否正确和合法。最常见的方法是向用户发送电子邮件，并要求他们点击电子邮件中的链接，或输入发送给他们的代码。这提供了基本的保证：

- 电子邮件地址是正确的。
- 应用程序可以成功向其发送电子邮件。
- 用户可以访问邮箱。

发送给用户以证明所有权的链接应包含一个：

- 至少 32 个字符长。
- 使用[安全的随机性源](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation)生成。
- 单次使用。
- 时间限制（例如，8 小时后过期）。

验证电子邮件地址所有权后，用户应通过常规机制在应用程序中进行身份验证。

#### 一次性电子邮件地址

在某些情况下，用户在注册应用程序时可能不想提供真实的电子邮件地址，而是提供一次性电子邮件地址。这些是公开可用的地址，不需要用户进行身份验证，通常用于减少用户主要电子邮件地址收到的垃圾邮件数量。

阻止一次性电子邮件地址几乎是不可能的，因为有大量网站提供这些服务，并且每天都有新域名被创建。有许多公开可用的列表和商业列表，列出已知的一次性域名，但这些列表总是不完整的。

如果使用这些列表阻止一次性电子邮件地址，则应向用户显示解释被阻止原因的消息（尽管他们可能只是搜索另一个一次性提供商，而不是提供其合法地址）。

如果必须阻止一次性电子邮件地址，则只能从特定允许的电子邮件提供商注册。但是，如果这包括 Google 或 Yahoo 等公共提供商，用户可以简单地在这些提供商处注册自己的一次性地址。

#### 子地址

子地址允许用户在电子邮件地址的本地部分（`@` 之前）指定一个*标记*，该标记将被邮件服务器忽略。例如，如果 `example.org` 域支持子地址，则以下电子邮件地址是等效的：

- `user@example.org`
- `user+site1@example.org`
- `user+site2@example.org`

许多邮件提供商（如 Microsoft Exchange）不支持子地址。最著名的支持提供商是 Gmail，尽管还有许多其他提供商也支持。

一些用户会为他们注册的每个网站使用不同的*标记*，这样如果他们开始在某个子地址收到垃圾邮件，就可以识别哪个网站泄露或出售了他们的电子邮件地址。

因为它可能允许用户使用单个电子邮件地址注册多个帐户，一些网站可能希望通过删除 `+` 和 `@` 符号之间的所有内容来阻止子地址。这通常不建议，因为这表明网站所有者要么不了解子地址，要么希望在他们泄露或出售电子邮件地址时阻止用户识别他们。此外，这可以通过使用[一次性电子邮件地址](#一次性电子邮件地址)或简单地使用可信提供商注册多个电子邮件帐户来轻易绕过。

## 参考文献

- [OWASP 2024 主动控制前 10 名：C3：验证所有输入并处理异常](https://top10proactive.owasp.org/the-top-10/c3-validate-input-and-handle-exceptions)
- [CWE-20 不正确的输入验证](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP 2021 前 10 名：A03:2021-注入](https://owasp.org/Top10/A03_2021-Injection/)
- [Snyk：不正确的输入验证](https://learn.snyk.io/lesson/improper-input-validation/)
