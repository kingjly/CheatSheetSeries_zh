# GraphQL 备忘录

## 引言

[GraphQL](https://graphql.org) 是一种开源查询语言，最初由 Facebook 开发，可用作 REST 和 SOAP 的 API 替代方案。自 2012 年诞生以来，由于其为构建和调用 API 提供的原生灵活性，它越来越受欢迎。有多种语言实现的 GraphQL 服务器和客户端。[许多公司](https://foundation.graphql.org/)使用 GraphQL，包括 GitHub、Credit Karma、Intuit 和 PayPal。

本备忘录提供了使用 GraphQL 时需要考虑的各个领域的指导：

- 对所有传入数据应用适当的[输入验证](Input_Validation_Cheat_Sheet.md)检查。
- 昂贵的查询会导致[拒绝服务（DoS）](Denial_of_Service_Cheat_Sheet.md)，因此添加检查以限制或防止过于昂贵的查询。
- 确保 API 具有适当的[访问控制](Access_Control_Cheat_Sheet.md)检查。
- 禁用不安全的默认配置（例如过多的错误、内省、GraphiQL 等）。

## 常见攻击

- [注入](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa8-injection.md) - 通常包括但不限于：
    - [SQL](https://owasp.org/www-community/attacks/SQL_Injection) 和 [NoSQL](https://www.netsparker.com/blog/web-security/what-is-nosql-injection/) 注入
    - [操作系统命令注入](https://owasp.org/www-community/attacks/Command_Injection)
    - [SSRF](https://portswigger.net/web-security/ssrf) 和 [CRLF](https://owasp.org/www-community/vulnerabilities/CRLF_Injection) [注入](https://www.acunetix.com/websitesecurity/crlf-injection/)/[请求](https://portswigger.net/web-security/request-smuggling) [走私](https://www.pentestpartners.com/security-blog/http-request-smuggling-a-how-to/)
- [DoS](https://owasp.org/www-community/attacks/Denial_of_Service)（[拒绝服务](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/)）
- 滥用损坏的授权：[不当](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md)或[过度](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md)访问，包括 [IDOR](https://portswigger.net/web-security/access-control/idor)
- 批处理攻击，这是一种特定于 GraphQL 的暴力破解攻击方法
- 滥用不安全的默认配置

## 最佳实践和建议

### 输入验证

添加严格的输入验证可以帮助防止注入和 DoS。GraphQL 的主要设计是用户提供一个或多个标识符，后端有多个数据获取器使用给定的标识符发出 HTTP、数据库或其他调用。这意味着用户输入将包含在 HTTP 请求、数据库查询或其他请求/调用中，为可能导致各种注入攻击或 DoS 的注入提供了机会。

有关如何最好地执行输入验证和防止注入的完整详细信息，请参见 OWASP 关于[输入验证](Input_Validation_Cheat_Sheet.md)和一般[注入防护](Injection_Prevention_Cheat_Sheet.md)的备忘录。

#### 一般实践

验证所有传入数据，仅允许有效值（即白名单）。

- 使用特定的 GraphQL [数据类型](https://graphql.org/learn/schema/#type-language)，如[标量](https://graphql.org/learn/schema/#scalar-types)或[枚举](https://graphql.org/learn/schema/#enumeration-types)。为更复杂的验证编写自定义 GraphQL [验证器](https://graphql.org/learn/validation/)。[自定义标量](https://itnext.io/custom-scalars-in-graphql-9c26f43133f3)也可能派上用场。
- 为变更输入定义[架构](https://graphql.org/learn/schema/#input-types)。
- [列出允许的字符](Input_Validation_Cheat_Sheet.md#allow-list-vs-block-list) - 不要使用黑名单
    - 允许字符列表越严格越好。很多时候，一个好的起点是只允许字母数字、非 Unicode 字符，因为这将禁止许多攻击。
- 要正确处理 Unicode 输入，使用[单一内部字符编码](Input_Validation_Cheat_Sheet.md#validating-free-form-unicode-text)
- 优雅地[拒绝无效输入](Error_Handling_Cheat_Sheet.md)，注意不要过多地透露 API 及其验证工作的信息。

#### 注入防护

处理旨在传递给另一个解释器（例如 SQL/NoSQL/ORM、操作系统、LDAP、XML）的输入时：

- 始终选择提供安全 API 的库/模块/包，如参数化语句。
    - 确保遵循文档，正确使用工具
    - 使用 ORM 和 ODM 是个好选择，但必须正确使用以避免 [ORM 注入](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)等缺陷。
- 如果没有这样的工具，始终根据目标解释器的最佳实践对输入数据进行转义/编码
    - 选择一个有良好文档且积极维护的转义/编码库。许多语言和框架都内置了这种功能。

更多信息请参见以下页面：

- [SQL 注入防护](SQL_Injection_Prevention_Cheat_Sheet.md)
- [NoSQL 注入防护](https://www.netsparker.com/blog/web-security/what-is-nosql-injection/)
- [LDAP 注入防护](LDAP_Injection_Prevention_Cheat_Sheet.md)
- [操作系统命令注入防护](OS_Command_Injection_Defense_Cheat_Sheet.md)
- [XML 安全](XML_Security_Cheat_Sheet.md)和 [XXE 注入防护](XML_External_Entity_Prevention_Cheat_Sheet.md)

#### 处理验证

使用用户输入时，即使已经清理和/或验证，也不应将其用于可能让用户控制数据流的某些目的。例如，不要向用户提供的主机发出 HTTP/资源请求（除非有绝对的业务需求）。

### DoS 防护

DoS 是针对 API 的可用性和稳定性的攻击，可能使其变慢、无响应或完全不可用。本备忘录详细介绍了在应用层和技术堆栈的其他层限制 DoS 攻击可能性的多种方法。还有一个专门讨论 [DoS](Denial_of_Service_Cheat_Sheet.md) 的备忘录。

以下是特定于 GraphQL 的建议，以限制 DoS 的潜在风险：

- 对传入查询添加深度限制
- 对传入查询添加数量限制
- 添加[分页](https://graphql.org/learn/pagination/)以限制单个响应中可返回的数据量
- 在应用层、基础设施层或两者添加合理的超时
- 考虑执行查询成本分析并对每个查询强制执行最大允许成本
- 对每个 IP 或用户（或两者）的传入请求强制执行速率限制，以防止基本的 DoS 攻击
- 在服务器端实施[批处理和缓存技术](https://graphql.org/learn/best-practices/#server-side-batching-caching)（可以使用 Facebook 的 [DataLoader](https://github.com/facebook/dataloader)）

#### 查询限制（深度和数量）

在 GraphQL 中，每个查询都有深度（例如嵌套对象），并且查询中的每个对象都可以指定数量（例如对象的 99999999 个）。默认情况下，这两者都可以是无限的，这可能导致 DoS。您应该设置深度和数量的限制以防止 DoS，但这通常需要一个小型自定义实现，因为 GraphQL 本身不原生支持。有关这些攻击以及如何添加深度和数量限制的更多信息，请参见[此处](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b)和[此处](https://www.howtographql.com/advanced/4-security/)。添加[分页](https://graphql.org/learn/pagination/)也可以帮助性能。

使用 graphql-java 的 API 可以利用内置的 [MaxQueryDepthInstrumentation](https://github.com/graphql-java/graphql-java/blob/master/src/main/java/graphql/analysis/MaxQueryDepthInstrumentation.java) 进行深度限制。使用 JavaScript 的 API 可以使用 [graphql-depth-limit](https://www.npmjs.com/package/graphql-depth-limit) 实现深度限制，使用 [graphql-input-number](https://github.com/joonhocho/graphql-input-number) 实现数量限制。

以下是深度为 N 的 GraphQL 查询示例：

```javascript
query evil {            # 深度：0
  album(id: 42) {       # 深度：1
    songs {             # 深度：2
      album {           # 深度：3
        ...             # 深度：...
        album {id: N}   # 深度：N
      }
    }
  }
}
```

以下是请求 99999999 个对象的 GraphQL 查询示例：

```javascript
query {
  author(id: "abc") {
    posts(first: 99999999) {
      title
    }
  }
}
```

#### 超时

添加超时可以是限制单个请求可以消耗的资源的简单方法。但是超时并不总是有效，因为它们可能直到恶意查询已经消耗过多资源后才会激活。超时要求将因 API 和数据获取机制而异；没有一个适用于所有情况的超时值。

在应用层，可以为查询和解析器函数添加超时。这个选项通常更有效，因为一旦达到超时，查询/解析就可以停止。GraphQL 本身不原生支持查询超时，因此需要自定义代码。有关将超时与 GraphQL 一起使用的更多信息，请参见[此博客文章](https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d)或下面的两个示例。

***JavaScript 超时示例***

来自[此 SO 答案](https://stackoverflow.com/a/53277955/1200388)的代码片段：

```javascript
request.incrementResolverCount =  function () {
    var runTime = Date.now() - startTime;
    if (runTime > 10000) {  // 10秒的超时
      if (request.logTimeoutError) {
        logger('ERROR', `Request ${request.uuid} query execution timeout`);
      }
      request.logTimeoutError = false;
      throw 'Query execution has timeout. Field resolution aborted';
    }
    this.resolverCount++;
  };
```

***使用[检测](https://www.graphql-java.com/documentation/instrumentation)的 Java 超时示例***

```java
public class TimeoutInstrumentation extends SimpleInstrumentation {
    @Override
    public DataFetcher<?> instrumentDataFetcher(
            DataFetcher<?> dataFetcher, InstrumentationFieldFetchParameters parameters
    ) {
        return environment ->
            Observable.fromCallable(() -> dataFetcher.get(environment))
                .subscribeOn(Schedulers.computation())
                .timeout(10, TimeUnit.SECONDS)  // 10秒超时
                .blockingFirst();
    }
}
```

***基础设施超时***

另一个通常更容易添加超时的选项是在 HTTP 服务器（[Apache/httpd](https://httpd.apache.org/docs/2.4/mod/core.html#timeout)、[nginx](http://nginx.org/en/docs/http/ngx_http_core_module.html#send_timeout)）、反向代理或负载均衡器上添加超时。然而，基础设施超时通常不准确，比应用层超时更容易绕过。

（之前的内容保持不变，在末尾添加以下内容）

#### 查询成本分析

查询成本分析涉及为传入查询中字段或类型的解析分配成本，以便服务器可以拒绝运行成本过高或将消耗过多资源的查询。这不容易实现，可能并不总是必要，但这是防止 DoS 最彻底的方法。有关实施此控制的更多详细信息，请参见[此博客文章](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries-16130a324a6b)中的"查询成本分析"部分。

Apollo 建议：

> **在花大量时间实施查询成本分析之前，请确定你确实需要它。** 尝试用恶意查询使你的测试 API 崩溃或变慢，看看能走多远 - 也许你的 API 没有这种嵌套关系，或者它可以完全正常地获取数千条记录，不需要查询成本分析！

使用 graphql-java 的 API 可以利用内置的 [MaxQueryComplexityInstrumentationto](https://github.com/graphql-java/graphql-java/blob/master/src/main/java/graphql/analysis/MaxQueryComplexityInstrumentation.java) 来强制执行最大查询复杂度。使用 JavaScript 的 API 可以利用 [graphql-cost-analysis](https://github.com/pa-bru/graphql-cost-analysis) 或 [graphql-validation-complexity](https://github.com/4Catalyzer/graphql-validation-complexity) 来强制执行最大查询成本。

#### 速率限制

在每个 IP 或用户（针对匿名和未授权访问）基础上强制执行速率限制，可以帮助限制单个用户向服务发送大量请求并影响性能的能力。理想情况下，这可以通过 WAF、API 网关或 Web 服务器（[Nginx](https://www.nginx.com/blog/rate-limiting-nginx/)、[Apache](https://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html)/[HTTPD](https://github.com/jzdziarski/mod_evasive)）来减少添加速率限制的工作量。

或者，您可以通过节流使其变得相对复杂并在代码中实现（非平凡）。有关 GraphQL 特定速率限制的更多信息，请参见[此处](https://www.howtographql.com/advanced/4-security/)的"节流"部分。

#### 服务器端批处理和缓存

为了提高 GraphQL API 的效率并减少其资源消耗，可以使用[批处理和缓存技术](https://graphql.org/learn/best-practices/#server-side-batching-caching)来防止在短时间内对数据片段重复发出请求。Facebook 的 [DataLoader](https://github.com/facebook/dataloader) 工具是实现这一点的一种方式。

#### 系统资源管理

不正确地限制 API 可以使用的资源数量（例如 CPU 或内存）可能会损害 API 的响应性和可用性，使其容易受到 DoS 攻击。某些限制可以在操作系统级别完成。

在 Linux 上，可以使用[控制组（cgroups）](https://en.wikipedia.org/wiki/Cgroups)、[用户限制（ulimits）](https://linuxhint.com/linux_ulimit_command/)和 [Linux 容器（LXC）](https://linuxcontainers.org/lxc/security/)的组合。

然而，容器化平台往往使这项任务变得更加容易。有关在使用容器时防止 DoS 的方法，请参见 [Docker 安全备忘录](Docker_Security_Cheat_Sheet.md#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts)中的资源限制部分。

### 访问控制

为确保 GraphQL API 具有适当的访问控制，请执行以下操作：

- 始终验证请求者是否有权查看或修改/变更他们正在请求的数据。这可以通过[基于角色的访问控制（RBAC）](Access_Control_Cheat_Sheet.md#role-based-access-control-rbac)或其他访问控制机制来完成。
    - 这将防止[不安全的直接对象引用（IDOR）](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)问题，包括[批量对象级别授权（BOLA）](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md)和[批量功能级别授权（BFLA）](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa5-broken-function-level-authorization.md)。
- 在边缘和节点上强制执行授权检查（参见[漏洞报告](https://hackerone.com/reports/489146)，其中节点没有授权检查，但边缘有）。
- 使用[接口](https://graphql.org/learn/schema/#interfaces)和[联合类型](https://graphql.org/learn/schema/#union-types)创建结构化的分层数据类型，可根据请求者权限返回更多或更少的对象属性。
- 查询和变更[解析器](https://graphql.org/learn/execution/#root-fields-resolvers)可用于执行访问控制验证，可能使用某些 RBAC 中间件。
- 在任何生产或公开可访问的环境中[禁用内省查询](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/)。
- 在生产或公开可访问的环境中禁用 [GraphiQL](https://github.com/graphql/graphiql) 和其他类似的架构探索工具。

#### 常规数据访问

GraphQL 请求通常包括一个或多个对象的直接 ID，以获取或修改它们。例如，请求特定图片可能包括该图片在数据库中的主键 ID。与任何请求一样，服务器必须验证调用者是否有权访问他们正在请求的对象。但有时开发人员会犯错，认为拥有对象的 ID 意味着调用者应该有权访问。未能验证请求者的访问权限称为[对象级别身份验证损坏](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa1-broken-object-level-authorization.md)，也称为[不安全的直接对象引用（IDOR）](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)。

GraphQL API 可能支持使用对象 ID 访问对象，即使这不是本意。有时查询对象中有 `node` 或 `nodes` 或两者，可以直接通过 `ID` 访问对象。您可以通过在命令行上运行以下命令来检查架构是否有这些字段（假设 `schema.json` 包含您的 GraphQL 架构）：`cat schema.json | jq ".data.__schema.types[] | select(.name==\"Query\") | .fields[] | .name" | grep node`。从架构中删除这些字段应该会禁用该功能，但您应始终应用适当的授权检查以验证调用者有权访问他们正在请求的对象。

#### 查询访问（数据获取）

作为 GraphQL API 的一部分，将有各种可返回的数据字段。需要考虑的一件事是是否希望围绕这些字段有不同的访问级别。例如，您可能只希望某些使用者能够获取某些数据字段，而不是允许所有使用者检索所有可用字段。这可以通过在代码中添加检查来确保请求者应该能够读取他们正在尝试获取的字段。

#### 变更访问（数据操作）

除了最常见的数据获取用例外，GraphQL 还支持变更，即数据操作。如果 API 实现/允许变更，则可能需要设置访问控制以限制哪些使用者（如果有）可以通过 API 修改数据。需要变更访问控制的设置包括仅打算对请求者进行读取访问的 API，或者只有某些方可以修改某些字段的 API。

### 批处理攻击

GraphQL 支持批处理请求，也称为[查询批处理](https://www.apollographql.com/blog/query-batching-in-apollo-63acfd859862/)。这允许调用者在单个网络调用中批处理多个查询或批处理多个对象实例的请求，这就是所谓的[批处理攻击](https://lab.wallarm.com/graphql-batching-attack/)。这是一种特定于 GraphQL 的暴力破解攻击，通常允许更快、不易被检测的漏洞利用。以下是最常见的查询批处理方式：

```javascript
[
  {
    query: < query 0 >,
    variables: < query 0 的变量 >,
  },
  {
    query: < query 1 >,
    variables: < query 1 的变量 >,
  },
  {
    query: < query n >
    variables: < query n 的变量 >,
  }
]
```

以下是请求多个不同 `droid` 对象实例的单个批处理 GraphQL 调用的示例查询：

```javascript
query {
  droid(id: "2000") {
    name
  }
  second:droid(id: "2001") {
    name
  }
  third:droid(id: "2002") {
    name
  }
}
```

在这种情况下，它可以用于在很少的网络请求中枚举服务器上存储的每个可能的 `droid` 对象，而不是在标准 REST API 中，请求者需要为每个不同的 `droid` ID 提交不同的网络请求。这种攻击可能导致以下问题：

- 应用程序级 DoS 攻击 - 单个网络调用中的大量查询或对象请求可能导致数据库挂起或耗尽其他可用资源（例如内存、CPU、下游服务）。
- 枚举服务器上的对象，如用户、电子邮件和用户 ID。
- 暴力破解密码、双因素身份验证码（OTP）、会话令牌或其他敏感值。
- WAF、RASP、IDS/IPS、SIEM 或其他安全工具可能无法检测到这些攻击，因为它们看起来只是一个单一请求，而不是大量网络流量。
- 此攻击可能绕过 Nginx 或其他代理/网关中现有的速率限制，因为它们依赖于查看原始请求数量。

#### 缓解批处理攻击

为了缓解这种类型的攻击，您应该在代码级别对传入请求设置限制，以便可以按请求应用。有 3 个主要选项：

- 在代码中添加对象请求速率限制
- 防止敏感对象的批处理
- 限制可同时运行的查询数量

一种选择是在代码级别对调用者可以请求的对象数量设置速率限制。这意味着后端将跟踪调用者已请求的不同对象实例数量，以便即使他们在单个网络调用中批处理对象请求，也会在请求过多对象后被阻止。这复制了 WAF 或其他工具将执行的网络级速率限制。

另一种选择是防止对敏感对象（如用户名、电子邮件、密码、OTP、会话令牌等）进行批处理。这迫使攻击者像使用 REST API 一样攻击 API，并为每个对象实例发出不同的网络调用。这不是原生支持的，因此需要自定义解决方案。但是，一旦建立了这种控制，其他标准控制将正常运行，以帮助防止任何暴力破解。

限制可以批处理和同时运行的操作数量是缓解导致 DoS 的 GraphQL 批处理攻击的另一种选择。但这并非万能药，应与其他方法一起使用。

### 安全配置

默认情况下，大多数 GraphQL 实现都有一些不安全的默认配置，应该更改：

- 不要返回过多的错误消息（例如禁用堆栈跟踪和调试模式）。
- 根据需要禁用或限制内省和 GraphiQL。
- 如果禁用内省，则建议禁用错误类型字段的建议。

#### 内省 + GraphiQL

GraphQL 通常默认启用内省和/或 GraphiQL，并且不需要身份验证。这允许 API 的使用者了解有关 API、架构、变更、已弃用字段甚至有时是不需要的"私有字段"的所有信息。

如果 API 设计为供外部客户端使用，这可能是预期的配置，但如果 API 仅设计为内部使用，则可能是一个问题。尽管不建议使用安全性隐藏，但考虑删除内省以避免任何泄漏可能是个好主意。如果您的 API 是公开使用的，您可能希望考虑对未经身份验证或未授权的用户禁用内省。

对于内部 API，最简单的方法是完全禁用内省。请参见[此页面](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/)或查阅您的 GraphQL 实现文档，了解如何完全禁用内省。如果您的实现不原生支持禁用内省，或者您希望允许某些使用者/角色访问，可以在服务中构建一个过滤器，仅允许批准的使用者访问内省系统。

请记住，即使禁用了内省，攻击者仍可通过暴力破解猜测字段。此外，GraphQL 有一个内置功能，当请求者提供的字段名称与现有字段相似（但不正确）时返回提示（例如，请求有 `usr`，响应将询问"您是指'user'吗？"）。如果已禁用内省，您应考虑禁用此功能以减少暴露，但并非所有 GraphQL 实现都支持这样做。[Shapeshifter](https://github.com/szski/shapeshifter) 是一个[应该能够做到这一点](https://www.youtube.com/watch?v=NPDp7GHmMa0&t=2580)的工具。

***禁用内省 - Java***

```Java
GraphQLSchema schema = GraphQLSchema.newSchema()
    .query(StarWarsSchema.queryType)
    .fieldVisibility( NoIntrospectionGraphqlFieldVisibility.NO_INTROSPECTION_FIELD_VISIBILITY )
    .build();
```

***禁用内省和 GraphiQL - JavaScript***

```javascript
app.use('/graphql', graphqlHTTP({
  schema: MySessionAwareGraphQLSchema,
+ validationRules: [NoIntrospection]
  graphiql: process.env.NODE_ENV === 'development',
}));
```

#### 不要返回过多错误

生产环境中的 GraphQL API 不应返回堆栈跟踪或处于调试模式。这是特定于实现的，但使用中间件是一种流行的方式，可以更好地控制服务器返回的错误。要[禁用过多错误](https://www.apollographql.com/docs/apollo-server/data/errors/)，可以在 Apollo Server 构造函数中传递 `debug: false`，或将 `NODE_ENV` 环境变量设置为 'production' 或 'test'。但是，如果您希望在内部记录堆栈跟踪而不将其返回给用户，请参见[此处](https://www.apollographql.com/docs/apollo-server/data/errors/#masking-and-logging-errors)了解如何屏蔽和记录错误，使其对开发人员可用但对 API 调用者不可用。

## 其他资源

### 工具

- [InQL 扫描器](https://github.com/doyensec/inql) - GraphQL 安全扫描器。特别适合从给定架构自动生成查询和变更，然后将它们馈送到扫描器。
- [GraphiQL](https://github.com/graphql/graphiql) - 架构/对象探索
- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) - 架构/对象探索

### GraphQL 安全最佳实践 + 文档

- [保护 GraphQL API 免受安全威胁 - 博客文章](https://medium.com/swlh/protecting-your-graphql-api-from-security-vulnerabilities-e8afdfa6fbe4)
- [实施 GraphQL 之前需要考虑的安全点](https://nordicapis.com/security-points-to-consider-before-implementing-graphql/)
- [限制资源使用以防止 DoS（超时、限流、复杂度管理、深度限制等）](https://developer.github.com/v4/guides/resource-limitations/)
- [GraphQL 安全视角](https://www.abhaybhargav.com/from-the-trenches-diy-security-perspectives-of-graphql/)
- [开发者的 GraphQL 安全视角](https://planes.studio/blog/how-to-survive-a-penetration-test-as-a-graph-ql-developer)

### 更多关于 GraphQL 攻击

- [一些常见的 GraphQL 攻击 + 攻击者思维](https://blog.doyensec.com/2018/05/17/graphql-security-overview.html)
- [通过走私参数绕过权限](https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [关于 GraphQL 的漏洞赏金写作](https://medium.com/bugbountywriteup/graphql-voyager-as-a-tool-for-security-testing-86d3c634bcd9)
- [关于滥用 GraphQL 的安全讲座](https://www.youtube.com/watch?v=NPDp7GHmMa0)
- [过去针对 GraphQL 的真实攻击案例](https://vulners.com/myhack58/MYHACK58:62201994269)
  - [WordPress GraphQL 攻击](https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/)
  - [HackerOne 报告](https://hackerone.com/reports/419883)
  - [其他漏洞](https://vulners.com/hackerone/H1:435066)
  - [New Relic 内部 API 滥用导致 IDOR](https://www.jonbottarini.com/2018/01/02/abusing-internal-api-to-achieve-idor-in-new-relic/)
  - [GitLab GraphQL 授权问题](https://about.gitlab.com/blog/2019/07/03/security-release-gitlab-12-dot-0-dot-3-released/#authorization-issues-in-graphql)
- [针对 GraphQL 端点的攻击示例](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
