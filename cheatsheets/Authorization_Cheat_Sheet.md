# 授权备忘录

## 引言

授权可定义为“验证请求的操作或服务是否已获特定实体的批准的过程”（[NIST](https://csrc.nist.gov/glossary/term/authorization)）。授权与身份验证不同，后者是验证实体身份的过程。在设计和开发软件解决方案时，应牢记这些区别。一个通过用户名和密码进行了身份验证的用户，通常并不被授权访问系统中所有资源或执行所有可能的技术操作。例如，一个 web 应用可以同时拥有普通用户和管理员，管理员能够执行普通用户无权执行的操作，尽管他们已经完成了身份验证。此外，并非所有访问资源都需要进行身份验证；未经过身份验证的用户也可能会被授权访问某些公共资源，如一张图片或登录页面，甚至整个 web 应用。

本备忘录旨在帮助开发者实现稳健、符合应用业务背景、易于维护和扩展的授权逻辑。本指南中的建议应适用于开发生命周期的所有阶段，并且足够灵活以满足不同开发环境的需求。

与授权相关的缺陷是 web 应用的一大关注点。[OWASP 2021 年度十大风险](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)中，损坏的访问控制被列为最令人担忧的安全漏洞，并且据 [MITRE 的 CWE 程序](https://cwe.mitre.org/data/definitions/285.html)称，其利用可能性较高。此外，根据 [Veracode 《软件状态报告》第 10 卷](https://www.veracode.com/sites/default/files/pdf/resources/sossreports/state-of-software-security-volume-10-veracode-report.pdf)，尽管访问控制是 OWASP 的十大风险中被滥用最多的漏洞之一，但其在实际攻击中的发生频率却相对较低。

授权缺陷的潜在影响因形式和严重程度而异。攻击者可能能够读取、创建、修改或删除本应受保护的资源（从而危及它们的机密性、完整性和可用性）；然而，此类操作的实际影响必然与其被泄露资源的关键性和敏感度有关。因此，成功利用授权缺陷的企业成本可以从很低到非常高不等。

无论是完全未经过身份验证的外部用户还是已经过身份验证但未必被授权的用户都可以利用授权缺陷。虽然善意的错误或非恶意实体的粗心大意可能会导致授权绕过，但恶意意图通常需要才能实现访问控制威胁的最大化。水平权限提升（即能够访问其他用户的资源）是认证用户特别容易利用的一种常见弱点。与授权控制相关的故障可以允许恶意内鬼和外部人员查看、修改或删除各种形式的敏感资源（如数据库记录、静态文件、个人可识别信息 (PII) 等），或执行他们不应被赋予的操作，例如创建新账户或发起昂贵订单。

如果访问控制相关的日志未正确设置，则此类授权违规可能不会被检测到，或者至少无法明确归因于特定个体或群体。

## 推荐

### 实施最小权限原则

作为安全概念，“最小权限”指的是只授予用户完成其工作所需的最低权限。虽然这一原则通常应用于系统管理，但它对软件开发者也有相关性。最小权限必须在水平和垂直方向上都得到实施。例如，尽管会计人员和销售代表可能处于组织层次结构的同一层级，但他们需要访问不同的资源来完成各自的工作。会计人员不应被授予客户数据库的访问权，而销售代表也不应能访问薪酬数据。同样，销售部门负责人需要比其下属更多的权限。

如果未在应用程序中实施最小权限原则，则可能会危及敏感资源的机密性。主要的缓解策略应在架构和设计阶段应用（见 [CWE-272](https://cwe.mitre.org/data/definitions/272.html)）；然而，这一原则必须贯穿整个软件开发生命周期 (SDLC)。

考虑以下几点和最佳实践：

- 在设计阶段确保定义信任边界。列举将访问系统的用户类型、暴露的资源以及可能对这些资源执行的操作（如读取、写入、更新等）。为每种用户类型与资源组合确定用户（基于角色和其他属性）必须能够对该资源执行哪些操作。对于 ABAC 系统，应确保所有类别属性都被考虑在内。例如，销售代表可能需要在工作时间从公司内部网络访问客户数据库，但在深夜在家则不应如此。
- 创建验证设计阶段中分配的权限是否正确实施的测试。
- 在应用部署后定期审查系统中的权限以防止“权限蔓延”；确保当前环境中的用户权限不超过设计阶段定义的权限（加上任何正式批准的变化）。
- 请记住，向用户授予额外权限比撤销他们已享受的权限要容易得多。在 SDLC 的早期阶段仔细规划并实施最小权限原则有助于减少需要撤回过于宽泛权限的风险。

### 默认拒绝访问

即使没有明确匹配访问控制规则，当实体请求访问特定资源时，应用程序也不能保持中立状态。应用程序必须总是做出决策（隐式或显式的），要么拒绝访问，要么允许访问。与访问控制相关的逻辑错误或其他错误可能会发生，特别是在复杂的访问要求下；因此不应完全依赖于明确定义的规则来匹配所有可能的请求。出于安全考虑，应用应被配置为默认拒绝访问。

考虑以下几点和最佳实践：

- 在初始开发阶段及每次新功能或资源暴露给应用时都采用“默认拒绝”心态。应该能够明确说明为什么特定权限被授予某个用户或组，而不能假设默认是允许的。
- 尽管某些框架或库本身可能采用了默认拒绝策略，但应优先选择显式配置而不是依赖于框架或库的默认设置。第三方代码的逻辑和默认值可能会随着时间推移发生变化，而开发者对此无从得知。

### 验证每次请求的权限

权限应在每次请求中正确验证，无论该请求是由 AJAX 脚本、服务器端还是其他来源发起的。执行此类检查的技术应允许全局、应用范围内的配置，而不是需要单独应用于每个方法或类。记住攻击者只需找到一种方式即可进入。即使只是单次访问控制检查被“忽视”，资源的机密性和/或完整性也可能受到威胁。仅在多数请求上正确验证权限是不够的。以下技术有助于开发者进行一致的权限验证：

- [Java/Jakarta EE 过滤器](https://jakarta.ee/specifications/platform/8/apidocs/javax/servlet/Filter.html) 包括 [Spring Security](https://docs.spring.io/spring-security/site/docs/5.4.0/reference/html5/#servlet-security-filters) 的实现
- [Django 框架中的中间件](https://docs.djangoproject.com/en/4.0/ref/middleware/)
- [.NET Core 过滤器](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/filters?view=aspnetcore-3.1#authorization-filters)
- [Laravel PHP 框架中的中间件](https://laravel.com/docs/8.x/middleware)

### 根据所选工具和技术彻底审查授权逻辑，必要时实现自定义逻辑

今天，开发者可以利用大量的库、平台和框架来在应用中轻松地集成复杂的、健壮的逻辑。然而，这些框架和库不应被视为解决所有开发问题的快速万能药；开发者有责任负责任且明智地使用它们。

关于框架/库选择对适当访问控制的相关一般关注点包括开发者配置不当或缺乏配置（见 [A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration) 和 [A9](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html) 以获取这些主题的一般指导）。

即使在安全开发的应用程序中，第三方组件中的漏洞也可能允许攻击者绕过正常的授权控制。这种关注点不应仅限于未经验证或维护不佳的项目，而可能影响最强大和最受欢迎的库和框架。编写复杂、安全软件是困难的。即使是经验丰富的开发者，在高质量的库和框架上也会犯错。假设你整合到应用中的任何第三方组件 *可能会* 或者将来会成为授权漏洞的主题。

重要考虑因素包括：

- 创建、维护并遵循检测和响应漏洞的过程。
- 将 [Dependency Check](https://owasp.org/www-project-dependency-check/) 等工具纳入 SDLC，并考虑订阅来自供应商的数据流，如 NVD（[NVD](https://nvd.nist.gov/vuln/data-feeds)）或其他相关来源。
- 实施纵深防御。不要依赖任何单一的框架、库、技术或控制来作为唯一执行适当访问控制的方法。

配置不当（或完全缺乏配置）是组件开发者可以导致授权缺陷的另一个主要领域。这些组件通常旨在具有广泛的用途，以吸引广泛的受众群体。对于大多数非简单的用例来说，这些框架和库必须通过额外的逻辑进行定制或补充，以满足特定应用或环境的独特要求。当涉及安全要求时，包括授权要求，这一点尤为重要。

重要考虑因素包括：

- 投入时间充分理解你所构建授权逻辑的基础技术。分析该技术的能力，了解 *提供的组件授权逻辑可能无法满足应用程序的具体安全需求*。依赖预构建的逻辑虽然方便，但这并不意味着足够。理解自定义授权逻辑可能是必要的以满足应用的安全要求。
- 不要让任何库、平台或框架的功能引导你的授权要求。相反，应先确定授权要求，然后根据这些要求分析第三方组件。
- 不要依赖默认配置。
- 测试配置。不要仅仅假设任何对第三方组件执行的配置将在特定环境中按预期工作。文档可能会被误解、模糊不清、过时或不准确。

### 优先考虑基于属性和关系的访问控制而非 RBAC

在软件工程中，两种基本形式的访问控制广泛使用：基于角色的访问控制（RBAC）和基于属性的访问控制（ABAC）。还有一种较新的模型逐渐流行起来：基于关系的访问控制（ReBAC）。授权模型的选择具有重要的影响，并应在尽可能早的时候做出决定。

- RBAC 是一种访问控制模型，其中权限是根据分配给用户的角色进行授予或拒绝的。权限不是直接分配给实体；相反，权限与角色相关联，用户继承了其被赋予的角色的权限。通常，角色和用户之间的关系可以是一对多或多对一的关系，并且角色可能是层次化的。

- ABAC 可以定义为一种访问控制模型，在这种模型中，“主体请求执行对象上的操作是基于分配给主体的属性、分配给对象的属性、环境条件以及用这些属性和条件表示的一组策略”（[NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf) 第7页）。根据 NIST SP 800-162 的定义，属性可以表示为名称值对，并被分配给主体、对象或环境。职位角色、工作时间、项目名称、MAC 地址和创建日期只是 ABAC 实现中可能的属性的一小部分示例。

- ReBAC 是一种基于资源间关系进行授权访问的模型。例如，仅允许发布者编辑其发布的帖子。这在社交媒体应用（如 Twitter 或 Facebook）中尤为重要，用户希望限制对其数据（推文或帖子）的访问权限给他们选择的人（朋友、家人、关注者）。

尽管 RBAC 有着悠久的历史并且仍然是今天软件开发者中最受欢迎的选择之一，但 ABAC 和 ReBAC 应当通常优先用于应用程序开发。它们相对于 RBAC 的优势包括：

- **支持细粒度复杂的布尔逻辑**。在 RBAC 中，访问决策基于角色的存在或不存在；即，请求实体的主要特征是其被分配的角色。这种简单的逻辑对于支持对象级别或水平的访问控制决策和需要多个因素的情况表现不佳。

    - ABAC 显著扩展了可以考虑的属性数量和类型。在 ABAC 中，“角色”或职位功能当然可以是一个分配给主体的属性，但不一定单独考虑（或者根本不考虑如果这种特征与所请求的访问无关）。此外，ABAC 可以结合环境和其他动态属性，例如工作时间、使用的设备类型以及地理位置。在正常业务小时之外拒绝对敏感资源的访问或用户未完成必要的强制性培训也是 ABAC 能满足而 RBAC 难以实现的访问控制要求的例子。因此，与 RBAC 相比，ABAC 更有效地支持最小权限原则。
    - ReBAC 由于它支持直接对象和直接用户的关联关系（而不是仅角色），允许细粒度的权限。一些系统还支持使用算术运算符如 AND 和 NOT 来表达策略，例如“如果用户与对象的关系 X 但不具有关系 Y，则授予访问权”。

- **稳健性**。在大型项目或存在多个角色的情况下，容易遗漏或错误地执行角色检查（见 [OWASP C7: 强制访问控制](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)）。这可能导致权限过多和不足。特别是在没有角色层次结构的 RBAC 实现中，当需要多个角色检查时，这种问题会变得更加突出（即 `if(user.hasAnyRole("SUPERUSER", "ADMIN", "ACCT_MANAGER")`）。
- **速度**。在 RBAC 中，“角色膨胀”可能发生在系统定义了太多角色的情况下。如果用户通过 HTTP 头发送凭证和角色，而这些头有大小限制，则可能没有足够的空间包含所有用户的角色。一个可行的解决方案是仅发送用户 ID，并让应用程序检索用户的角色，但这会增加每个请求的延迟。
- **支持多租户和跨组织请求**。RBAC 不适合用于不同组织或客户需要访问同一组受保护资源的情况。使用 RBAC 满足此类要求可能需要繁琐的方法，如在多租户环境中为每个客户配置规则集或强制预配置身份以处理跨组织请求（见 [OWASP C7](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)；[NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf))。相比之下，只要属性定义一致，ABAC 实现允许在相同的或不同的基础设施上执行和管理访问控制决策，并保持适当的安全级别（见 [NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf) 第6页）。
- **易于管理**。尽管 RBAC 的初始设置通常比 ABAC 简单，但随着系统规模和复杂性的增长，这种短期优势很快就会消失。在开始时，几个简单的角色（如用户和管理员）可能足以满足某些应用的需求，但这很难长期维持在生产应用中。随着角色数量的增加，测试和审计变得越来越困难，这是建立对代码库和逻辑的信任的关键过程（见 [OWASP C7](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)）。相比之下，ABAC 和 ReBAC 更加表达能力强、包含属性和布尔逻辑更好地反映了现实世界的问题，并且当访问控制需求发生变化时更容易更新。它们还鼓励将策略管理与执行以及身份的分配分离（见 [NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf)；请参阅 [XACML-V3.0](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) 以了解这些优势）。

### 确保查找 ID 不可被猜出或篡改

应用程序通常会暴露用于定位和引用对象的内部对象标识符（如银行账户号码或数据库中的主键）。这个 ID 可能作为查询参数、路径变量、“隐藏”的表单字段或其他地方公开。例如：

```https://mybank.com/accountTransactions?acct_id=901```

基于此 URL，可以合理地假设应用程序将返回交易列表，并且返回的交易将仅限于特定账户——在 `acct_id` 参数中指示的账户。但如果用户将 `acct_id` 参数更改为其值为 `523` 的另一个值会发生什么？用户是否能够查看与另一账户相关的交易，即使该账户不属于他？如果不能，失败只是因为没有找到帐户“523”还是由于访问控制检查失败？尽管这个例子可能过于简化了，但它说明了一个常见的应用程序开发中的安全漏洞——[CWE 639: 通过用户可控键的授权绕过](https://cwe.mitre.org/data/definitions/639.html)。当被利用时，这种弱点可能导致授权绕过、水平权限提升和不太常见的垂直权限提升（见 [CWE-639](https://cwe.mitre.org/data/definitions/639.html))）。这种类型的漏洞还代表了一种直接对象引用 (IDOR) 的形式。以下段落将描述该弱点及其可能的缓解措施。

在上述示例中，查找 ID 不仅暴露给了用户且易于被篡改，而且似乎是一个相当可预测、也许按顺序排列的值。虽然可以使用各种技术来掩盖或随机化这些 ID 并使其难以猜测，但这通常不足以单独依靠它。用户不应仅仅因为能够猜测和操控对象标识符（在查询参数或其他地方）就能访问他们没有权限的资源。而应该关注控制对底层对象及其标识符本身的访问。推荐的缓解措施包括：

- 尽可能避免向用户提供标识符。例如，根据安全实现的 JSON Web Token (JWT) 或服务器端会话中的信息，某些对象（如账户详细信息）可以通过当前认证用户的身份和属性来检索。
- 使用工具如 [OWASP ESAPI](https://owasp.org/www-project-enterprise-security-api/) 实现用户/会话特定的间接引用（见 [OWASP 2013 Top 10 - A4 直接对象引用不安全](https://wiki.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References))。
- 在每次访问具体对象或功能时对 *每个* 请求进行访问控制检查。仅仅因为用户有权访问某种类型的对象并不意味着他们应该有权访问该类型的所有对象。

### 对静态资源执行授权检查

静态资源的安全性通常被忽视或至少被其他安全问题所掩盖。尽管保护数据库和类似的数据存储通常会受到重视，但静态资源也必须适当保护。尽管未受保护的静态资源对于各种形式的网站和应用程序确实是一个问题，但在近年来，云存储服务（如 Amazon S3 桶）中的未受保护的资源已引起关注。在对静态资源进行安全保护时，请考虑以下几点：

- 确保将静态资源纳入访问控制策略中。静态资源所需的保护类型将不可避免地高度依赖于上下文。某些静态资源可能完全公开是合适的，而其他资源则需要一组严格的用户和环境属性才能访问。因此理解特定资源下暴露的数据类型至关重要。考虑是否应建立并整合到应用程序的访问控制逻辑中的正式数据分类方案（参见 [这里](https://resources.infosecinstitute.com/information-and-asset-classification/) 了解数据分类概述）。
- 确保任何用于存储静态资源的云服务都使用供应商提供的配置选项和工具进行保护。查阅云提供商文档（请参考来自 [AWS](https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/)、[Google Cloud](https://cloud.google.com/storage/docs/best-practices#security) 和 [Azure](https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations) 的具体实施细节）。
- 尽可能使用与保护其他应用程序资源和功能相同的访问控制逻辑和机制。

### 确保授权检查在正确的位置执行

开发人员绝不能依赖客户端的访问控制检查。虽然此类检查可以用来改善用户体验，但它们不应是决定是否授予或拒绝资源访问的关键因素；客户端逻辑通常很容易绕过。授权检查必须在服务器端、网关处或使用无服务器函数进行。

### 在授权检查失败时安全退出

授权检查失败在安全的应用程序中是一个正常现象；因此开发人员必须为此规划并安全地处理这些失败。不适当的失败处理可能导致应用程序处于不可预测的状态（见 [CWE-280: 处理不足的权限或特权](https://cwe.mitre.org/data/definitions/280.html)）。具体建议包括：

- 确保所有异常和授权检查失败都得到妥善处理，无论它们看似多么不可能发生（见 [OWASP Top Ten Proactive Controls C10: 处理错误和异常](https://owasp.org/www-project-proactive-controls/v3/en/c10-errors-exceptions.html)）。这并不意味着应用程序应该总是尝试“纠正”失败的检查；通常一个简单的消息或 HTTP 状态码就足够了。
- 集中处理授权检查失败的逻辑。
- 检查异常和授权失败的处理。确保无论多么不可能，这些失败都不会使软件处于不稳定状态，从而导致授权绕过。
- 确保敏感信息（如系统日志或调试输出）不暴露在错误消息中。配置不当的错误消息可以增加应用程序的攻击面。（见 [CWE-209: 生成包含敏感信息的错误消息](https://cwe.mitre.org/data/definitions/209.html)）

### 实施适当的日志记录

日志是应用程序安全中最重要的侦探控制之一；不充分的日志和监控被认定为在 [OWASP 2021 年度十大风险](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) 中最严重的安全风险。适当的日志不仅可以检测恶意活动，而且还是事件后调查的重要资源，可用于解决访问控制和其他安全相关问题，并在安全审计中发挥作用。尽管在初始设计和需求阶段容易被忽视，但日志是整体应用程序安全的重要组成部分，并且必须融入 SDLC 的所有阶段。建议包括：

- 使用一致、定义明确的日志格式进行记录，以便于分析（见 [OWASP Top Ten Proactive Controls C9](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html) 中的 Apache Logging Services 项目支持多个语言和平台）。
- 精确确定要记录的信息量。这应根据特定的应用程序环境和需求来确定。记录过多或过少都可能被视为安全弱点（参见 [CWE-778](https://cwe.mitre.org/data/definitions/778.html) 和 [CWE-779](https://cwe.mitre.org/data/definitions/779.html))。记录不足可能导致恶意活动未被检测到，大大降低事件后分析的有效性。记录过多不仅会增加资源负担并导致过高的假阳性率，还可能导致敏感数据无谓地被记录。
- 确保系统之间时钟和时区同步。在攻击期间及之后的响应过程中，准确性对于拼凑出攻击序列至关重要。
- 考虑将应用程序日志集成到中央日志服务器或 SIEM 中。

### 为授权逻辑创建单元和集成测试用例

单元测试和集成测试是验证应用是否按预期工作并保持一致性的关键。访问控制逻辑中的缺陷可能是微妙的，特别是当需求复杂时；但是即使是访问控制逻辑中简单的逻辑或配置错误也可能导致严重后果。虽然不是替代专门的安全测试或渗透测试（参见 [OWASP WSTG 4.5](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/README) 关于此主题的优秀指南），但对访问控制逻辑进行自动化单元和集成测试可以帮助减少进入生产的安全缺陷数量。这些测试擅长检测“低垂的果实”安全问题，但不是更复杂的攻击向量（参见 [OWASP SAMM: 安全测试](https://owaspsamm.org/model/verification/security-testing/)）。

单元测试和集成测试应旨在包含此文档中探索的概念。例如，是否默认拒绝访问？当授权检查失败时应用是否会安全退出，即使在异常条件下也是如此？ABAC 策略是否被正确执行？

## 参考资料

### ABAC

- [使用 Spring Security 实现基于属性的访问控制](https://dzone.com/articles/simple-attribute-based-access-control-with-spring)

- [什么是 ABAC？实现模式和示例](https://www.osohq.com/learn/what-is-attribute-based-access-control-abac)

- [NIST 特别出版物 800-162 关于属性基于访问控制 (ABAC) 定义与考虑事项指南](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf)
  
- [NIST SP 800-178 A 比较 ABAC 标准在数据服务应用程序中的应用](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-178.pdf)
  
- [NIST SP 800-205 访问控制系统的属性考虑事项](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-205.pdf)

- [XACML-V3.0](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) 以标准的形式突显了这些优势。

### 通用

- [OWASP 应用安全验证标准 4.0（特别是 V4: 访问控制验证要求）](https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.pdf)

- [OWASP 网站安全测试指南 - 4.5 访问控制测试](https://owasp.org/www-project-web-security-testing-guide/v42)

### 最小权限

- [最小权限原则](https://us-cert.cisa.gov/bsi/articles/knowledge/principles/least-privilege)

### RBAC

- [基于角色的访问控制](https://csrc.nist.gov/CSRC/media/Publications/conference-paper/1992/10/13/role-based-access-controls/documents/ferraiolo-kuhn-92.pdf)

### ReBAC

- [基于关系的访问控制 (ReBAC)](https://www.osohq.com/academy/relationship-based-access-control-rebac)
- [Google Zanzibar](https://zanzibar.academy/)
