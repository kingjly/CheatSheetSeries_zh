# 滥用案例备忘录

## 引言

当提及应用程序的安全级别时，常常会遇到以下表述：

- _应用程序必须是安全的_。
- _应用程序必须防御针对该类应用程序的所有攻击_。
- _应用程序必须防御 OWASP TOP 10 中的攻击_。
- ...

这些安全需求过于笼统，对开发团队来说毫无实际意义...

从实用的角度来看，为了构建一个安全的应用程序，重要的是根据其业务和技术背景识别出必须防御的攻击。滥用案例是一种常被推荐的_威胁建模_工具，建议查看[威胁建模](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)备忘录以获取更多信息。

### 目标

本备忘录的目标是：
1. 解释什么是**滥用案例**
2. 说明滥用案例在考虑应用程序安全性时的重要性
3. 提供一种构建和跟踪每个计划实施功能的滥用案例列表的实用方法

无论项目方法论是瀑布模型还是敏捷开发，均可使用本备忘录。

**关于本备忘录的重要说明：**

```text
主要目标是提供一种实用方法，使公司或项目团队能够开始构建和处理滥用案例列表，
并根据自身背景/文化定制所提供的元素，最终建立自己的方法。

本备忘录可视为入门教程。
```

### 背景与方法

#### 为什么要明确识别攻击

明确识别应用程序必须防御的攻击对于项目或冲刺阶段的以下步骤至关重要：

- 评估每个已识别攻击的业务风险，以便根据业务风险和项目/冲刺预算进行选择。
- 推导安全需求，并将其添加到项目规范或冲刺的用户故事和验收标准中。
- 估算初始项目/冲刺工作量中实施对策所需的额外开销。
- 关于对策：使项目团队能够定义对策，并确定应在何处（网络、基础设施、代码等）部署。

#### 滥用案例的概念

您可以从两个角度思考**滥用案例**。第一个是发现攻击（回答"可能出现什么问题"），第二个是帮助记录这些攻击（非正式地，包括威胁、问题、风险）并以对开发人员不太具有威胁性的形式记录。

**滥用案例**可以定义为：

```text
一种超出实施者预期的功能使用方式，
使攻击者能够基于其行为（或输入）影响功能或使用结果。
```

Synopsis 这样定义**滥用案例**：

```text
误用和滥用案例描述了用户如何滥用或利用软件功能控制中的弱点来攻击应用程序。

当直接攻击可带来收入或提供正面用户体验的业务功能时，
可能会带来实际的业务影响。

滥用案例也是推动安全需求的有效方式，
从而为这些关键业务用例提供适当保护。
```

[Synopsis 来源](https://www.synopsys.com/blogs/software-security/abuse-cases-can-drive-security-requirements.html)

#### 如何定义滥用案例列表

有多种不同方法可以为功能（在敏捷项目中可映射到用户故事）定义滥用案例列表。

[威胁建模](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)是一套预测可能出错的技术，并确保对每个已识别的可能场景采取行动。将"我们将对此做些什么"列表中的每一项写成滥用案例可能有助于工程团队处理输出。

#### 定义滥用案例列表的另一种方法（自下而上、协作导向）

组织一个包括以下角色的研讨会：

- **业务分析师**：将从业务角度描述每个功能的关键业务人员。
- **风险分析师**：公司的风险人员，将评估针对建议攻击的业务风险（有时由**业务分析师**兼任，取决于公司情况）。
- **渗透测试员**：将扮演"攻击者"，提出可对业务功能执行的攻击。如果公司没有这类人员，可以请求外部专家服务。如果可能，邀请2名背景不同的渗透测试员，以增加可识别和考虑的潜在攻击数量。
- **项目技术负责人**：项目的技术人员，将就已识别的攻击和对策进行技术交流。
- **质量保证分析师或功能测试员**：了解应用程序/功能预期工作方式（正面测试）、不应工作方式（负面测试）以及导致其失败的情况（失败场景）的人员。

在此研讨会期间（持续时间取决于功能列表的大小，但4小时是个不错的起点），将处理项目或冲刺中的所有业务功能。研讨会的输出将是所有业务功能的攻击（滥用案例）列表。所有滥用案例都将有风险评级，以便进行过滤和优先排序。

重要的是要考虑**技术**和**业务**类型的滥用案例并进行相应标记。

_示例：_

- 技术标记的滥用案例：在评论输入字段中添加跨站脚本注入。
- 业务标记的滥用案例：在在线商店中能够在下单前任意修改商品价格，导致用户以较低价格购买所需商品。

#### 何时定义滥用案例列表

在敏捷项目中，定义研讨会必须在将用户故事纳入冲刺的会议之后进行。

在瀑布项目中，定义研讨会必须在识别并被业务方知晓待实施的业务功能时进行。

无论采用何种项目模式（敏捷或瀑布），被选择处理的滥用案例必须成为每个功能规范部分（瀑布）或用户故事验收标准（敏捷）中的安全需求，以便：
- 允许额外成本/工作量评估
- 识别和实施对策

每个滥用案例必须有唯一标识符，以便在整个项目/冲刺中进行跟踪（后续部分将详细说明）。

唯一ID格式的示例可以是 **ABUSE_CASE_001**。

下图提供了涉及的不同步骤的概览（从左到右）：

![概览架构](../assets/Abuse_Case_Cheat_Sheet_Overview.png)

### 建议

建议将重点放在前一节所述研讨会的输出上。

#### 步骤1：研讨会准备

首先，即使看起来很明显，关键业务人员必须确保了解并能够解释将在研讨会上处理的业务功能。

其次，创建一个新的 Microsoft Excel 文件（也可以使用 Google 表格或任何类似软件），包含以下工作表（或选项卡）：

- **功能**
    - 将包含计划在研讨会上处理的业务功能列表的表格。
- **滥用案例**
    - 将包含研讨会期间识别的所有滥用案例的表格。
- **对策**
    - 将包含为已识别的滥用案例想象的可能对策的列表（简要描述）。
    - 此工作表非必需，但可能很有用（对于滥用案例来说），如果修复很容易实施，则可能影响风险评级。
    - 对策可以由应用安全配置文件在研讨会期间识别，因为应用安全人员必须能够执行攻击，同时也能构建或识别防御（这并非总是渗透测试员的情况，因为此人通常专注于攻击方面，因此渗透测试员 + 应用安全的组合非常高效，可以提供360度视角）。

以下是每个工作表的表示，以及研讨会期间将填写的内容示例：

#### 步骤2：研讨会期间

使用电子表格审查所有功能。

对于每个功能，遵循以下流程：

1. 关键业务人员从业务角度解释当前功能。
2. 渗透测试员提出并解释他们可以对该功能执行的一系列攻击。
3. 对于每个提出的攻击：
   1. 应用安全专家提出对策和首选部署位置（基础设施、网络、代码、设计...）。
   2. 技术人员就所提议对策的可行性提供反馈。
   3. 渗透测试员使用 CVSS v3（或其他标准）计算器确定风险评级。（例如：[CVSS V3 计算器](https://www.first.org/cvss/calculator/3.0)）
   4. 风险负责人应接受或修改风险评级，以确定最终风险得分准确反映公司的实际业务影响。

4. 业务、风险和技术负责人应达成共识，过滤当前功能的滥用案例列表，保留必须处理的案例，并在**滥用案例**表中相应标记（**如果接受风险，则添加注释解释原因**）。
5. 转到下一个功能...

如果无法邀请渗透测试员，可以使用以下参考资料识别功能的适用攻击：

- [OWASP 针对 Web 应用程序的自动化威胁](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [OWASP 测试指南](https://owasp.org/www-project-web-security-testing-guide/stable/)
- [OWASP 移动测试指南](https://github.com/OWASP/owasp-mstg)
- [通用攻击模式枚举与分类（CAPEC）](https://capec.mitre.org/)

关于攻击和对策知识库的重要说明：

```text
随着项目经验的积累，您将获得适用于业务领域应用程序的攻击和对策词典。

这个词典将显著加快未来研讨会的进程。

为了促进这个词典的创建，您可以在项目/冲刺结束时，
将已识别的攻击和对策列表收集到中央位置（wiki、数据库、文件等），
并在下次研讨会中结合渗透测试员的输入使用。
```

### 结语

滥用案例是一种强大的安全需求定义和风险管理工具。通过系统性地识别和评估潜在攻击，组织可以：

- 更全面地理解应用程序的安全风险
- 制定更有针对性的安全对策
- 在开发早期就将安全考虑纳入产品设计
- 有效分配安全资源，优先处理高风险滥用场景

重要的是要将滥用案例视为一个持续的过程，随着应用程序的演进和新威胁的出现而不断更新和完善。

### 建议的后续步骤

1. 组织首次滥用案例研讨会
2. 建立攻击和对策知识库
3. 将滥用案例集成到开发流程中
4. 定期审查和更新滥用案例列表
5. 培训团队成员识别和应对潜在安全威胁

通过采用这种系统化的方法，组织可以显著提高其应用程序的安全性和韧性。

#### 第3步：研讨会后

电子表格此时包含了所有必须处理的滥用案例，并可能包含相应的对策（取决于能力）。

现在还有两个剩余任务：

1. 关键业务人员必须更新每个功能的规格说明（瀑布模型）或每个功能的用户故事（敏捷模型），将相关的滥用案例作为安全需求（瀑布模型）或验收标准（敏捷模型）包括在内。
2. 关键技术人员必须评估考虑对策的开销和成本/工作量。

#### 第4步：实施期间 - 滥用案例处理跟踪

为了跟踪所有滥用案例的处理，可以使用以下方法：

如果在以下层面处理一个或多个滥用案例：

- **设计、基础设施或网络层面**
    - 在文档或架构中做一个注释，说明"此设计/网络/基础设施考虑了滥用案例 ABUSE_CASE_001、ABUSE_CASE_002、ABUSE_CASE_xxx"。
- **代码层面**
    - 在类/脚本/模块中放置特殊注释，说明"此类/模块/脚本考虑了滥用案例 ABUSE_CASE_001、ABUSE_CASE_002、ABUSE_CASE_xxx"。
    - 可以使用专门的注解，如 `@AbuseCase(ids={"ABUSE_CASE_001","ABUSE_CASE_002"})`，以便于跟踪并在集成开发环境中识别。

通过这种方式，可以（通过一些简单的脚本）识别滥用案例的处理位置。

#### 第5步：实施期间 - 滥用案例处理验证

随着滥用案例的定义，可以建立自动化或手动验证，以确保：

- 所有选定的滥用案例都已处理。
- 滥用案例被正确且完整地处理。

验证可以采用以下几种形式：

- 自动化（在项目的持续集成作业中定期运行，如提交时、每日或每周）：
    - 静态应用程序安全测试（SAST）或动态应用程序安全测试（DAST）工具中的自定义审计规则。
    - 专门针对安全的单元、集成或功能测试。
    - ……
- 手动：
    - 项目成员之间在设计或实施阶段进行安全代码审查。
    - 向渗透测试人员提供所有已处理的滥用案例列表，以便他们在对应用程序进行入侵测试时验证每个滥用案例的保护效率（渗透测试人员将验证已识别的攻击不再有效，并尝试发现其他可能的攻击）。
    - ……

添加自动化测试还可以帮助团队跟踪针对滥用案例的对策的有效性，并确定在项目维护或修复缺陷阶段对策是否仍然有效（防止意外移除/禁用）。在使用[持续交付](https://continuousdelivery.com/)方法时，这也很有用，可以确保在开放应用程序访问之前所有滥用案例的保护措施都已就位。

### 滥用案例作为用户故事的推导示例

以下部分展示了使用 [OWASP TOP 10](https://owasp.org/www-project-top-ten/) 作为输入源的滥用案例推导示例。

面向威胁的角色：

- 恶意用户
- 滥用用户
- 无意识用户

#### A1:2017-注入攻击

*概述：*

几乎任何数据源都可能成为注入向量，包括环境变量、参数、外部和内部 Web 服务，以及所有类型的用户。当攻击者可以向解释器发送恶意数据时，就会发生[注入](https://owasp.org/www-community/Injection_Flaws)缺陷。

*滥用案例：*

作为攻击者，我将对用户或 API 接口的输入字段执行注入攻击（SQL、LDAP、XPath 或 NoSQL 查询、OS 命令、XML 解析器、SMTP 头、表达式语言和 ORM 查询）

#### A2:2017-身份认证被破坏

*概述：*

攻击者可以获取数百万个有效的用户名和密码组合，用于凭据填充、默认管理员账户列表、自动暴力破解和字典攻击工具。会话管理攻击已被充分理解，尤其是与未过期的会话令牌有关。

*滥用案例：*

作为攻击者，我可以获取数百万个有效的用户名和密码组合用于凭据填充。

*滥用案例：*

作为攻击者，我拥有默认管理员账户列表、自动暴力破解和字典攻击工具，并将其用于应用程序和支持系统的登录区域。

*滥用案例：*

作为攻击者，我通过使用过期和伪造的令牌操纵会话令牌来获取访问权限。

#### A3:2017-敏感数据暴露

*概述：*

攻击者不是直接攻击加密，而是窃取密钥、执行中间人攻击，或从服务器、传输过程中或用户客户端（如浏览器）窃取明文数据。通常需要手动攻击。之前检索到的密码数据库可以通过图形处理单元（GPU）进行暴力破解。

*滥用案例：*

作为攻击者，我窃取在应用程序中暴露的密钥，以获取对应用程序或系统的未授权访问。

*滥用案例：*

作为攻击者，我执行中间人攻击以获取流量并利用它获取敏感数据，并可能获得对应用程序的未授权访问。

*滥用案例：*

作为攻击者，我从服务器、传输过程中或用户客户端（如浏览器）窃取明文数据，以获取对应用程序或系统的未授权访问。

*滥用案例：*

作为攻击者，我通过捕获流量并破解加密来查找和针对旧的或弱的加密算法。

#### A4:2017-XML外部实体（XXE）

*概述：*

如果攻击者可以上传XML或在XML文档中包含恶意内容，并利用易受攻击的XML处理器、代码、依赖项或集成，则可以发起攻击。

*滥用案例：*

作为攻击者，我利用应用程序中用户或系统可以上传XML的脆弱区域来提取数据、从服务器执行远程请求、扫描内部系统、执行拒绝服务攻击以及执行其他攻击。

*滥用案例：*

作为攻击者，我在上传到应用程序或系统的XML文档中包含恶意内容，以提取数据、从服务器执行远程请求、扫描内部系统、执行拒绝服务攻击以及执行其他攻击。

*滥用案例：*

作为攻击者，我包含恶意XML代码来利用脆弱的代码、依赖项或集成，以提取数据、从服务器执行远程请求、扫描内部系统、执行拒绝服务攻击（例如十亿笑攻击），以及执行其他攻击。

#### A5:2017-访问控制被破坏

*概述：*

利用访问控制是攻击者的核心技能。可以通过手动方式或可能通过自动化方式检测缺少访问控制的框架。

*滥用案例：*

作为攻击者，我通过修改URL、内部应用程序状态或HTML页面，或简单地使用自定义API攻击工具来绕过访问控制检查。

*滥用案例：*

作为攻击者，我操纵主键并将其更改为访问另一个用户的记录，从而允许查看或编辑他人的账户。

*滥用案例：*

作为攻击者，我操纵会话、访问令牌或应用程序中的其他访问控制，在未登录的情况下充当用户，或在以普通用户身份登录时充当管理员/特权用户。

*滥用案例：*

作为攻击者，我利用元数据操纵，如重放或篡改JSON Web令牌（JWT）访问控制令牌或Cookie或被篡改的隐藏字段，以提升权限或滥用JWT失效。

*滥用案例：*

作为攻击者，我利用跨源资源共享（CORS）配置错误，允许未经授权的API访问。

*滥用案例：*

作为攻击者，我强制浏览未经身份验证的页面或以标准用户身份浏览特权页面。

*滥用案例：*

作为攻击者，我访问缺少访问控制的API，包括POST、PUT和DELETE。

*滥用案例：*

作为攻击者，我针对正在使用的默认加密密钥、生成或重复使用的弱加密密钥，或缺少密钥轮换的区域。

*滥用案例：*

作为攻击者，我发现用户代理（如应用程序、邮件客户端）未验证接收到的服务器证书是否有效的区域，并执行获取对数据未授权访问的攻击。

#### A6:2017-安全配置错误

*概述：*

攻击者经常尝试利用未修补的缺陷或访问默认账户、未使用的页面、未受保护的文件和目录等，以获取未授权访问或获取系统知识。

*滥用案例：*

作为攻击者，我发现并利用应用程序堆栈任何部分上缺少适当的安全强化配置，或云服务上配置不当的权限。

*滥用案例：*

作为攻击者，我发现并利用已启用或安装的不必要功能（如不必要的端口、服务、页面、账户或权限）。

*滥用案例：*

作为攻击者，我使用默认账户及其密码访问系统、接口或对我不应该能够执行的组件执行操作。

*滥用案例：*

作为攻击者，我发现应用程序中错误处理显示堆栈跟踪或其他过于详细的错误消息，我可以用于进一步利用。

*滥用案例：*

作为攻击者，我发现升级的系统、最新的安全功能被禁用或未安全配置。

*滥用案例：*

作为攻击者，我发现应用程序服务器、应用程序框架（如Struts、Spring、ASP.NET）、库、数据库等中的安全设置未设置为安全值。

*滥用案例：*

作为攻击者，我发现服务器未发送安全标头或指令，或设置为不安全的值。

#### A7:2017-跨站脚本（XSS）

*概述：*

XSS 是 OWASP Top 10 中第二常见的问题，在大约三分之二的应用程序中都存在。

*滥用案例：*

作为攻击者，我执行反射型 XSS，其中应用程序或 API 在 HTML 输出中包含未验证和未转义的用户输入。我成功的攻击可以允许在受害者的浏览器中执行任意 HTML 和 JavaScript。通常，受害者需要与指向攻击者控制页面的恶意链接进行交互，如恶意水坑网站、广告或类似内容。

*滥用案例：*

作为攻击者，我执行存储型 XSS，其中应用程序或 API 存储未经净化的用户输入，并在稍后由另一个用户或管理员查看。

*滥用案例：*

作为攻击者，我执行 DOM XSS，其中 JavaScript 框架、单页面应用程序和 API 动态包含攻击者可控制的数据到页面时存在漏洞。

#### A8:2017-不安全的反序列化

*概述：*

利用反序列化有些困难，现成的漏洞利用很少能直接使用，需要对底层漏洞利用代码进行更改或调整。

*滥用案例：*

作为攻击者，我发现应用程序和 API 中可以提供恶意或篡改对象的反序列化区域。因此，我可以专注于对象和数据结构相关的攻击，攻击者可以修改应用程序逻辑或在反序列化期间或之后实现任意远程代码执行（如果应用程序有可用的类可以改变反序列化期间或之后的行为）。或者我专注于数据篡改攻击，如访问控制相关攻击，使用现有的数据结构但更改内容。

#### A9:2017-使用存在已知漏洞的组件

*概述：*

虽然很容易找到许多已知漏洞的现成漏洞利用，但其他漏洞需要集中精力开发自定义漏洞利用。

*滥用案例：*

作为攻击者，我发现具有弱点的常见开源或闭源包，并对已披露的漏洞和利用进行攻击。

#### A10:2017-日志和监控不足

*概述：*

几乎每一起重大事件的根源都是日志和监控不足。攻击者依赖缺乏监控和及时响应来实现他们的目标而不被发现。2016年，识别一次入侵平均需要[191天](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN)，这为造成实质性损害提供了相当大的机会。

*滥用案例：*

作为攻击者，我攻击一个组织，而日志、监控系统和团队看不到或不响应我的攻击。

## 图表来源

所有图表都是使用 <https://www.draw.io/> 网站创建，并导出为 PNG 图像以集成到本文中。

所有模式的 XML 描述符文件可在下方获取（使用 XML 描述，可以使用 DRAW.IO 网站修改模式）：

[模式描述符存档](../assets/Abuse_Case_Cheat_Sheet_SchemaBundle.zip)
