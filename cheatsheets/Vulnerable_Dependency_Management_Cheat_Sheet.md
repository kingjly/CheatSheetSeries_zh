# 易受攻击依赖管理备忘录

## 引言

本备忘录的目标是提供一种方法，用于处理检测到的第三方依赖漏洞，并根据不同情况采取相应措施。

本备忘录不是面向工具的，但包含一个[工具](#工具)部分，为读者提供可用于检测易受攻击依赖的免费和商业解决方案，具体取决于所涉及技术的支持水平。

**注意：**

本备忘录中提到的建议并非万能解决方案（在所有情况下都适用的配方），但可以作为基础，并根据具体情况进行调整。

## 背景

大多数项目使用第三方依赖来委托处理各种操作，例如生成特定格式的文档、HTTP 通信、特定格式的数据解析等。

这是一个好方法，因为它允许开发团队专注于支持预期业务功能的实际应用程序代码。但依赖带来的不利之处在于，应用程序的安全状况现在取决于该依赖。

这一方面在以下项目中有所提及：

- [OWASP TOP 10 2017](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/) 中的 *[A9 - 使用已知存在漏洞的组件](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities.html)*。
- [OWASP 应用程序安全验证标准项目](https://owasp.org/www-project-application-security-verification-standard/) 中的 *V14.2 依赖* 部分。

基于这一背景，对于一个项目来说，确保所有实施的第三方依赖都没有安全问题至关重要。如果它们确实包含任何安全问题，开发团队需要意识到这一点，并采取必要的缓解措施来保护受影响的应用程序。

强烈建议从项目诞生之初就进行依赖的自动化分析。事实上，如果在项目中期或后期添加此任务，可能意味着需要大量工作来处理已识别的所有问题，这将给开发团队带来巨大负担，并可能阻碍项目的推进。

**注意：**

在备忘录的其余部分，当我们提到*开发团队*时，我们假设团队中有具备所需应用程序安全技能的成员，或者可以咨询公司中具有这类技能的人员来分析影响依赖的漏洞。

## 关于检测的备注

重要的是要牢记发现安全问题后处理的不同方式。

### 1. 负责任披露

参见[此处](https://en.wikipedia.org/wiki/Responsible_disclosure)的描述。

研究人员在组件中发现漏洞，并在与组件提供者合作后，他们发布与问题相关的 [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)（有时会为提供者创建特定的漏洞标识符，但通常首选 CVE 标识符），允许公开引用问题以及可用的修复/缓解措施。

如果提供者未能与研究人员适当合作，预期会出现以下情况：

- CVE 被供应商接受，但提供者[拒绝修复问题](https://www.excellium-services.com/cert-xlm-advisory/cve-2019-7161/)。
- 大多数情况下，如果研究人员在 30 天内未收到回复，他们将继续进行漏洞的[全面披露](#2-全面披露)。

在这里，漏洞始终在 [CVE 全球数据库](https://nvd.nist.gov/vuln/data-feeds)中被引用，通常被检测工具用作多个输入源之一。

### 2. 全面披露

参见[此处](https://en.wikipedia.org/wiki/Full_disclosure)的描述，在**计算机**部分的**计算机安全**中。

研究人员决定在 [Full Disclosure 邮件列表](https://seclists.org/fulldisclosure/)、[Exploit-DB](https://www.exploit-db.com) 等服务上发布所有信息，包括利用代码/方法。

在这种情况下，CVE 并不总是被创建，因此漏洞并不总是在 CVE 全球数据库中，这可能导致检测工具盲目，除非工具使用其他输入源。

## 关于安全问题处理决策的备注

当检测到安全问题时，可以决定接受该安全问题所代表的风险。然而，这个决定必须由公司的[首席风险官](https://en.wikipedia.org/wiki/Chief_risk_officer)（可以回退到[首席信息安全官](https://en.wikipedia.org/wiki/Chief_information_security_officer)）基于分析该问题的开发团队的技术反馈以及 CVE 的 [CVSS](https://www.first.org/cvss/user-guide) 评分指标来做出。

## 案例

当检测到安全问题时，开发团队可能遇到以下小节中呈现的情况（在备忘录的其余部分称为*案例*）。

如果漏洞影响[传递依赖](https://en.wikipedia.org/wiki/Transitive_dependency)，则操作将在项目的直接依赖上进行，因为处理传递依赖通常会影响应用程序的稳定性。

处理传递依赖需要开发团队首先完全理解从项目第一级依赖到受安全漏洞影响的依赖的完整关系/通信/使用情况，这项任务非常耗时。

### 案例 1

#### 背景

组件的修补版本已由提供者发布。

#### 方法应用的理想条件

存在用于使用受影响依赖的应用程序功能的自动化单元、集成、功能或安全测试集，以验证功能是否正常运行。

#### 方法

**步骤 1：**

在测试环境中更新项目中依赖的版本。

**步骤 2：**

在运行测试之前，可能出现 2 种输出路径：

- 所有测试成功，因此可以将更新推送到生产环境。
- 一个或多个测试失败，可能出现几种输出路径：
    - 失败是由于某些函数调用的更改（例如签名、参数、包等）。开发团队必须更新其代码以适应新库。完成后，重新运行测试。
    - 发布的依赖存在技术不兼容性（例如需要更新的运行时版本），这将导致以下操作：
    1. 向提供者提出问题。
    2. 在等待提供者反馈时应用[案例 2](#案例-2)。

### 案例 2

#### 背景

提供者告知团队修复问题需要一段时间，因此在几个月内不会提供修补版本。

#### 方法应用的理想条件

提供者可以与开发团队共享以下任何信息：

- 利用代码。
- 漏洞影响的函数列表。
- 防止利用问题的解决方法。

#### 方法

**步骤 1：**

如果提供了解决方法，应在测试环境中应用并验证，然后部署到生产环境。

如果提供者给出了受影响函数的列表，必须使用防护代码包装对这些函数的调用，以确保输入和输出数据是安全的。

此外，Web 应用程序防火墙（WAF）等安全设备可以通过参数验证和为这些特定库生成检测规则来保护内部应用程序。但是，在本备忘录中，重点放在应用程序级别，以尽可能接近源头地修补漏洞。

*使用 Java 代码的示例，其中受影响的函数存在[远程代码执行](https://www.netsparker.com/blog/web-security/remote-code-evaluation-execution/)问题：*

```java
public void callFunctionWithRCEIssue(String externalInput){
    //使用正则表达式对外部输入进行输入验证
    if(Pattern.matches("[a-zA-Z0-9]{1,50}", externalInput)){
        //使用安全输入调用有缺陷的函数
        functionWithRCEIssue(externalInput);
    }else{
        //记录利用检测
        SecurityLogger.warn("检测到 RCE 问题 XXXXX 的利用！");
        //引发异常，导致向客户端发送通用错误...
    }
}
```

如果提供者对漏洞没有提供任何信息，可以应用[案例 3](#案例-3)，跳过本案例的*步骤 2*。我们在这里假设至少提供了 [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)。

**步骤 2：**

如果提供者提供了利用代码，并且团队已经为易受攻击的库/代码添加了安全包装，则执行利用代码，以确保库现在是安全的，不会影响应用程序。

如果存在应用程序的自动化单元、集成、功能或安全测试集，运行它们以验证添加的保护代码不会影响应用程序的稳定性。

在项目的 *README* 中添加注释，解释在等待修补版本期间如何处理问题（指定相关的 [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)），因为检测工具将继续对此依赖项发出警报。

**注意：** 您可以将依赖项添加到忽略列表中，但此依赖项的忽略范围只能覆盖与漏洞相关的 [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)，因为一个依赖项可能受到多个漏洞的影响，每个漏洞都有自己的 [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)。

### 案例 3

#### 背景

提供者告知团队他们无法修复问题，因此根本不会发布修补版本（如果提供者不想修复问题或根本不回应，也适用此情况）。

在这种情况下，开发团队获得的唯一信息是 [CVE](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)。

**注意：**

- 这种情况非常复杂且耗时，通常作为最后的手段。
- 如果受影响的依赖是开源库，那么我们（开发团队）可以创建补丁并创建[拉取请求](https://help.github.com/en/articles/about-pull-requests) - 这样我们不仅可以保护我们的公司/应用程序，还可以帮助其他人保护他们的应用程序。

#### 方法应用的理想条件

没有特定条件，因为我们处于"自行修补"的情况。

#### 方法

**步骤 1：**

如果出现以下情况，最好开始平行研究，以找到另一个维护更好的组件，或者如果是有支持的商业组件，**则在首席风险官**（[可回退到首席信息安全官](https://en.wikipedia.org/wiki/Chief_information_security_officer)）的帮助下对提供者施加压力：

- 提供者不想修复问题。
- 提供者根本不回应。

在所有情况下，我们现在需要立即处理漏洞。

**步骤 2：**

既然我们知道易受攻击的依赖，就知道它在应用程序中的使用位置（如果是传递依赖，则可以使用 [IDE](https://en.wikipedia.org/wiki/Integrated_development_environment) 内置功能或使用的依赖管理系统（Maven、Gradle、NuGet、npm 等）识别使用它的第一级依赖）。注意 IDE 也用于识别对依赖的调用。

识别对此依赖的调用是好的，但这只是第一步。团队仍然缺乏需要执行的修补类型的信息。

为获取这些信息，团队使用 CVE 内容来了解影响依赖的漏洞类型。`description` 属性提供答案：SQL 注入、远程代码执行、跨站脚本、跨站请求伪造等。

在识别上述 2 点之后，团队了解需要采取的修补类型（使用防护代码的[案例 2](#案例-2)）和添加位置。

*示例：*

团队有一个使用 Jackson API 的应用程序，该版本暴露于 [CVE-2016-3720](https://nvd.nist.gov/vuln/detail/CVE-2016-3720)。

CVE 的描述如下：

```text
Jackson 的数据格式扩展（即 jackson-dataformat-xml）中的 XmlMapper 存在 XML 外部实体（XXE）漏洞，攻击者可以通过未知向量产生不确定的影响。
```

基于这些信息，团队确定必要的修补将是在传递给 Jackson API 的任何 XML 数据上添加[预验证](XML_External_Entity_Prevention_Cheat_Sheet.md)，以防止 [XML 外部实体（XXE）](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/)漏洞。

**步骤 3：**

如果可能，创建一个模仿漏洞的单元测试，以确保补丁有效，并在项目演进过程中持续确保补丁到位。

如果存在应用程序的自动化单元、集成、功能或安全测试集，则运行它们以验证补丁不会影响应用程序的稳定性。

### 案例 4

#### 背景

在以下情况下发现易受攻击的依赖，且提供者尚未意识到漏洞：

- 通过在互联网上发现全面披露的帖子。
- 在渗透测试期间。

#### 方法应用的理想条件

提供者在收到漏洞通知后与您合作。

#### 方法

**步骤 1：**

通过与提供者共享帖子来告知他们关于漏洞的情况。

**步骤 2：**

使用全面披露帖子或渗透测试者的利用反馈中的信息，如果提供者合作，则应用[案例 2](#案例-2)，否则应用[案例 3](#案例-3)，但不是分析 CVE 信息，团队需要分析全面披露帖子/渗透测试者利用反馈中的信息。

## 工具

本节列出了几种可用于分析项目所使用依赖以检测漏洞的工具。

在选择易受攻击依赖检测工具的过程中，确保该工具：

- 使用多个可靠的输入源，以处理两种漏洞披露方式。
- 支持将组件上提出的问题标记为[误报](https://www.whitehatsec.com/glossary/content/false-positive)。

- 免费工具
    - [OWASP 依赖检查](https://owasp.org/www-project-dependency-check/):
        - 完全支持：Java, .Net.
        - 实验性支持：Python, Ruby, PHP (composer), NodeJS, C, C++.
    - [NPM 审计](https://docs.npmjs.com/cli/audit)
        - 完全支持：NodeJS, JavaScript.
        - 可通过此[模块](https://www.npmjs.com/package/npm-audit-html)获取 HTML 报告。
    - [OWASP 依赖追踪](https://dependencytrack.org/) 可用于管理组织中的易受攻击依赖。
    - [ThreatMapper](https://github.com/deepfence/ThreatMapper)
        - 完全支持：基础操作系统, Java, NodeJS, JavaScript, Ruby, Python
        - 目标：Kubernetes（节点和容器）, Docker（节点和容器）, Fargate（容器）, 裸机/虚拟机（主机和应用）

- 商业工具
    - [Snyk](https://snyk.io/)（可用开源和免费选项）:
        - 对[多种语言和包管理器](https://snyk.io/docs/)提供完全支持。
    - [JFrog XRay](https://jfrog.com/xray/):
        - 对[多种语言和包管理器](https://jfrog.com/integration/)提供完全支持。
    - [Renovate](https://renovatebot.com)（允许检测过时依赖）:
        - 对[多种语言和包管理器](https://renovatebot.com/docs/)提供完全支持。
    - [Requires.io](https://requires.io/)（允许检测过时依赖 - 可用开源和免费选项）:
        - [完全支持](https://requires.io/features/)：仅限 Python。
