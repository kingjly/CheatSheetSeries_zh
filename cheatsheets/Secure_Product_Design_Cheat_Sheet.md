# 安全产品设计备忘录

## 引言

安全产品设计的目的是确保所有产品满足或超过组织在开发生命周期中制定的安全要求，并确保关于所开发产品的所有安全决策都是明确的选择，并为产品提供正确的安全级别。

## 方法论

作为基本起点，建立安全默认值，最小化攻击面，并安全地失败到那些明确定义和理解的默认值。

安全产品设计通过两个过程实现：

1. **_产品构思_**；和
2. **_产品设计_**

第一个过程发生在产品被构思时，或者对现有产品进行重新设计时。后者是持续的、渐进的，并以敏捷的方式进行，靠近代码编写的地方。

## 安全原则

### 1. 最小权限和职责分离原则

最小权限是一个安全原则，规定用户应该只被赋予执行工作所必需的最小访问权限。这意味着用户应该只能访问完成工作所需的资源，仅此而已。这有助于减少对敏感数据或系统的未经授权的访问风险，因为用户只能访问他们需要的资源。最小权限是一个重要的安全原则，应该遵循以确保组织数据和系统的安全。

职责分离是商业和组织内部控制的基本原则。这是一个检查和平衡系统，确保没有单一个人控制交易的所有方面。这是通过将不同的任务分配给不同的人来完成的，以便没有人控制整个流程。这有助于减少欺诈和错误的风险，并确保所有任务能够及时完成。职责分离是任何组织内部控制系统的重要组成部分，对于维护组织财务记录的完整性至关重要。

### 2. 纵深防御原则

纵深防御是一种安全策略，涉及多层安全控制以保护组织的资产。它基于这样一个理念：如果一层安全失败，其他层仍然能够保护资产。安全层可以包括物理安全、网络安全、应用程序安全和数据安全。纵深防御的目标是创建一个安全的环境，能够抵御攻击并快速检测和响应任何安全事件。通过实施多层安全，组织可以降低成功攻击的风险，并最大限度地减少任何成功攻击造成的损害。

### 3. 零信任原则

零信任是一种安全模型，假设所有用户、设备和网络都是不可信的，必须在授予访问权限之前进行验证。它基于这样一个理念：组织不应信任任何用户、设备或网络，即使它们在组织的网络内部。相反，所有访问请求都必须在授予访问权限之前进行身份验证和授权。零信任还要求组织持续监控和审核用户活动，以确保只有需要访问的用户才能获得访问权限。这个模型旨在通过确保只有经授权的用户能访问敏感数据，从而减少数据泄露和其他安全事件的风险。

### 4. 开放安全原则

开放安全是一个强调开源软件开发中安全重要性的概念。它关注开发人员需要了解其代码的安全影响，并采取措施确保代码安全。这包括使用安全的编码实践、测试漏洞以及使用安全的开发工具。开放安全还鼓励开发人员与安全专家合作，以确保其代码的安全性。

## 安全重点领域

### 1. 上下文

这个正在考虑的应用程序在组织生态系统中处于什么位置？哪些部门使用它，出于什么原因？它可能包含什么类型的数据，因此其风险概况是什么？

构建应用程序安全上下文的过程包括[威胁建模](Threat_Modeling_Cheat_Sheet.md)——这导致在每次*产品交付*迭代中的**_产品设计_**阶段添加与安全相关的故事——以及在执行业务影响评估时——这导致在**_产品构思_**阶段为给定产品设置正确的产品安全级别。

上下文非常重要，因为过度设计安全性可能比过度设计规模或性能有更大的成本影响，但是安全性不足也可能带来毁灭性的后果。

### 2. 组件

从应用程序使用的库（在任何**_产品设计_**阶段选择）到它可能使用的外部服务（在**_产品构思_**阶段发生变更），构成这个应用程序的部分是什么，这些部分如何保持安全？为此，我们利用在您的黄金路径/铺平道路文档中定义的安全设计模式和现成组件库，并通过[威胁建模](Threat_Modeling_Cheat_Sheet.md)分析这些选择。

组件审查的一部分还必须包括选择正确组件的更多商业方面（许可和维护）以及可能需要的使用限制。

### 3. 连接

如何与此应用程序交互，它如何连接到之前提到的组件和服务？数据存储在哪里，如何访问？连接还可以描述任何有意的非连接。根据所需的产品安全级别和可能需要的不同租户的数据或整个环境隔离，考虑可能需要的层级隔离。

添加（或删除）连接可能是**_产品构思_**正在发生的标志。

### 4. 代码

代码是产品意图的最终表达，因此首先必须是功能性的。但是提供该功能的方式必须满足或超过对其的期望。

安全编码的一些基本原则包括：

   1. 输入验证：在处理输入数据之前，验证所有输入数据是否有效，并符合预期的类型、格式和长度。这可以帮助防止SQL注入和缓冲区溢出等攻击。
   2. 错误处理：以安全的方式处理错误和异常，例如以安全的方式记录它们，并且不向攻击者泄露敏感信息。
   3. 身份验证和授权：实施强大的身份验证和授权机制，确保只有授权用户可以访问敏感数据和资源。
   4. 密码学：使用加密函数和协议来保护传输中和静态的数据，如HTTPS和加密——对于给定的产品安全级别，预期的级别通常可以通过查看您的黄金路径/铺平道路文档来找到。
   5. 最小权限：在编写代码时使用最小权限原则，使代码和运行它的系统被赋予执行其功能所需的最小访问权限。
   6. 安全的内存管理：使用黄金路径/铺平道路文档中推荐的高级语言，或正确管理内存以防止与内存相关的漏洞，如缓冲区溢出和使用后释放。
   7. 避免硬编码的秘密：应避免在代码中硬编码密码和加密密钥，并应将其存储在安全的存储中。
   8. 安全测试：在开发过程中和部署之前测试软件的安全漏洞。
   9. 代码审计和审查：定期审计和审查代码中的安全漏洞，例如使用自动化工具或让第三方审查代码。
   10. 保持最新：使代码与最新的安全最佳实践和漏洞修复保持同步，以确保软件尽可能安全。

确保在应用程序的每一层（例如，从前端到后端）集成合理性检查，并确保编写单元和集成测试以验证在[威胁建模](Threat_Modeling_Cheat_Sheet.md)期间发现的所有威胁已被缓解到组织可接受的风险水平。利用这一点为应用程序的每一层编制用例和[滥用用例](Abuse_Case_Cheat_Sheet.md)。

### 5. 配置

安全地构建应用程序如果配置不安全，很容易前功尽弃。至少我们应确保以下几点：

1. 牢记最小权限原则：将系统组件和用户的访问和权限限制在执行任务所需的最小范围。
2. 记住纵深防御：实施多层安全控制，以防范各种威胁。
3. 确保默认安全：配置系统和软件默认为安全，需要最少的手动设置或配置。
4. 保护数据：通过在传输和静态时加密来保护敏感数据，如个人信息和财务数据。保护数据还意味着确保正确备份数据，并根据所需的产品安全级别正确设置数据保留。
5. 计划安全失败：设计系统在故障时以安全状态失败，而不是在出现故障时暴露漏洞。
6. 始终使用安全通信：使用安全协议（如HTTPS）进行通信，以防止窃听和篡改。
7. 执行定期更新 - 或利用[维护的镜像](https://www.cisecurity.org/cis-hardened-images)：保持软件、Docker镜像和基础操作系统与[最新安全补丁](https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final)同步是维护安全系统的essential部分。
8. 制定经过实践的安全事件响应计划：制定应对安全事件的计划对于最大限度地减少任何成功攻击造成的损害以及产品支持模型的关键部分至关重要。

有关如何精确确保安全配置的详细信息，请参见[基础设施即代码安全备忘录](Infrastructure_as_Code_Security_Cheat_Sheet.md)
