
# 威胁建模备忘录

## 引言

威胁建模对于现代应用开发者来说是一个重要的概念。本备忘录的目标是为威胁建模的新手和需要复习的人提供简明但可操作的参考。官方项目页面是 [https://owasp.org/www-project-threat-model/](https://owasp.org/www-project-threat-model/)。

## 概述

在应用安全的背景下，威胁建模是一个结构化、可重复的过程，用于获取特定系统安全特征的可操作洞察。它涉及从安全角度对系统进行建模、基于此模型识别适用的威胁，并确定对这些威胁的响应。威胁建模从对手的角度分析系统，重点关注攻击者可能利用系统的方式。

威胁建模最好在软件开发生命周期（SDLC）的早期阶段进行，例如设计阶段。此外，这不是一次性的工作。威胁模型应该随系统一起维护、更新和完善。理想情况下，威胁建模应无缝地集成到团队的正常 SDLC 流程中；它应被视为流程中标准且必要的步骤，而非附加任务。

根据[威胁建模宣言](https://www.threatmodelingmanifesto.org/)，威胁建模过程应回答以下四个问题：

1. 我们正在处理什么？
2. 可能出现什么问题？
3. 我们将如何应对？
4. 我们是否做得足够好？

这四个问题将作为下面描述的四个主要阶段的基础。

## 优势

在概述流程之前，值得解答这个问题：为什么要进行威胁建模？为什么要为开发过程增加更多工作？有什么好处？下面将简要概述这些问题的答案。

### 及早识别风险

威胁建模旨在设计阶段识别潜在的安全问题。这使得安全可以"内置"于系统，而非"附加"到系统。这比在生产环境中识别和解决安全缺陷更加高效。

### 提高安全意识

正确的威胁建模要求参与者对特定应用的安全和威胁环境进行创造性和批判性思考。它挑战个人"像攻击者一样思考"，并将一般安全知识应用于特定情境。威胁建模通常也是一项团队工作，鼓励成员分享想法并对他人的意见提供反馈。总的来说，威胁建模可以成为一项极具教育意义的活动，使参与者受益。

### 改善评估目标（TOE）的可见性

威胁建模需要深入了解被评估的系统。要正确进行威胁建模，必须了解数据流、信任边界和系统的其他特征。因此，[Stiliyana Simeonova](https://securityintelligence.com/threat-modeling-in-the-enterprise-part-1-understanding-the-basics/) 断言，威胁建模的一个优势是提高了对系统及其交互的可见性。

## 解答每个问题

目前没有被普遍接受的威胁建模流程行业标准，也没有适用于每种情况的"正确"答案。然而，尽管存在这种多样性，大多数方法都以某种形式包括系统建模、威胁识别和风险响应的过程。受这些共性的启发，并遵循上面讨论的威胁建模四个关键问题，本备忘录将威胁建模分解为四个基本步骤：应用分解、威胁识别和排序、缓解措施以及审查和验证。还有一些不太符合这种方法的流程，如 PASTA 和 OCTAVE，每种方法都有热情的支持者。

### 系统建模

系统建模步骤旨在回答"我们正在构建什么？"这个问题。如果不了解系统，就无法真正理解对该系统最适用的威胁；因此，这一步为后续活动提供了关键基础。尽管在威胁建模的第一步可能使用不同的技术，但数据流图（DFD）可以说是最常见的方法。

数据流图允许对系统及其与数据和其他实体的交互进行可视化建模；它们使用[少量简单的符号](https://github.com/adamshostack/DFD3)创建。可以在专门的威胁建模工具（如 [OWASP 的 Threat Dragon](https://github.com/OWASP/threat-dragon) 或 [微软的威胁建模工具](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)）中创建 DFD，也可以使用通用绘图解决方案（如 [draw.io](https://draw.io)）。如果你更喜欢代码形式的方法，[OWASP 的 pytm](https://owasp.org/www-project-pytm/) 可以提供帮助。根据被建模系统的规模和复杂性，可能需要多个 DFD。例如，可以创建一个代表整个系统的高级概述的 DFD，以及若干更详细地描述子系统的 DFD。技术工具并非绝对必要；在某些情况下，白板可能就足够了，尽管最好将 DFD 保存在可以轻松存储、引用和更新的形式。

无论如何生成 DFD 或可比较的模型，重要的是解决方案能清晰地展示信任边界、数据流、数据存储、进程以及可能与系统交互的外部实体。这些往往代表可能的攻击点，并为后续步骤提供关键输入。

另一种数据流图（DFD）的方法是头脑风暴技术，这是一种有效的生成想法和发现项目领域的方法。在这种情况下应用头脑风暴可带来诸多好处，如提高团队参与度、统一知识和术语、建立对领域的共同理解，以及快速识别关键流程和依赖关系。使用头脑风暴的主要论点之一是其灵活性和适应性，几乎可以应用于任何场景，包括业务逻辑。此外，当参与者不太懂技术时，这种技术特别有用，因为它消除了理解和应用 DFD 模型及其正确性的相关障碍。

头脑风暴让所有参与者都参与其中，促进更好的沟通和对问题的相互理解。每个团队成员都有机会贡献，这增加了责任感和参与度。在头脑风暴会议期间，参与者可以协作定义和商定关键术语和概念，从而形成项目中使用的统一语言。这在复杂项目中尤其重要，不同团队可能对术语有不同的理解。由于头脑风暴的动态特性，团队可以快速识别关键业务流程及其相互关系。

将头脑风暴的结果与正式建模技术相结合，可以更好地理解领域并实现更有效的系统设计。

### 威胁识别

在系统建模后，现在是解答"可能出现什么问题？"这个问题的时候。这个问题必须结合第一步的输入来探索；也就是说，它应该专注于在被评估的特定系统背景下识别和排序威胁。在试图回答这个问题时，威胁建模者有丰富的数据源和技术可供选择。为了说明，本备忘录将使用 STRIDE；然而，在实践中，可能会与 STRIDE 一起使用或代替其他方法。

STRIDE 是最初由微软员工开发的成熟且流行的威胁建模技术和助记符。为了便于威胁识别，STRIDE 将威胁分为六个一般性提示，并鼓励工程师系统地考虑这些一般性威胁如何在被评估的特定系统背景下具体化。每个 STRIDE 威胁可以被视为对理想安全属性的违反；类别及相关的理想属性如下：

| 威胁类别             | 违反          | 示例                                                                                     |
| -------------------- | ------------- | ---------------------------------------------------------------------------------------- |
| **S**poofing（欺骗） | 真实性        | 攻击者窃取合法用户的身份验证令牌并使用它来冒充用户。                                     |
| **T**ampering（篡改） | 完整性        | 攻击者滥用应用程序对数据库执行非预期的更新。                                             |
| **R**epudiation（抵赖） | 不可抵赖性    | 攻击者操纵日志以掩盖其行为。                                                             |
| **I**nformation Disclosure（信息泄露） | 机密性        | 攻击者从包含用户账户信息的数据库中提取数据。                                             |
| **D**enial of Service（拒绝服务） | 可用性        | 攻击者通过执行多次失败的身份验证尝试，将合法用户锁定在其账户之外。                       |
| **E**levation of Privileges（权限提升） | 授权          | 攻击者篡改 JWT 以更改其角色。                                                            |

STRIDE 为回答"可能出现什么问题？"提供了宝贵的结构。它也是一种高度灵活的方法，入门不需要很复杂。简单的技术如头脑风暴、白板甚至[游戏](https://github.com/adamshostack/eop/)都可以初步使用。STRIDE 还被整合到流行的威胁建模工具中，如 [OWASP 的 Threat Dragon](https://github.com/OWASP/threat-dragon) 和 [微软的威胁建模工具](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)。此外，作为相对高层次的流程，STRIDE 与更战术的方法（如杀伤链或 [MITRE 的 ATT&CK](https://attack.mitre.org/)）很好地配合（请参考[这篇文章](https://web.isc2ncrchapter.org/under-attck-how-mitres-methodology-to-find-threats-and-embed-counter-measures-might-work-in-your-organization/)了解 STRIDE 和 ATT&CK 如何协同工作）。

识别可能的威胁后，人们通常会对其进行排序。理论上，排序应基于已识别威胁的发生可能性和影响的数学乘积。一个很可能发生并造成严重损害的威胁将被优先级排得much更高，而不太可能发生且只会产生中等影响的威胁则排在后面。然而，这两者都很难计算，而且忽略了解决问题的工作。有些人主张将这些因素纳入单一优先级考虑中。

### 响应和缓解措施

掌握了对系统和适用威胁的理解后，现在是回答"我们将如何应对？"的时候。之前识别的每个威胁都必须有一个响应。威胁响应类似但不完全等同于风险响应。[Adam Shostack](https://shostack.org/resources/threat-modeling) 列出了以下响应：

- **缓解：** 采取行动减少威胁实现的可能性。
- **消除：** 简单地移除导致威胁的功能或组件。
- **转移：** 将责任转移给另一个实体，如客户。
- **接受：** 鉴于业务需求或约束，不缓解、消除或转移风险。

如果决定缓解威胁，必须制定并将缓解策略记录为需求。根据系统的复杂性、已识别威胁的性质以及用于识别威胁的流程（STRIDE 或其他方法），缓解响应可以在类别或单个威胁级别应用。在前一种情况下，缓解将适用于该类别中的所有威胁。缓解策略必须是可操作的，而非假设性的；它们必须是可以实际构建到正在开发的系统中的内容。尽管缓解策略必须针对特定应用量身定制，但诸如 [OWASP 的 ASVS](https://owasp.org/www-project-application-security-verification-standard/) 和 [MITRE 的 CWE 列表](https://cwe.mitre.org/index.html) 等资源在制定这些响应时可能会很有价值。

### 审查与验证

最后，是时候回答"我们是否做得足够好"这个问题了？威胁模型必须由所有利益相关者审查，而不仅仅是开发或安全团队。重点关注的领域包括：

- 数据流图（或类似图）是否准确反映了系统？
- 是否已识别所有威胁？
- 对于每个已识别的威胁，是否已商定应对策略？
- 对于希望通过缓解来应对的已识别威胁，是否已制定能将风险降低到可接受水平的缓解策略？
- 威胁模型是否已正式归档？威胁模型过程的工件是否以"需要知道"的人可访问的方式存储？
- 可以测试商定的缓解措施吗？可以衡量威胁模型的需求和建议的成功或失败吗？

## 威胁建模与开发团队

### 挑战

出于几个关键原因，威胁建模对开发团队来说可能具有挑战性。首先，许多开发人员缺乏安全领域的充分知识和经验，这阻碍了他们有效使用方法论和框架、识别和建模威胁的能力。如果没有对基本安全原则的适当培训和理解，开发人员可能会忽视潜在威胁或错误评估其风险。

此外，威胁建模过程可能复杂且耗时。它需要系统性方法和深入分析，这往往难以与紧张的进度和交付新功能的压力相协调。开发团队可能感到缺乏支持此任务的工具和资源，从而导致沮丧和气馁。

另一个挑战是组织内不同部门之间的沟通和协作。如果开发团队、安全团队和其他利益相关者之间缺乏有效沟通，威胁建模可能不完整或方向错误。

### 应对挑战

在许多情况下，解决方案在于邀请安全团队成员参与威胁建模会议，这可以显著改善流程。安全专家带来关于潜在威胁的关键知识，对有效识别、风险分析和缓解至关重要。他们对网络犯罪分子使用的最新趋势和技术的经验和理解可以为学习和发展开发团队的能力提供关键见解。这种联合会议不仅能提高开发人员的知识，还能建立组织内部的协作和相互支持文化，从而形成更全面的安全方法。

为改变当前状况，组织应投资于为其开发团队进行定期 IT 安全培训。这些培训会议应由专家进行，并针对团队的具体需求定制。此外，实施简化和自动化威胁建模的流程和工具也很有益。这些工具可以帮助识别和评估威胁，使流程更易访问且耗时更少。

重要的是要在整个组织中推广安全文化，使威胁建模被视为软件开发生命周期（SDLC）不可或缺的一部分，而非额外负担。定期审查会议和跨团队研讨会可以改善协作和沟通，从而形成更有效、更全面的安全方法。通过这些行动，组织可以使威胁建模成为一个负担更少、效率更高的过程，为其系统的安全带来真正的好处。

## 参考资料

### 方法和技术

按字母顺序排列的技术：

- [LINDDUN](https://linddun.org/)
- [PASTA](https://cdn2.hubspot.net/hubfs/4598121/Content%20PDFs/VerSprite-PASTA-Threat-Modeling-Process-for-Attack-Simulation-Threat-Analysis.pdf)
- [STRIDE](<https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823878(v=cs.20)?redirectedfrom=MSDN>)
- [OCTAVE](https://insights.sei.cmu.edu/library/introduction-to-the-octave-approach/)
- [VAST](https://go.threatmodeler.com/vast-methodology-data-sheet)

### 工具

- [Cairis](https://github.com/cairis-platform/cairis)
- [draw.io](https://draw.io) - 另请参见该工具的[威胁建模库](https://github.com/michenriksen/drawio-threatmodeling)
- [IriusRisk](https://www.iriusrisk.com/) - 提供免费社区版
- [微软威胁建模工具](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [OWASP 威胁龙](https://github.com/OWASP/threat-dragon)
- [OWASP pytm](https://owasp.org/www-project-pytm/)
- [TaaC-AI](https://github.com/yevh/TaaC-AI) - 人工智能驱动的代码形式威胁建模（TaaC）
- 威胁编辑器 - [演示](https://awslabs.github.io/threat-composer), [仓库](https://github.com/awslabs/threat-composer/)

### 常规参考

- [优秀威胁建模](https://github.com/hysnsec/awesome-threat-modelling) - 资源列表
- [战术威胁建模](https://safecode.org/wp-content/uploads/2017/05/SAFECode_TM_Whitepaper.pdf)
- [威胁建模：可用方法总结](https://insights.sei.cmu.edu/library/threat-modeling-a-summary-of-available-methods/)
- 面向构建者的威胁建模，可在 [AWS 技能构建器](https://explore.skillbuilder.aws/learn/course/external/view/elearning/13274/threat-modeling-for-builders-workshop)和 [AWS 工作坊工作室](https://catalog.workshops.aws/threatmodel/en-US)获取免费在线培训
- [威胁建模手册](https://security.cms.gov/policy-guidance/threat-modeling-handbook)
- [威胁建模流程](https://owasp.org/www-community/Threat_Modeling_Process)
- [威胁建模终极新手指南](https://shostack.org/resources/threat-modeling)
