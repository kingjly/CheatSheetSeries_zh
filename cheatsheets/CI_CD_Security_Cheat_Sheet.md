# CI/CD 安全备忘录

## 介绍

持续集成/持续交付 (CI/CD) 管道和流程在现代软件开发生命周期中起着至关重要的作用，它们能够实现高效、可重复的软件构建与部署。然而，由于其重要性和流行性，CI/CD 管道也成为恶意黑客的目标，并且安全性不容忽视。本速查表旨在为开发者提供实用指南，以减少这些关键组件相关风险。本速查表将重点讨论如何确保 CI/CD 管道本身的安全。

### 定义与背景

CI/CD 指的是一系列主要用于构建和交付软件的大规模自动化流程；通常被描述为一个由一系列顺序、离散步骤组成的管道。该管道一般从开发中的代码推送到仓库开始，如果所有步骤成功完成，则以构建、测试并部署到生产环境结束。CI/CD 可分解为两个部分：持续集成 (CI) 和持续交付或持续部署 (CD)。CI 侧重于构建和测试自动化；而 CD 则专注于将此构建代码推广到测试或更高版本的环境，并通常进行额外的自动化测试。虽然在定义中 CI/CD 的连续交付和持续部署可能不总是区分，但根据 NIST（国家研究所标准技术局）的定义 [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204C.pdf)，连续交付需要手动将代码推送到生产环境，而持续部署则自动化了这一步骤。

CI/CD 管道的具体步骤可能因组织和项目而异；然而，自动化、重复性和灵活性应是任何 CI/CD 实施的核心重点。

### 了解 CI/CD 风险

尽管 CI/CD 带来了许多好处，但它也增加了组织的攻击面。CI/CD 的实现需要人员、流程和技术，所有这些都可能成为攻击途径；代码仓库、如 Jenkins 这样的自动化服务器、部署程序以及运行 CI/CD 管道的节点都是恶意实体可以利用的组件。此外，由于 CI/CD 步骤通常使用高权限身份执行，成功的 CI/CD 攻击往往具有很高的破坏潜力。如果组织选择充分利用 CI/CD 的许多好处，也必须确保投资必要的资源来妥善保护它；Codecov 和 SolarWinds 事件就是两个令人警醒的例子，展示了 CI/CD 被攻破可能带来的潜在影响。

攻击者利用 CI/CD 环境的方法多种多样；然而，某些风险更为突出。虽然不应将自己局限于这些知识，但理解 CI/CD 环境中最主要的风险可以帮助组织更有效地分配安全资源。OWASP（开放Web应用安全项目）的《CI/CD 安全十大风险》是一个有价值的资源 [OWASP](https://owasp.org/www-project-top-10-ci-cd-security-risks/)；该项目识别了以下作为前 10 大 CI/CD 风险：

- CICD-SEC-1：不足的流程控制机制
- CICD-SEC-2：不充分的身份和访问管理
- CICD-SEC-3：依赖链滥用
- CICD-SEC-4：恶意执行管道（PPE）
- CICD-SEC-5：不足的基于流水线的访问控制 (PBAC)
- CICD-SEC-6：不充分的凭据卫生
- CICD-SEC-7：不安全的系统配置
- CICD-SEC-8：不受治理的第三方服务使用
- CICD-SEC-9：不当的文件完整性验证
- CICD-SEC-10：不足的日志记录和可见性

本速查表其余部分将重点提供针对这些前 10 大 CI/CD 风险及其他相关风险的指导。

## 安全配置

必须投入时间和精力来妥善保护支持 CI/CD 过程的组件，如版本控制系统 (SCM) 系统和自动化服务器（Jenkins、TeamCity 等）。无论使用何种具体工具，绝不能盲目依赖默认供应商设置。同时，在不了解全部影响的情况下调整设置或以完全随意的方式进行任何必要的配置更新也是不可取的。变更管理及适当治理必须到位。此外，教育至关重要；在利用工具执行关键的安全操作（如代码部署）之前，务必花时间理解其底层技术。安全配置不会自动完成；它需要教育和规划。

此外，还必须采取措施确保运行或支持上述 CI/CD 组件的操作系统、容器镜像、Web 服务器或其他基础设施的安全性。这些系统必须保持适当修补，并维护一份包含软件版本在内的资产清单。应根据适用的标准（如 [CIS 基准](https://www.cisecurity.org/cis-benchmarks) 或 [STIGs](https://public.cyber.mil/stigs/downloads/)）来强化这些技术。

除了上述一般原则之外，接下来将探讨一些特定于 CI/CD 配置的具体指南。

### 安全的 SCM 配置

CI/CD 环境允许代码被推送到仓库，然后在几乎没有手动干预的情况下部署到生产环境。然而，如果这种好处允许未受信任、可能恶意的代码直接部署到生产系统中，则会迅速成为一个攻击向量。适当配置 SCM 系统可以帮助缓解这一风险。最佳实践包括：

- 避免在如 GitLab（[文档](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)）、GitHub（[文档](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request)）或 Bitbucket 等平台中使用自动合并规则。
- 在合并之前要求代码拉取请求进行审查，并确保此审查步骤不能被绕过。
- 利用 [保护分支](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)。
- 要求提交时进行签名
- 仔细权衡允许临时贡献者的风险与利益。尽可能限制外部贡献的数量和权限。
- 在可能的情况下启用多因素身份验证 (MFA)
- 避免为具有访问 SCM 资产的用户和角色分配默认权限。精心管理您的权限。
- 限制私有或内部仓库的分支克隆功能。
- 限制更改仓库可见性至公共选项。

您可以在此 [文档](https://policies.legitify.dev/) 中找到更多相关策略。

为了帮助导航 SCM 配置挑战，有一些可用的工具，例如 Legitify（[GitHub](https://github.com/Legit-Labs/legitify)），这是由 Legit 安全公司开发的一个开源工具。Legitify 扫描 SCM 资产并识别配置错误和安全问题，包括所有上述最佳实践策略（适用于 GitHub 和 GitLab）。

### 管道和执行环境

除了版本控制系统外，还必须确保负责运行管道的自动化服务器也进行了安全配置。这些技术示例包括 Travis、TeamCity、Jenkins 和 CircleCI。虽然具体的强化过程会根据所使用的特定平台而有所不同，但一些通用的最佳实践包括：

- 在适当隔离的节点上执行构建（参见 Jenkins 示例 [这里](https://www.jenkins.io/doc/book/security/controller-isolation/)）
- 确保 SCM 与 CI/CD 平台之间的通信使用广泛接受的协议（如 TLS 1.2 或更高版本）进行加密。
- 如果可能，通过 IP 控制对 CI/CD 环境的访问。
- 如果可行，在代码仓库之外存储 CI 配置文件。如果将文件放在与构建代码相同的仓库中，则在批准任何合并请求之前必须审查该文件。
- 启用适当的日志记录级别（参见 [可见性和监控](#visibility-and-monitoring) 下面讨论）
- 将语言相关的 SAST、DAST 和 IaC 漏洞扫描工具及相关工具整合到管道中。
- 在触发生产部署之前要求手动批准和审查。
- 如果流水线步骤在 Docker 镜像中执行，请避免使用 `--privileged` 标志 [参考](https://research.nccgroup.com/2022/01/13/10-real-world-stories-of-how-weve-compromised-ci-cd-pipelines/)
- 确保流水线配置代码进行版本控制（[参考](https://www.cisa.gov/sites/default/files/publications/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF)）
- 在可能的情况下强制启用多因素身份验证 (MFA)

## IAM

身份和访问管理 (IAM) 是管理和控制数字资源访问的一种过程。身份示例包括系统账户、角色、组或个别用户账户。IAM 广泛应用于 CI/CD 之外的许多领域，但身份及其底层凭据的误管理是影响 CI/CD 环境的主要风险之一。以下部分将突出一些特别相关的 IAM 安全最佳实践。

### 密钥管理

在 CI/CD 环境中，密钥（如 API 密钥或密码）通常用于执行成功所需的步骤。CI/CD 环境中的密钥可能很多，并且至少有些提供对敏感系统或操作的大量访问权限。这种组合引入了挑战：如何安全地管理这些密钥并允许自动化 CI/CD 过程按需访问它们？遵循一些简单指南可以帮助显著降低风险，但不可能完全消除。

首先，应采取措施减少密钥被盗用的可能性。密钥 **绝不能** 在代码仓库或 CI/CD 配置文件中硬编码。可以使用 [git-leaks](https://github.com/gitleaks/gitleaks) 或 [git-secrets](https://github.com/awslabs/git-secrets) 等工具检测此类密钥。应努力防止密钥被提交，并进行持续监控以检测任何偏差。密钥还必须从其他资产（如 Docker 镜像和编译的二进制文件）中移除。密钥始终必须使用行业认可的标准加密。在文件系统、保险库或其他存储中对密钥进行静态加密，但务必确保这些密钥不会因 CI/CD 管道中的使用而以明文形式披露或持久化。例如，密钥不应打印到控制台、记录日志或存储在系统的命令历史文件（如 `~/.bash-history`）中。可以使用第三方解决方案如 HashiCorp Vault（[参考](https://www.hashicorp.com/products/vault)）、AWS Secrets Manager（[参考](https://aws.amazon.com/secrets-manager/)）、AKeyless（[参考](https://www.akeyless.io/)）或 CyberArk（[参考](https://www.cyberark.com/)）来实现此目的。

其次，必须采取措施减少在密钥以攻击者可利用格式被盗用的情况下影响。使用临时凭据或一次性密码 (OTP) 是一种降低影响的方法。此外，可以施加基于 IP 的或其他限制，即使有效凭据也需满足这些进一步要求才能访问资源。[最小权限](#least-privilege) 和 [身份生命周期管理](#identity-lifecycle-management) 部分提供了进一步减少与密钥被盗用相关的风险的技术。

### 最小权限

最小权限由 NIST（美国国家标准与技术研究所）定义为：

> 一种安全架构设计原则，即每个实体只被授予执行其功能所需的最少系统资源和授权。”

在 CI/CD 环境中，这一原则应应用于至少三个主要领域：流水线步骤用于访问外部资源的密钥、一个流水线或步骤对 CI/CD 平台中配置的其他资源（如 Palo Alto Networks）的访问权限以及操作系统用户执行流水线时的权限。

无论具体应用如何，一般指导方针仍然相同：必须证明授权，而不能假设。应采用“默认拒绝”的心态。任何用于流水线的身份都只能被分配完成其任务所需的最小权限。例如，如果一个流水线必须访问 AWS 服务以完成其任务，则该流水线中使用的 AWS 凭据仅能执行特定操作、特定服务和资源所需的操作。同样，流水线之间的凭据共享应尽可能减少；特别是不应在具有不同敏感度或价值级别的流水线之间共享。如果流水线 A 不需要访问与流水线 B 所需相同的密钥，则它们原则上不应该被共享。最后，负责运行流水线的 OS 账户不应拥有 root 或类似权限；这将有助于减轻授权后的影响。

### 身份生命周期管理

尽管正确的密钥管理和最小权限原则对于安全 IAM 是必要的，但它们并不足够。身份从创建到撤销的过程必须仔细管理，以减少 CI/CD 和其他环境中的风险。

在身份管理的初始或“加入者”阶段（根据 [ILM 指南](https://www.idmanagement.gov/playbooks/ilm/) 定义），考虑因素包括使用中央 IdP 而不是允许本地账户、禁止共享账户、禁止自我生成身份，并仅允许与负责 CI/CD 环境的组织相关的域中的电子邮件帐户。一旦创建，身份必须被跟踪、维护，并在必要时撤销。特别是在复杂的分布式 CI/CD 环境中，确保维护准确、全面且最新的身份库存尤为重要。此库存的具体格式可能因组织需求而异，但除了身份本身外，建议字段还包括身份所有者或责任人、身份提供者、最后使用时间、最后更新时间、授予的权限以及实际使用的权限。此类库存将有助于快速识别可能存在过度授权的身份或可能是撤销候选的身份。正确的身份维护不可忽视；“遗忘”的身份可以成为攻击者利用以攻破 CI/CD 系统的途径。

## 第三方代码管理

部分由于 SolarWinds 事件等高调泄露，软件供应链安全的概念近年来受到了越来越多的关注。在 CI/CD 的背景下，这种问题尤其紧迫，因为此类环境通过多种方式与第三方代码交互。下面将讨论两个这样的交互区域：运行在管道内的项目所使用的依赖项和 CI/CD 系统本身的第三方集成和插件。

### 依赖管理

使用已知存在漏洞的第三方包是软件工程中的一个众所周知的问题，并且已经开发了许多工具来解决这一问题。在 CI/CD 的背景下，自动化的 SCA（软件组成分析）和其他类似工具实际上可以帮助改善此区域的安全性。然而，在 CI/CD 环境本身也存在另一种不同的但相关的风险：依赖链滥用。

依赖链滥用涉及利用系统依赖链和依赖解析过程中的漏洞；成功的攻击可能导致从受控包中执行恶意代码。依赖链是指一个软件解决方案所需的一系列包，包括内部、直接第三方以及传递依赖项的集合。攻击者可以通过诸如 [依赖混淆](https://fossa.com/blog/dependency-confusion-understanding-preventing-attacks/)、[同音域名劫持](https://blog.gitguardian.com/protecting-your-software-supply-chain-understanding-typosquatting-and-dependency-confusion-attacks/) 或接管有效包维护者的账号等方法利用此依赖链。依赖链滥用攻击可能相当复杂，相应的防御措施也相应复杂；然而，基本的缓解措施却非常简单。

缓解技术始于 SDLC（软件开发生命周期）早期，在 CI/CD 管道开始执行之前。项目的包管理技术（如 npm）应配置为确保依赖引用不可变 [CISA et al. (2022)](https://www.cisa.gov/sites/default/files/publications/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF)。进行版本锁定，所选择的版本必须是已知有效且安全的版本，并通过将下载包的哈希或校验和与已知良好哈希值进行比较来验证任何系统下载包的完整性。具体实现此目标的过程将根据项目的底层技术而异，但一般而言，版本锁定和哈希验证可以通过平台的“锁”文件（如 [package-lock.json](https://docs.npmjs.com/cli/v7/configuring-npm/package-lock-json) 或 [Pipfile.lock](https://pipenv.pypa.io/en/latest/pipfile.html)）来完成。尽可能使用私有仓库，并配置包管理器仅使用单一私有源（Microsoft, 2021）。对于私有包，利用 [scoped NPM 包](https://docs.npmjs.com/cli/v10/using-npm/scope)、[NuGet 包的 ID 前缀](https://learn.microsoft.com/en-us/nuget/nuget-org/id-prefix-reservation) 或类似功能以减少依赖混淆的风险。最后，无论使用哪个平台，确保负责控制这些设置的文件（如 node 环境中的 .npmrc）被提交到源代码控制系统并可在 CI/CD 环境中访问。

### 插件和集成管理

大多数 CI/CD 平台可以通过插件或其他第三方集成来扩展。虽然这些扩展可以带来许多好处，包括可能提高系统的安全能力，但也增加了攻击面。这并不是说应该禁止使用插件；相反，风险必须被考虑并降低到可接受的水平。

安装插件或与第三方服务集成应像任何软件的获取一样进行管理。这些工具通常很容易安装和配置，但这并不意味着它们的安装和使用应该不受控制。必须实施最小权限原则，以确保只有少量用户才有扩展 CI/CD 平台所需的权限。此外，在安装之前必须对这些扩展进行审核。在软件获取前应考虑的问题类似：

- 供应商是否是公认的且受尊敬的开发者或公司？
- 供应商在应用程序安全方面有怎样的历史记录（强或弱）？
- 特定插件或集成端点有多受欢迎？
- 插件或集成是否被积极维护？
- 此扩展是否会要求配置更改从而降低安全性（例如，暴露额外的端口）？
- 组织是否有适当的资源和经验来正确配置和维护此扩展？

在批准插件或其他集成后，必须将其纳入组织的配置管理流程中。该软件必须保持最新，并特别注意任何安全补丁。此外，还必须不断审查其价值；如果不再需要，则应移除该扩展。

## 完整性保障

CI/CD 攻击通常要求攻击者在流水线正常流程中插入自身并修改一个或多个步骤的输入和输出。因此，完整性验证是减少 CI/CD 环境风险的重要方法之一。

与其他防御措施一样，实施与完整性相关的控制从 SDLC 的早期阶段就开始。正如早前所述，SCM 应要求在代码可以合并之前提交被签名。此外，在 [依赖管理](#dependency-management) 中讨论过，包管理系统应配置为使用哈希或其他方式验证包的完整性。代码签名也应被采用；技术如 Sigstore（[参考](https://www.sigstore.dev/)）或 Signserver（[参考](https://www.signserver.org/)）可用于此目的。然而，重要的是要指出，代码签名及相关技术并不是绝对的安全保障；代码签名过程本身也可能被利用。请参阅 [NIST 的代码签名安全考量](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01262018.pdf) 以获得进一步的指南，确保代码签名过程的安全性。最后，集成 in-toto.to 或类似框架可以进一步帮助在 CI/CD 环境中提高完整性。

## 可见性和监控

CI/CD 环境可能非常复杂，并且对开发者来说往往像是一个黑箱。然而，这些系统的可见性对于检测潜在攻击、更好地了解自身风险状况以及检测和修复漏洞至关重要。虽然其价值经常被低估，但日志记录和分析对于提供 CI/CD 系统的可见性是至关重要的。

提高 CI/CD 可见性的第一步是确保 CI/CD 环境内的日志配置符合组织的日志管理策略。除了遵守内部政策外，还应将系统配置为以易于解析的格式（如 JSON 或 syslog）记录数据。仔细考虑需要记录的内容和详细程度。虽然适当的日志记录应该允许对管道进行端到端跟踪，但更多的日志并不总是更好的。不仅必须考虑与日志相关的存储成本，还需要小心避免记录任何敏感信息。例如，大多数身份验证相关事件可能应被记录。然而，绝不要记录明文密码、认证令牌、API 密钥等敏感秘密。

一旦定义了适当的日志策略并进行了必要的配置，则可以开始利用这些日志来降低风险。将聚合的日志发送到集中式日志管理系统或更理想的 SIEM（安全信息与事件管理）系统是实现日志价值的第一步。如果使用 SIEM，应仔细配置告警，并定期调整以提供及时的异常和潜在攻击警告。具体的配置将根据 CI/CD 环境、SIEM 平台和其他因素而异。有关 ELK Stack（一个流行的 SIEM 平台）上下文中的 CI/CD 可观察性的概述，请参阅此 [文章](https://www.elastic.co/guide/en/observability/current/ci-cd-observability.html#ci-cd-developers) 或参考 [这篇文章](https://dzone.com/articles/jenkins-log-monitoring-with-elk)，该文提供了可适应各种 CI/CD 环境的替代方法。重要的是要记住，SIEM 告警永远不会 100% 准确地检测到 CI/CD 攻击。假阳性和假阴性都会发生。这些平台不应被无条件依赖，但它们确实提供了关于 CI/CD 环境的重要可见性，并在精心配置时可以作为重要的告警系统。

## 参考资料

### 通用参考文献

- [CISA, NSA & ODNI (2022). 保护软件供应链：开发人员推荐的过程](https://www.cisa.gov/sites/default/files/publications/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.PDF)
- [Microsoft (2021). 使用私有包源减轻风险的三种方法](https://azure.microsoft.com/mediahandler/files/resourcefiles/3-ways-to-mitigate-risk-using-private-package-feeds/3%20Ways%20to%20Mitigate%20Risk%20When%20Using%20Private%20Package%20Feeds%20-%20v1.0.pdf)
- [OWASP (n.d.). CI/CD 安全十大风险](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Palo Alto Networks (n.d.). 不足的基于流水线的访问控制](https://www.paloaltonetworks.com/cyberpedia/pipeline-based-access-controls-cicd-sec5)

### CI/CD 平台

- [CircleCI](https://circleci.com/)
- [Jenkins](https://www.jenkins.io/)
- [SignServer](https://www.signserver.org/)
- [TeamCity](https://www.jetbrains.com/teamcity/)
- [TravisCI](https://www.travisci.net/)

### IaC 扫描

- [Checkov](https://www.checkov.io/)
- [Kics](https://www.kics.io/)
- [SonarSource](https://www.sonarsource.com/)
- [TerraScan](https://runterrascan.io/)

### 完整性验证和签名

- [In-toto](https://in-toto.io/)
- [SignServer](https://www.signserver.org/)
- [SigStore](https://www.sigstore.dev/)
- [SLSA](https://slsa.dev/)

### 密钥管理工具

- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/)
- [CyberArk Secrets Management](https://www.cyberark.com/products/secrets-management/)
- [Google Cloud Key Management](https://cloud.google.com/security/products/security-key-management)
- [HashiCorp Vault](https://www.hashicorp.com/products/vault)
