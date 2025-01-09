# Kubernetes 安全备忘录

## 概述

本备忘录为保护 Kubernetes 集群提供了起点。内容分为以下类别：

- 接收 Kubernetes 更新通知
- 介绍：什么是 Kubernetes？
- 保护 Kubernetes 主机
- 保护 Kubernetes 组件
- 使用 Kubernetes 仪表板
- Kubernetes 安全最佳实践：构建阶段
- Kubernetes 安全最佳实践：部署阶段
- Kubernetes 安全最佳实践：运行时阶段

欲了解更多关于 Kubernetes 的信息，请参阅附录。

## 接收安全更新通知和报告漏洞

加入 kubernetes-announce 群组（<https://kubernetes.io/docs/reference/issues-security/security/>）以接收安全公告邮件。有关如何报告漏洞的更多信息，请查看安全报告页面（<https://kubernetes.io/docs/reference/issues-security/security>）。

## 介绍：什么是 Kubernetes？

Kubernetes 是一个用于自动部署、扩展和管理容器化应用程序的开源容器编排引擎。该开源项目由云原生计算基金会（CNCF）托管。

部署 Kubernetes 时，您将获得一个集群。Kubernetes 集群由一组运行容器化应用程序的工作机器（称为节点）组成。控制平面管理集群中的工作节点和 Pod。

### 控制平面组件

控制平面的组件对集群做全局决策，并检测和响应集群事件。它由 kube-apiserver、etcd、kube-scheduler、kube-controller-manager 和 cloud-controller-manager 等组件组成。

**组件：** kube-apiserver  
**描述：** 公开 Kubernetes API。API 服务器是 Kubernetes 控制平面的前端。

**组件：** etcd  
**描述：** 一个一致且高可用的键值存储，用作 Kubernetes 所有集群数据的后备存储。

**组件：** kube-scheduler  
**描述：** 监视新创建且尚未分配节点的 Pod，并为其选择运行节点。

**组件：** kube-controller-manager  
**描述：** 运行控制器进程。从逻辑上讲，每个控制器是一个单独的进程，但为了降低复杂性，它们都编译到单个二进制文件中并在单个进程中运行。

**组件：** cloud-controller-manager  
**描述：** 云控制器管理器允许您将集群链接到云提供商的 API，并将与云平台交互的组件与仅与集群交互的组件分离。

### 节点组件

节点组件在每个节点上运行，维护运行中的 Pod 并提供 Kubernetes 运行时环境。它由 kubelet、kube-proxy 和容器运行时等组件组成。

**组件：** kubelet  
**描述：** 在集群中每个节点上运行的代理。确保容器在 Pod 中运行。

**组件：** kube-proxy  
**描述：** 在集群中每个节点上运行的网络代理，实现 Kubernetes Service 概念的一部分。

**容器：** 运行时  
**描述：** 容器运行时是负责运行容器的软件

## 第 1 节：保护 Kubernetes 主机

Kubernetes 可以通过多种方式部署：在裸机上、本地或公有云（自定义 Kubernetes 构建在虚拟机上或使用托管服务）。由于 Kubernetes 设计为高度可移植，客户可以轻松迁移工作负载并在多个安装之间切换。

因为 Kubernetes 可以设计以适应各种场景，所以这种灵活性在保护 Kubernetes 集群时是一个弱点。负责部署 Kubernetes 平台的工程师必须了解其集群的所有潜在攻击向量和漏洞。

为了加固 Kubernetes 集群的底层主机，我们建议：
- 安装操作系统的最新版本
- 加固操作系统
- 实施必要的补丁管理和配置管理系统
- 实施基本防火墙规则
- 执行特定的数据中心安全措施

### 更新 Kubernetes

由于没有人能追踪您的 Kubernetes 集群的所有潜在攻击向量，首要且最佳防御是始终运行 Kubernetes 的最新稳定版本。

对于在运行容器中发现的漏洞，建议始终更新源镜像并重新部署容器。**尽量避免直接更新正在运行的容器，因为这可能会破坏镜像-容器关系。**

```
示例：apt-update
```

**使用 Kubernetes 滚动更新功能可以极其轻松地升级容器 - 这允许通过将其镜像逐步升级到最新版本来更新正在运行的应用程序。**

#### Kubernetes 发布时间表

Kubernetes 项目为最近的三个次要版本维护发布分支，并根据严重性和可行性，将适用的修复（包括安全修复）反向移植到这三个发布分支。补丁版本按定期节奏从这些分支中切出，并在必要时额外发布紧急版本。因此，始终建议将 Kubernetes 集群升级到最新可用的稳定版本。建议参考版本偏差策略以获取更多详细信息 <https://kubernetes.io/docs/setup/release/version-skew-policy/>。

有几种技术，如滚动更新和节点池迁移，可以让您以最小的中断和停机时间完成更新。

## 第 2 节：保护 Kubernetes 组件

本节讨论如何保护 Kubernetes 组件。涵盖以下主题：

- 保护 Kubernetes 仪表板
- 限制对 etcd 的访问（重要）
- 控制对敏感端口的网络访问
- 控制对 Kubernetes API 的访问
- 在 Kubernetes 中实施基于角色的访问控制
- 限制对 Kubelets 的访问

### 保护 Kubernetes 仪表板

Kubernetes 仪表板是用于管理集群的 Web 应用程序。它不是 Kubernetes 集群本身的一部分，必须由集群所有者安装。因此，有很多关于如何安装的教程。不幸的是，大多数教程创建了具有非常高权限的服务帐户。这导致特斯拉和其他一些公司通过这种配置不当的 K8s 仪表板被黑。（参考：特斯拉云资源被黑用于挖矿 - <https://arstechnica.com/information-technology/2018/02/tesla-cloud-resources-are-hacked-to-run-cryptocurrency-mining-malware/>）

为防止通过仪表板的攻击，您应遵循以下建议：

- 不要在没有额外身份验证的情况下将仪表板暴露给公众。无需从外部网络访问如此强大的工具
- 启用基于角色的访问控制（见下文），以便可以限制仪表板使用的服务帐户
- 不要为仪表板服务帐户授予高权限
- 按用户授予权限，使每个用户只能看到他们应该看到的内容
- 如果使用网络策略，可以阻止来自内部 Pod 的仪表板请求（这不会影响通过 kubectl proxy 的代理隧道）
- 在 1.8 版本之前，仪表板有一个具有完全权限的服务帐户，因此检查是否遗留有集群管理员的角色绑定
- 使用经过身份验证的反向代理部署仪表板，并启用多因素身份验证。这可以通过嵌入式 OIDC `id_tokens` 或使用 Kubernetes 模拟来完成。这允许您使用用户的凭据而不是使用特权 `ServiceAccount` 来使用仪表板。此方法可用于本地和托管云集群。

### 限制对 etcd 的访问（重要）

etcd 是一个关键的 Kubernetes 组件，存储状态和机密信息，应与集群的其他部分不同地保护。对 API 服务器的 etcd 的写入访问等同于获得整个集群的 root 权限，即使读取访问也可以相当容易地用于提升权限。

Kubernetes 调度程序将搜索 etcd 中尚未分配节点的 Pod 定义。然后，它将找到的 Pod 发送到可用的 kubelet 进行调度。API 服务器在将 Pod 写入 etcd 之前会对提交的 Pod 进行验证，因此恶意用户直接写入 etcd 可以绕过许多安全机制 - 例如 PodSecurityPolicies。

管理员应始终对 API 服务器到 etcd 服务器使用强凭据，如通过 TLS 客户端证书进行的相互认证，并且通常建议将 etcd 服务器隔离在防火墙后，只有 API 服务器可以访问。

#### 限制对主 etcd 实例的访问

允许集群中的其他组件访问主 etcd 实例并对完整键空间进行读取或写入访问，相当于授予集群管理员访问权限。强烈建议对其他组件使用单独的 etcd 实例，或使用 etcd ACL 将读写访问限制到键空间的子集。

### 控制对敏感端口的网络访问

强烈建议在集群和集群节点上配置身份验证和授权。由于 Kubernetes 集群通常在一系列定义明确且独特的端口上侦听，因此攻击者更容易识别集群并攻击它们。

下面提供了 Kubernetes 中使用的默认端口概述。确保您的网络阻止对端口的访问，并且您应该认真考虑将对 Kubernetes API 服务器的访问限制在可信网络。

**控制平面节点：**

| 协议 | 端口范围 | 目的                   |
| ---- | -------- | ---------------------- |
| TCP  | 6443-    | Kubernetes API 服务器  |
| TCP  | 2379-2380| etcd 服务器客户端 API  |
| TCP  | 10250    | Kubelet API            |
| TCP  | 10251    | kube-scheduler         |
| TCP  | 10252    | kube-controller-manager|
| TCP  | 10255    | 只读 Kubelet API       |

**工作节点：**

| 协议 | 端口范围  | 目的               |
| ---- | --------- | ------------------ |
| TCP  | 10250     | Kubelet API        |
| TCP  | 10255     | 只读 Kubelet API   |
| TCP  | 30000-32767| NodePort 服务      |

--

### 控制对 Kubernetes API 的访问

Kubernetes 针对攻击者的第一道防线是限制和保护对 API 请求的访问，因为这些请求用于控制 Kubernetes 平台。欲了解更多信息，请参考 <https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/> 上的文档。

本部分包含以下主题：

- Kubernetes 如何处理 API 授权
- Kubernetes 的外部 API 身份验证（推荐）
- Kubernetes 内置 API 身份验证（不推荐）
- 在 Kubernetes 中实施基于角色的访问控制
- 限制对 Kubelets 的访问

--

#### Kubernetes 如何处理 API 授权

在 Kubernetes 中，在请求被授权（授予访问权限）之前，您必须先通过身份验证（登录），并且 Kubernetes 期望 REST API 请求的常见属性。这意味着可能处理其他 API 的组织范围或云提供商范围的访问控制系统也可以与 Kubernetes 授权一起工作。

当 Kubernetes 使用 API 服务器授权 API 请求时，默认拒绝权限。它根据所有策略评估请求的所有属性并允许或拒绝请求。API 请求的所有部分必须得到某些策略的允许才能继续。

--

#### Kubernetes 的外部 API 身份验证（推荐）

由于 Kubernetes 内部 API 身份验证机制的弱点，我们强烈建议大型或生产集群使用外部 API 身份验证方法之一。

- [OpenID Connect](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)（OIDC）允许您外部化身份验证，使用短期令牌，并利用集中式组进行授权。
- 托管的 Kubernetes 发行版，如 GKE、EKS 和 AKS，支持使用各自 IAM 提供商的凭据进行身份验证。
- [Kubernetes 模拟](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)可用于托管云集群和本地集群，以外部化身份验证，而无需访问 API 服务器配置参数。

除了选择适当的身份验证系统外，API 访问应被视为特权，并对所有用户访问使用多因素身份验证（MFA）。

欲了解更多信息，请查阅 Kubernetes 身份验证参考文档 <https://kubernetes.io/docs/reference/access-authn-authz/authentication>。

--

#### Kubernetes 内置 API 身份验证选项（不推荐）

Kubernetes 提供了多种 API 服务器内部身份验证机制，但这些通常仅适用于非生产或小型集群。我们将简要讨论每种内部机制并解释为什么不应使用它们。

- [静态令牌文件](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#static-token-file)：身份验证使用存储在 API 服务器节点上的 CSV 文件中的明文令牌。警告：在重新启动 API 服务器之前，您无法修改此文件中的凭据。

- [X509 客户端证书](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certs)可用，但不适合生产使用，因为 Kubernetes [不支持证书吊销](https://github.com/kubernetes/kubernetes/issues/18982)。因此，这些用户凭据无法在不轮换根证书颁发机构密钥并重新颁发所有集群证书的情况下修改或吊销。

- [服务帐户令牌](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens)也可用于身份验证。其主要intended用途是允许在集群中运行的工作负载向 API 服务器进行身份验证，但也可用于用户身份验证。

--

### 在 Kubernetes 中实施基于角色的访问控制

基于角色的访问控制（RBAC）是一种根据组织中个人用户的角色来管理对计算机或网络资源访问的方法。幸运的是，Kubernetes 自带了一个集成的基于角色的访问控制（RBAC）组件，其默认角色允许您根据客户端可能想要执行的操作来定义用户职责。您应该将节点和 RBAC 授权器与 NodeRestriction 准入插件一起使用。

RBAC 组件将传入的用户或组与链接到角色的一组权限匹配。这些权限将动词（获取、创建、删除）与资源（Pod、服务、节点）相结合，可以是命名空间或集群范围。RBAC 授权使用 rbac.authorization.k8s.io API 组来驱动授权决策，允许您通过 Kubernetes API 动态配置策略。

要启用 RBAC，请使用包含 RBAC 的逗号分隔列表启动 API 服务器的 --authorization-mode 标志；例如：

```bash
kube-apiserver --authorization-mode=Example,RBAC --other-options --more-options
```

有关利用 RBAC 的详细示例，请参考 Kubernetes 文档 <https://kubernetes.io/docs/reference/access-authn-authz/rbac>

--

### 限制对 Kubelets 的访问

Kubelets 公开 HTTPS 端点，授予对节点和容器的强大控制。默认情况下，Kubelets 允许对此 API 进行未经身份验证的访问。生产集群应启用 Kubelet 身份验证和授权。

欲了解更多信息，请参考 Kubelet 身份验证/授权文档 <https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/>

--

## 第 3 节：Kubernetes 安全最佳实践：构建阶段

在构建阶段，您应通过构建安全镜像并扫描这些镜像以发现任何已知漏洞来保护 Kubernetes 容器镜像。

--

### 什么是容器镜像？

容器镜像（CI）是一个不可变的、轻量级、独立的可执行软件包，包含运行应用程序所需的所有内容：代码、运行时、系统工具、系统库和设置 [<https://www.docker.com/resources/what-container>]。每个镜像共享主机机器中存在的操作系统内核。

您的容器镜像必须基于经批准和安全的基础镜像构建。这个基础镜像必须定期扫描和监控，以确保所有容器镜像都基于安全和可信的镜像。实施强有力的治理策略，确定镜像的构建方式以及存储在可信镜像仓库中的方式。

--

#### 确保容器镜像是最新的

确保您的镜像（以及包含的任何第三方工具）是最新的，并使用其组件的最新版本。

--

### 仅在您的环境中使用授权镜像

从未知来源下载和运行容器镜像非常危险。确保只允许运行符合组织策略的镜像，否则组织将面临运行易受攻击甚至恶意容器的风险。

--

### 使用 CI 管道控制和识别漏洞

Kubernetes 容器注册表作为系统中所有容器镜像的中央仓库。根据您的需求，您可以使用公共仓库或拥有私有仓库作为容器注册表。我们建议您将批准的镜像存储在私有注册表中，并且仅推送批准的镜像到这些注册表，这将自动将进入管道的潜在镜像数量从数十万个公开可用镜像减少到一小部分。

我们强烈建议您添加一个 CI 管道，将安全评估（如漏洞扫描）集成到构建过程中。此管道应审查所有批准用于生产的代码并用于构建镜像。镜像构建后，应对其进行安全漏洞扫描。只有在未发现问题时，镜像才会被推送到私有注册表并部署到生产环境。如果安全评估机制对任何代码失败，它应在管道中创建失败，这将帮助您找到存在安全问题的镜像并阻止它们进入镜像注册表。

许多源代码仓库提供扫描功能（例如 [Github](https://docs.github.com/en/code-security/supply-chain-security)、[GitLab](https://docs.gitlab.com/ee/user/application_security/container_scanning/index.html)），许多 CI 工具提供与开源漏洞扫描器（如 [Trivy](https://github.com/aquasecurity/trivy) 或 [Grype](https://github.com/anchore/grype)）的集成。

项目正在开发 Kubernetes 的镜像授权插件，以防止未经授权的镜像发布。欲了解更多信息，请参考 PR <https://github.com/kubernetes/kubernetes/pull/27129>。

--

### 最小化所有 CI 中的功能

作为最佳实践，谷歌和其他科技巨头多年来一直严格限制其运行时容器中的代码。这种方法提高了扫描器（例如 CVE）的信噪比，并将建立出处的负担仅限于您所需的内容。

考虑使用最小的 CI，如无发行版镜像（见下文）。如果这是不可能的，请不要在 CI 中包含操作系统包管理器或 shell，因为它们可能存在未知的漏洞。如果绝对必须包含任何操作系统软件包，请在生成过程的后续步骤中删除包管理器。

--

#### 尽可能使用无发行版或空镜像

无发行版镜像通过不包含 shell 且包含的软件包比其他镜像少，大大减少了攻击面。有关无发行版镜像的更多信息，请参考 <https://github.com/GoogleContainerTools/distroless>。

空镜像对于静态编译语言（如 Go）来说是理想的，因为镜像是空的 - 其攻击面确实是最小的 - 只有您的代码！

欲了解更多信息，请参考 <https://hub.docker.com/_/scratch>

---

## 第 4 节：Kubernetes 安全最佳实践：部署阶段

一旦 Kubernetes 基础设施就位，在部署任何工作负载之前，必须对其进行安全配置。在配置基础设施时，确保您能够了解正在部署的容器镜像以及部署方式，否则将无法识别和响应安全策略违规。在部署之前，您的系统应该知道并能告诉您：

- **正在部署什么** - 包括正在使用的镜像的信息，如组件或漏洞，以及将要部署的 Pod。
- **部署到哪里** - 哪些集群、命名空间和节点。
- **如何部署** - 是否以特权模式运行，可以与哪些其他部署通信，应用了什么 Pod 安全上下文（如果有）。
- **可以访问什么** - 包括 Secrets、卷和其他基础设施组件，如主机或编排器 API。
- **是否合规？** - 是否符合您的策略和安全要求。

--

### 使用命名空间隔离 Kubernetes 资源的代码

命名空间使您能够创建逻辑分区，强制资源分离并限制用户权限的范围。

--

#### 为请求设置命名空间

要为当前请求设置命名空间，请使用 --namespace 标志。参考以下示例：

```bash
kubectl run nginx --image=nginx --namespace=<insert-namespace-name-here>
kubectl get pods --namespace=<insert-namespace-name-here>
```

--

#### 设置命名空间首选项

您可以使用以下命令永久保存当前上下文中所有后续 kubectl 命令的命名空间：

```bash
kubectl config set-context --current --namespace=<insert-namespace-name-here>
```

然后使用以下命令验证：

```bash
kubectl config view --minify | grep namespace:
```

在 <https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces> 了解更多关于命名空间的信息

--

### 使用 ImagePolicyWebhook 管理镜像来源

我们强烈建议使用准入控制器 ImagePolicyWebhook 来：
- 防止使用未经批准的镜像
- 拒绝使用未经批准镜像的 Pod
- 拒绝符合以下条件的容器镜像：
  - 最近未经扫描的镜像
  - 使用未明确允许的基础镜像
  - 来自不安全的注册表的镜像

在 <https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook> 了解更多关于 webhook 的信息

--

### 实施持续的安全漏洞扫描

由于新的漏洞不断被发现，您可能并不总是知道容器是否存在最近披露的漏洞（CVE）或过时的软件包。为保持强大的安全态势，请定期对自有容器（您构建并之前已扫描的应用程序）和第三方容器（来自可信仓库和供应商）进行生产扫描。

开源项目如 [ThreatMapper](https://github.com/deepfence/ThreatMapper) 可以帮助识别和优先处理漏洞。

--

### 对 Pod 和容器应用安全上下文

安全上下文是在部署 yaml 中定义的属性，用于控制所有 Pod/容器/卷的安全参数，并且应该在整个基础设施中应用。当安全上下文属性在各处正确实施时，可以消除依赖特权访问的整类攻击。例如，如果在安全上下文中指定只读根文件系统，任何依赖安装软件或写入文件系统的攻击都将被阻止。

在为 Pod 配置安全上下文时，只授予资源在容器和卷中正常运行所需的权限。安全上下文属性中一些重要的参数包括：

安全上下文设置：

1. SecurityContext->**runAsNonRoot**  
   描述：指示容器应以非 root 用户运行。

2. SecurityContext->**Capabilities**  
   描述：控制分配给容器的 Linux 权能。

3. SecurityContext->**readOnlyRootFilesystem**  
   描述：控制容器是否能够写入根文件系统。

4. PodSecurityContext->**runAsNonRoot**  
   描述：防止在 Pod 中以 'root' 用户身份运行容器。

#### 安全上下文示例：包含安全上下文参数的 Pod 定义

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hello-world
spec:
  containers:
  # Pod 容器的规格
  # ...
  # ...
  # 安全上下文
  securityContext:
    readOnlyRootFilesystem: true
    runAsNonRoot: true
```

有关 Pod 安全上下文的更多信息，请参考 <https://kubernetes.io/docs/tasks/configure-pod-container/security-context> 上的文档

--

### 持续评估容器使用的权限

我们强烈建议所有容器都遵循最小权限原则，因为您的安全风险在很大程度上受到授予容器的权能、角色绑定和权限的影响。每个容器只应具有执行其预期功能所需的最小权限和权能。

#### 利用 Pod 安全标准和内置的 Pod 安全准入控制器来强制执行容器权限级别

Pod 安全标准结合 Pod 安全准入控制器允许集群管理员对 Pod 的 `securityContext` 字段强制执行要求。存在三种 Pod 安全标准配置文件：

- **特权（Privileged）**：不受限制，允许已知的权限提升。旨在用于需要特权才能正常运行的系统和基础设施级工作负载。允许所有 securityContext 设置。
- **基线（Baseline）**：为常见的容器化工作负载设计的最小限制策略，同时防止已知的权限提升。针对非关键应用的开发人员和操作员。不允许最危险的 securityContext 设置，如 securityContext.privileged、hostPID、hostPath、hostIPC。
- **受限（Restricted）**：最严格的策略，旨在以牺牲一些兼容性为代价强制执行当前的 Pod 强化实践。针对安全关键型工作负载或不受信任的用户。受限策略包括基线策略的所有强制执行，以及更多严格的要求，如要求删除所有权能、强制执行 runAsNotRoot 等。

每个配置文件的详细设置基线可以在[此处](https://kubernetes.io/docs/concepts/security/pod-security-standards/#profile-details)找到更多详细信息。

Pod 安全准入控制器允许您对违反已定义策略的情况进行强制执行、审核或警告。`audit` 和 `warn` 模式可用于确定在设置为 `enforce` 模式时特定的 Pod 安全标准是否通常会阻止 Pod 的部署。

下面是一个仅允许部署符合受限 Pod 安全标准的命名空间的示例：

### 使用 Pod 安全策略控制 Pod 的安全相关属性，包括容器权限级别

> **警告**  
> Kubernetes 已弃用 Pod 安全策略，转而支持 Pod 安全标准和 Pod 安全准入控制器，并在 v1.25 版本中将其移除。建议使用 Pod 安全标准和 Pod 安全准入控制器。

所有安全策略应包括以下条件：

- 应用程序进程不以 root 身份运行。
- 不允许权限提升。
- 根文件系统为只读。
- 使用默认（屏蔽的）/proc 文件系统挂载。
- 不应使用主机网络或进程空间 - 使用 `hostNetwork: true` 将导致 NetworkPolicies 被忽略，因为 Pod 将使用其主机网络。
- 消除未使用和不必要的 Linux 权能。
- 使用 SELinux 选项进行更细粒度的进程控制。
- 为每个应用程序提供其自己的 Kubernetes 服务账户。
- 如果容器不需要访问 Kubernetes API，则不要让其挂载服务账户凭据。

有关 Pod 安全策略的更多信息，请参考 <https://kubernetes.io/docs/concepts/policy/pod-security-policy/> 上的文档。

--

### 使用服务网格提供额外安全性

服务网格是一个基础设施层，可以快速、安全、可靠地处理应用程序中服务之间的通信，有助于降低管理微服务和部署的复杂性。它们提供了一种统一的方式来保护、连接和监控微服务，并且在运行容器和微服务时能很好地解决操作挑战和问题。

#### 服务网格的优势

服务网格提供以下优势：

1. 可观测性

它生成跟踪和遥测指标，使您能够轻松理解系统并快速找出任何问题的根源。

2. 专门的安全功能

它提供安全功能，可以快速识别进入集群的任何可疑流量，并在正确实施的情况下保护网络内的服务。它还可以帮助您通过 mTLS、入口和出口控制等管理安全。

3. 使用 mTLS 保护微服务的能力

由于保护微服务很困难，有许多工具可以解决微服务安全问题。然而，服务网格是解决网络内流量加密的最优雅的解决方案。

它通过服务间流量的双向 TLS（mTLS）加密提供防御，网格可以自动加密和解密请求和响应，从而减轻了应用程序开发人员的负担。网格还可以通过优先重用现有的持久连接来提高性能，从而减少计算昂贵的新连接创建的需求。使用服务网格，您可以保护线路上的流量，并为每个微服务进行基于强身份的身份验证和授权。

我们发现服务网格对企业公司有很大价值，因为网格允许您查看 mTLS 是否在每个服务之间启用和工作。此外，如果安全状态发生变化，您可以立即收到警报。

4. 入口和出口控制

它允许您监控和处理通过网格的可疑流量。例如，如果 Istio 作为入口控制器集成到 Kubernetes 中，它可以处理入口的负载均衡。这使防御者能够通过入口规则在边界添加一层安全性，而出口控制允许您查看和管理外部服务并控制服务如何与流量交互。

5. 操作控制

它可以帮助安全和平台团队设置正确的宏观控制以执行访问控制，同时允许开发人员在这些护栏内快速进行所需的自定义。

6. 管理 RBAC 的能力

服务网格可以帮助防御者实施强大的基于角色的访问控制（RBAC）系统，这可以说是大型工程组织中最关键的要求之一。即使是安全系统也可以很容易地被特权过高的用户或员工规避，RBAC 系统可以：

- 将特权用户限制为执行工作职责所需的最小权限
- 确保对系统的访问默认为"全部拒绝"
- 帮助开发人员确保有适当的文档详细说明角色和职责，这是企业中最关键的安全问题之一。

#### 服务网格的缺点

尽管服务网格有许多优势，但它们也带来了一系列独特的挑战，其中一些列举如下：

- 增加了复杂性
  当代理、边车和其他组件引入已经复杂的环境时，会极大地增加开发和运营的复杂性。

- 需要额外专业知识
  如果在 Kubernetes 等编排器之上添加 Istio 等网格，操作员需要成为这两种技术的专家。

- 基础设施可能会变慢
  因为服务网格是一种侵入性和复杂的技术，它可能会显著减慢架构速度。

- 需要采用另一个平台
  由于服务网格是侵入性的，它迫使开发人员和操作员适应高度固执己见的平台并遵守其规则。

--

### 实施集中式策略管理

有许多项目能够为 Kubernetes 集群提供集中式策略管理，包括 [Open Policy Agent](https://www.openpolicyagent.org/)（OPA）项目、[Kyverno](https://kyverno.io/) 或 [验证准入策略](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)（在 1.30 版本中正式发布的内置功能）。为了提供一个深入的示例，我们将在此备忘单中重点关注 OPA。

OPA 于 2016 年启动，旨在统一不同技术和系统的策略执行，并可用于在 Kubernetes 等平台上执行策略。目前，OPA 作为孵化项目隶属于 CNCF。它可以创建一种统一的方法来执行堆栈中的安全策略。虽然开发人员可以通过 RBAC 和 Pod 安全策略对集群进行细粒度控制，但这些技术仅适用于集群，而不适用于集群外。

由于 OPA 是一个通用的、与域无关的策略执行工具，不基于任何其他项目，因此策略查询和决策不遵循特定格式。因此，它可以与 API、Linux SSH 守护程序、像 Ceph 这样的对象存储集成，只要提供所需数据，您就可以使用任何有效的 JSON 数据作为请求属性。OPA 允许您选择输入和输出 - 例如，您可以选择让 OPA 返回一个 True 或 False JSON 对象、一个数字、一个字符串，甚至一个复杂的数据对象。

#### OPA 的最常见用例

##### OPA 用于应用程序授权

OPA 可以为开发人员提供一种已开发的授权技术，这样团队就不必从头开发一个。它使用专门构建的声明性策略语言来编写和执行规则，如"Alice 可以写入此存储库"或"Bob 可以更新此帐户"。这项技术提供了丰富的工具套件，使开发人员能够将策略集成到他们的应用程序中，并允许最终用户为其租户创建策略。

如果您已经有一个自制的应用程序授权解决方案，可能不想替换它。但是，如果您希望通过迁移到能够随微服务扩展并允许您分解单体应用的解决方案来提高开发人员效率，那么您将需要一个分布式授权系统，OPA（或相关竞争对手之一）可能是答案。

##### OPA 用于 Kubernetes 准入控制

由于 Kubernetes 为开发人员提供了对传统"计算、网络和存储"的巨大控制，他们可以按照自己的方式设置网络和存储。但这意味着管理员和安全团队必须确保开发人员不会伤害自己或邻居。

OPA 可以通过允许安全团队构建策略来解决这些安全问题，例如要求所有容器镜像来自可信来源、防止开发人员以 root 身份运行软件、确保存储始终标记加密位且存储不会因 Pod 重新启动而被删除、限制互联网访问等。

它还可以帮助管理员确保策略更改不会无意中造成更多损害。OPA 直接集成到 Kubernetes API 服务器中，并且完全有权拒绝准入策略认为不属于集群的任何资源 - 无论是计算相关、网络相关还是存储相关等。此外，策略可以离线运行以监控结果，OPA 的策略可以在开发生命周期的早期（例如 CICD 管道或开发人员笔记本电脑）公开，如果开发人员需要早期反馈。

##### OPA 用于服务网格授权

最后，OPA 可以调节服务网格架构的使用。管理员通常通过在服务网格中构建策略来确保合规性要求得到满足，即使涉及源代码修改。即使您不嵌入 OPA 来实现应用程序授权逻辑（上面讨论的主要用例），您也可以通过将授权策略放入服务网格来控制微服务的 API。但如果出于安全考虑，您可以在服务网格中实施策略以限制微服务架构内的横向移动。

### 限制集群上的资源使用

在 Kubernetes 中为容器定义资源配额很重要，因为默认情况下，Kubernetes 集群中的所有资源都创建了无界的 CPU 限制和内存请求/限制。如果运行资源不受限制的容器，您的系统将面临拒绝服务（DoS）或"吵闹的邻居"场景的风险。幸运的是，OPA 可以在命名空间上使用资源配额，这将限制授予该命名空间的资源数量或容量，并通过定义其 CPU 容量、内存或持久磁盘空间来限制该命名空间。

此外，OPA 可以限制每个命名空间中存在的 Pod、服务或卷的数量，并可以限制上述某些资源的最大或最小大小。资源配额在未指定时提供默认限制，并防止用户为内存等常用保留资源请求不合理的高或低值。

下面是在适当的 yaml 中定义命名空间资源配额的示例。它将命名空间中的 Pod 数量限制为 4，将其 CPU 请求限制在 1 到 2 之间，将内存请求限制在 1GB 到 2GB 之间。

## 第 5 节：Kubernetes 安全最佳实践：运行时阶段

当 Kubernetes 基础设施进入运行时阶段时，容器化应用程序面临着一系列新的安全挑战。您必须获得对运行环境的可见性，以便在威胁出现时能够检测和响应。

如果您在构建和部署阶段主动保护容器和 Kubernetes 部署，您可以大大降低运行时安全事件的可能性，并减少响应这些事件所需的后续工作。

首先，监控最安全相关的容器活动，包括：

- 进程活动
- 容器化服务之间的网络通信
- 容器化服务与外部客户端和服务器之间的网络通信

由于容器和 Kubernetes 的声明性特性，通过观察容器行为来检测异常情况通常比在虚拟机中更容易。这些属性允许更容易地内省您部署的内容及其预期活动。

### 使用 Pod 安全准入来防止部署高风险容器/Pod

之前推荐的 [Pod 安全策略](https://kubernetes.io/docs/concepts/policy/pod-security-policy/) 已被弃用，并被 [Pod 安全准入](https://kubernetes.io/docs/concepts/security/pod-security-admission/)取代，这是一个允许您在 Kubernetes 集群中对 Pod 强制执行安全策略的新功能。

建议至少使用 `baseline` 级别作为所有 Pod 的最低安全要求，以确保整个集群的标准安全级别。但是，集群应该努力应用 `restricted` 级别，该级别遵循 Pod 强化最佳实践。

有关配置 Pod 安全准入的更多信息，请参考 <https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-admission-controller/> 上的文档。

### 容器运行时安全

如果容器在运行时是强化的，安全团队就有能力检测和响应正在运行的容器或工作负载中的威胁和异常。通常，这是通过拦截低级系统调用并查找可能表明受损的事件来完成的。应触发警报的事件示例包括：

- 在容器内运行 shell
- 容器挂载主机的敏感路径，如 /proc
- 在运行的容器中意外读取敏感文件，如 /etc/shadow
- 建立出站网络连接

Sysdig 的 Falco 等开源工具可以帮助操作员通过提供大量开箱即用的检测以及创建自定义规则的能力，快速启动容器运行时安全。

### 容器沙盒

当容器运行时被允许直接调用主机内核时，内核通常与硬件和设备交互以响应请求。尽管 Cgroups 和命名空间为容器提供了一定程度的隔离，但内核仍然呈现出大的攻击面。当防御者必须处理多租户和高度不受信任的集群时，他们通常会添加额外的沙盒层，以确保不存在容器突破和内核漏洞。下面，我们将探索一些有助于进一步将正在运行的容器与主机内核隔离的开源技术：

- Kata Containers：Kata Containers 是一个开源项目，使用精简的虚拟机来保持资源占用最小并最大化性能，最终进一步隔离容器。
- gVisor：gVisor 比虚拟机（即使是精简的）更轻量。它是一个用 Go 编写的独立内核，位于容器和主机内核之间。它是一个强大的沙盒 - gVisor 支持容器的约 70% 的 Linux 系统调用，但只使用约 20 个系统调用到主机内核。
- Firecracker：它是一个超轻量级的在用户空间运行的虚拟机。由于它被 seccomp、cgroup 和命名空间策略锁定，系统调用非常有限。Firecracker 在安全方面构建，但可能不支持所有 Kubernetes 或容器运行时部署。

### 防止容器加载不需要的内核模块

因为 Linux 内核在某些情况下会自动从磁盘加载内核模块，例如连接硬件或挂载文件系统时，这可能是一个重要的攻击面。与 Kubernetes 特别相关的是，即使是非特权进程也可以通过创建适当类型的套接字来导致某些与网络协议相关的内核模块被加载。这种情况可能允许攻击者利用管理员认为未使用的内核模块中的安全漏洞。

要防止特定模块自动加载，您可以从节点中卸载它们，或添加规则阻止它们。在大多数 Linux 发行版上，您可以通过创建如 `/etc/modprobe.d/kubernetes-blacklist.conf` 的文件来实现，内容如下：

```conf
# DCCP 不太可能被需要，有多个严重的漏洞，且未得到良好维护。
blacklist dccp

# SCTP 在大多数 Kubernetes 集群中未使用，过去也有漏洞。
blacklist sctp
```

要更通用地阻止模块加载，您可以使用 Linux 安全模块（如 SELinux）完全拒绝容器的 module_request 权限，防止内核为容器加载模块。（Pod 仍然可以使用手动加载的模块，或由某些更高权限的进程代表内核加载的模块）。

### 比较和分析同一部署中 Pod 的不同运行时活动

当容器化应用程序出于高可用性、容错性或扩展规模的原因被复制时，这些副本的行为应该几乎完全相同。如果一个副本与其他副本有显著偏差，防御者会希望进一步调查。您的 Kubernetes 安全工具应该与其他外部系统（电子邮件、PagerDuty、Slack、Google Cloud 安全指挥中心、SIEM [安全信息和事件管理]等）集成，并利用部署标签或注释，在检测到潜在威胁时向负责特定应用程序的团队发出警报。如果您选择使用商业 Kubernetes 安全供应商，他们应该支持与外部工具的广泛集成。

### 监控网络流量以限制不必要或不安全的通信

容器化应用程序通常广泛使用集群网络，因此观察活动网络流量是了解应用程序如何相互交互并识别意外通信的好方法。您应该观察活动网络流量，并将该流量与基于 Kubernetes 网络策略允许的内容进行比较。

同时，将活动流量与允许的流量进行比较，可以为您提供关于未发生但被允许的内容的有价值信息。有了这些信息，您可以进一步收紧允许的网络策略，以消除多余的连接并减少整体攻击面。

开源项目如 <https://github.com/kinvolk/inspektor-gadget> 或 <https://github.com/deepfence/PacketStreamer> 可能对此有帮助，商业安全解决方案提供不同程度的容器网络流量分析。

### 如果被入侵，将可疑 Pod 缩放至零

使用 Kubernetes 原生控制来遏制成功的入侵，将可疑 Pod 缩放至零，或终止并重启被入侵的应用程序实例。

### 频繁轮换基础设施凭据

秘密或凭据的生命周期越短，攻击者利用该凭据就越困难。为证书设置短生命周期并自动轮换。使用可以控制已颁发令牌可用时间的身份验证提供程序，并尽可能使用短生命周期。如果在外部集成中使用服务账户令牌，请计划频繁轮换这些令牌。例如，一旦引导阶段完成，用于设置节点的引导令牌应被撤销或删除其授权。

### 日志记录

Kubernetes 提供基于集群的日志记录，允许您将容器活动记录到中央日志中心。创建集群时，每个容器的标准输出和标准错误输出可以使用在每个节点上运行的 Fluentd 代理摄取（到 Google Stackdriver 日志或 Elasticsearch），并使用 Kibana 查看。

#### 启用审计日志

审计日志是一个测试版功能，记录 API 执行的操作，以便在发生入侵时进行后续分析。建议启用审计日志并将审计文件存档到安全服务器。

确保日志监控异常或不需要的 API 调用，特别是任何授权失败（这些日志条目将有"Forbidden"状态消息）。授权失败可能意味着攻击者正在尝试滥用被盗凭据。

托管的 Kubernetes 提供商（包括 GKE）在其云控制台中提供对此数据的访问，并可能允许您对授权失败设置警报。

##### 审计日志

审计日志对合规性很有用，因为它们应该帮助您回答发生了什么、谁做了什么和何时做的问题。Kubernetes 根据策略提供 kube-apiserver 请求的灵活审计。这些有助于您按时间顺序跟踪所有活动。

以下是审计日志示例：

```json
{
  "kind":"Event",
  "apiVersion":"audit.k8s.io/v1beta1",
  "metadata":{ "creationTimestamp":"2019-08-22T12:00:00Z" },
  "level":"Metadata",
  "timestamp":"2019-08-22T12:00:00Z",
  "auditID":"23bc44ds-2452-242g-fsf2-4242fe3ggfes",
  "stage":"RequestReceived",
  "requestURI":"/api/v1/namespaces/default/persistentvolumeclaims",
  "verb":"list",
  "user": {
    "username":"user@example.org",
    "groups":[ "system:authenticated" ]
  },
  "sourceIPs":[ "172.12.56.1" ],
  "objectRef": {
    "resource":"persistentvolumeclaims",
    "namespace":"default",
    "apiVersion":"v1"
  },
  "requestReceivedTimestamp":"2019-08-22T12:00:00Z",
  "stageTimestamp":"2019-08-22T12:00:00Z"
}
```

#### 定义审计策略

审计策略设置规则，定义应记录哪些事件以及事件包含时存储哪些数据。审计策略对象结构在 audit.k8s.io API 组中定义。处理事件时，将其与规则列表按顺序比较。第一个匹配的规则设置事件的"审计级别"。

已知的审计级别包括：

- None - 不记录与此规则匹配的事件
- Metadata - 记录请求元数据（请求用户、时间戳、资源、动词等），但不记录请求或响应正文
- Request - 记录事件元数据和请求正文，但不记录响应正文。不适用于非资源请求
- RequestResponse - 记录事件元数据、请求和响应正文。不适用于非资源请求

您可以使用 --audit-policy-file 标志将带有策略的文件传递给 kube-apiserver。如果省略该标志，则不记录任何事件。请注意，审计策略文件中必须提供规则字段。没有（0）规则的策略被视为非法。

#### 理解日志记录

Kubernetes 日志记录的一个主要挑战是理解生成了哪些日志以及如何使用它们。让我们从检查 Kubernetes 日志架构的整体图景开始。

##### 容器日志

可以从 Kubernetes 集群收集的第一层日志是由容器化应用程序生成的日志。记录容器的最简单方法是写入标准输出（stdout）和标准错误（stderr）流。

清单如下：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
    - name: example
      image: busybox
      args: [/bin/sh, -c, 'while true; do echo $(date); sleep 1; done']
```

要应用清单，请运行：

```bash
kubectl apply -f example.yaml
```

要查看此容器的日志，请运行：

```bash
kubectl log <container-name> 命令。
```

对于持久化容器日志，常见的方法是将日志写入日志文件，然后使用边车容器。如上面 Pod 配置所示，边车容器将在与应用程序容器相同的 Pod 中运行，挂载相同的卷并单独处理日志。

下面是 Pod 清单示例：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: busybox
    args:
    - /bin/sh
    - -c
    - >
      while true;
      do
        echo "$(date)\n" >> /var/log/example.log;
        sleep 1;
      done
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  - name: sidecar
    image: busybox
    args: [/bin/sh, -c, 'tail -f /var/log/example.log']
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  volumes:
  - name: varlog
    emptyDir: {}
```

##### 节点日志

当在 Kubernetes 上运行的容器将其日志写入 stdout 或 stderr 流时，容器引擎会将它们流式传输到 Kubernetes 配置设置的日志驱动程序。

在大多数情况下，这些日志最终会出现在主机的 /var/log/containers 目录中。Docker 支持多个日志驱动程序，但不幸的是，不支持通过 Kubernetes API 配置驱动程序。

当容器终止或重启时，kubelet 会在节点上存储日志。为防止这些文件消耗主机的所有存储空间，Kubernetes 节点实现了日志轮换机制。当容器从节点中逐出时，所有具有相应日志文件的容器也会被逐出。

根据您在主机机器上运行的操作系统和其他服务，您可能需要查看其他日志。

例如，可以使用以下命令检索 systemd 日志：

```bash
journalctl -u
```

##### 集群日志

在 Kubernetes 集群本身中，还有许多可以记录的集群组件以及可以使用的其他数据类型（事件、审计日志）。这些不同类型的数据可以让您了解 Kubernetes 作为系统的性能。

这些组件中的一些在容器中运行，一些在操作系统级别运行（在大多数情况下是 systemd 服务）。systemd 服务写入 journald，在容器中运行的组件将日志写入 /var/log 目录，除非容器引擎已配置为以不同方式流式传输日志。

#### 事件

Kubernetes 事件可以指示任何 Kubernetes 资源状态变化和错误，如超过资源配额、挂起的 Pod 以及任何信息性消息。

以下命令返回特定命名空间内的所有事件：

```bash
kubectl get events -n <namespace>

NAMESPACE LAST SEEN TYPE   REASON OBJECT MESSAGE
kube-system  8m22s  Normal   Scheduled            pod/metrics-server-66dbbb67db-lh865                                       Successfully assigned kube-system/metrics-server-66dbbb67db-lh865 to aks-agentpool-42213468-1
kube-system     8m14s               Normal    Pulling                   pod/metrics-server-66dbbb67db-lh865                                       Pulling image "aksrepos.azurecr.io/mirror/metrics-server-amd64:v0.2.1"
kube-system     7m58s               Normal    Pulled                    pod/metrics-server-66dbbb67db-lh865                                       Successfully pulled image "aksrepos.azurecr.io/mirror/metrics-server-amd64:v0.2.1"
kube-system     7m57s               Normal     Created                   pod/metrics-server-66dbbb67db-lh865                                       Created container metrics-server
kube-system     7m57s               Normal    Started                   pod/metrics-server-66dbbb67db-lh865                                       Started container metrics-server
kube-system     8m23s               Normal    SuccessfulCreate          replicaset/metrics-server-66dbbb67db             Created pod: metrics-server-66dbbb67db-lh865
```

以下命令将显示特定 Kubernetes 资源的最新事件：

## 第 5 节：最终思考

### 尽早将安全性嵌入容器生命周期

您必须更早地将安全性集成到容器生命周期中，并确保安全团队和 DevOps 团队之间的一致性和共同目标。安全性可以（并且应该）成为一个使能器，让您的开发人员和 DevOps 团队能够自信地构建和部署适用于规模、稳定性和安全性的生产就绪型应用程序。

### 使用 Kubernetes 原生安全控制来降低运营风险

尽可能利用 Kubernetes 中内置的原生控制来执行安全策略，以确保您的安全控制不会与编排器发生冲突。例如，与使用第三方代理或垫片来强制执行网络分段不同，您可以使用 Kubernetes 网络策略来确保安全的网络通信。

### 利用 Kubernetes 提供的上下文来确定修复工作的优先级

请注意，在庞大的 Kubernetes 环境中，手动分类安全事件和策略违规是非常耗时的。

例如，如果包含严重性评分为 7 或更高的漏洞的部署包含特权容器并且对互联网开放，则应提高其修复优先级；但如果它位于测试环境中并支持非关键应用，则应降低优先级。

---

## 参考文献

控制平面文档 - <https://kubernetes.io>

1. 每个人都必须遵循的 Kubernetes 安全最佳实践 - <https://www.cncf.io/blog/2019/01/14/9-kubernetes-security-best-practices-everyone-must-follow>
2. 保护集群 - <https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster>
3. Kubernetes 部署的安全最佳实践 - <https://kubernetes.io/blog/2016/08/security-best-practices-kubernetes-deployment>
4. Kubernetes 安全最佳实践 - <https://phoenixnap.com/kb/kubernetes-security-best-practices>
5. Kubernetes 安全 101：风险和 29 个最佳实践 - <https://www.stackrox.com/post/2020/05/kubernetes-security-101>
6. 保护集群的 15 个 Kubernetes 安全最佳实践 - <https://www.mobilise.cloud/15-kubernetes-security-best-practice-to-secure-your-cluster>
7. Kubernetes 安全终极指南 - <https://neuvector.com/container-security/kubernetes-security-guide>
8. 黑客的 Kubernetes 安全指南 - <https://techbeacon.com/enterprise-it/hackers-guide-kubernetes-security>
9. 11 种（不）被黑的方式 - <https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked>
10. 12 个 Kubernetes 配置最佳实践 - <https://www.stackrox.com/post/2019/09/12-kubernetes-configuration-best-practices/#6-securely-configure-the-kubernetes-api-server>
11. Kubernetes 日志记录实用指南 - <https://logz.io/blog/a-practical-guide-to-kubernetes-logging>
12. Kubernetes Web UI（仪表板） - <https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard>
13. 特斯拉云资源被黑用于挖矿 - <https://arstechnica.com/information-technology/2018/02/tesla-cloud-resources-are-hacked-to-run-cryptocurrency-mining-malware>
14. 开放策略代理：云原生授权 - <https://blog.styra.com/blog/open-policy-agent-authorization-for-the-cloud>
15. 引入策略即代码：开放策略代理（OPA） - <https://www.magalix.com/blog/introducing-policy-as-code-the-open-policy-agent-opa>
16. 服务网格提供的内容 - <https://aspenmesh.io/wp-content/uploads/2019/10/AspenMesh_CompleteGuide.pdf>
17. 服务网格的三个技术优势及其运营限制，第 1 部分 - <https://glasnostic.com/blog/service-mesh-istio-limits-and-benefits-part-1>
18. 开放策略代理：OPA 是什么以及它是如何工作的（示例） - <https://spacelift.io/blog/what-is-open-policy-agent-and-how-it-works>
19. 将 Kubernetes 指标发送到 Kibana 和 Elasticsearch - <https://logit.io/sources/configure/kubernetes/>
20. Kubernetes 安全检查清单 - <https://kubernetes.io/docs/concepts/security/security-checklist/>
