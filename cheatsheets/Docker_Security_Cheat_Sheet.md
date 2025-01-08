# Docker 安全备忘录

## 简介

Docker 是最流行的容器化技术。当正确使用时，与直接在主机系统上运行应用程序相比，它可以增强安全性。然而，某些错误配置可能会降低安全级别或引入新的漏洞。

本备忘录旨在提供一个简单明了的常见安全错误和最佳实践列表，以帮助保护 Docker 容器的安全。

## 规则

### 规则 \#0 - 保持主机和 Docker 为最新

为了防止已知的容器逃逸漏洞（如 [Leaky Vessels](https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/)，通常会导致攻击者获得主机的 root 访问权限），保持主机和 Docker 为最新状态至关重要。这包括定期更新主机内核和 Docker 引擎。

这是因为容器共享主机的内核。如果主机的内核存在漏洞，容器也会受到影响。例如，在一个隔离良好的容器内执行内核权限提升漏洞 [Dirty COW](https://github.com/scumjr/dirtycow-vdso) 仍然会在易受攻击的主机上获得 root 访问权限。

### 规则 \#1 - 不要暴露 Docker 守护进程套接字（即使对容器也是如此）

Docker 套接字 */var/run/docker.sock* 是 Docker 监听的 UNIX 套接字。这是 Docker API 的主要入口点。该套接字的所有者是 root。给某人访问它相当于给予对主机的无限制 root 访问权限。

**不要启用 *tcp* Docker 守护进程套接字。** 如果你使用 `-H tcp://0.0.0.0:XXX` 或类似命令运行 docker 守护进程，你就暴露了未加密和未经身份验证的对 Docker 守护进程的直接访问。如果主机连接到互联网，这意味着你计算机上的 docker 守护进程可以被公共互联网上的任何人使用。
如果你真的、**真的**必须这样做，你应该保护它。请查看 [Docker 官方文档](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option)了解如何操作。

**不要将 */var/run/docker.sock* 暴露给其他容器**。如果你使用 `-v /var/run/docker.sock://var/run/docker.sock` 或类似命令运行 docker 镜像，你应该更改它。请记住，以只读方式挂载套接字不是解决方案，只是使其更难利用。在 docker compose 文件中，类似的内容如下：

```yaml
    volumes:
    - "/var/run/docker.sock:/var/run/docker.sock"
```

### 规则 \#2 - 设置用户

配置容器使用非特权用户是防止权限提升攻击的最佳方法。这可以通过以下三种方式实现：

1. 在运行时使用 `docker run` 命令的 `-u` 选项，例如：

```bash
docker run -u 4000 alpine
```

2. 在构建时。在 Dockerfile 中简单地添加用户并使用它。例如：

```dockerfile
FROM alpine
RUN groupadd -r myuser && useradd -r -g myuser myuser
#    <在这里以 ROOT 用户身份执行必要的操作，如安装软件包等>
USER myuser
```

3. 在 [Docker 守护进程](https://docs.docker.com/engine/security/userns-remap/#enable-userns-remap-on-the-daemon)中启用用户命名空间支持（`--userns-remap=default`）

关于此主题的更多信息可以在 [Docker 官方文档](https://docs.docker.com/engine/security/userns-remap/)中找到。为了额外的安全性，你还可以以无根模式运行，这在[规则 \#11](#规则-11---以无根模式运行-docker) 中讨论。

在 Kubernetes 中，这可以在[安全上下文](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)中使用 `runAsUser` 字段配置，例如：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 4000 # <-- 这是 pod 用户 ID
```

作为 Kubernetes 集群管理员，你可以使用内置的[Pod 安全准入控制器](https://kubernetes.io/docs/concepts/security/pod-security-admission/)配置 [`Restricted` 级别](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)的强化默认设置，如果需要更大的自定义性，可以考虑使用[准入 Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks) 或[第三方替代方案](https://kubernetes.io/docs/concepts/security/pod-security-standards/#alternatives)。

### 规则 \#3 - 限制权能（仅授予容器所需的特定权能）

[Linux 内核权能](http://man7.org/linux/man-pages/man7/capabilities.7.html)是一组可由特权用户使用的权限。Docker 默认情况下仅运行一部分权能。
你可以更改它，通过使用 `--cap-drop` 删除一些权能来加强 docker 容器，或者在需要时使用 `--cap-add` 添加一些权能。
请记住不要使用 `--privileged` 标志运行容器 - 这将为容器添加所有 Linux 内核权能。

最安全的设置是删除所有权能 `--cap-drop all`，然后仅添加所需的权能。例如：

```bash
docker run --cap-drop all --cap-add CHOWN alpine
```

**并且记住：不要使用 *--privileged* 标志运行容器！**

在 Kubernetes 中，这可以在[安全上下文](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)中使用 `capabilities` 字段配置，例如：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
        capabilities:
            drop:
                - ALL
            add: ["CHOWN"]
```

作为 Kubernetes 集群管理员，你可以使用内置的[Pod 安全准入控制器](https://kubernetes.io/docs/concepts/security/pod-security-admission/)配置 [`Restricted` 级别](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)的强化默认设置，如果需要更大的自定义性，可以考虑使用[准入 Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks) 或[第三方替代方案](https://kubernetes.io/docs/concepts/security/pod-security-standards/#alternatives)。

### 规则 \#4 - 防止容器内权限提升

始终使用 `--security-opt=no-new-privileges` 运行 docker 镜像，以防止权限提升。这将阻止容器通过 `setuid` 或 `setgid` 二进制文件获得新的权限。

在 Kubernetes 中，这可以在[安全上下文](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)中使用 `allowPrivilegeEscalation` 字段配置，例如：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      allowPrivilegeEscalation: false
```

作为 Kubernetes 集群管理员，你可以使用内置的[Pod 安全准入控制器](https://kubernetes.io/docs/concepts/security/pod-security-admission/)配置 [`Restricted` 级别](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)的强化默认设置，如果需要更大的自定义性，可以考虑使用[准入 Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks) 或[第三方替代方案](https://kubernetes.io/docs/concepts/security/pod-security-standards/#alternatives)。

### 规则 \#5 - 注意容器间连接

默认情况下启用容器间连接（icc），允许所有容器通过 [`docker0` 桥接网络](https://docs.docker.com/network/drivers/bridge/)相互通信。与使用 Docker 守护进程的 `--icc=false` 标志完全禁用容器间通信不同，考虑定义特定的网络配置。这可以通过创建自定义 Docker 网络并指定应附加哪些容器来实现。这种方法提供了对容器通信更细粒度的控制。

有关配置 Docker 网络以进行容器通信的详细指导，请参考 [Docker 文档](https://docs.docker.com/network/#communication-between-containers)。

在 Kubernetes 环境中，可以使用[网络策略](https://kubernetes.io/docs/concepts/services-networking/network-policies/)来定义规则，以调节集群内 pod 的交互。这些策略提供了一个强大的框架，用于控制 pod 如何相互通信以及与其他网络端点通信。此外，[网络策略编辑器](https://networkpolicy.io/)简化了网络策略的创建和管理，通过用户友好的界面使定义复杂的网络规则变得更加容易。

### 规则 \#6 - 使用 Linux 安全模块（seccomp、AppArmor 或 SELinux）

**首先，不要禁用默认安全配置文件！**

考虑使用 [seccomp](https://docs.docker.com/engine/security/seccomp/) 或 [AppArmor](https://docs.docker.com/engine/security/apparmor/) 等安全配置文件。

在 Kubernetes 中如何执行此操作的说明可以在[为 Pod 或容器配置安全上下文](https://kubernetes.io/docs/tutorials/security/seccomp/)中找到。

### 规则 \#7 - 限制资源（内存、CPU、文件描述符、进程、重启）

避免 DoS 攻击的最佳方法是限制资源。你可以限制[内存](https://docs.docker.com/config/containers/resource_constraints/#memory)、[CPU](https://docs.docker.com/config/containers/resource_constraints/#cpu)、最大重启次数（`--restart=on-failure:<number_of_restarts>`）、最大文件描述符数量（`--ulimit nofile=<number>`）和最大进程数量（`--ulimit nproc=<number>`）。

[查看有关 ulimits 的更多详细信息](https://docs.docker.com/engine/reference/commandline/run/#set-ulimits-in-container---ulimit)

你也可以在 Kubernetes 中执行此操作：[为容器和 Pod 分配内存资源](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/)、[为容器和 Pod 分配 CPU 资源](https://kubernetes.io/docs/tasks/configure-pod-container/assign-cpu-resource/) 和 [为容器分配扩展资源](https://kubernetes.io/docs/tasks/configure-pod-container/extended-resource/)

### 规则 \#8 - 将文件系统和卷设置为只读

**使用 `--read-only` 标志运行只读文件系统的容器**。例如：

```bash
docker run --read-only alpine sh -c 'echo "whatever" > /tmp'
```

如果容器内的应用程序需要临时保存内容，可以将 `--read-only` 标志与 `--tmpfs` 结合使用：

```bash
docker run --read-only --tmpfs /tmp alpine sh -c 'echo "whatever" > /tmp/file'
```

Docker Compose 的 `compose.yml` 等效写法：

```yaml
version: "3"
services:
  alpine:
    image: alpine
    read_only: true
```

在 Kubernetes 的[安全上下文](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)中的等效写法：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
  - name: example
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      readOnlyRootFilesystem: true
```

另外，如果卷仅用于读取，**请将其挂载为只读**
可以通过在 `-v` 后附加 `:ro` 来实现：

```bash
docker run -v volume-name:/path/in/container:ro alpine
```

或使用 `--mount` 选项：

```bash
docker run --mount source=volume-name,destination=/path/in/container,readonly alpine
```

### 规则 \#9 - 将容器扫描工具集成到 CI/CD 流水线中

[CI/CD 流水线](CI_CD_Security_Cheat_Sheet.md)是软件开发生命周期的关键部分，应包括各种安全检查，如代码风格检查、静态代码分析和容器扫描。

在编写 Dockerfile 时遵循一些最佳实践可以防止许多问题。但是，在构建流水线中添加安全代码风格检查可以帮助避免更多麻烦。常见检查的问题包括：

- 确保指定了 `USER` 指令
- 确保固定基础镜像版本
- 确保固定操作系统软件包版本
- 避免使用 `ADD`，改用 `COPY`
- 避免在 `RUN` 指令中使用 curl 管道

参考资料：

- [DevSec 上的 Docker 基线](https://dev-sec.io/baselines/docker/)
- [使用 Docker 命令行](https://docs.docker.com/engine/reference/commandline/cli/)
- [Docker Compose v2 CLI 概述](https://docs.docker.com/compose/reference/overview/)
- [配置日志驱动程序](https://docs.docker.com/config/containers/logging/configure/)
- [查看容器或服务的日志](https://docs.docker.com/config/containers/logging/)
- [Dockerfile 安全最佳实践](https://cloudberry.engineering/article/dockerfile-security-best-practices/)

作为成功安全策略的重要组成部分，容器扫描工具尤其重要。它们可以检测容器镜像中已知的漏洞、秘密和错误配置，并提供发现报告和修复建议。一些流行的容器扫描工具包括：

- 免费工具
    - [Clair](https://github.com/coreos/clair)
    - [ThreatMapper](https://github.com/deepfence/ThreatMapper)
    - [Trivy](https://github.com/aquasecurity/trivy)
- 商业工具
    - [Snyk](https://snyk.io/) **(有开源和免费选项)**
    - [Anchore](https://github.com/anchore/grype/) **(有开源和免费选项)**
    - [Docker Scout](https://www.docker.com/products/docker-scout/) **(有开源和免费选项)**
    - [JFrog XRay](https://jfrog.com/xray/)
    - [Qualys](https://www.qualys.com/apps/container-security/)

用于检测镜像中的秘密：

- [ggshield](https://github.com/GitGuardian/ggshield) **(有开源和免费选项)**
- [SecretScanner](https://github.com/deepfence/SecretScanner) **(开源)**

用于检测 Kubernetes 中的错误配置：

- [kubeaudit](https://github.com/Shopify/kubeaudit)
- [kubesec.io](https://kubesec.io/)
- [kube-bench](https://github.com/aquasecurity/kube-bench)

用于检测 Docker 中的错误配置：

- [inspec.io](https://www.inspec.io/docs/reference/resources/docker/)
- [dev-sec.io](https://dev-sec.io/baselines/docker/)
- [Docker 安全基准](https://github.com/docker/docker-bench-security)

### 规则 \#10 - 将 Docker 守护进程日志级别保持为 `info`

默认情况下，Docker 守护进程配置的基本日志级别为 `info`。可以通过检查守护进程配置文件 `/etc/docker/daemon.json` 中的 `log-level` 键来验证。如果该键不存在，默认日志级别为 `info`。此外，如果使用 `--log-level` 选项启动 docker 守护进程，则配置文件中 `log-level` 键的值将被覆盖。要检查 Docker 守护进程是否以不同的日志级别运行，可以使用以下命令：

```bash
ps aux | grep '[d]ockerd.*--log-level' | awk '{for(i=1;i<=NF;i++) if ($i ~ /--log-level/) print $i}'
```

设置适当的日志级别，可以配置 Docker 守护进程记录稍后要审查的事件。基本日志级别 'info' 及以上将捕获除调试日志之外的所有日志。除非必要，否则不应在 'debug' 日志级别运行 docker 守护进程。

### 规则 \#11 - 以无根模式运行 Docker

无根模式确保 Docker 守护进程和容器以非特权用户身份运行，这意味着即使攻击者突破容器，他们也不会在主机上拥有 root 权限，从而大大限制了攻击面。这与[用户命名空间重映射](#规则-2---设置用户)模式不同，后者的守护进程仍以 root 权限运行。

评估环境的[特定要求](Attack_Surface_Analysis_Cheat_Sheet.md)和[安全态势](Threat_Modeling_Cheat_Sheet.md)，以确定无根模式是否是最佳选择。对于安全性至关重要且[无根模式的限制](https://docs.docker.com/engine/security/rootless/#known-limitations)不会干扰操作需求的环境，这是强烈推荐的配置。或者考虑使用 [Podman](#作为-docker-替代品的-podman) 作为 Docker 的替代品。

> 无根模式允许以非 root 用户运行 Docker 守护进程和容器，以减轻守护进程和容器运行时中的潜在漏洞。
> 只要满足[先决条件](https://docs.docker.com/engine/security/rootless/#prerequisites)，无根模式在安装 Docker 守护进程期间不需要 root 权限。

在 [Docker 文档](https://docs.docker.com/engine/security/rootless/)页面上阅读有关无根模式及其限制、安装和使用说明的更多信息。

### 规则 \#12 - 利用 Docker Secrets 管理敏感数据

Docker Secrets 提供了一种安全的方式来存储和管理敏感数据，如密码、令牌和 SSH 密钥。使用 Docker Secrets 有助于避免在容器镜像或运行时命令中暴露敏感数据。

```bash
docker secret create my_secret /path/to/super-secret-data.txt
docker service create --name web --secret my_secret nginx:latest
```

或对于 Docker Compose：

```yaml
  version: "3.8"
  secrets:
    my_secret:
      file: ./super-secret-data.txt
  services:
    web:
      image: nginx:latest
      secrets:
        - my_secret
```

虽然 Docker Secrets 通常为 Docker 环境中的敏感数据管理提供了一种安全的方式，但不建议在 Kubernetes 中使用这种方法，因为默认情况下秘密以明文存储。在 Kubernetes 中，考虑使用额外的安全措施，如 etcd 加密或第三方工具。请参考[秘密管理备忘录](Secrets_Management_Cheat_Sheet.md)获取更多信息。

### 规则 \#13 - 增强供应链安全

基于[规则 \#9](#规则-9---将容器扫描工具集成到-cicd-流水线中)的原则，增强供应链安全涉及实施额外措施，以保护从创建到部署的容器镜像整个生命周期的安全。一些关键实践包括：

- [镜像出处](https://slsa.dev/spec/v1.0/provenance)：记录容器镜像的来源和历史，以确保可追溯性和完整性。
- [SBOM 生成](https://cyclonedx.org/guides/CycloneDX%20One%20Pager.pdf)：为每个镜像创建软件物料清单（SBOM），详细列出所有组件、库和依赖项，以实现透明度和漏洞管理。
- [镜像签名](https://github.com/notaryproject/notary)：对镜像进行数字签名，以验证其完整性和真实性，建立对其安全性的信任。
- [可信注册表](https://snyk.io/learn/container-security/container-registry-security/)：将带有文档、签名的镜像及其 SBOM 存储在强制执行严格[访问控制](Access_Control_Cheat_Sheet.md)并支持元数据管理的安全注册表中。
- [安全部署](https://www.openpolicyagent.org/docs/latest/#overview)：实施安全部署策略，如镜像验证、运行时安全和持续监控，以确保已部署镜像的安全性。

## 作为 Docker 替代品的 Podman

[Podman](https://podman.io/) 是一个符合 OCI 标准的开源容器管理工具，由 [Red Hat](https://www.redhat.com/en) 开发，提供与 Docker 兼容的命令行界面和用于管理容器的桌面应用程序。它旨在成为 Docker 的更安全、更轻量的替代品，特别是在偏好安全默认设置的环境中。Podman 的一些安全优势包括：

1. 无守护进程架构：与需要中央守护进程（dockerd）来创建、运行和管理容器的 Docker 不同，Podman 直接采用 fork-exec 模型。当用户请求启动容器时，Podman 从当前进程分叉，然后子进程执行容器的运行时。
2. 无根容器：fork-exec 模型使 Podman 能够在不需要 root 权限的情况下运行容器。当非 root 用户启动容器时，Podman 在用户的权限下分叉和执行。
3. SELinux 集成：Podman 专为与 SELinux 协同工作而构建，通过对容器及其与主机系统交互的强制访问控制，提供额外的安全层。

## 参考资料和进一步阅读

[OWASP Docker Top 10](https://github.com/OWASP/Docker-Security)
[Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
[Docker Engine Security](https://docs.docker.com/engine/security/)
[Kubernetes Security Cheat Sheet](Kubernetes_Security_Cheat_Sheet.md)
[SLSA - Supply Chain Levels for Software Artifacts](https://slsa.dev/)
[Sigstore](https://sigstore.dev/)
[Docker Build Attestation](https://docs.docker.com/build/attestations/)
[Docker Content Trust](https://docs.docker.com/engine/security/trust/)
