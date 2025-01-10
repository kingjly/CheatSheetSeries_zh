# Node.js Docker 备忘录

以下备忘录提供了构建优化和安全的 [Node.js Docker](https://snyk.io/blog/10-best-practices-to-containerize-nodejs-web-applications-with-docker/) 的生产级指南。无论您要构建什么 Node.js 应用程序，都会发现这很有帮助。如果以下情况适用于您，本文将很有用：

- 您的目标是使用服务器端渲染（SSR）的 Node.js 功能构建前端应用程序。
- 您正在寻找如何为微服务正确构建 Node.js Docker 镜像的建议，运行 Fastify、NestJS 或其他应用程序框架。

## 1) 使用明确和确定性的 Docker 基础镜像标签

使用 `node` Docker 镜像作为基础镜像可能看起来是一个明显的选择，但是您实际上在构建镜像时拉取了什么？Docker 镜像总是通过标签引用，当您不指定标签时，默认使用 `:latest` 标签。

例如，在 Dockerfile 中指定以下内容时，您始终构建由 **Node.js Docker 工作组** 构建的最新版本 Docker 镜像：

### FROM node

基于默认 `node` 镜像构建的缺点如下：

1. Docker 镜像构建不一致。就像我们使用 `lockfiles` 来获得每次安装 npm 包时确定性的 `npm install` 行为一样，我们也希望获得确定性的 Docker 镜像构建。如果我们从 node 构建镜像（实际上意味着 `node:latest` 标签），那么每次构建都会拉取新构建的 Docker 镜像。我们不希望引入这种非确定性行为。

2. Node Docker 镜像基于功能齐全的操作系统，充满了运行 Node.js Web 应用程序可能需要也可能不需要的库和工具。这有两个缺点。首先，更大的镜像意味着更大的下载大小，这不仅增加了存储需求，还意味着下载和重新构建镜像需要更多时间。其次，这意味着您可能引入了这些库和工具中可能存在的安全漏洞。

事实上，`node` Docker 镜像相当大，并包含数百个不同类型和严重程度的安全漏洞。如果您使用它，那么默认情况下，您的起点将是 642 个安全漏洞的基线，并且每次拉取和构建都会下载数百兆字节的镜像数据。

构建更好的 Docker 镜像的建议是：

1. 使用小型 Docker 镜像 - 这将转化为 Docker 镜像上更小的软件占用空间，减少潜在的漏洞向量，并且体积更小，这将加快镜像构建过程。
2. 使用 Docker 镜像摘要，即镜像的静态 SHA256 哈希。这确保从基础镜像获得确定性的 Docker 镜像构建。

基于此，让我们确保使用 Node.js 的长期支持（LTS）版本，并使用最小的 `alpine` 镜像类型，以在镜像上拥有最小的大小和软件占用空间：

### FROM node:lts-alpine

尽管如此，这个基础镜像指令仍将拉取该标签的新构建。我们可以在 [Docker Hub 上为此 Node.js 标签](https://hub.docker.com/layers/node/library/node/lts-alpine/images/sha256-51e341881c2b77e52778921c685e711a186a71b8c6f62ff2edfc6b6950225a2f?context=explore)找到其 `SHA256` 哈希，或者在本地拉取此镜像后运行以下命令，并在输出中定位 `Digest` 字段：

    $ docker pull node:lts-alpine
    lts-alpine: Pulling from library/node
    0a6724ff3fcd: Already exists
    9383f33fa9f3: Already exists
    b6ae88d676fe: Already exists
    565e01e00588: Already exists
    Digest: sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    Status: Downloaded newer image for node:lts-alpine
    docker.io/library/node:lts-alpine

另一种查找 `SHA256` 哈希的方法是运行以下命令：

    $ docker images --digests
    REPOSITORY                     TAG              DIGEST                                                                    IMAGE ID       CREATED             SIZE
    node                           lts-alpine       sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a   51d926a5599d   2 weeks ago         116MB

现在我们可以按如下方式更新 Node.js Docker 镜像的 Dockerfile：

    FROM node@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm install
    CMD "npm" "start"

然而，上面的 Dockerfile 仅指定了 Node.js Docker 镜像名称，没有镜像标签，这会造成使用哪个确切镜像标签的歧义 - 这不可读，难以维护，并且不能创建良好的开发者体验。

让我们通过更新 Dockerfile 来修复它，为对应该 `SHA256` 哈希的 Node.js 版本提供完整的基础镜像标签：

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm install
    CMD "npm" "start"

## 2) 仅在 Node.js Docker 镜像中安装生产依赖

以下 Dockerfile 指令在容器中安装所有依赖，包括 `devDependencies`，这对于功能性应用程序的运行是不需要的。它增加了来自开发依赖包的不必要的安全风险，并且不必要地膨胀了镜像大小。

**`RUN npm install`**

使用 `npm ci` 强制执行确定性构建。这可以防止持续集成（CI）流程中的意外，因为如果与锁文件有任何偏差，它都会停止。

在构建生产环境的 Docker 镜像时，我们希望确保以确定性的方式仅安装生产依赖，这为我们带来了在容器镜像中安装 npm 依赖的最佳实践建议：

**`RUN npm ci --omit=dev`**

此阶段更新后的 Dockerfile 内容如下：

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm ci --omit=dev
    CMD "npm" "start"

## 3) 为生产环境优化 Node.js 工具

在为生产环境构建 Node.js Docker 镜像时，您希望确保所有框架和库都使用性能和安全性的最佳设置。

这促使我们添加以下 Dockerfile 指令：

**`ENV NODE_ENV production`**

乍看之下，这看起来是多余的，因为我们已经在 `npm install` 阶段仅指定了生产依赖 - 那为什么这是必要的？

开发者主要将 `NODE_ENV=production` 环境变量设置与安装生产相关依赖关联，然而，这个设置还有其他影响需要我们注意。

一些框架和库可能只有在 `NODE_ENV` 环境变量设置为 `production` 时才会启用适合生产的优化配置。撇开我们对框架采用这种做法的看法，了解这一点很重要。

例如，[Express 文档](https://expressjs.com/en/advanced/best-practice-performance.html#set-node_env-to-production)概述了设置此环境变量对启用性能和安全相关优化的重要性。

性能影响可能非常显著。

您依赖的许多其他库可能也期望设置此变量，因此我们应该在 Dockerfile 中设置它。

现在，Dockerfile 应该如下所示，内置了 `NODE_ENV` 环境变量设置：

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    ENV NODE_ENV production
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm ci --omit=dev
    CMD "npm" "start"
    
## 4) 不要以 root 用户运行容器

最小权限原则是 Unix 早期的一项长期安全控制，我们在运行容器化的 Node.js Web 应用程序时应始终遵循这一原则。

威胁评估非常直接 - 如果攻击者能够以允许[命令注入](https://owasp.org/www-community/attacks/Command_Injection)或[目录路径遍历](https://owasp.org/www-community/attacks/Path_Traversal)的方式破坏 Web 应用程序，这些操作将以拥有应用程序进程的用户身份执行。如果该进程恰好是 root，那么他们几乎可以在容器内执行任何操作，包括[尝试容器逃逸](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation)。我们为什么要冒这个险？没错，我们不应该。

请记住：**"朋友不会让朋友以 root 用户运行容器！"**

官方的 `node` Docker 镜像及其变体（如 `alpine`）包含一个同名的最小权限用户：`node`。然而，仅仅以 `node` 用户运行进程是不够的。例如，以下方式可能不适合应用程序正常运行：

    USER node
    CMD "npm" "start"

原因是 Dockerfile 的 `USER` 指令只确保进程由 `node` 用户拥有。但是我们之前使用 `COPY` 指令复制的所有文件呢？它们是由 root 拥有的。这是 Docker 的默认行为。

完整且正确的降低权限的方法如下，同时展示了我们到目前为止的 Dockerfile 最佳实践：

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    ENV NODE_ENV production
    WORKDIR /usr/src/app
    COPY --chown=node:node . /usr/src/app
    RUN npm ci --omit=dev
    USER node
    CMD "npm" "start"

## 5) 正确处理事件以安全地终止 Node.js Docker Web 应用程序

在关于容器化 Node.js 应用程序的博客和文章中，我经常看到一个最常见的错误是调用进程的方式。以下所有方式及其变体都是应该避免的不良模式：

- `CMD "npm" "start"`
- `CMD ["yarn", "start"]`
- `CMD "node" "server.js"`
- `CMD "start-app.sh"`

让我们深入探讨！我将带您了解它们的区别以及为什么都是应该避免的模式。

理解正确运行和终止 Node.js Docker 应用程序的关键点如下：

1. 编排引擎（如 Docker Swarm、Kubernetes 或仅仅是 Docker 引擎本身）需要一种向容器中的进程发送信号的方法。主要是终止应用程序的信号，如 `SIGTERM` 和 `SIGKILL`。
2. 进程可能间接运行，如果发生这种情况，则不能保证它会收到这些信号。
3. Linux 内核对以进程 ID 1（PID）运行的进程的处理方式与其他进程 ID 不同。

掌握了这些知识，让我们开始研究容器进程调用的方式，从我们正在构建的 Dockerfile 中的示例开始：

**`CMD "npm" "start"`**

这里有两个问题。首先，我们通过直接调用 npm 客户端间接运行 Node 应用程序。谁能保证 npm CLI 将所有事件转发到 Node 运行时？事实上，它并不会，我们可以轻松地测试这一点。

确保在您的 Node.js 应用程序中设置 `SIGHUP` 信号的事件处理程序，每次发送事件时都记录到控制台。一个简单的代码示例应如下所示：

    function handle(signal) {
       console.log(`*^!@4=> Received event: ${signal}`)
    }
    process.on('SIGHUP', handle)

然后运行容器，一旦它启动，使用 `docker` CLI 和特殊的 `--signal` 命令行标志专门向其发送 `SIGHUP` 信号：

**`$ docker kill --signal=SIGHUP elastic_archimedes`**

什么都没发生，对吧？这是因为 npm 客户端不会将任何信号转发到它生成的 Node 进程。

另一个问题与在 Dockerfile 中指定 `CMD` 指令的不同方式有关。有两种方式，它们并不相同：

1. shell 形式表示法，容器生成一个包装进程的 shell 解释器。在这种情况下，shell 可能无法正确地将信号转发到您的进程。
2. exec 形式表示法，直接生成进程而不将其包装在 shell 中。使用 JSON 数组表示法指定，例如：`CMD ["npm", "start"]`。发送到容器的任何信号都直接发送到进程。

基于这些知识，我们希望按如下方式改进 Dockerfile 进程执行指令：

**`CMD ["node", "server.js"]`**

我们现在直接调用 Node 进程，确保它接收发送给它的所有信号，而不是被 shell 解释器包装。

然而，这又引入了另一个陷阱。

当进程以 PID 1 运行时，它实际上承担了初始化系统的一些职责，该系统通常负责初始化操作系统和进程。内核以不同于其他进程标识符的方式处理 PID 1。这种内核的特殊处理意味着，如果进程尚未为其设置处理程序，则向正在运行的进程发送 `SIGTERM` 信号不会调用默认的终止进程行为。

引用 [Node.js Docker 工作组的建议](https://github.com/nodejs/docker-node/blob/master/docs/BestPractices.md#handling-kernel-signals)："Node.js 并非设计为在 PID 1 下运行，这在 Docker 内部会导致意外行为。例如，作为 PID 1 运行的 Node.js 进程不会响应 SIGINT（CTRL-C）和类似信号"。

因此，正确的做法是使用一个充当初始化进程的工具，它以 PID 1 调用，然后生成我们的 Node.js 应用程序作为另一个进程，同时确保所有信号都代理到该 Node.js 进程。如果可能，我们希望使用尽可能小的工具来完成此操作，以避免向容器镜像添加安全漏洞。

[dumb-init](https://engineeringblog.yelp.com/2016/01/dumb-init-an-init-for-docker.html) 就是这样一个工具，它是静态链接的，并且占用空间很小。以下是设置方法：

    RUN apk add dumb-init
    CMD ["dumb-init", "node", "server.js"]

这为我们带来了以下最新的 Dockerfile。请注意，我们将 `dumb-init` 包安装放在镜像声明之后，以便利用 Docker 的层缓存：

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    RUN apk add dumb-init
    ENV NODE_ENV production
    WORKDIR /usr/src/app
    COPY --chown=node:node . .
    RUN npm ci --omit=dev
    USER node
    CMD ["dumb-init", "node", "server.js"]

需要了解的是：`docker kill` 和 `docker stop` 命令只向 PID 1 的容器进程发送信号。如果您运行的是运行 Node.js 应用程序的 shell 脚本，请注意 shell 实例（如 `/bin/sh`）不会将信号转发给子进程，这意味着您的应用程序永远不会收到 `SIGTERM`。

## 6) 为 Node.js Web 应用程序提供优雅的关闭机制

既然我们已经在讨论终止应用程序的进程信号，让我们确保以不中断用户的方式正确且优雅地关闭它们。

当 Node.js 应用程序接收到中断信号（也称为 `SIGINT` 或 `CTRL+C`）时，除非设置了任何事件处理程序以不同方式处理，否则将导致进程突然终止。这意味着连接到 Web 应用程序的客户端将立即断开连接。现在，想象一下由 Kubernetes 编排的数百个 Node.js Web 容器，根据需要上下扩展以管理错误。这不是最佳的用户体验。

您可以轻松模拟这个问题。以下是一个带有 60 秒端点延迟响应的 Fastify Web 应用程序示例：

    fastify.get('/delayed', async (request, reply) => {
     const SECONDS_DELAY = 60000
     await new Promise(resolve => {
         setTimeout(() => resolve(), SECONDS_DELAY)
     })
     return { hello: 'delayed world' }
    })
     
    const start = async () => {
     try {
       await fastify.listen(PORT, HOST)
       console.log(`*^!@4=> Process id: ${process.pid}`)
     } catch (err) {
       fastify.log.error(err)
       process.exit(1)
     }
    }
     
    start()

运行此应用程序，一旦运行，向此端点发送简单的 HTTP 请求：

`$ time curl https://localhost:3000/delayed`

在 Node.js 控制台窗口中按 `CTRL+C`，您会发现 curl 请求突然退出。这模拟了容器拆除时用户将体验到的情况。

为提供更好的体验，我们可以执行以下操作：

1. 为各种终止信号（如 `SIGINT` 和 `SIGTERM`）设置事件处理程序。
2. 处理程序等待清理操作，如数据库连接、正在进行的 HTTP 请求等。
3. 处理程序随后终止 Node.js 进程。

具体对于 Fastify，我们可以让处理程序调用 [fastify.close()](https://www.fastify.io/docs/latest/Server/)，它返回一个我们将等待的 promise，并且 Fastify 还会负责对每个新连接以 HTTP 状态码 503 响应，以表示应用程序不可用。

让我们添加事件处理程序：

    async function closeGracefully(signal) {
       console.log(`*^!@4=> Received signal to terminate: ${signal}`)
     
       await fastify.close()
       // await db.close() 如果我们在此应用程序中有数据库连接
       // await 其他我们应该优雅清理的事项
       process.exit()
    }
    process.on('SIGINT', closeGracefully)
    process.on('SIGTERM', closeGracefully)

诚然，这更多是一个通用的 Web 应用程序问题，而非 Dockerfile 相关，但在编排环境中更为重要。

## 7) 查找并修复 Node.js Docker 镜像中的安全漏洞

请参阅 [Docker 安全备忘录 - 使用静态分析工具](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-9-use-static-analysis-tools)

## 8) 使用多阶段构建

多阶段构建是一种很好的方式，可以从简单但可能有错误的 Dockerfile 转变为分离的 Docker 镜像构建步骤，以避免泄露敏感信息。不仅如此，我们还可以使用更大的 Docker 基础镜像来安装依赖、编译任何本地 npm 包（如果需要），然后将所有这些工件复制到一个小型生产基础镜像中，就像我们的 alpine 示例一样。

### 防止敏感信息泄露

这里避免敏感信息泄露的用例比您想象的更常见。

如果您为工作构建 Docker 镜像，很高的可能性是您还维护私有 npm 包。如果是这种情况，那么您可能需要找到某种方法使秘密的 `NPM_TOKEN` 对 npm 安装可用。

以下是我所说的示例：

    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    RUN apk add dumb-init
    ENV NODE_ENV production
    ENV NPM_TOKEN 1234
    WORKDIR /usr/src/app
    COPY --chown=node:node . .
    #RUN npm ci --omit=dev
    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev
    USER node
    CMD ["dumb-init", "node", "server.js"]

这样做会在 Docker 镜像中留下包含秘密 npm 令牌的 `.npmrc` 文件。您可以尝试通过之后删除它来改进，如下所示：

    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev
    RUN rm -rf .npmrc

然而，现在 `.npmrc` 文件在 Docker 镜像的不同层中可用。如果此 Docker 镜像是公开的，或者有人以某种方式访问它，那么您的令牌就会被泄露。更好的改进方法如下：

    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev; \
       rm -rf .npmrc

现在问题是 Dockerfile 本身需要被视为秘密资产，因为它包含了内部的秘密 npm 令牌。

幸运的是，Docker 支持在构建过程中传递参数：

    ARG NPM_TOKEN
    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev; \
       rm -rf .npmrc

然后我们这样构建：

**`$ docker build . -t nodejs-tutorial --build-arg NPM_TOKEN=1234`**

我知道您认为此时我们已经完成了，但很抱歉让您失望 🙂

这就是安全性 - 有时看似明显的事情却是另一个陷阱。

现在您想知道问题是什么？传递给 Docker 的构建参数会保留在历史日志中。让我们用自己的眼睛看看。运行此命令：

**`$ docker history nodejs-tutorial`**

它会打印以下内容：

    IMAGE          CREATED              CREATED BY                                      SIZE      COMMENT
    b4c2c78acaba   About a minute ago   CMD ["dumb-init" "node" "server.js"]            0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   USER node                                       0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   RUN |1 NPM_TOKEN=1234 /bin/sh -c echo "//reg…   5.71MB    buildkit.dockerfile.v0
    <missing>      About a minute ago   ARG NPM_TOKEN                                   0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   COPY . . # buildkit                             15.3kB    buildkit.dockerfile.v0
    <missing>      About a minute ago   WORKDIR /usr/src/app                            0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   ENV NODE_ENV=production                         0B        buildkit.dockerfile.v0
    <missing>      About a minute ago   RUN /bin/sh -c apk add dumb-init # buildkit     1.65MB    buildkit.dockerfile.v0

您看到秘密 npm 令牌了吗？这就是我的意思。

有一个很好的方法来管理容器镜像的秘密，但现在是时候引入多阶段构建作为缓解此问题的方法，同时展示我们如何构建最小的镜像。

### 为 Node.js Docker 镜像引入多阶段构建

就像软件开发中的关注点分离原则一样，我们将在构建 Node.js Docker 镜像时应用相同的思想。我们将有一个镜像用于构建 Node.js 应用程序运行所需的所有内容，在 Node.js 世界中，这意味着安装 npm 包，并在必要时编译本地 npm 模块。这将是我们的第一阶段。

第二个 Docker 镜像，代表 Docker 构建的第二阶段，将是生产 Docker 镜像。这第二个也是最后一个阶段是我们实际优化并发布到注册表（如果有）的镜像。我们将称为 `build` 的第一个镜像将被丢弃，并在构建它的 Docker 主机上保留为悬空镜像，直到被清理。

以下是代表我们迄今为止进展的 Dockerfile 更新，但分为两个阶段：

    # --------------> 构建镜像
    FROM node:latest AS build
    ARG NPM_TOKEN
    WORKDIR /usr/src/app
    COPY package*.json /usr/src/app/
    RUN echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc && \
       npm ci --omit=dev && \
       rm -f .npmrc
     
    # --------------> 生产镜像
    FROM node:lts-alpine@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    RUN apk add dumb-init
    ENV NODE_ENV production
    USER node
    WORKDIR /usr/src/app
    COPY --chown=node:node --from=build /usr/src/app/node_modules /usr/src/app/node_modules
    COPY --chown=node:node . /usr/src/app
    CMD ["dumb-init", "node", "server.js"]

如您所见，我为 `build` 阶段选择了一个更大的镜像，因为我可能需要像 `gcc`（GNU 编译器集合）这样的工具来编译本地 npm 包，或者用于其他需求。

在第二阶段，`COPY` 指令有一个特殊的表示法，将 `node_modules/` 文件夹从构建 Docker 镜像复制到这个新的生产基础镜像中。

另外，现在您看到作为构建参数传递给 `build` 中间 Docker 镜像的 `NPM_TOKEN` 了吗？它在 `docker history nodejs-tutorial` 命令输出中不再可见，因为它不存在于我们的生产 Docker 镜像中。

## 9) 将不必要的文件排除在 Node.js Docker 镜像之外

您有一个 `.gitignore` 文件，以避免用不必要的文件（可能还有敏感文件）污染 git 仓库，对吗？对于 Docker 镜像也是如此。

Docker 有一个 `.dockerignore`，它将确保跳过发送任何与其中的 glob 模式匹配的文件到 Docker 守护进程。以下是一个文件列表，让您了解可能放入 Docker 镜像但理想情况下应避免的文件：

    .dockerignore
    node_modules
    npm-debug.log
    Dockerfile
    .git
    .gitignore

如您所见，`node_modules/` 实际上非常重要，需要跳过，因为如果我们没有忽略它，那么我们最初的简单 Dockerfile 版本会导致本地 `node_modules/` 文件夹原样复制到容器中。

    FROM node@sha256:b2da3316acdc2bec442190a1fe10dc094e7ba4121d029cb32075ff59bb27390a
    WORKDIR /usr/src/app
    COPY . /usr/src/app
    RUN npm install
    CMD "npm" "start"

事实上，在实践多阶段 Docker 构建时，拥有 `.dockerignore` 文件变得更加重要。让我们回顾一下第二阶段 Docker 构建的样子：

    # --------------> 生产镜像
    FROM node:lts-alpine
    RUN apk add dumb-init
    ENV NODE_ENV production
    USER node
    WORKDIR /usr/src/app
    COPY --chown=node:node --from=build /usr/src/app/node_modules /usr/src/app/node_modules
    COPY --chown=node:node . /usr/src/app
    CMD ["dumb-init", "node", "server.js"]

拥有 `.dockerignore` 的重要性在于，当我们在第二阶段 Dockerfile 中执行 `COPY . /usr/src/app` 时，我们也会将任何本地 `node_modules/` 复制到 Docker 镜像中。这是绝对不行的，因为我们可能会复制 `node_modules/` 中修改过的源代码。

除此之外，由于我们使用通配符 `COPY .`，我们可能还会将包含凭据或本地配置的敏感文件复制到 Docker 镜像中。

对于 `.dockerignore` 文件，要点是：

- 跳过 Docker 镜像中可能被修改的 `node_modules/` 副本。
- 避免凭据泄露，如 `.env` 或 `aws.json` 文件中的内容进入 Node.js Docker 镜像。
- 帮助加速 Docker 构建，因为它忽略了原本会导致缓存失效的文件。例如，如果修改了日志文件或本地环境配置文件，都会导致 Docker 镜像缓存在复制本地目录的那一层失效。

## 10) 将秘密挂载到 Docker 构建镜像中

关于 `.dockerignore` 文件，需要注意的是它是一种全有或全无的方法，在 Docker 多阶段构建中无法针对每个构建阶段开启或关闭。

为什么这很重要？理想情况下，我们希望在构建阶段使用 `.npmrc` 文件，因为我们可能需要它来访问私有 npm 包的秘密 npm 令牌。也许它还需要特定的代理或注册表配置来拉取包。

这意味着在 `build` 阶段提供 `.npmrc` 文件是有意义的 - 然而，在生产镜像的第二阶段，我们根本不需要它，也不希望它在那里，因为它可能包含敏感信息，如秘密 npm 令牌。

缓解这个 `.dockerignore` 缺陷的一种方法是挂载本地文件系统，但有一种更好的方法。

Docker 支持一种相对较新的功能，称为 Docker 秘密，这正好适合我们处理 `.npmrc` 的情况。其工作原理如下：

- 运行 `docker build` 命令时，我们将指定命令行参数，定义一个新的秘密 ID 并引用文件作为秘密的源。
- 在 Dockerfile 中，我们将为 `RUN` 指令添加标志，以安装生产 npm，这将挂载由秘密 ID 引用的文件到目标位置 - 本地目录 `.npmrc` 文件，这是我们希望它可用的地方。
- `.npmrc` 文件作为秘密挂载，永远不会复制到 Docker 镜像中。
- 最后，别忘了将 `.npmrc` 文件添加到 `.dockerignore` 文件的内容中，以确保它根本不会进入镜像，无论是构建还是生产镜像。

让我们看看所有这些是如何协同工作的。首先是更新后的 `.dockerignore` 文件：

    .dockerignore
    node_modules
    npm-debug.log
    Dockerfile
    .git
    .gitignore
    .npmrc

然后是完整的 Dockerfile，更新了 RUN 指令以在指定 `.npmrc` 挂载点的同时安装 npm 包：

    # --------------> 构建镜像
    FROM node:latest AS build
    WORKDIR /usr/src/app
    COPY package*.json /usr/src/app/
    RUN --mount=type=secret,mode=0644,id=npmrc,target=/usr/src/app/.npmrc npm ci --omit=dev
     
    # --------------> 生产镜像
    FROM node:lts-alpine
    RUN apk add dumb-init
    ENV NODE_ENV production
    USER node
    WORKDIR /usr/src/app
    COPY --chown=node:node --from=build /usr/src/app/node_modules /usr/src/app/node_modules
    COPY --chown=node:node . /usr/src/app
    CMD ["dumb-init", "node", "server.js"]

最后，构建 Node.js Docker 镜像的命令：

    docker build . -t nodejs-tutorial --secret id=npmrc,src=.npmrc

**注意：** 秘密是 Docker 的一个新功能，如果您使用的是旧版本，可能需要按如下方式启用 Buildkit：

    DOCKER_BUILDKIT=1 docker build . -t nodejs-tutorial --build-arg NPM_TOKEN=1234 --secret id=npmrc,src=.npmrc
