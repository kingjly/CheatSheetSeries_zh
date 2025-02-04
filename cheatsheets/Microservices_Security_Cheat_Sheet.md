# 微服务安全备忘录

## 引言

微服务架构正越来越多地被用于设计和实现云端和本地基础设施中的应用系统、高规模应用和服务。在应用设计和实现阶段，需要解决许多安全挑战。在设计阶段必须解决的基本安全要求是身份认证和授权。因此，对于应用安全架构师来说，理解并正确使用现有的架构模式来在基于微服务的系统中实现身份认证和授权至关重要。本备忘录的目标是识别这些模式，并为应用安全架构师提供使用这些模式的可能方法建议。

## 边缘层授权

在简单场景中，授权可以仅在边缘层（API 网关）进行。API 网关可以集中执行所有下游微服务的授权，消除了为每个单独的服务提供身份认证和访问控制的需要。在这种情况下，NIST 建议实施缓解控制措施，如双向认证，以防止对内部服务的直接匿名连接（绕过 API 网关）。需要注意的是，边缘层授权存在以下[局限性](https://www.youtube.com/watch?v=UnXjwCWgBKU)：

- 将所有授权决策推送到 API 网关在具有多个角色和访问控制规则的复杂生态系统中可能变得难以管理。
- API 网关可能成为单一决策点，这可能违反"纵深防御"原则。
- 运维团队通常拥有 API 网关，因此开发团队无法直接进行授权更改，这会由于额外的沟通和流程开销而降低效率。

在大多数情况下，开发团队在两个地方实现授权 - 在边缘层以粗粒度方式，并在服务层。要对外部实体进行身份认证，边缘层可以使用通过 HTTP 标头（例如"Cookie"或"Authorization"）传输的访问令牌（引用令牌或自包含令牌）或使用 mTLS。

## 服务层授权

服务层授权使每个微服务能够更好地执行访问控制策略。
为进一步讨论，我们将使用[NIST SP 800-162](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf)中的术语和定义。访问控制系统的功能组件可以分类如下：

- 策略管理点（PAP）：提供创建、管理、测试和调试访问控制规则的用户界面。
- 策略决策点（PDP）：通过评估适用的访问控制策略来计算访问决策。
- 策略执行点（PEP）：响应主体请求访问受保护对象的请求，执行策略决策。
- 策略信息点（PIP）：作为属性或策略评估所需数据的检索源，为 PDP 提供做出决策所需的信息。

![NIST ABAC 框架](../assets/NIST_ABAC.png)

### 服务层授权：现有模式

#### 去中心化模式

开发团队直接在微服务代码级别实现 PDP 和 PEP。所有需要实现该规则的访问控制规则和属性都在每个微服务上定义和存储（步骤 1）。当微服务接收到带有一些授权元数据（例如，最终用户上下文或请求的资源 ID）的请求时，微服务对其进行分析（步骤 3）以生成访问控制策略决策，然后执行授权（步骤 4）。

![去中心化模式高级设计](../assets/Dec_pattern_HLD.png)

现有的编程语言框架允许开发团队在微服务层实现授权。例如，[Spring Security 允许](https://www.youtube.com/watch?v=v2J32nd0g24)开发人员在资源服务器中启用作用域检查（例如，使用从传入的 JWT 中提取的作用域）并用它来执行授权。

在源代码级别实现授权意味着每当开发团队想要修改授权逻辑时，必须更新代码。

#### 具有单一策略决策点的集中化模式

在这种模式中，访问控制规则被集中定义、存储和评估。使用 PAP 定义访问控制规则（步骤 1），并将这些规则以及评估这些规则所需的属性传递给集中的 PDP（步骤 2）。当主体调用微服务端点（步骤 3）时，微服务代码通过网络调用调用集中的 PDP，PDP 通过根据访问控制规则和属性评估查询输入来生成访问控制策略决策（步骤 4）。基于 PDP 的决策，微服务执行授权（步骤 5）。

![具有单一策略决策点的集中化模式高级设计](../assets/Single_PDP_HLD.png)

要定义访问控制规则，开发/运维团队必须使用某种语言或符号。一个例子是可扩展访问控制标记语言（XACML）和下一代访问控制（NGAC），这是描述策略规则的标准。

由于额外的网络调用到远程 PDP 端点，此模式可能导致延迟问题，但可以通过在微服务级别缓存授权策略决策来缓解。应该提到，PDP 必须以高可用性模式运行，以防止弹性和可用性问题。应用安全架构师应将其与其他模式（例如，API 网关级别的授权）结合，以执行"纵深防御"原则。

#### 具有嵌入式策略决策点的集中化模式

在这种模式中，访问控制规则集中定义，但在微服务级别存储和评估。使用 PAP 定义访问控制规则（步骤 1），并将这些规则以及评估这些规则所需的属性传递给嵌入式 PDP（步骤 2）。当主体调用微服务端点（步骤 3）时，微服务代码调用 PDP，PDP 通过根据访问控制规则和属性评估查询输入来生成访问控制策略决策（步骤 4）。基于 PDP 的决策，微服务执行授权（步骤 5）。

![具有嵌入式策略决策点的集中化模式高级设计](../assets/Embed_PDP_HLD.png)

在这种情况下，PDP 代码可以作为微服务内置库或服务网格架构中的边车实现。由于可能的网络/主机故障和网络延迟，建议将嵌入式 PDP 实现为与微服务位于同一主机上的微服务库或边车。嵌入式 PDP 通常将授权策略和策略相关数据存储在内存中，以最大限度地减少授权执行期间的外部依赖并获得低延迟。与"具有单一策略决策点的集中化模式"方法的主要区别在于，微服务端不存储授权*决策*，而是存储最新的授权*策略*。应该提到，缓存授权决策可能导致应用过时的授权规则和访问控制违规。

Netflix 展示了[（链接）](https://www.youtube.com/watch?v=R6tUNpRpdnY)，[（链接）](https://conferences.oreilly.com/velocity/vl-ca-2018/public/schedule/detail/66606.html)使用"具有嵌入式 PDP 的集中化模式"在微服务级别实现授权的实际案例。

![具有嵌入式策略决策点的集中化模式高级设计](../assets/Netflix_AC.png)

- 策略门户和策略存储库是基于 UI 的系统，用于创建、管理和版本化访问控制规则。
- 聚合器从所有外部源获取访问控制规则中使用的数据并保持其最新。
- 分发器从策略存储库中提取访问控制规则，从聚合器中提取访问控制规则中使用的数据，以将它们分发到 PDP 中。
- PDP（库）异步拉取访问控制规则和数据并保持其最新，以由 PEP 组件执行授权。

### 关于如何实现授权的建议

1. 为了实现可扩展性，不建议在源代码中硬编码授权策略（去中心化模式），而是使用特殊语言来表达策略。目标是将授权从代码中外部化/解耦，而不仅仅是网关/代理作为检查点。由于其弹性和广泛采用，推荐的服务层授权模式是"具有嵌入式 PDP 的集中化模式"。
2. 授权解决方案应该是平台级解决方案；专门的团队（例如，平台安全团队）必须对授权解决方案的开发和运营负责，并在开发团队之间共享实现授权的微服务蓝图/库/组件。
3. 授权解决方案应基于广泛使用的解决方案，因为实施自定义解决方案有以下缺点：
    - 安全或工程团队必须构建和维护自定义解决方案。
    - 需要为系统架构中使用的每种语言构建和维护客户端库 SDK。
    - 需要培训每个开发人员使用自定义授权服务 API 和集成，并且没有开源社区可以获取信息。
4. 可能并非所有访问控制策略都可以由网关/代理和共享授权库/组件执行，因此某些特定的访问控制规则仍然必须在微服务业务代码级别实现。为此，建议微服务开发团队使用简单的问卷/检查清单来发现此类安全需求并在微服务开发期间正确处理它们。
5. 建议实施"纵深防御"原则，并在以下层面执行授权：
    - 网关和代理层，以粗粒度方式。
    - 微服务层，使用共享授权库/组件执行细粒度决策。
    - 微服务业务代码层，以实施特定于业务的访问控制规则。
6. 必须在开发、批准和推出过程中实施正式的访问控制策略程序。

## 外部实体身份传播

为了在微服务级别做出细粒度的授权决策，微服务必须了解调用者的上下文（例如，用户 ID、用户角色/组）。为了允许内部服务层执行授权，边缘层必须将经过身份认证的外部实体身份（例如，最终用户上下文）与请求一起传播到下游微服务。传播外部实体身份的最简单方法之一是重用边缘层接收到的访问令牌并将其传递给内部微服务。然而，应该提到，由于可能的外部访问令牌泄露，这种方法极不安全，并且可能增加攻击面，因为通信依赖于专有的基于令牌的系统实现。如果内部服务无意中暴露在外部网络中，则可以直接使用泄露的访问令牌访问它。如果内部服务只接受仅内部服务已知的令牌格式，则此攻击是不可能的。这种模式也不是外部访问令牌不可知的，即内部服务必须理解外部访问令牌，并支持广泛的身份认证技术，以从不同类型的外部令牌（例如，JWT、Cookie、OpenID Connect 令牌）中提取身份。

### 身份传播：现有模式

#### 以明文或自签名数据结构发送外部实体身份

在这种方法中，微服务从传入请求中提取外部实体身份（例如，通过解析传入的访问令牌），创建包含该上下文的数据结构（例如，JSON 或自签名 JWT），并将其传递给内部微服务。
在这种情况下，接收方微服务必须信任调用微服务。如果调用微服务想要违反访问控制规则，它可以在 HTTP 标头中设置任何它想要的用户/客户端 ID 或用户角色。这种方法仅适用于高度可信的环境，其中每个微服务都由应用安全软件开发实践的可信开发团队开发。

#### 使用受信任颁发者签名的数据结构

在这种模式中，在边缘层的身份认证服务对外部请求进行身份认证后，生成一个代表外部实体身份的数据结构（例如，包含用户 ID、用户角色/组或权限），由受信任的颁发者签名或加密，并传播到内部微服务。

![签名身份传播](../assets/Signed_ID_propogation.png)

[Netflix 展示了](https://www.infoq.com/presentations/netflix-user-identity/)使用该模式的真实案例：一个名为"Passport"的结构，其中包含用户 ID 及其属性，并在边缘层对每个传入请求进行 HMAC 保护。此结构传播到内部微服务，并且永不对外暴露。

1. 边缘身份认证服务（EAS）从密钥管理系统获取密钥。
2. EAS 从传入请求中接收访问令牌（例如，在 Cookie、JWT、OAuth2 令牌中）。
3. EAS 解密访问令牌，解析外部实体身份，并在签名的"Passport"结构中将其发送到内部服务。
4. 内部服务可以使用包装器提取用户身份以执行授权（例如，实现基于身份的授权）。
5. 如有必要，内部服务可以在调用链中将"Passport"结构传播到下游服务。

![Netflix 身份传播方法](../assets/Netflix_ID_prop.png)

应该提到，该模式对外部访问令牌不可知，并允许将外部实体与其内部表示解耦。

### 关于如何实现身份传播的建议

1. 为了实现对外部访问令牌不可知且可扩展的系统，将为外部实体颁发的访问令牌与其内部表示解耦。使用单一数据结构在微服务之间表示和传播外部实体身份。边缘层服务必须验证传入的外部访问令牌，颁发内部实体表示结构，并将其传播到下游服务。
2. 使用受信任颁发者签名（对称或非对称加密）的内部实体表示结构是社区采用的推荐模式。
3. 内部实体表示结构应具有可扩展性，以便能够添加可能导致低延迟的更多声明。
4. 内部实体表示结构不得对外暴露（例如，不得暴露给浏览器或外部设备）

## 服务间身份认证

### 现有模式

#### 双向传输层安全（mTLS）

使用 mTLS 方法，每个微服务都可以合法地识别其通信对象，同时还实现传输数据的保密性和完整性。部署中的每个微服务必须携带公钥/私钥对，并使用该密钥对通过 mTLS 向接收方微服务进行身份认证。mTLS 通常使用自托管的公钥基础设施（PKI）实现。使用 mTLS 的主要挑战是密钥配置、信任引导、证书吊销和密钥轮换。

#### 基于令牌的认证

基于令牌的方法在应用层工作。令牌是一个可以包含调用者 ID（微服务 ID）及其权限（作用域）的容器。调用方微服务可以通过使用其自身的服务 ID 和密码调用特殊的安全令牌服务来获取签名令牌，然后将其附加到每个传出请求中，例如通过 HTTP 标头。被调用的微服务可以提取令牌并进行在线或离线验证。

![签名身份传播](../assets/Token_validation.png)

1. 在线场景：
    - 要验证传入的令牌，微服务通过网络调用调用集中的服务令牌服务。
    - 可以检测到已吊销（已泄露）的令牌。
    - 高延迟。
    - 应用于关键请求。
2. 离线场景：
    - 要验证传入的令牌，微服务使用下载的服务令牌服务公钥。
    - 可能无法检测到已吊销（已泄露）的令牌。
    - 低延迟。
    - 应用于非关键请求。

在大多数情况下，基于令牌的身份认证通过 TLS 工作，提供传输中数据的保密性和完整性。

## 日志记录

基于微服务的系统中的日志服务旨在满足问责制和可追溯性原则，并通过日志分析帮助检测操作中的安全异常。因此，对于应用安全架构师来说，理解并恰当地使用现有的架构模式在基于微服务的系统中实现审计日志记录至关重要。下图显示了高级架构设计，基于以下原则：

- 每个微服务使用标准输出（通过 stdout、stderr）将日志消息写入本地文件。
- 日志代理定期拉取日志消息并将其发送（发布）到消息代理（例如，NATS、Apache Kafka）。
- 中央日志服务订阅消息代理中的消息，接收并处理它们。

![日志记录模式](../assets/ms_logging_pattern.png)

以下是日志子系统架构的高级建议及其原理：

1. 微服务不得直接使用网络通信向中央日志子系统发送日志消息。微服务应将其日志消息写入本地日志文件：
    - 这可以减轻由于日志服务因攻击或被合法微服务淹没而导致的数据丢失威胁
    - 在日志服务中断的情况下，微服务仍将日志消息写入本地文件（不会丢失数据），并在日志服务恢复后可用于传输

2. 应有一个与微服务解耦的专用组件（日志代理）。日志代理应收集微服务的日志数据（读取本地日志文件）并将其发送到中央日志子系统。由于可能存在网络延迟问题，日志代理应部署在与微服务相同的主机（虚拟或物理机）上：
    - 这可以减轻由于日志服务因攻击或被合法微服务淹没而导致的数据丢失威胁
    - 在日志代理故障的情况下，微服务仍会将信息写入日志文件，日志代理恢复后将读取文件并将信息发送到消息代理

3. 为防止对中央日志子系统的可能 DoS 攻击，日志代理不应使用同步请求/响应模式发送日志消息。应使用消息代理在日志代理和中央日志服务之间实现异步连接：
    - 这可以减轻由于日志服务被合法微服务淹没而导致的数据丢失威胁
    - 在日志服务中断的情况下，微服务仍将日志消息写入本地文件（不会丢失数据），并在日志服务恢复后可用于传输

4. 日志代理和消息代理应使用双向认证（例如，基于 TLS）来加密所有传输的数据（日志消息）并进行自身认证：
    - 这可以减轻微服务欺骗、日志/传输系统欺骗、网络流量注入、嗅探网络流量等威胁

5. 消息代理应执行访问控制策略以防止未经授权的访问并实施最小权限原则：
    - 这可以减轻微服务权限提升的威胁

6. 日志代理应过滤/净化输出日志消息，确保敏感数据（例如，个人可识别信息、密码、API 密钥）永远不会发送到中央日志子系统（数据最小化原则）。有关应从日志中排除的项目的全面概述，请参见 [OWASP 日志备忘录](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Cheat_Sheet.md#data-to-exclude)。

7. 微服务应生成唯一标识每个调用链的关联 ID，并帮助对日志消息进行分组以进行调查。日志代理应在每个日志消息中包含关联 ID。

8. 日志代理应定期提供运行状况和状态数据，以指示其可用性或不可用性。

9. 日志代理应以结构化日志格式（例如，JSON、CSV）发布日志消息。

10. 日志代理应附加上下文数据的日志消息，例如平台上下文（主机名、容器名）、运行时上下文（类名、文件名）。

有关应记录的事件和可能的数据格式的全面概述，请参见 [OWASP 日志备忘录](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Cheat_Sheet.md#which-events-to-log) 和 [应用日志词汇备忘录](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Vocabulary_Cheat_Sheet.md)

## 参考文献

- [NIST 特别出版物 800-204](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf) "微服务应用系统的安全策略"
- [NIST 特别出版物 800-204A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf) "使用服务网格架构构建安全的微服务应用"
- [《微服务安全实战》](https://www.manning.com/books/microservices-security-in-action)，Prabath Siriwardena 和 Nuwan Dias，2020年，Manning出版社
