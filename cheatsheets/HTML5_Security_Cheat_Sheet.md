# HTML5 安全备忘录

## 引言

以下备忘录作为安全实施 HTML5 的指南。

## 通信 API

### Web 消息传递

Web 消息传递（也称为跨域消息传递）提供了一种在不同源的文档之间传递消息的方法，这种方法通常比过去使用的多种黑客技术更安全。但仍有一些建议需要注意：

- 发送消息时，明确指定 `postMessage` 的第二个参数为预期的源，而不是 `*`，以防止在重定向或目标窗口源发生变化后将消息发送到未知源。
- 接收页面应该**始终**：
    - 检查发送者的 `origin` 属性，以验证数据是否来自预期位置。
    - 对事件的 `data` 属性执行输入验证，确保其为所需格式。
- 不要假定你可以控制 `data` 属性。发送页面中的单个[跨站脚本](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)漏洞允许攻击者发送任何给定格式的消息。
- 双方都应该仅将交换的消息解释为**数据**。切勿通过 `eval()` 评估传递的消息，或将其插入页面 DOM（例如通过 `innerHTML`），否则会创建基于 DOM 的 XSS 漏洞。更多信息请参见 [DOM 基于 XSS 预防备忘录](DOM_based_XSS_Prevention_Cheat_Sheet.md)。
- 要将数据值分配给元素，不要使用不安全的方法如 `element.innerHTML=data;`，而应使用更安全的选项：`element.textContent=data;`
- 精确检查源以匹配你预期的完全限定域名（FQDN）。注意，以下代码非常不安全：`if(message.origin.indexOf(".owasp.org")!=-1) { /* ... */ }`，因为 `owasp.org.attacker.com` 也会匹配。
- 如果需要嵌入外部内容/不受信任的小工具并允许用户控制的脚本（强烈不建议），请查看[沙盒框架](HTML5_Security_Cheat_Sheet.md#sandboxed-frames)的相关信息。

### 跨源资源共享（CORS）

- 验证传递给 `XMLHttpRequest.open` 的 URL。当前浏览器允许这些 URL 是跨域的；这种行为可能导致远程攻击者进行代码注入。对绝对 URL 要特别注意。
- 确保响应 `Access-Control-Allow-Origin: *` 的 URL 不包含任何敏感内容或可能帮助攻击者进一步攻击的信息。仅对需要跨域访问的特定 URL 使用 `Access-Control-Allow-Origin` 标头。不要为整个域使用该标头。
- 在 `Access-Control-Allow-Origin` 标头中仅允许选定的受信任域。优先允许特定域，而不是阻止或允许任何域（不要使用 `*` 通配符，也不要盲目返回 `Origin` 标头内容而不进行任何检查）。
- 请记住，CORS 并不能阻止请求的数据被发送到未经授权的位置。服务器仍然需要执行常规的 [CSRF](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) 预防。
- 虽然 [Fetch 标准](https://fetch.spec.whatwg.org/#http-cors-protocol)建议使用 `OPTIONS` 动词进行预检请求，但当前实现可能不会执行此请求，因此对"普通"（`GET` 和 `POST`）请求执行必要的访问控制很重要。
- 丢弃通过纯 HTTP 接收的带有 HTTPS 源的请求，以防止混合内容错误。
- 不要仅依赖 Origin 标头进行访问控制检查。浏览器在 CORS 请求中始终发送此标头，但在浏览器外可能被伪造。应使用应用程序级协议来保护敏感数据。

### WebSocket

- 在实现的客户端/服务器中放弃向后兼容性，仅使用 hybi-00 以上的协议版本。流行的 Hixie-76 版本（hiby-00）及更早版本已过时且不安全。
- 推荐的版本是在所有当前浏览器的最新版本中支持的 [RFC 6455](http://tools.ietf.org/html/rfc6455)（被 Firefox 11+、Chrome 16+、Safari 6、Opera 12.50 和 IE10 支持）。
- 虽然通过 WebSocket 隧道传输 TCP 服务（如 VNC、FTP）相对容易，但这样做会在跨站脚本攻击的情况下使浏览器内攻击者能够访问这些隧道服务。这些服务也可能直接从恶意页面或程序调用。
- 该协议不处理授权和/或身份验证。如果传输敏感数据，应用程序级协议应单独处理这些问题。
- 将 WebSocket 接收的消息作为数据处理。不要尝试直接将其分配给 DOM 或作为代码评估。如果响应是 JSON，切勿使用不安全的 `eval()` 函数；改用安全的 `JSON.parse()` 选项。
- 通过 `ws://` 协议公开的端点很容易还原为纯文本。只应使用 `wss://`（基于 SSL/TLS 的 WebSocket）以防止中间人攻击。
- 在浏览器外可以伪造客户端，因此 WebSocket 服务器应能处理不正确/恶意的输入。始终验证来自远程站点的输入，因为它可能已被更改。
- 在实现服务器时，检查 WebSocket 握手中的 `Origin:` 标头。尽管在浏览器外可能被伪造，但浏览器始终添加发起 WebSocket 连接的页面的源。
- 由于浏览器中的 WebSocket 客户端可通过 JavaScript 调用访问，所有 WebSocket 通信都可能通过[跨站脚本](https://owasp.org/www-community/attacks/xss/)被伪造或劫持。始终验证通过 WebSocket 连接传输的数据。

### 服务器发送事件（Server-Sent Events）

- 验证传递给 `EventSource` 构造函数的 URL，即使仅允许同源 URL。
- 如前所述，将消息（`event.data`）作为数据处理，切勿将内容评估为 HTML 或脚本代码。
- 始终检查消息的源属性（`event.origin`），确保消息来自受信任的域。使用允许列表方法。

## 存储 API

### 本地存储（Local Storage）

- 也称为离线存储、Web 存储。底层存储机制可能因用户代理而异。换句话说，应用程序要求的任何身份验证都可以被对存储数据的机器具有本地权限的用户绕过。因此，建议避免在本地存储中存储任何敏感信息，其中身份验证被假定为已存在。
- 由于浏览器的安全保证，在不假定对数据的访问需要身份验证或授权时，使用本地存储是适当的。
- 如果不需要持久存储，请使用 sessionStorage 对象而非 localStorage。sessionStorage 对象仅在窗口/标签关闭之前可用。
- 单个[跨站脚本](https://owasp.org/www-community/attacks/xss/)可用于窃取这些对象中的所有数据，因此再次建议不要在本地存储中存储敏感信息。
- 单个[跨站脚本](https://owasp.org/www-community/attacks/xss/)也可用于将恶意数据加载到这些对象中，因此不要认为这些对象中的数据是可信的。
- 特别注意 HTML5 页面中的 "localStorage.getItem" 和 "setItem" 调用。这有助于检测开发人员构建的将敏感信息存储在本地存储中的解决方案，如果对该数据的身份验证或授权不正确，这可能是一个严重的风险。
- 不要在本地存储中存储会话标识符，因为数据始终可以通过 JavaScript 访问。Cookie 可以通过 `httpOnly` 标志缓解此风险。
- 没有办法像 HTTP Cookie 的 path 属性那样将对象的可见性限制到特定路径，每个对象在源内共享并受同源策略保护。避免在同一源上托管多个应用程序，所有应用程序将共享相同的 localStorage 对象，改用不同的子域。

### 客户端数据库

- 2010 年 11 月，W3C 宣布 Web SQL 数据库（关系型 SQL 数据库）为已弃用的规范。一个新的标准 Indexed Database API 或 IndexedDB（以前称为 WebSimpleDB）正在积极开发，它提供键值数据库存储和执行高级查询的方法。
- 底层存储机制可能因用户代理而异。换句话说，应用程序要求的任何身份验证都可以被对存储数据的机器具有本地权限的用户绕过。因此，建议不要在本地存储中存储任何敏感信息。
- 如果使用，客户端的 WebDatabase 内容可能容易受到 SQL 注入攻击，需要进行适当的验证和参数化。
- 与本地存储一样，单个[跨站脚本](https://owasp.org/www-community/attacks/xss/)也可用于将恶意数据加载到 Web 数据库中。不要认为这些数据是可信的。

## 地理定位

- [地理定位 API](https://www.w3.org/TR/2021/WD-geolocation-20211124/#security) 要求用户代理在计算位置之前询问用户权限。浏览器对于是否记住此决定以及如何记住的方式各不相同。某些用户代理要求用户再次访问页面才能在不询问的情况下关闭获取用户位置的能力，因此出于隐私考虑，建议在调用 `getCurrentPosition` 或 `watchPosition` 之前需要用户输入。

## Web Workers

- Web Workers 允许使用 `XMLHttpRequest` 对象执行同域和跨源资源共享请求。请参阅本备忘录的相关章节以确保 CORS 安全。
- 尽管 Web Workers 无法访问调用页面的 DOM，但恶意的 Web Workers 可能会过度使用 CPU 进行计算，导致拒绝服务条件，或滥用跨源资源共享进行进一步利用。确保所有 Web Workers 脚本中的代码不具有恶意。不要允许从用户提供的输入创建 Web Worker 脚本。
- 验证与 Web Worker 交换的消息。不要尝试交换用于评估的 JavaScript 代码片段（例如通过 `eval()`），因为这可能引入[基于 DOM 的 XSS](DOM_based_XSS_Prevention_Cheat_Sheet.md) 漏洞。

## Tabnabbing（标签劫持）

攻击细节在此[文章](https://owasp.org/www-community/attacks/Reverse_Tabnabbing)中详细描述。

总之，这是通过 **opener** JavaScript 对象实例公开的返回链接，从新打开的页面对父页面的内容或位置进行操作的能力。

这适用于 HTML 链接或 JavaScript 的 `window.open` 函数，使用 `target` 属性/指令指定不替换当前位置的[目标加载位置](https://www.w3schools.com/tags/att_a_target.asp)，然后使当前窗口/标签可用。

为防止此问题，可采取以下操作：

切断父页面和子页面之间的返回链接：

- 对于 HTML 链接：
    - 要切断此返回链接，在从父页面到子页面的链接标签上添加 `rel="noopener"` 属性。这个属性值会切断链接，但取决于浏览器，可能会在对子页面的请求中保留引用信息。
    - 要同时删除引用信息，请使用此属性值：`rel="noopener noreferrer"`。
- 对于 JavaScript 的 `window.open` 函数，在 `window.open` 函数的 [windowFeatures](https://developer.mozilla.org/en-US/docs/Web/API/Window/open) 参数中添加 `noopener,noreferrer` 值。

由于上述元素的行为在不同浏览器中存在差异，因此要最大化跨支持，可以：

- 对于 [HTML 链接](https://www.scaler.com/topics/html/html-links/)，为每个链接添加 `rel="noopener noreferrer"` 属性。
- 对于 JavaScript，使用以下函数打开窗口（或标签）：

``` javascript
function openPopup(url, name, windowFeatures){
  // 打开弹出窗口并设置 opener 和引用策略指令
  var newWindow = window.open(url, name, 'noopener,noreferrer,' + windowFeatures);
  // 重置 opener 链接
  newWindow.opener = null;
}
```

- 为应用程序发送的每个 HTTP 响应添加 HTTP 响应标头 `Referrer-Policy: no-referrer`（[标头 Referrer-Policy 信息](https://owasp.org/www-project-secure-headers/)）。此配置将确保不会随页面的请求发送任何引用信息。

兼容性矩阵：

- [noopener](https://caniuse.com/#search=noopener)
- [noreferrer](https://caniuse.com/#search=noreferrer)
- [referrer-policy](https://caniuse.com/#feat=referrer-policy)

## 沙盒框架

- 对不受信任的内容使用 `iframe` 的 `sandbox` 属性。
- `iframe` 的 `sandbox` 属性可以对 `iframe` 内的内容启用限制。设置 `sandbox` 属性时，以下限制处于活动状态：
    1. 所有标记都被视为来自唯一源。
    2. 所有表单和脚本被禁用。
    3. 所有链接被阻止针对其他浏览上下文。
    4. 所有自动触发的功能被阻止。
    5. 所有插件被禁用。

可以使用 `sandbox` 属性的值对 `iframe` 功能进行[细粒度控制](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox)。

- 在不支持此功能的旧版用户代理中，此属性将被忽略。将此功能用作额外的保护层，或检查浏览器是否支持沙盒框架，并仅在支持时显示不受信任的内容。
- 除了此属性外，为防止点击劫持攻击和未经请求的框架，建议使用支持 `deny` 和 `same-origin` 值的 `X-Frame-Options` 标头。不推荐使用其他解决方案，如框架破坏 `if(window!==window.top) { window.top.location=location;}`。


## 凭据和个人可识别信息（PII）输入提示

- 防止浏览器缓存输入值。

> 在公共计算机上访问金融账户。即使已注销，下一个使用该机器的人仍可通过浏览器自动完成功能登录。为缓解这一问题，我们告诉输入字段不要以任何方式辅助。

```html
<input type="text" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></input>
```

对于 PII（姓名、电子邮件、地址、电话号码）和登录凭据（用户名、密码）的文本区域和输入字段，应防止浏览器存储。使用这些 HTML5 属性防止浏览器存储表单中的 PII：

- `spellcheck="false"`
- `autocomplete="off"`
- `autocorrect="off"`
- `autocapitalize="off"`

## 离线应用

- 用户代理是否请求用户权限存储离线浏览数据以及何时删除此缓存，因浏览器而异。如果用户通过不安全的网络连接，缓存污染是一个问题，因此出于隐私考虑，建议在发送任何 `manifest` 文件之前需要用户输入。
- 用户应仅缓存受信任的网站，并在通过开放或不安全的网络浏览后清理缓存。

## 渐进增强和优雅降级风险

- 现在的最佳实践是确定浏览器支持的功能，并为不直接支持的功能提供某种替代方案。这可能意味着一个洋葱状的元素，例如在不支持 `<video>` 标签时回退到 Flash Player，或者可能意味着来自各种源的额外脚本代码，这些代码应进行代码审查。

## 增强安全性的 HTTP 标头

请查阅 [OWASP 安全标头](https://owasp.org/www-project-secure-headers/)项目，以获取应用程序应使用的 HTTP 安全标头列表，以在浏览器级别启用防御。

## WebSocket 实施提示

除了上面提到的元素外，以下是实施过程中必须谨慎对待的领域列表。

- 通过 "Origin" HTTP 请求标头进行访问过滤
- 输入/输出验证
- 身份验证
- 授权
- 访问令牌显式失效
- 机密性和完整性

下面的章节将为每个领域提供一些实施建议，并配有展示所有描述点的应用示例。

示例应用的完整源代码可在[此处](https://github.com/righettod/poc-websocket)获得。

### 访问过滤

在 WebSocket 通道启动期间，浏览器发送 **Origin** HTTP 请求标头，其中包含请求握手的源域发起。即使此标头可以在伪造的 HTTP 请求（非浏览器基础）中被伪造，但在浏览器上下文中也无法覆盖或强制。因此，它是根据预期值应用过滤的良好候选者。

使用此向量的攻击，名为*跨站 WebSocket 劫持（CSWSH）*，在[此处](https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html)描述。

下面的代码定义了一个基于"允许列表"的源进行过滤的配置。这确保只有允许的源可以建立完整的握手：

``` java
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.server.ServerEndpointConfig;
import java.util.Arrays;
import java.util.List;

/**
 * 为应用程序的所有 WebSocket 端点设置握手规则。
 * 用于使用 "Origin" HTTP 标头作为输入信息设置访问过滤。
 *
 * @see "http://docs.oracle.com/javaee/7/api/index.html?javax/websocket/server/
 * ServerEndpointConfig.Configurator.html"
 * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin"
 */
public class EndpointConfigurator extends ServerEndpointConfig.Configurator {

    /**
     * 日志记录器
     */
    private static final Logger LOG = LoggerFactory.getLogger(EndpointConfigurator.class);

    /**
     * 从 JVM 属性获取预期的源域，以允许外部配置
     */
    private static final List<String> EXPECTED_ORIGINS =  Arrays.asList(System.getProperty("source.origins")
                                                          .split(";"));

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean checkOrigin(String originHeaderValue) {
        boolean isAllowed = EXPECTED_ORIGINS.contains(originHeaderValue);
        String safeOriginValue = Encode.forHtmlContent(originHeaderValue);
        if (isAllowed) {
            LOG.info("[EndpointConfigurator] 收到来自 {} 的新握手请求并已接受。",
                      safeOriginValue);
        } else {
            LOG.warn("[EndpointConfigurator] 收到来自 {} 的新握手请求并已拒绝！",
                      safeOriginValue);
        }
        return isAllowed;
    }

}
```

### 认证与输入/输出验证

在使用 WebSocket 作为通信通道时，重要的是使用一种认证方法，允许用户接收一个访问*令牌*，该令牌不会被浏览器自动发送，而必须由客户端代码在每次交换中显式发送。

HMAC 摘要是最简单的方法，而 [JSON Web Token](https://jwt.io/introduction/)（JWT）是一个功能丰富的优秀替代方案，因为它允许以无状态且不可更改的方式传输访问凭证信息。此外，它还定义了有效期限。关于 JWT 强化的更多信息，可以查看这个[备忘录](JSON_Web_Token_for_Java_Cheat_Sheet.md)。

[JSON 验证模式](http://json-schema.org/)用于定义和验证输入和输出消息中的预期内容。

下面的代码定义了完整的认证消息流处理：

**WebSocket 认证端点** - 提供一个支持认证交换的 WS 端点

``` java
import org.owasp.pocwebsocket.configurator.EndpointConfigurator;
import org.owasp.pocwebsocket.decoder.AuthenticationRequestDecoder;
import org.owasp.pocwebsocket.encoder.AuthenticationResponseEncoder;
import org.owasp.pocwebsocket.handler.AuthenticationMessageHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.CloseReason;
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

/**
 * 负责管理客户端认证的类。
 *
 * @see "http://docs.oracle.com/javaee/7/api/javax/websocket/server/ServerEndpointConfig.Configurator.html"
 * @see "http://svn.apache.org/viewvc/tomcat/trunk/webapps/examples/WEB-INF/classes/websocket/"
 */
@ServerEndpoint(value = "/auth", configurator = EndpointConfigurator.class,
子协议 = {"authentication"}, 编码器 = {AuthenticationResponseEncoder.class},
解码器 = {AuthenticationRequestDecoder.class})
public class AuthenticationEndpoint {

    /**
     * 日志记录器
     */
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationEndpoint.class);

    /**
     * 处理交换的开始
     *
     * @param session 交换会话信息
     */
    @OnOpen
    public void start(Session session) {
        // 定义连接空闲超时和消息限制，尽可能减轻使用大量连接打开或发送大消息的 DOS 攻击
        int msgMaxSize = 1024 * 1024; // 1 MB
        session.setMaxIdleTimeout(60000); // 1 分钟
        session.setMaxTextMessageBufferSize(msgMaxSize);
        session.setMaxBinaryMessageBufferSize(msgMaxSize);
        // 记录交换开始
        LOG.info("[AuthenticationEndpoint] 会话 {} 已开始", session.getId());
        // 分配一个新的消息处理程序实例以处理交换
        session.addMessageHandler(new AuthenticationMessageHandler(session.getBasicRemote()));
        LOG.info("[AuthenticationEndpoint] 会话 {} 已分配消息处理程序进行处理",
                  session.getId());
    }

    /**
     * 处理错误情况
     *
     * @param session 交换会话信息
     * @param thr     错误详情
     */
    @OnError
    public void onError(Session session, Throwable thr) {
        LOG.error("[AuthenticationEndpoint] 会话 {} 发生错误", session.getId(), thr);
    }

    /**
     * 处理关闭事件
     *
     * @param session     交换会话信息
     * @param closeReason 交换关闭原因
     */
    @OnClose
    public void onClose(Session session, CloseReason closeReason) {
        LOG.info("[AuthenticationEndpoint] 会话 {} 已关闭：{}", session.getId(),
                  closeReason.getReasonPhrase());
    }

}
```

**认证消息处理器** - 处理所有认证请求

``` java
import org.owasp.pocwebsocket.enumeration.AccessLevel;
import org.owasp.pocwebsocket.util.AuthenticationUtils;
import org.owasp.pocwebsocket.vo.AuthenticationRequest;
import org.owasp.pocwebsocket.vo.AuthenticationResponse;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.EncodeException;
import javax.websocket.MessageHandler;
import javax.websocket.RemoteEndpoint;
import java.io.IOException;

/**
 * 处理认证消息流
 */
public class AuthenticationMessageHandler implements MessageHandler.Whole<AuthenticationRequest> {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationMessageHandler.class);

    /**
     * 与客户端通信的通道引用
     */
    private RemoteEndpoint.Basic clientConnection;

    /**
     * 构造函数
     *
     * @param clientConnection 与客户端通信的通道引用
     */
    public AuthenticationMessageHandler(RemoteEndpoint.Basic clientConnection) {
        this.clientConnection = clientConnection;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void onMessage(AuthenticationRequest message) {
        AuthenticationResponse response = null;
        try {
            // 认证
            String authenticationToken = "";
            String accessLevel = this.authenticate(message.getLogin(), message.getPassword());
            if (accessLevel != null) {
                // 创建表示认证配置文件的简单 JSON 令牌
                authenticationToken = AuthenticationUtils.issueToken(message.getLogin(), accessLevel);
            }
            // 构建响应对象
            String safeLoginValue = Encode.forHtmlContent(message.getLogin());
            if (!authenticationToken.isEmpty()) {
                response = new AuthenticationResponse(true, authenticationToken, "认证成功！");
                LOG.info("[AuthenticationMessageHandler] 用户 {} 认证成功。", safeLoginValue);
            } else {
                response = new AuthenticationResponse(false, authenticationToken, "认证失败！");
                LOG.warn("[AuthenticationMessageHandler] 用户 {} 认证失败。", safeLoginValue);
            }
        } catch (Exception e) {
            LOG.error("[AuthenticationMessageHandler] 认证过程中发生错误。", e);
            // 构建表示认证失败的响应对象
            response = new AuthenticationResponse(false, "", "认证失败！");
        } finally {
            // 发送响应
            try {
                this.clientConnection.sendObject(response);
            } catch (IOException | EncodeException e) {
                LOG.error("[AuthenticationMessageHandler] 发送响应对象时发生错误。", e);
            }
        }
    }

    /**
     * 用户认证
     *
     * @param login    用户登录名
     * @param password 用户密码
     * @return 认证成功时返回访问级别，认证失败时返回 NULL
     */
    private String authenticate(String login, String password) {
      ....
    }
}
```

**管理 JWT 的实用类** - 处理访问令牌的签发和验证。本示例使用了简单的 JWT（重点放在全局 WS 端点实现上），未进行额外的强化（请参阅此[备忘录](JSON_Web_Token_for_Java_Cheat_Sheet.md)以对 JWT 应用额外的强化）

``` java
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Calendar;
import java.util.Locale;

/**
 * 管理认证 JWT 令牌的实用类
 */
public class AuthenticationUtils {

    /**
     * 为用户构建 JWT 令牌
     *
     * @param login       用户登录名
     * @param accessLevel 用户访问级别
     * @return Base64 编码的 JWT 令牌
     * @throws Exception 签发过程中发生任何错误
     */
    public static String issueToken(String login, String accessLevel) throws Exception {
        // 签发有效期为 30 分钟的 JWT 令牌
        Algorithm algorithm = Algorithm.HMAC256(loadSecret());
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, 30);
        return JWT.create().withIssuer("WEBSOCKET-SERVER").withSubject(login).withExpiresAt(c.getTime())
                  .withClaim("access_level", accessLevel.trim().toUpperCase(Locale.US)).sign(algorithm);
    }

    /**
     * 验证提供的 JWT 令牌的有效性
     *
     * @param token 要验证的编码 JWT 令牌
     * @return 经过验证和解码的令牌，包含用户认证和授权（访问级别）信息
     * @throws Exception 令牌验证过程中发生任何错误
     */
    public static DecodedJWT validateToken(String token) throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(loadSecret());
        JWTVerifier verifier = JWT.require(algorithm).withIssuer("WEBSOCKET-SERVER").build();
        return verifier.verify(token);
    }

    /**
     * 加载用于签名令牌的 JWT 密钥，使用字节数组存储密钥以避免在内存中持久化字符串
     *
     * @return 以字节数组形式返回的密钥
     * @throws IOException 加载密钥过程中发生任何错误
     */
    private static byte[] loadSecret() throws IOException {
        return Files.readAllBytes(Paths.get("src", "main", "resources", "jwt-secret.txt"));
    }
}
```

**认证消息的 JSON 模式** - 定义从认证端点的角度看输入和输出消息的预期结构

```json
{
    "$schema": "http://json-schema.org/schema#",
    "title": "认证请求",
    "type": "object",
    "properties": {
    "login": {
        "type": "string",
        "pattern": "^[a-zA-Z]{1,10}$"
    },
    "password": {
        "type": "string"
    }
    },
    "required": [
    "login",
    "password"
    ]
}

{
"$schema": "http://json-schema.org/schema#",
"title": "认证响应",
"type": "object",
"properties": {
    "isSuccess": {
    "type": "boolean"
    },
    "token": {
    "type": "string",
    "pattern": "^[a-zA-Z0-9+/=\\._-]{0,500}$"
    },
    "message": {
    "type": "string",
    "pattern": "^[a-zA-Z0-9!\\s]{0,100}$"
    }
},
"required": [
    "isSuccess",
    "token",
    "message"
]
}
```

**认证消息解码器和编码器** - 使用专用的 JSON 模式执行 JSON 序列化/反序列化和输入/输出验证。这使得能够系统地确保端点接收和发送的所有消息严格遵守预期的结构和内容。

``` java
import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.core.exceptions.ProcessingException;
import com.github.fge.jsonschema.core.report.ProcessingReport;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.google.gson.Gson;
import org.owasp.pocwebsocket.vo.AuthenticationRequest;

import javax.websocket.DecodeException;
import javax.websocket.Decoder;
import javax.websocket.EndpointConfig;
import java.io.File;
import java.io.IOException;

/**
 * 将 JSON 文本表示解码为 AuthenticationRequest 对象
 * <p>
 * 由于每个端点会话只有一个解码器类实例，因此可以将 JsonSchema 用作解码器实例变量。
 */
public class AuthenticationRequestDecoder implements Decoder.Text<AuthenticationRequest> {

    /**
     * 与此类型消息关联的 JSON 验证模式
     */
    private JsonSchema validationSchema = null;

    /**
     * 初始化解码器和关联的 JSON 验证模式
     *
     * @throws IOException 对象创建期间发生任何错误
     * @throws ProcessingException 模式加载期间发生任何错误
     */
    public AuthenticationRequestDecoder() throws IOException, ProcessingException {
        JsonNode node = JsonLoader.fromFile(
                        new File("src/main/resources/authentication-request-schema.json"));
        this.validationSchema = JsonSchemaFactory.byDefault().getJsonSchema(node);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticationRequest decode(String s) throws DecodeException {
        try {
            // 根据专用模式验证提供的表示
            // 使用带报告的验证模式，以便进一步检查/跟踪错误详情
            // 此外，验证方法 "validInstance()" 如果表示不符合预期模式，会生成 NullPointerException
            // 因此使用带报告的验证方法更为恰当
            ProcessingReport validationReport = this.validationSchema.validate(JsonLoader.fromString(s),
                                                                               true);
            // 确保没有错误
            if (!validationReport.isSuccess()) {
                // 此处简单拒绝消息：不关心错误详情...
                throw new DecodeException(s, "提供的表示验证失败！");
            }
        } catch (IOException | ProcessingException e) {
            throw new DecodeException(s, "无法将提供的表示验证为有效的 JSON 表示！", e);
        }

        return new Gson().fromJson(s, AuthenticationRequest.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean willDecode(String s) {
        boolean canDecode = false;

        // 如果提供的 JSON 表示为空/null，则表明无法解码为预期对象
        if (s == null || s.trim().isEmpty()) {
            return canDecode;
        }

        // 尝试将提供的 JSON 表示转换为我们的对象，以验证至少其结构（内容验证在解码期间完成）
        try {
            AuthenticationRequest test = new Gson().fromJson(s, AuthenticationRequest.class);
            canDecode = (test != null);
        } catch (Exception e) {
            // 显式忽略任何转换错误...
        }

        return canDecode;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(EndpointConfig config) {
        // 未使用
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {
        // 未使用
    }
}
```

``` java
import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.core.exceptions.ProcessingException;
import com.github.fge.jsonschema.core.report.ProcessingReport;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.google.gson.Gson;
import org.owasp.pocwebsocket.vo.AuthenticationResponse;

import javax.websocket.EncodeException;
import javax.websocket.Encoder;
import javax.websocket.EndpointConfig;
import java.io.File;
import java.io.IOException;

/**
 * 将 AuthenticationResponse 对象编码为 JSON 文本表示。
 * <p>
 * 由于每个端点会话只有一个编码器类实例，因此可以将 JsonSchema 用作编码器实例变量。
 */
public class AuthenticationResponseEncoder implements Encoder.Text<AuthenticationResponse> {

    /**
     * 与此类型消息关联的 JSON 验证模式
     */
    private JsonSchema validationSchema = null;

    /**
     * 初始化编码器和关联的 JSON 验证模式
     *
     * @throws IOException 对象创建期间发生任何错误
     * @throws ProcessingException 模式加载期间发生任何错误
     */
    public AuthenticationResponseEncoder() throws IOException, ProcessingException {
        JsonNode node = JsonLoader.fromFile(
                        new File("src/main/resources/authentication-response-schema.json"));
        this.validationSchema = JsonSchemaFactory.byDefault().getJsonSchema(node);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encode(AuthenticationResponse object) throws EncodeException {
        // 生成 JSON 表示
        String json = new Gson().toJson(object);
        try {
            // 根据专用模式验证生成的表示
            // 使用带报告的验证模式，以便进一步检查/跟踪错误详情
            // 此外，验证方法 "validInstance()" 如果表示不符合预期模式，会生成 NullPointerException
            // 因此使用带报告的验证方法更为恰当
            ProcessingReport validationReport = this.validationSchema.validate(JsonLoader.fromString(json),
                                                                                true);
            // 确保没有错误
            if (!validationReport.isSuccess()) {
                // 此处简单拒绝消息：不关心错误详情...
                throw new EncodeException(object, "生成的表示验证失败！");
            }
        } catch (IOException | ProcessingException e) {
            throw new EncodeException(object, "无法将生成的表示验证为有效的 JSON 表示！", e);
        }

        return json;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(EndpointConfig config) {
        // 未使用
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {
        // 未使用
    }

}
```

注意，在 POC 的消息处理部分使用了相同的方法。客户端和服务器之间交换的所有消息都使用专用的 JSON 模式和相应的编码器/解码器（序列化/反序列化）进行系统性验证。

### 授权和访问令牌显式失效

授权信息使用 JWT 的 *Claim* 特性存储在访问令牌中（在 POC 中，声明的名称是 *access_level*）。在接收到请求并使用用户输入信息执行任何其他操作之前，都会验证授权。

访问令牌随每个发送到消息端点的消息一起传递，并使用拒绝列表，以允许用户请求显式令牌失效。

从用户的角度来看，显式令牌失效很有意义，因为在使用令牌时，令牌的有效期通常相对较长（看到超过 1 小时的有效期是很常见的），因此允许用户向系统表明"好的，我已经完成了与你的交互，你可以关闭我们的交换会话并清理相关链接"是很重要的。

这还有助于用户在检测到使用相同令牌的恶意并发访问时撤销当前访问（令牌被盗的情况）。

**令牌拒绝列表** - 使用内存和时间受限的缓存维护令牌哈希的临时列表，这些令牌不再允许使用

``` java
import org.apache.commons.jcs.JCS;
import org.apache.commons.jcs.access.CacheAccess;
import org.apache.commons.jcs.access.exception.CacheException;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 管理已声明不再可用的访问令牌的实用类（显式用户登出）
 */
public class AccessTokenBlocklistUtils {
    /**
     * 用户发送的消息内容，表示必须将随消息一起的访问令牌列入黑名单，不再使用
     */
    public static final String MESSAGE_ACCESS_TOKEN_INVALIDATION_FLAG = "INVALIDATE_TOKEN";

    /**
     * 使用缓存存储黑名单令牌哈希，以避免内存耗尽并保持一致性
     * 因为令牌有效期为 30 分钟，所以缓存中的项目保留 60 分钟
     */
    private static final CacheAccess<String, String> TOKEN_CACHE;

    static {
        try {
            TOKEN_CACHE = JCS.getInstance("default");
        } catch (CacheException e) {
            throw new RuntimeException("无法初始化令牌缓存！", e);
        }
    }

    /**
     * 将令牌添加到拒绝列表
     *
     * @param token 需要添加哈希的令牌
     * @throws NoSuchAlgorithmException 如果 SHA256 不可用
     */
    public static void addToken(String token) throws NoSuchAlgorithmException {
        if (token != null && !token.trim().isEmpty()) {
            String hashHex = computeHash(token);
            if (TOKEN_CACHE.get(hashHex) == null) {
                TOKEN_CACHE.putSafe(hashHex, hashHex);
            }
        }
    }

    /**
     * 检查令牌是否存在于拒绝列表中
     *
     * @param token 需要验证哈希存在性的令牌
     * @return 如果令牌在黑名单中，则返回 TRUE
     * @throws NoSuchAlgorithmException 如果 SHA256 不可用
     */
    public static boolean isBlocklisted(String token) throws NoSuchAlgorithmException {
        boolean exists = false;
        if (token != null && !token.trim().isEmpty()) {
            String hashHex = computeHash(token);
            exists = (TOKEN_CACHE.get(hashHex) != null);
        }
        return exists;
    }

    /**
     * 计算令牌的 SHA256 哈希
     *
     * @param token 需要计算哈希的令牌
     * @return 以十六进制编码的哈希
     * @throws NoSuchAlgorithmException 如果 SHA256 不可用
     */
    private static String computeHash(String token) throws NoSuchAlgorithmException {
        String hashHex = null;
        if (token != null && !token.trim().isEmpty()) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes());
            hashHex = DatatypeConverter.printHexBinary(hash);
        }
        return hashHex;
    }
}
```

**消息处理** - 处理用户添加消息到列表的请求。展示授权验证方法的示例

``` java
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.owasp.pocwebsocket.enumeration.AccessLevel;
import org.owasp.pocwebsocket.util.AccessTokenBlocklistUtils;
import org.owasp.pocwebsocket.util.AuthenticationUtils;
import org.owasp.pocwebsocket.util.MessageUtils;
import org.owasp.pocwebsocket.vo.MessageRequest;
import org.owasp.pocwebsocket.vo.MessageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.EncodeException;
import javax.websocket.RemoteEndpoint;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 处理消息流
 */
public class MessageHandler implements javax.websocket.MessageHandler.Whole<MessageRequest> {

    private static final Logger LOG = LoggerFactory.getLogger(MessageHandler.class);

    /**
     * 与客户端通信的通道引用
     */
    private RemoteEndpoint.Basic clientConnection;

    /**
     * 构造函数
     *
     * @param clientConnection 与客户端通信的通道引用
     */
    public MessageHandler(RemoteEndpoint.Basic clientConnection) {
        this.clientConnection = clientConnection;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onMessage(MessageRequest message) {
        MessageResponse response = null;
        try {
            /*步骤1：验证令牌*/
            String token = message.getToken();
            // 验证是否在黑名单中
            if (AccessTokenBlocklistUtils.isBlocklisted(token)) {
                throw new IllegalAccessException("令牌在黑名单中！");
            }

            // 验证令牌签名
            DecodedJWT decodedToken = AuthenticationUtils.validateToken(token);

            /*步骤2：验证授权（访问级别）*/
            Claim accessLevel = decodedToken.getClaim("access_level");
            if (accessLevel == null || AccessLevel.valueOf(accessLevel.asString()) == null) {
                throw new IllegalAccessException("令牌具有无效的访问级别声明！");
            }

            /*步骤3：执行预期处理*/
            // 为当前用户初始化消息列表
            if (!MessageUtils.MESSAGES_DB.containsKey(decodedToken.getSubject())) {
                MessageUtils.MESSAGES_DB.put(decodedToken.getSubject(), new ArrayList<>());
            }

            // 如果消息不是令牌失效标志，则添加到用户消息列表；否则将令牌添加到黑名单
            if (AccessTokenBlocklistUtils.MESSAGE_ACCESS_TOKEN_INVALIDATION_FLAG
                .equalsIgnoreCase(message.getContent().trim())) {
                AccessTokenBlocklistUtils.addToken(message.getToken());
            } else {
                MessageUtils.MESSAGES_DB.get(decodedToken.getSubject()).add(message.getContent());
            }

            // 根据用户访问级别，返回自己的消息或所有消息
            List<String> messages = new ArrayList<>();
            if (accessLevel.asString().equals(AccessLevel.USER.name())) {
                MessageUtils.MESSAGES_DB.get(decodedToken.getSubject())
                .forEach(s -> messages.add(String.format("(%s): %s", decodedToken.getSubject(), s)));
            } else if (accessLevel.asString().equals(AccessLevel.ADMIN.name())) {
                MessageUtils.MESSAGES_DB.forEach((k, v) ->
                v.forEach(s -> messages.add(String.format("(%s): %s", k, s))));
            }

            // 构建响应对象，指示交换成功
            if (AccessTokenBlocklistUtils.MESSAGE_ACCESS_TOKEN_INVALIDATION_FLAG
                .equalsIgnoreCase(message.getContent().trim())) {
                response = new MessageResponse(true, messages, "令牌已添加到黑名单");
            } else {
                response = new MessageResponse(true, messages, "");
            }

        } catch (Exception e) {
            LOG.error("[MessageHandler] 交换过程中发生错误。", e);
            // 构建响应对象，指示交换失败
            // 因为是 POC，所以向客户端发送错误详情（实际应用中不会这样做）
            response = new MessageResponse(false, new ArrayList<>(), "交换期间发生错误：" 
                       + e.getMessage());
        } finally {
            // 发送响应
            try {
                this.clientConnection.sendObject(response);
            } catch (IOException | EncodeException e) {
                LOG.error("[MessageHandler] 发送响应对象时发生错误。", e);
            }
        }
    }
}
```

### 机密性和完整性

如果使用原始版本的协议（协议 `ws://`），则传输的数据将暴露于窃听和潜在的即时篡改。

使用 [Wireshark](https://www.wireshark.org/) 捕获并搜索存储的 PCAP 文件中的密码交换的示例（已从命令结果中显式删除不可打印的字符）：

``` shell
$ grep -aE '(password)' capture.pcap
{"login":"bob","password":"bob123"}
```

可以通过在 *session* 对象实例上调用 `isSecure()` 方法，在 WebSocket 端点级别检查通道是否安全。

在负责设置会话并影响消息处理程序的端点方法中的实现示例：

``` java
/**
 * 处理交换的开始
 *
 * @param session 交换会话信息
 */
@OnOpen
public void start(Session session) {
    ...
    // 仅在通道安全的情况下，影响新的消息处理程序实例以处理交换
    if(session.isSecure()) {
        session.addMessageHandler(new AuthenticationMessageHandler(session.getBasicRemote()));
    }else{
        LOG.info("[AuthenticationEndpoint] 会话 {} 未使用安全通道，因此未分配消息处理程序进行处理，会话已显式关闭！", session.getId());
        try{
            session.close(new CloseReason(CloseReason.CloseCodes.CANNOT_ACCEPT,"使用了不安全的通道！"));
        }catch(IOException e){
            LOG.error("[AuthenticationEndpoint] 会话 {} 无法显式关闭！", session.getId(), e);
        }
    }
    LOG.info("[AuthenticationEndpoint] 会话 {} 已分配消息处理程序进行处理", session.getId());
}
```

仅在 [wss://](https://kaazing.com/html5-websocket-security-is-strong/) 协议（通过 SSL/TLS 的 WebSocket）上公开 WebSocket 端点，以确保流量的*机密性*和*完整性*，类似于使用 HTTP over SSL/TLS 来保护 HTTP 交换。
