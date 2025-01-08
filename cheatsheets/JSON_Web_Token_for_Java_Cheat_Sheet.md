# Java JSON Web Token 备忘录

## 引言

许多应用程序使用 **JSON Web Tokens**（JWT）允许客户端在认证后为进一步交换指示其身份。

来自 [JWT.IO](https://jwt.io/introduction)：

> JSON Web Token（JWT）是一个开放标准（RFC 7519），定义了一种紧凑且自包含的方式，用于在各方之间以 JSON 对象安全地传输信息。这些信息可以被验证和信任，因为它们是数字签名的。JWT 可以使用秘密（使用 HMAC 算法）或使用 RSA 的公钥/私钥对进行签名。

JSON Web Token 用于携带与客户端身份和特征（声明）相关的信息。服务器对这些信息进行签名，以便检测在发送给客户端后是否被篡改。这将防止攻击者更改身份或任何特征（例如，将角色从普通用户更改为管理员或更改客户端登录）。

此令牌在认证期间创建（在成功认证的情况下提供），并在任何处理之前由服务器验证。应用程序使用它允许客户端向服务器出示代表用户"身份证"的令牌，并允许服务器以安全的方式验证令牌的有效性和完整性，所有这些都以无状态和可移植的方式进行（可移植意味着客户端和服务器技术可以不同，传输通道也可以不同，尽管 HTTP 是最常用的）。

## 令牌结构

来自 [JWT.IO](https://jwt.io/#debugger) 的令牌结构示例：

`[Base64(头部)].[Base64(有效载荷)].[Base64(签名)]`

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

第一部分：**头部**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

第二部分：**有效载荷**

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

第三部分：**签名**

```javascript
HMACSHA256( base64UrlEncode(头部) + "." + base64UrlEncode(有效载荷), 密钥 )
```

## 目标

本备忘录提供了在使用 Java 处理 JSON Web Tokens（JWT）时防止常见安全问题的建议。

本文中介绍的建议是 Java 项目的一部分，该项目旨在展示正确处理 JSON Web Tokens 的创建和验证方法。

你可以在[这里](https://github.com/righettod/poc-jwt)找到 Java 项目，它使用官方 [JWT 库](https://jwt.io/#libraries)。

在本文的其余部分，术语**令牌**指的是 **JSON Web Tokens**（JWT）。

## 关于使用 JWT 的考虑

即使 JWT 使用"简单"且允许以无状态方式公开服务（主要是 REST 风格），但它并不适合所有应用程序，因为它带有一些注意事项，例如令牌存储问题（在本备忘录中讨论）等。

如果你的应用程序不需要完全无状态，可以考虑使用所有 Web 框架提供的传统会话系统，并遵循[会话管理备忘录](Session_Management_Cheat_Sheet.md)中的建议。但是，对于无状态应用程序，当正确实施时，它是一个很好的候选方案。

## 问题

### 无哈希算法

#### 症状

这种攻击在[此处](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)有描述，当攻击者更改令牌并将哈希算法更改为通过 *none* 关键字指示令牌完整性已被验证时发生。正如上面链接中解释的，*一些库将使用 none 算法签名的令牌视为具有已验证签名的有效令牌*，因此攻击者可以更改令牌声明，修改后的令牌仍将被应用程序信任。

#### 如何预防

首先，使用不受此漏洞影响的 JWT 库。

最后，在令牌验证期间，明确要求使用预期的算法。

#### 实现示例

``` java
// HMAC 密钥 - 阻止在 JVM 内存中序列化和存储为字符串
private transient byte[] keyHMAC = ...;

...

//为令牌创建验证上下文，明确要求使用 HMAC-256 哈希算法
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC)).build();

//验证令牌，如果验证失败则抛出异常
DecodedJWT decodedToken = verifier.verify(token);
```

### 令牌劫持

#### 症状

当令牌被攻击者拦截/窃取并用于使用目标用户身份访问系统时，会发生此攻击。

#### 如何预防

防止这种攻击的一种方法是在令牌中添加"用户上下文"。用户上下文将由以下信息组成：

- 在认证阶段生成的随机字符串。它将作为强化 cookie 发送给客户端（标志：[HttpOnly + Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) + [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies) + [Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) + [cookie 前缀](https://googlechrome.github.io/samples/cookie-prefixes/)）。避免设置 *expires* 标头，以便在浏览器关闭时清除 cookie。将 *Max-Age* 设置为小于或等于 JWT 到期值的值，但永远不要超过。
- 随机字符串的 SHA256 哈希值将存储在令牌中（而不是原始值），以防止任何允许攻击者读取随机字符串值并设置预期 cookie 的 XSS 问题。

不应使用 IP 地址，因为在某些合法情况下，IP 地址可能在同一会话期间发生变化。例如，当用户通过移动设备访问应用程序，并且移动运营商在交换期间发生变化时，IP 地址可能（经常）会更改。此外，使用 IP 地址可能会导致与[欧洲 GDPR](https://gdpr.eu/) 合规性相关的潜在问题。

在令牌验证期间，如果收到的令牌不包含正确的上下文（例如，如果它已被重放），则必须拒绝该令牌。

#### 实现示例

认证成功后创建令牌的代码。

``` java
// HMAC 密钥 - 阻止在 JVM 内存中序列化和存储为字符串
private transient byte[] keyHMAC = ...;
// 随机数据生成器
private SecureRandom secureRandom = new SecureRandom();

...

//生成将构成此用户指纹的随机字符串
byte[] randomFgp = new byte[50];
secureRandom.nextBytes(randomFgp);
String userFingerprint = DatatypeConverter.printHexBinary(randomFgp);

//在强化 cookie 中添加指纹 - 手动添加 cookie，因为 javax.servlet.http.Cookie 类不支持 SameSite 属性
String fingerprintCookie = "__Secure-Fgp=" + userFingerprint
                           + "; SameSite=Strict; HttpOnly; Secure";
response.addHeader("Set-Cookie", fingerprintCookie);

//计算指纹的 SHA256 哈希值，以便在令牌中存储指纹哈希（而不是原始值）
//防止 XSS 攻击读取指纹并设置预期 cookie
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

//创建有效期为 15 分钟的令牌，并包含客户端上下文（指纹）信息
Calendar c = Calendar.getInstance();
Date now = c.getTime();
c.add(Calendar.MINUTE, 15);
Date expirationDate = c.getTime();
Map<String, Object> headerClaims = new HashMap<>();
headerClaims.put("typ", "JWT");
String token = JWT.create().withSubject(login)
   .withExpiresAt(expirationDate)
   .withIssuer(this.issuerID)
   .withIssuedAt(now)
   .withNotBefore(now)
   .withClaim("userFingerprint", userFingerprintHash)
   .withHeader(headerClaims)
   .sign(Algorithm.HMAC256(this.keyHMAC));
```

验证令牌的代码。

``` java
// HMAC 密钥 - 阻止在 JVM 内存中序列化和存储为字符串
private transient byte[] keyHMAC = ...;

...

//从专用 cookie 中检索用户指纹
String userFingerprint = null;
if (request.getCookies() != null && request.getCookies().length > 0) {
 List<Cookie> cookies = Arrays.stream(request.getCookies()).collect(Collectors.toList());
 Optional<Cookie> cookie = cookies.stream().filter(c -> "__Secure-Fgp"
                                            .equals(c.getName())).findFirst();
 if (cookie.isPresent()) {
   userFingerprint = cookie.get().getValue();
 }
}

//计算 cookie 中接收到的指纹的 SHA256 哈希值，以便与令牌中存储的指纹哈希进行比较
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

//为令牌创建验证上下文
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC))
                              .withIssuer(issuerID)
                              .withClaim("userFingerprint", userFingerprintHash)
                              .build();

//验证令牌，如果验证失败则抛出异常
DecodedJWT decodedToken = verifier.verify(token);
```

### 用户无法内置令牌撤销

#### 症状

这个问题是 JWT 固有的，因为令牌只有在过期时才会失效。用户没有明确撤销令牌有效性的内置功能。这意味着如果令牌被盗，用户无法自行撤销令牌，从而阻止攻击者。

#### 如何预防

由于 JWT 是无状态的，服务器不会维护处理客户端请求的会话。因此，服务器端没有可以使会话无效的会话。上面解释的令牌劫持解决方案应该可以缓解在服务器端维护拒绝列表的需要。这是因为令牌劫持中使用的强化 cookie 可以被视为与传统会话系统中使用的会话 ID 一样安全，除非同时拦截/窃取 cookie 和 JWT，否则 JWT 是不可用的。因此，注销可以通过从会话存储中清除 JWT 来"模拟"。如果用户选择关闭浏览器，则 cookie 和 sessionStorage 会自动清除。

另一种防护方法是实现一个令牌拒绝列表，用于模仿传统会话管理系统中存在的"注销"功能。

拒绝列表将保留令牌的摘要（十六进制编码的 SHA-256）和撤销日期。此条目必须至少持续到令牌过期。

当用户想要"注销"时，调用专门的服务，将提供的用户令牌添加到拒绝列表中，从而立即使令牌在应用程序中进一步使用无效。

#### 实现示例

##### 黑名单存储

将使用以下结构的数据库表作为中央拒绝列表存储。

``` sql
create table if not exists revoked_token(jwt_token_digest varchar(255) primary key,
revocation_date timestamp default now());
```

##### 令牌撤销管理

负责将令牌添加到拒绝列表并检查令牌是否被撤销的代码。

``` java
/**
* 处理令牌撤销（注销）。
* 使用数据库以允许多个实例检查被撤销的令牌
* 并允许在中央数据库级别进行清理。
*/
public class TokenRevoker {

 /** 数据库连接 */
 @Resource("jdbc/storeDS")
 private DataSource storeDS;

 /**
  * 验证十六进制编码的密文令牌摘要是否存在于撤销表中
  *
  * @param jwtInHex 十六进制编码的令牌
  * @return 存在标志
  * @throws Exception 与数据库通信期间发生任何问题
  */
 public boolean isTokenRevoked(String jwtInHex) throws Exception {
     boolean tokenIsPresent = false;
     if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
         //解码密文令牌
         byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

         //计算密文令牌的 SHA256
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] cipheredTokenDigest = digest.digest(cipheredToken);
         String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

         //在数据库中搜索十六进制的令牌摘要
         try (Connection con = this.storeDS.getConnection()) {
             String query = "select jwt_token_digest from revoked_token where jwt_token_digest = ?";
             try (PreparedStatement pStatement = con.prepareStatement(query)) {
                 pStatement.setString(1, jwtTokenDigestInHex);
                 try (ResultSet rSet = pStatement.executeQuery()) {
                     tokenIsPresent = rSet.next();
                 }
             }
         }
     }

     return tokenIsPresent;
 }


 /**
  * 将十六进制编码的密文令牌摘要添加到令牌撤销表
  *
  * @param jwtInHex 十六进制编码的令牌
  * @throws Exception 与数据库通信期间发生任何问题
  */
 public void revokeToken(String jwtInHex) throws Exception {
     if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
         //解码密文令牌
         byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

         //计算密文令牌的 SHA256
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] cipheredTokenDigest = digest.digest(cipheredToken);
         String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

         //检查十六进制的令牌摘要是否已在数据库中，如果不存在则添加
         if (!this.isTokenRevoked(jwtInHex)) {
             try (Connection con = this.storeDS.getConnection()) {
                 String query = "insert into revoked_token(jwt_token_digest) values(?)";
                 int insertedRecordCount;
                 try (PreparedStatement pStatement = con.prepareStatement(query)) {
                     pStatement.setString(1, jwtTokenDigestInHex);
                     insertedRecordCount = pStatement.executeUpdate();
                 }
                 if (insertedRecordCount != 1) {
                     throw new IllegalStateException("插入记录数无效，" +
                     "预期为 1，但实际为 " + insertedRecordCount);
                 }
             }
         }

     }
 }
}
```

### 令牌信息泄露

#### 症状

当攻击者获取令牌（或一组令牌）并提取其中存储的信息（JWT 的内容是 base64 编码，但默认情况下未加密）以获取关于系统的信息时，会发生此攻击。信息可以是例如安全角色、登录格式等。

#### 如何预防

防止此攻击的一种方法是使用对称算法对令牌进行加密。

同时，保护加密数据免受[填充预言攻击](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle.html)或任何使用密码分析的攻击也很重要。

为了实现所有这些目标，使用了 *AES-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)* 算法，它提供了*带关联数据的认证加密*。

更多详情来自[此处](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#deterministic-authenticated-encryption-with-associated-data)：

```text
AEAD 原语（带关联数据的认证加密）提供对称认证加密的功能。

该原语的实现对自适应选择密文攻击是安全的。

加密明文时，可以选择性地提供应被认证但不加密的关联数据。

也就是说，带关联数据的加密确保了该数据的真实性（即发送者是谁）和完整性（即数据未被篡改），但不保证其保密性。

参见 RFC5116：https://tools.ietf.org/html/rfc5116
```

**注意：**

这里添加加密主要是为了隐藏内部信息，但重要的是要记住，防止 JWT 篡改的首要保护是签名。因此，令牌签名及其验证必须始终存在。

#### 实现示例

##### 令牌加密

负责管理加密的代码。使用 [Google Tink](https://github.com/google/tink) 专用加密库来处理加密操作，以使用该库提供的内置最佳实践。

``` java
/**
 * 使用 AES-GCM 处理令牌的加密和解密。
 *
 * @see "https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md"
 */
public class TokenCipher {

    /**
     * 构造函数 - 注册 AEAD 配置
     *
     * @throws Exception 在 AEAD 配置注册期间发生任何问题
     */
    public TokenCipher() throws Exception {
        AeadConfig.register();
    }

    /**
     * 加密 JWT
     *
     * @param jwt          要加密的令牌
     * @param keysetHandle 密钥集句柄的指针
     * @return 十六进制编码的令牌加密版本
     * @throws Exception 在令牌加密操作期间发生任何问题
     */
    public String cipherToken(String jwt, KeysetHandle keysetHandle) throws Exception {
        //验证参数
        if (jwt == null || jwt.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("必须指定两个参数！");
        }

        //获取原语
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        //加密令牌
        byte[] cipheredToken = aead.encrypt(jwt.getBytes(), null);

        return DatatypeConverter.printHexBinary(cipheredToken);
    }

    /**
     * 解密 JWT
     *
     * @param jwtInHex     十六进制编码的要解密的令牌
     * @param keysetHandle 密钥集句柄的指针
     * @return 明文令牌
     * @throws Exception 在令牌解密操作期间发生任何问题
     */
    public String decipherToken(String jwtInHex, KeysetHandle keysetHandle) throws Exception {
        //验证参数
        if (jwtInHex == null || jwtInHex.isEmpty() || keysetHandle == null) {
            throw new IllegalArgumentException("必须指定两个参数！");
        }

        //解码加密令牌
        byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

        //获取原语
        Aead aead = AeadFactory.getPrimitive(keysetHandle);

        //解密令牌
        byte[] decipheredToken = aead.decrypt(cipheredToken, null);

        return new String(decipheredToken);
    }
}
```

##### 令牌的创建/验证

在令牌的创建和验证期间使用令牌加密处理程序。

加载密钥（使用 [Google Tink](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#generating-new-keysets) 生成并存储加密密钥）并设置加密。

``` java
//从配置文本/json文件加载密钥，以避免在 JVM 内存中将密钥存储为字符串
private transient byte[] keyHMAC = Files.readAllBytes(Paths.get("src", "main", "conf", "key-hmac.txt"));
private transient KeysetHandle keyCiphering = CleartextKeysetHandle.read(JsonKeysetReader.withFile(
Paths.get("src", "main", "conf", "key-ciphering.json").toFile()));

...

//初始化令牌加密处理程序
TokenCipher tokenCipher = new TokenCipher();
```

令牌创建。

``` java
//使用 JWT API 生成 JWT 令牌...
//加密令牌（字符串 JSON 表示）
String cipheredToken = tokenCipher.cipherToken(token, this.keyCiphering);
//在 HTTP 响应中将十六进制编码的加密令牌发送给客户端...
```

令牌验证。

``` java
//从 HTTP 请求中检索十六进制编码的加密令牌...
//解密令牌
String token = tokenCipher.decipherToken(cipheredToken, this.keyCiphering);
//使用 JWT API 验证令牌...
//验证访问...
```

### 客户端令牌存储

#### 症状

当应用程序以以下行为方式存储令牌时发生：

- 浏览器自动发送（*Cookie* 存储）。
- 即使浏览器重新启动也能检索（使用浏览器 *localStorage* 容器）。
- 在 [XSS](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) 问题的情况下可检索（Cookie 可被 JavaScript 代码访问，或令牌存储在浏览器本地/会话存储中）。

#### 如何预防

1. 使用浏览器 *sessionStorage* 容器存储令牌，或使用带有 *私有* 变量的 JavaScript *闭包*。
2. 调用服务时使用 JavaScript 将其作为 *Bearer* HTTP `Authentication` 标头添加。
3. 向令牌添加[指纹](JSON_Web_Token_for_Java_Cheat_Sheet.md#token-sidejacking)信息。

在浏览器 *sessionStorage* 容器中存储令牌会使令牌暴露于通过 XSS 攻击被盗的风险。然而，添加到令牌的指纹可以防止攻击者在其机器上重复使用被盗令牌。为了最大程度地减少攻击者的利用面，添加浏览器[内容安全策略](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)以加强执行上下文。

存储令牌在浏览器 *sessionStorage* 的替代方案是使用 JavaScript 私有变量或闭包。在这种情况下，所有 Web 请求的访问都通过一个 JavaScript 模块路由，该模块将令牌封装在一个私有变量中，除了模块内部，其他地方无法访问。

*注意：*

- 剩余的情况是攻击者使用用户的浏览上下文作为代理，通过合法用户使用目标应用程序，但内容安全策略可以防止与非预期域的通信。
- 还可以以这样的方式实现身份验证服务：令牌在强化的 Cookie 中发出，但在这种情况下，必须实现防止[跨站请求伪造](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)攻击的保护。

#### 实现示例

认证后存储令牌的 JavaScript 代码。

``` javascript
/* 处理 JWT 令牌和本地存储的请求 */
function authenticate() {
    const login = $("#login").val();
    const postData = "login=" + encodeURIComponent(login) + "&password=test";

    $.post("/services/authenticate", postData, function (data) {
        if (data.status == "Authentication successful!") {
            ...
            sessionStorage.setItem("token", data.token);
        }
        else {
            ...
            sessionStorage.removeItem("token");
        }
    })
    .fail(function (jqXHR, textStatus, error) {
        ...
        sessionStorage.removeItem("token");
    });
}
```

调用服务时将令牌作为 *Bearer* HTTP 认证标头添加的 JavaScript 代码，例如这里验证令牌的服务。

``` javascript
/* 处理 JWT 令牌验证的请求 */
function validateToken() {
    var token = sessionStorage.getItem("token");

    if (token == undefined || token == "") {
        $("#infoZone").removeClass();
        $("#infoZone").addClass("alert alert-warning");
        $("#infoZone").text("请先获取 JWT 令牌 :)");
        return;
    }

    $.ajax({
        url: "/services/validate",
        type: "POST",
        beforeSend: function (xhr) {
            xhr.setRequestHeader("Authorization", "bearer " + token);
        },
        success: function (data) {
            ...
        },
        error: function (jqXHR, textStatus, error) {
            ...
        },
    });
}
```

使用私有变量实现闭包的 JavaScript 代码：

``` javascript
function myFetchModule() {
    // 保护原始的 'fetch' 不被 XSS 覆盖
    const fetch = window.fetch;

    const authOrigins = ["https://yourorigin", "http://localhost"];
    let token = '';

    this.setToken = (value) => {
        token = value
    }

    this.fetch = (resource, options) => {
        let req = new Request(resource, options);
        destOrigin = new URL(req.url).origin;
        if (token && authOrigins.includes(destOrigin)) {
            req.headers.set('Authorization', token);
        }
        return fetch(req)
    }
}

...

// 使用：
const myFetch = new myFetchModule()

function login() {
  fetch("/api/login")
      .then((res) => {
          if (res.status == 200) {
              return res.json()
          } else {
              throw Error(res.statusText)
          }
      })
      .then(data => {
          myFetch.setToken(data.token)
          console.log("令牌已接收并存储。")
      })
      .catch(console.error)
}

...

// 登录后，后续 API 调用：
function makeRequest() {
    myFetch.fetch("/api/hello", {headers: {"MyHeader": "foobar"}})
        .then((res) => {
            if (res.status == 200) {
                return res.text()
            } else {
                throw Error(res.statusText)
            }
        }).then(responseText => console.log("helloResponse", responseText))
        .catch(console.error)
}
```

### 弱令牌密钥

#### 风险描述

当使用基于 HMAC 的算法保护令牌时，令牌的安全性完全取决于与 HMAC 一起使用的密钥的强度。如果攻击者获得了一个有效的 JWT，他们可以进行离线攻击，并尝试使用诸如 [John the Ripper](https://github.com/magnumripper/JohnTheRipper) 或 [Hashcat](https://github.com/hashcat/hashcat) 等工具破解密钥。

如果攻击成功，他们将能够修改令牌并使用获得的密钥重新签名。这可能使他们能够提升权限、破坏其他用户的账户，或根据 JWT 的内容执行其他操作。

有许多[指南](https://www.notsosecure.com/crafting-way-json-web-tokens/)详细记录了这一过程。

#### 如何预防

防止此攻击的最简单方法是确保用于签署 JWT 的密钥强且唯一，以增加攻击者破解的难度。由于此密钥永远不需要人工输入，因此应至少为 64 个字符，并使用[安全的随机性源](Cryptographic_Storage_Cheat_Sheet.md#secure-random-number-generation)生成。

另外，可以考虑使用由 RSA 签名而非 HMAC 和密钥的令牌。

#### 延伸阅读

- [{JWT}.{Attack}.Playbook](https://github.com/ticarpi/jwt_tool/wiki) - 一个记录 JSON Web 令牌已知攻击和潜在安全漏洞与错误配置的项目。
- [JWT 最佳实践互联网草案](https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/)
