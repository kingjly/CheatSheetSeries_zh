# .NET 安全备忘录

## 简介

本页面旨在为开发者提供快速的 .NET 安全基本技巧。

### .NET Framework

.NET Framework 是微软企业开发的主要平台。它是 ASP.NET、Windows 桌面应用程序、Windows Communication Foundation 服务、SharePoint、Visual Studio Office 工具和其他技术的支持 API。

.NET Framework 由一系列 API 组成，便于使用高级类型系统、管理数据、图形、网络、文件操作等，基本涵盖了在微软生态系统中开发企业应用程序的绝大多数需求。它是一个几乎无处不在的库，在程序集级别具有强名称和版本控制。

### 更新框架

.NET Framework 由微软通过 Windows Update 服务保持最新。开发者通常不需要单独运行框架更新。可以通过 [Windows Update](http://windowsupdate.microsoft.com/) 或 Windows 计算机上的 Windows Update 程序访问。

可以使用 [NuGet](https://docs.microsoft.com/en-us/nuget/) 保持单个框架最新。随着 Visual Studio 提示更新，将其纳入生命周期。

请记住，第三方库需要单独更新，并非所有库都使用 NuGet。例如，ELMAH 需要单独的更新工作。

### 安全公告

通过在以下仓库选择"Watch"按钮来接收安全通知：

- [.NET Core 安全公告](https://github.com/dotnet/announcements/issues?q=is%3Aopen+is%3Aissue+label%3ASecurity)
- [ASP.NET Core & Entity Framework Core 安全公告](https://github.com/aspnet/Announcements/issues?q=is%3Aopen+is%3Aissue+label%3ASecurity)

## .NET 通用指南

本节包含 .NET 应用程序的通用指南。
这适用于所有 .NET 应用程序，包括 ASP.NET、WPF、WinForms 等。

OWASP Top 10 列出了当今世界上对 Web 安全最普遍和最危险的威胁，每隔几年就会被审查和更新。本备忘录基于这个列表。
保护 Web 应用程序的方法应该从下面的 A1 顶级威胁开始，逐步向下；
这将确保在安全方面花费的任何时间都是最有效的，首先覆盖最重要的威胁，然后再处理较小的威胁。覆盖 Top 10 后，通常建议评估其他威胁或进行专业的渗透测试。

### A01 访问控制失效

#### 弱账户管理

确保 Cookie 设置了 HttpOnly 标志，以防止客户端脚本访问 Cookie：

```csharp
CookieHttpOnly = true,
```

通过减少会话超时时间和删除滑动过期来缩短会话可被窃取的时间：

```csharp
ExpireTimeSpan = TimeSpan.FromMinutes(60),
SlidingExpiration = false
```

请参见[此处](https://github.com/johnstaveley/SecurityEssentials/blob/master/SecurityEssentials/App_Start/Startup.Auth.cs)获取完整的启动代码片段示例。

确保在生产环境中通过 HTTPS 发送 Cookie。这应在配置转换中强制执行：

```xml
<httpCookies requireSSL="true" />
<authentication>
    <forms requireSSL="true" />
</authentication>
```

通过限制请求来保护登录、注册和密码重置方法，防止暴力攻击（见下面的代码）。还可以考虑使用 ReCaptcha。

```csharp
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
[AllowXRequestsEveryXSecondsAttribute(Name = "LogOn",
Message = "您在最近 {n} 秒内执行此操作超过 {x} 次。",
Requests = 3, Seconds = 60)]
public async Task<ActionResult> LogOn(LogOnViewModel model, string returnUrl)
```

禁止：自行开发身份验证或会话管理。使用 .NET 提供的方法。

禁止：在登录、注册或密码重置时告知账户是否存在。说类似"用户名或密码不正确"，或"如果此账户存在，重置令牌将发送到注册的电子邮件地址"。这可以防止账户枚举。

无论账户是否存在，用户反馈都应该相同，包括内容和行为。例如，如果响应在账户真实存在时耗时 50% 更长，则可以猜测和测试成员信息。

#### 缺少功能级访问控制

执行：在所有面向外部的端点上授权用户。.NET 框架有多种授权用户的方法，在方法级别使用：

```csharp
[Authorize(Roles = "Admin")]
[HttpGet]
public ActionResult Index(int page = 1)
```

或更好的是，在控制器级别：

```csharp
[Authorize]
public class UserController
```

还可以使用 .NET 的身份特性在代码中检查角色：`System.Web.Security.Roles.IsUserInRole(userName, roleName)`

可以在[授权备忘录](Authorization_Cheat_Sheet.md)和[授权测试自动化备忘录](Authorization_Testing_Automation_Cheat_Sheet.md)中找到更多信息。

#### 不安全的直接对象引用

当有一个可以通过引用访问的资源（对象）时（在下面的示例中是 `id`），需要确保用户intended 访问该资源。

```csharp
// 不安全
public ActionResult Edit(int id)
{
  var user = _context.Users.FirstOrDefault(e => e.Id == id);
  return View("Details", new UserViewModel(user);
}

// 安全
public ActionResult Edit(int id)
{
  var user = _context.Users.FirstOrDefault(e => e.Id == id);
  // 确认用户有权编辑这些详细信息
  if (user.Id != _userIdentity.GetUserId())
  {
        HandleErrorInfo error = new HandleErrorInfo(
            new Exception("提示：您没有权限编辑这些详细信息"));
        return View("Error", error);
  }
  return View("Edit", new UserViewModel(user);
}
```

更多信息可以在[不安全直接对象引用预防备忘录](Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md)中找到。

### A02 加密失败

#### 常规加密指南

- **绝不要编写自己的加密函数。**
- 尽可能避免编写任何加密代码。相反，尝试使用现有的秘密管理解决方案或云提供商提供的秘密管理解决方案。更多信息请参见 [OWASP 秘密管理备忘录](Secrets_Management_Cheat_Sheet.md)。
- 如果无法使用现有的秘密管理解决方案，请尝试使用知名可信的实现库，而不是使用内置在 .NET 中的库，因为使用内置库很容易犯加密错误。
- 确保您的应用程序或协议可以轻松支持未来更改加密算法。

#### 哈希

执行：使用强哈希算法。

- 在 .NET（Framework 和 Core），对于常规哈希需求，最强的哈希算法是 [System.Security.Cryptography.SHA512](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512)。
- 在 .NET Framework 4.6 及更早版本中，密码哈希的最强算法是 PBKDF2，实现为 [System.Security.Cryptography.Rfc2898DeriveBytes](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes)。
- 在 .NET Framework 4.6.1 及更高版本和 .NET Core 中，密码哈希的最强算法是 PBKDF2，实现为 [Microsoft.AspNetCore.Cryptography.KeyDerivation.Pbkdf2](https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing)，相比 `Rfc2898DeriveBytes` 有几个显著优势。
- 在使用哈希函数哈希非唯一输入（如密码）时，在原始值哈希之前添加盐值。
- 更多信息请参见[密码存储备忘录](Password_Storage_Cheat_Sheet.md)。

#### 密码

执行：强制使用能够抵御字典攻击的最低复杂度密码；即使用完整字符集（数字、符号和字母）的更长密码以增加熵。

#### 加密

执行：对需要恢复为原始格式的个人可识别数据使用强加密算法，如 AES-512。

执行：保护加密密钥比保护任何其他资产更重要。有关在静态存储加密密钥的更多信息，请参见[密钥管理备忘录](Key_Management_Cheat_Sheet.md#storage)。

执行：为整个站点使用 TLS 1.2+。获取免费证书 [LetsEncrypt.org](https://letsencrypt.org/) 并自动续期。

禁止：[允许 SSL，这已经过时](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)。

执行：制定强大的 TLS 策略（参见 [SSL 最佳实践](https://www.ssllabs.com/projects/best-practices/index.html)），尽可能使用 TLS 1.2+。然后使用 [SSL 测试](https://www.ssllabs.com/ssltest/) 或 [TestSSL](https://testssl.sh/) 检查配置。

传输层保护的更多信息可以在[传输层安全备忘录](Transport_Layer_Security_Cheat_Sheet.md)中找到。

执行：确保标头不会泄露关于应用程序的信息。参见 [HttpHeaders.cs](https://github.com/johnstaveley/SecurityEssentials/blob/master/SecurityEssentials/Core/HttpHeaders.cs)、[Dionach StripHeaders](https://github.com/Dionach/StripHeaders/)，通过 `web.config` 或 [Startup.cs](https://medium.com/bugbountywriteup/security-headers-1c770105940b) 禁用。

例如 Web.config：

```xml
<system.web>
    <httpRuntime enableVersionHeader="false"/>
</system.web>
<system.webServer>
    <security>
        <requestFiltering removeServerHeader="true" />
    </security>
    <httpProtocol>
        <customHeaders>
            <add name="X-Content-Type-Options" value="nosniff" />
            <add name="X-Frame-Options" value="DENY" />
            <add name="X-Permitted-Cross-Domain-Policies" value="master-only"/>
            <add name="X-XSS-Protection" value="0"/>
            <remove name="X-Powered-By"/>
        </customHeaders>
    </httpProtocol>
</system.webServer>
```

例如 Startup.cs：

```csharp
app.UseHsts(hsts => hsts.MaxAge(365).IncludeSubdomains());
app.UseXContentTypeOptions();
app.UseReferrerPolicy(opts => opts.NoReferrer());
app.UseXXssProtection(options => options.FilterDisabled());
app.UseXfo(options => options.Deny());

app.UseCsp(opts => opts
 .BlockAllMixedContent()
 .StyleSources(s => s.Self())
 .StyleSources(s => s.UnsafeInline())
 .FontSources(s => s.Self())
 .FormActions(s => s.Self())
 .FrameAncestors(s => s.Self())
 .ImageSources(s => s.Self())
 .ScriptSources(s => s.Self())
 );
```

有关标头的更多信息可以在 [OWASP 安全标头项目](https://owasp.org/www-project-secure-headers/)中找到。

#### 存储加密

- 对敏感数据的安全本地存储使用 [Windows 数据保护 API (DPAPI)](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)。
- 无法使用 DPAPI 时，遵循 [OWASP 加密存储备忘录](Cryptographic_Storage_Cheat_Sheet.md#algorithms)中的算法指南。

下面的代码片段展示了使用 AES-GCM 执行数据加密/解密的示例。强烈建议让密码学专家审查您的最终设计和代码，因为即使是最微不足道的错误也可能严重削弱您的加密。

代码基于此示例：[https://www.scottbrady91.com/c-sharp/aes-gcm-dotnet](https://www.scottbrady91.com/c-sharp/aes-gcm-dotnet)

关于此代码的一些约束/陷阱：

- 它没有考虑密钥轮换或管理，这本身就是一个完整的主题。
- 即使使用相同的密钥，每次加密操作也必须使用不同的随机数。
- 密钥需要安全存储。

<details>
  <summary>点击查看"AES-GCM 对称加密"代码片段。</summary>

```csharp
// 代码基于此示例：
// https://www.scottbrady91.com/c-sharp/aes-gcm-dotnet

public class AesGcmSimpleTest
{
    public static void Main()
    {
        // AES 的 32 字节 / 256 位密钥
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // 最大大小 = 12 字节 / 96 位，并且应始终使用此大小。
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        // 用于认证加密的标签
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        var message = "这是要加密的消息";
        Console.WriteLine(message);

        // 加密消息
        var cipherText = AesGcmSimple.Encrypt(message, nonce, out tag, key);
        Console.WriteLine(Convert.ToBase64String(cipherText));

        // 解密消息
        var message2 = AesGcmSimple.Decrypt(cipherText, nonce, tag, key);
        Console.WriteLine(message2);
    }
}

public static class AesGcmSimple
{
    public static byte[] Encrypt(string plaintext, byte[] nonce, out byte[] tag, byte[] key)
    {
        using(var aes = new AesGcm(key))
        {
            // 用于认证加密的标签
            tag = new byte[AesGcm.TagByteSizes.MaxSize];

            // 创建要加密的消息的字节数组
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            // 密文字节长度将与明文相同
            var ciphertext = new byte[plaintextBytes.Length];

            // 执行实际加密
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            return ciphertext;
        }
    }

    public static string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
    {
        using(var aes = new AesGcm(key))
        {
            // 明文字节长度将与密文相同
            var plaintextBytes = new byte[ciphertext.Length];

            // 执行实际解密
            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}
```

</details>

#### 传输加密

- 再次遵循 [OWASP 加密存储备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#algorithms) 中的算法指南。

下面的代码片段展示了使用椭圆曲线/迪菲-赫尔曼（ECDH）与 AES-GCM 一起执行数据加密/解密的示例，无需在双方之间传输对称密钥。相反，双方交换公钥，然后可以使用 ECDH 生成共享密钥，用于对称加密。

再次强烈建议让密码学专家审查您的最终设计和代码，因为即使是最微不足道的错误也可能严重削弱您的加密。

请注意，此代码示例依赖于[上一节](#存储加密)中的 `AesGcmSimple` 类。

关于此代码的一些约束/陷阱：

- 它没有考虑密钥轮换或管理，这本身就是一个完整的主题。
- 代码故意为每次加密操作强制使用新的随机数，但必须将其作为密文旁边的单独数据项进行管理。
- 私钥需要安全存储。
- 代码没有考虑在使用前验证公钥。
- 总体而言，双方之间没有真实性验证。

<details>
  <summary>点击查看"ECDH非对称加密"代码片段。</summary>

```csharp
public class ECDHSimpleTest
{
    public static void Main()
    {
        // 为 Alice 生成 ECC 密钥对
        var alice = new ECDHSimple();
        byte[] alicePublicKey = alice.PublicKey;

        // 为 Bob 生成 ECC 密钥对
        var bob = new ECDHSimple();
        byte[] bobPublicKey = bob.PublicKey;

        string plaintext = "你好，Bob！你好吗？";
        Console.WriteLine("Alice 发送的秘密：" + plaintext);

        // 注意，每次加密操作都会生成新的随机数，符合 AES GCM 安全性要求
        byte[] tag;
        byte[] nonce;
        var cipherText = alice.Encrypt(bobPublicKey, plaintext, out nonce, out tag);
        Console.WriteLine("发送给 Bob 的密文、随机数和标签：" + Convert.ToBase64String(cipherText) + " " + Convert.ToBase64String(nonce) + " " + Convert.ToBase64String(tag));

        var decrypted = bob.Decrypt(alicePublicKey, cipherText, nonce, tag);
        Console.WriteLine("Bob 收到的秘密：" + decrypted);

        Console.WriteLine();

        string plaintext2 = "你好，Alice！我很好，你呢？";
        Console.WriteLine("Bob 发送的秘密：" + plaintext2);

        byte[] tag2;
        byte[] nonce2;
        var cipherText2 = bob.Encrypt(alicePublicKey, plaintext2, out nonce2, out tag2);
        Console.WriteLine("发送给 Alice 的密文、随机数和标签：" + Convert.ToBase64String(cipherText2) + " " + Convert.ToBase64String(nonce2) + " " + Convert.ToBase64String(tag2));

        var decrypted2 = alice.Decrypt(bobPublicKey, cipherText2, nonce2, tag2);
        Console.WriteLine("Alice 收到的秘密：" + decrypted2);
    }
}

public class ECDHSimple
{
    private ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng();

    public byte[] PublicKey
    {
        get
        {
            return ecdh.PublicKey.ToByteArray();
        }
    }

    public byte[] Encrypt(byte[] partnerPublicKey, string message, out byte[] nonce, out byte[] tag)
    {
        // 生成 AES 密钥和随机数
        var aesKey = GenerateAESKey(partnerPublicKey);

        // 用于认证加密的标签
        tag = new byte[AesGcm.TagByteSizes.MaxSize];

        // 最大大小 = 12 字节 / 96 位，并且应始终使用此大小。
        // 每次加密操作都会生成新的随机数，符合 AES GCM 安全模型
        nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        // 返回加密值
        return AesGcmSimple.Encrypt(message, nonce, out tag, aesKey);
    }

    public string Decrypt(byte[] partnerPublicKey, byte[] ciphertext, byte[] nonce, byte[] tag)
    {
        // 生成 AES 密钥和随机数
        var aesKey = GenerateAESKey(partnerPublicKey);

        // 返回解密值
        return AesGcmSimple.Decrypt(ciphertext, nonce, tag, aesKey);
    }

    private byte[] GenerateAESKey(byte[] partnerPublicKey)
    {
        // 基于此方的私钥和另一方的公钥推导出秘密
        byte[] secret = ecdh.DeriveKeyMaterial(CngKey.Import(partnerPublicKey, CngKeyBlobFormat.EccPublicBlob));

        byte[] aesKey = new byte[32]; // 256 位 AES 密钥
        Array.Copy(secret, 0, aesKey, 0, 32); // 复制前 32 字节作为密钥

        return aesKey;
    }
}
```

</details>

### A03 注入攻击

#### SQL 注入

执行：使用对象关系映射器（ORM）或存储过程是对抗 SQL 注入漏洞最有效的方法。

执行：在必须使用直接 SQL 查询时，使用参数化查询。更多信息可以在[查询参数化备忘录](Query_Parameterization_Cheat_Sheet.md)中找到。

例如，使用 Entity Framework：

```csharp
var sql = @"Update [User] SET FirstName = @FirstName WHERE Id = @Id";
context.Database.ExecuteSqlCommand(
    sql,
    new SqlParameter("@FirstName", firstname),
    new SqlParameter("@Id", id));
```

禁止：在代码中的任何位置拼接字符串并对数据库执行（称为*动态 SQL*）。

注意：即使使用 ORM 或存储过程，仍可能意外地这样做，所以请到处检查。例如：

```csharp
string sql = "SELECT * FROM Users WHERE UserName='" + txtUser.Text + "' AND Password='"
                + txtPassword.Text + "'";
context.Database.ExecuteSqlCommand(sql); // SQL 注入漏洞！
```

执行：最小权限原则 - 使用具有执行任务所需最小权限集的账户连接数据库，而不是数据库管理员账户。

#### 操作系统命令注入

关于操作系统命令注入的一般指导可以在[操作系统命令注入防御备忘录](OS_Command_Injection_Defense_Cheat_Sheet.md)中找到。

执行：使用 [System.Diagnostics.Process.Start](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start?view=netframework-4.7.2) 调用底层操作系统函数。

例如：

```csharp
var process = new System.Diagnostics.Process();
var startInfo = new System.Diagnostics.ProcessStartInfo();
startInfo.FileName = "validatedCommand";
startInfo.Arguments = "validatedArg1 validatedArg2 validatedArg3";
process.StartInfo = startInfo;
process.Start();
```

禁止：假设这种机制可以防止设计用于突破一个参数并篡改进程另一个参数的恶意输入。这仍然是可能的。

执行：尽可能对所有用户提供的输入使用白名单验证。输入验证可防止格式不正确的数据进入信息系统。更多信息请参见[输入验证备忘录](Input_Validation_Cheat_Sheet.md)。

例如，使用 [IPAddress.TryParse 方法](https://docs.microsoft.com/en-us/dotnet/api/system.net.ipaddress.tryparse?view=netframework-4.8)验证用户输入：

```csharp
// 用户输入
string ipAddress = "127.0.0.1";

// 检查是否提供了 IP 地址
if (!string.IsNullOrEmpty(ipAddress))
{
 // 为指定的地址字符串创建 IPAddress 实例（点分十进制或冒号十六进制表示法）
 if (IPAddress.TryParse(ipAddress, out var address))
 {
  // 以标准表示法显示地址
  return address.ToString();
 }
 else
 {
  // ipAddress 不是 IPAddress 类型
  ...
 }
    ...
}
```

执行：尽量只接受简单的字母数字字符。

禁止：假设可以在不实际删除特殊字符的情况下对其进行净化。```\```、```'``` 和 ```@``` 的各种组合可能会对净化尝试产生意外影响。

禁止：依赖没有安全保证的方法。

例如：.NET Core 2.2 及更高版本和 .NET 5 及更高版本支持 [ProcessStartInfo.ArgumentList](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)，它执行一些字符转义，但该对象[包含不适用于不受信任输入的免责声明](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist#remarks)。

执行：寻找通过命令行参数传递原始不受信任参数的替代方案，例如使用 Base64 编码（这将安全地对任何特殊字符进行编码），然后在接收应用程序中解码参数。

#### LDAP 注入

几乎任何字符都可以在可分辨名称中使用。但是，某些字符必须使用反斜杠 `\` 转义字符进行转义。
在[LDAP 注入预防备忘录](LDAP_Injection_Prevention_Cheat_Sheet.md)中可以找到显示应为 Active Directory 转义的字符的表格。

注意：空格字符只有在组件名称（如公共名称）的开头或结尾时才需要转义。
嵌入的空格不应转义。

更多信息可以在[LDAP 注入预防备忘录](LDAP_Injection_Prevention_Cheat_Sheet.md)中找到。

### A04 不安全设计

不安全设计指的是应用程序或系统设计中的安全失败。这与 OWASP Top 10 列表中的其他项目不同，后者指的是实现失败。因此，安全设计的主题与特定技术或语言无关，因此超出了本备忘录的范围。有关更多信息，请参见[安全产品设计备忘录](Secure_Product_Design_Cheat_Sheet.md)。

### A05 安全配置错误

#### 调试和堆栈跟踪

确保在生产环境中关闭调试和跟踪。可以使用 web.config 转换来强制执行：

```xml
<compilation xdt:Transform="RemoveAttributes(debug)" />
<trace enabled="false" xdt:Transform="Replace"/>
```

禁止：使用默认密码

推荐：将 HTTP 请求重定向到 HTTPS：

例如，Global.asax.cs：

```csharp
protected void Application_BeginRequest()
{
    #if !DEBUG
    // 安全：确保在生产环境中任何请求都通过 SSL/TLS 返回
    if (!Request.IsLocal && !Context.Request.IsSecureConnection) {
        var redirect = Context.Request.Url.ToString()
                        .ToLower(CultureInfo.CurrentCulture)
                        .Replace("http:", "https:");
        Response.Redirect(redirect);
    }
    #endif
}
```

例如，Startup.cs 中的 `Configure()` 方法：

``` csharp
  app.UseHttpsRedirection();
```

#### 跨站请求伪造（CSRF）

禁止：在未验证防伪令牌的情况下发送敏感数据（[.NET](https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks) / [.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-7.0#aspnet-core-antiforgery-configuration)）。

推荐：在每个 POST/PUT 请求中发送防伪令牌：

##### 使用 .NET Framework

```csharp
using (Html.BeginForm("LogOff", "Account", FormMethod.Post, new { id = "logoutForm",
                        @class = "pull-right" }))
{
    @Html.AntiForgeryToken()
    <ul class="nav nav-pills">
        <li role="presentation">
        登录用户 @User.Identity.Name
        </li>
        <li role="presentation">
        <a href="javascript:document.getElementById('logoutForm').submit()">注销</a>
        </li>
    </ul>
}
```

然后在方法或控制器级别验证：

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult LogOff()
```

确保在注销时完全移除令牌。

```csharp
/// <summary>
/// 安全：移除所有剩余的 Cookie，包括防 CSRF Cookie
/// </summary>
public void RemoveAntiForgeryCookie(Controller controller)
{
    string[] allCookies = controller.Request.Cookies.AllKeys;
    foreach (string cookie in allCookies)
    {
        if (controller.Response.Cookies[cookie] != null &&
            cookie == "__RequestVerificationToken")
        {
            controller.Response.Cookies[cookie].Expires = DateTime.Now.AddDays(-1);
        }
    }
}
```

##### 使用 .NET Core 2.0 或更高版本

从 .NET Core 2.0 开始，可以[自动生成和验证防伪令牌](https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-7.0#aspnet-core-antiforgery-configuration)。

如果使用[标签助手（tag-helpers）](https://docs.microsoft.com/en-us/aspnet/core/mvc/views/tag-helpers/intro)，这是大多数 Web 项目模板的默认设置，那么所有表单将自动发送防伪令牌。你可以通过检查主 `_ViewImports.cshtml` 文件是否包含以下内容来确认标签助手是否已启用：

```csharp
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
```

`IHtmlHelper.BeginForm` 也会自动发送防伪令牌。

如果未使用标签助手或 `IHtmlHelper.BeginForm`，则必须在表单上使用相应的帮助器，如下所示：

```html
<form action="RelevantAction" >
@Html.AntiForgeryToken()
</form>
```

要自动验证除 GET、HEAD、OPTIONS 和 TRACE 之外的所有请求，需要在 `Startup.cs` 中添加全局操作筛选器，并使用 [AutoValidateAntiforgeryToken](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.autovalidateantiforgerytokenattribute?view=aspnetcore-7.0) 属性，详情请参见以下[文章](https://andrewlock.net/automatically-validating-anti-forgery-tokens-in-asp-net-core-with-the-autovalidateantiforgerytokenattribute/)：

```csharp
services.AddMvc(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
```

如果需要为控制器上的特定方法禁用属性验证，可以为 MVC 控制器的方法或 Razor 页面的父类添加 [IgnoreAntiforgeryToken](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.ignoreantiforgerytokenattribute?view=aspnetcore-7.0) 属性：

```csharp
[IgnoreAntiforgeryToken]
[HttpDelete]
public IActionResult Delete()
```

```csharp
[IgnoreAntiforgeryToken]
public class UnsafeModel : PageModel
```

如果需要对 GET、HEAD、OPTIONS 和 TRACE 请求也进行令牌验证，可以为 MVC 控制器的方法或 Razor 页面的父类添加 [ValidateAntiforgeryToken](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.validateantiforgerytokenattribute?view=aspnetcore-7.0) 属性：

```csharp
[HttpGet]
[ValidateAntiforgeryToken]
public IActionResult DoSomethingDangerous()
```

```csharp
[HttpGet]
[ValidateAntiforgeryToken]
public class SafeModel : PageModel
```

如果无法使用全局操作筛选器，可以将 [AutoValidateAntiforgeryToken](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.autovalidateantiforgerytokenattribute?view=aspnetcore-7.0) 属性添加到控制器类或 Razor 页面模型：

```csharp
[AutoValidateAntiforgeryToken]
public class UserController
```

```csharp
[AutoValidateAntiforgeryToken]
public class SafeModel : PageModel
```

##### 在 .NET Core 或 .NET Framework 中使用 AJAX

需要将防伪令牌附加到 AJAX 请求。

如果在 ASP.NET Core MVC 视图中使用 jQuery，可以使用以下代码片段：

```javascript
@inject  Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgeryProvider
$.ajax(
{
    type: "POST",
    url: '@Url.Action("Action", "Controller")',
    contentType: "application/x-www-form-urlencoded; charset=utf-8",
    data: {
        id: id,
        '__RequestVerificationToken': '@antiforgeryProvider.GetAndStoreTokens(this.Context).RequestToken'
    }
})
```

如果使用 .NET Framework，可以在[此处](https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks#anti-csrf-and-ajax)找到一些代码片段。

更多信息可以在[跨站请求伪造预防备忘录](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)中找到。

### A06 易受攻击和过时的组件

推荐：保持 .NET 框架更新到最新补丁

推荐：保持 [NuGet](https://docs.microsoft.com/en-us/nuget/) 包为最新版本

推荐：在构建过程中运行 [OWASP 依赖检查器](Vulnerable_Dependency_Management_Cheat_Sheet.md#tools)，并对任何高级或关键级别的漏洞采取行动

推荐：在 CI/CD 管道中包含 SCA（软件成分分析）工具，以确保及时检测和处理依赖项中的任何新漏洞

### A07 身份识别和认证失败

推荐：使用 [ASP.NET Core Identity](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-2.2&)。ASP.NET Core Identity 框架默认配置良好，使用安全的密码哈希和单独的盐。Identity 使用 PBKDF2 哈希函数进行密码处理，并为每个用户生成随机盐。

推荐：设置安全的密码策略

例如 ASP.NET Core Identity：

``` csharp
//Startup.cs
services.Configure<IdentityOptions>(options =>
{
 // 密码设置
 options.Password.RequireDigit = true;
 options.Password.RequiredLength = 8;
 options.Password.RequireNonAlphanumeric = true;
 options.Password.RequireUppercase = true;
 options.Password.RequireLowercase = true;
 options.Password.RequiredUniqueChars = 6;

 options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
 options.Lockout.MaxFailedAccessAttempts = 3;

 options.SignIn.RequireConfirmedEmail = true;

 options.User.RequireUniqueEmail = true;
});
```

推荐：设置 Cookie 策略

例如：

``` csharp
//Startup.cs
services.ConfigureApplicationCookie(options =>
{
 options.Cookie.HttpOnly = true;
 options.Cookie.Expiration = TimeSpan.FromHours(1)
 options.SlidingExpiration = true;
});
```

### A08 软件和数据完整性失败

推荐：对程序集和可执行文件进行数字签名

推荐：使用 Nuget 包签名

推荐：审查代码和配置更改，避免引入恶意代码或依赖项

禁止：通过网络发送未签名或未加密的序列化对象

推荐：对从网络接收的序列化对象执行完整性检查或验证数字签名

禁止：使用 BinaryFormatter 类型，该类型是危险的，[不推荐](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)用于数据处理。
.NET 提供了几个可以安全处理不可信数据的内置序列化器：

- XmlSerializer 和 DataContractSerializer 用于将对象图序列化为 XML 和从 XML 反序列化。不要将 DataContractSerializer 与 NetDataContractSerializer 混淆。
- BinaryReader 和 BinaryWriter 用于 XML 和 JSON。
- System.Text.Json API 用于将对象图序列化为 JSON。

### A09 安全日志记录和监控失败

推荐：确保记录所有登录、访问控制和服务器端输入验证失败，并提供足够的用户上下文以识别可疑或恶意账户。

推荐：建立有效的监控和警报机制，及时检测和响应可疑活动。

禁止：记录通用错误消息，如：```csharp Log.Error("发生了错误");```。相反，应记录堆栈跟踪、错误消息和导致错误的用户 ID。

禁止：记录敏感数据，如用户密码。

#### 日志记录

关于要收集的日志和更多日志记录信息，请参见[日志记录备忘录](Logging_Cheat_Sheet.md)。

.NET Core 自带 LoggerFactory，位于 Microsoft.Extensions.Logging 中。关于 ILogger 的更多信息可以在[此处](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.logging.ilogger)找到。

以下是如何在 `Startup.cs` 中记录所有错误，使得任何错误抛出时都会被记录：

``` csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        _isDevelopment = true;
        app.UseDeveloperExceptionPage();
    }

    //记录应用程序中的所有错误
    app.UseExceptionHandler(errorApp =>
    {
        errorApp.Run(async context =>
        {
            var errorFeature = context.Features.Get<IExceptionHandlerFeature>();
            var exception = errorFeature.Error;

            Log.Error(String.Format("错误的堆栈跟踪: {0}",exception.StackTrace.ToString()));
        });
    });

    app.UseAuthentication();
    app.UseMvc();
 }
}
```

例如，在类构造函数中注入，这使得编写单元测试更简单。如果类的实例将使用依赖注入创建（例如 MVC 控制器），则推荐此方法。下面的示例展示了记录所有unsuccessful登录尝试。

``` csharp
public class AccountsController : Controller
{
        private ILogger _Logger;

        public AccountsController(ILogger logger)
        {
            _Logger = logger;
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    //记录所有成功的登录尝试
                    Log.Information(String.Format("用户: {0}, 成功登录", model.Email));
                    //成功登录的代码
                    //...
                }
                else
                {
                    //记录所有不正确的登录尝试
                    Log.Information(String.Format("用户: {0}, 密码不正确", model.Email));
                }
             }
            ...
        }
```

#### 监控

监控允许我们通过关键性能指标验证运行系统的性能和健康状况。

在 .NET 中，添加监控功能的一个很好选择是 [Application Insights](https://docs.microsoft.com/en-us/azure/azure-monitor/app/asp-net-core)。

关于日志记录和监控的更多信息可以在[此处](https://github.com/microsoft/code-with-engineering-playbook/blob/main/docs/observability/README.md)找到。

### A10 服务器端请求伪造（SSRF）

推荐：在使用用户输入发出请求之前验证和清理所有用户输入

推荐：使用允许的协议和域白名单

推荐：使用 `IPAddress.TryParse()` 和 `Uri.CheckHostName()` 确保 IP 地址和域名有效

禁止：跟随 HTTP 重定向

禁止：将原始 HTTP 响应转发给用户

更多信息请参见[服务器端请求伪造预防备忘录](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md)。

### OWASP 2013 和 2017

以下是 2013 年或 2017 年 OWASP Top 10 列表中包含但未在 2021 年列表中出现的漏洞。这些漏洞仍然相关，但由于变得不太普遍而未被列入 2021 年列表。

#### A04:2017 XML 外部实体（XXE）

当 XML 解析器未正确处理包含 doctype 中外部实体声明的用户输入时，会发生 XXE 攻击。

[本文](https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xml-processing-options)讨论了 .NET 最常见的 XML 处理选项。

请参阅 [XXE 备忘录](XML_External_Entity_Prevention_Cheat_Sheet.md#net)，了解更多关于防止 XXE 和其他 XML 拒绝服务攻击的详细信息。

#### A07:2017 跨站脚本（XSS）

禁止：信任用户发送的任何数据。优先使用白名单（始终安全）而非黑名单。

MVC3 会对所有 HTML 内容进行编码。要正确编码所有内容（无论是 HTML、JavaScript、CSS、LDAP 等），请使用 Microsoft AntiXSS 库：

`Install-Package AntiXSS`

然后在配置中设置：

```xml
<system.web>
<httpRuntime targetFramework="4.5"
enableVersionHeader="false"
encoderType="Microsoft.Security.Application.AntiXssEncoder, AntiXssLibrary"
maxRequestLength="4096" />
```

禁止：除非你绝对确定要写入浏览器的内容是安全的并已正确转义，否则不要使用 `[AllowHTML]` 属性或帮助器类 `@Html.Raw`。

推荐：启用[内容安全策略](Content_Security_Policy_Cheat_Sheet.md#context)。这将防止页面访问不应访问的资源（例如恶意脚本）：

```xml
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="Content-Security-Policy"
                value="default-src 'none'; style-src 'self'; img-src 'self';
                font-src 'self'; script-src 'self'" />
```

更多信息可以在[跨站脚本预防备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)中找到。

#### A08:2017 不安全的反序列化

禁止：接受来自不可信来源的序列化对象

推荐：验证用户输入

恶意用户能够使用 Cookie 等对象插入恶意信息以更改用户角色。在某些情况下，黑客能够通过使用先前会话中的预先存在或缓存的密码哈希来提升其权限至管理员权限。

推荐：防止反序列化域对象

推荐：使用有限的访问权限运行反序列化代码
如果反序列化的恶意对象试图启动系统进程或访问服务器或主机操作系统中的资源，将被拒绝访问，并将引发权限标志，以便系统管理员能够了解服务器上的任何异常活动。

关于不安全的反序列化的更多信息可以在[反序列化备忘录](Deserialization_Cheat_Sheet.md#net-csharp)中找到。

#### A10:2013 未验证的重定向和转发

MVC 3 模板中引入了针对此问题的保护。以下是代码：

```csharp
public async Task<ActionResult> LogOn(LogOnViewModel model, string returnUrl)
{
    if (ModelState.IsValid)
    {
        var logonResult = await _userManager.TryLogOnAsync(model.UserName, model.Password);
        if (logonResult.Success)
        {
            await _userManager.LogOnAsync(logonResult.UserName, model.RememberMe);  
            return RedirectToLocal(returnUrl);
...
```

```csharp
private ActionResult RedirectToLocal(string returnUrl)
{
    if (Url.IsLocalUrl(returnUrl))
    {
        return Redirect(returnUrl);
    }
    else
    {
        return RedirectToAction("Landing", "Account");
    }
}
```

### 其他建议

- 防止点击劫持和中间人攻击捕获初始非 TLS 请求：设置 `X-Frame-Options` 和 `Strict-Transport-Security`（HSTS）标头。详细信息[在此](https://github.com/johnstaveley/SecurityEssentials/blob/master/SecurityEssentials/Core/HttpHeaders.cs)
- 防止对从未访问过你网站的用户的中间人攻击。注册 [HSTS 预加载](https://hstspreload.org/)
- 对 Web API 服务进行安全测试和分析。它们隐藏在 MVC 站点内部，是攻击者会发现的站点的公共部分。所有 MVC 指南和大部分 WCF 指南同样适用于 Web API。
- 另请参见[未验证的重定向和转发备忘录](Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)。

#### 示例项目

有关上述所有内容和集成到增强安全基线的示例 MVC5 应用程序的代码示例，请访问 [安全基础项目](http://github.com/johnstaveley/SecurityEssentials/)。

## 特定主题指南

本节包含 .NET 特定主题的指南。

### 配置和部署

- 锁定配置文件。
    - 删除所有未使用的配置方面。
    - 使用 `aspnet_regiis -pe` 加密 `web.config` 的敏感部分（[命令行帮助](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-2.0/k6h9cz8h(v=vs.80))）。
- 对于 ClickOnce 应用程序，.NET Framework 应升级到最新版本，以确保支持 TLS 1.2 或更高版本。

### 数据访问

- 对所有数据访问使用[参数化 SQL](https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand.prepare?view=netframework-4.7.2) 命令，没有例外。
- 不要使用由[拼接 SQL 字符串](https://docs.microsoft.com/en-gb/visualstudio/code-quality/ca2100-review-sql-queries-for-security-vulnerabilities?view=vs-2017)组成的字符串参数的 [SqlCommand](https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand)。
- 列出来自用户的可接受值。使用枚举、[TryParse](https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse#System_Int32_TryParse_System_String_System_Int32__) 或查找值，以确保来自用户的数据符合预期。
    - 枚举仍然容易受到意外值的影响，因为 .NET 只验证对底层数据类型的成功转换，默认为整数。[Enum.IsDefined](https://docs.microsoft.com/en-us/dotnet/api/system.enum.isdefined) 可以验证输入值是否在定义的常量列表中有效。
- 在设置数据库用户时应用最小权限原则。数据库用户应该只能访问对用例有意义的项目。
- 使用 [Entity Framework](https://docs.microsoft.com/en-us/ef/) 是一种非常有效的 [SQL 注入](SQL_Injection_Prevention_Cheat_Sheet.md)预防机制。**请记住，在 Entity Framework 中构建自己的临时查询与普通 SQL 查询一样容易受到 SQLi 攻击**。
- 使用 SQL Server 时，优先使用[集成身份验证](https://learn.microsoft.com/en-us/sql/connect/odbc/linux-mac/using-integrated-authentication?view=sql-server-ver16)而非 [SQL 身份验证](https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver16#connecting-through-sql-server-authentication)。
- 尽可能对敏感数据使用[始终加密](https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-database-engine)（SQL Server 2016+ 和 Azure SQL）

## ASP.NET Web Forms 指南

ASP.NET Web Forms 是 .NET Framework 的原始浏览器应用程序开发 API，仍然是 Web 应用程序开发最常见的企业平台。

- 始终使用 [HTTPS](http://support.microsoft.com/kb/324069)。
- 在 web.config 中对 Cookie 和表单元素启用 [requireSSL](https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.requiressl)，对 Cookie 启用 [HttpOnly](https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection.httponlycookies)。
- 实施 [customErrors](https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.customerror)。
- 确保[跟踪](http://www.iis.net/configreference/system.webserver/tracing)已关闭。
- 虽然 ViewState 并不总是适合 Web 开发，但使用它可以提供 CSRF 缓解。要使 ViewState 防止 CSRF 攻击，需要设置 [ViewStateUserKey](https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.page.viewstateuserkey)：

```csharp
protected override OnInit(EventArgs e) {
    base.OnInit(e);
    ViewStateUserKey = Session.SessionID;
}
```

如果不使用 Viewstate，则查看 ASP.NET Web Forms 默认模板的主页面，使用双重提交 Cookie 的手动反 CSRF 令牌。

```csharp
private const string AntiXsrfTokenKey = "__AntiXsrfToken";
private const string AntiXsrfUserNameKey = "__AntiXsrfUserName";
private string _antiXsrfTokenValue;
protected void Page_Init(object sender, EventArgs e)
{
    // 下面的代码有助于防止 XSRF 攻击
    var requestCookie = Request.Cookies[AntiXsrfTokenKey];
    Guid requestCookieGuidValue;
    if (requestCookie != null && Guid.TryParse(requestCookie.Value, out requestCookieGuidValue))
    {
       // 使用 Cookie 中的防 XSRF 令牌
       _antiXsrfTokenValue = requestCookie.Value;
       Page.ViewStateUserKey = _antiXsrfTokenValue;
    }
    else
    {
       // 生成新的防 XSRF 令牌并保存到 Cookie
       _antiXsrfTokenValue = Guid.NewGuid().ToString("N");
       Page.ViewStateUserKey = _antiXsrfTokenValue;
       var responseCookie = new HttpCookie(AntiXsrfTokenKey)
       {
          HttpOnly = true,
          Value = _antiXsrfTokenValue
       };
       if (FormsAuthentication.RequireSSL && Request.IsSecureConnection)
       {
          responseCookie.Secure = true;
       }
       Response.Cookies.Set(responseCookie);
    }
    Page.PreLoad += master_Page_PreLoad;
}
protected void master_Page_PreLoad(object sender, EventArgs e)
{
    if (!IsPostBack)
    {
       // 设置防 XSRF 令牌
       ViewState[AntiXsrfTokenKey] = Page.ViewStateUserKey;
       ViewState[AntiXsrfUserNameKey] = Context.User.Identity.Name ?? String.Empty;
    }
    else
    {
       // 验证防 XSRF 令牌
       if ((string)ViewState[AntiXsrfTokenKey] != _antiXsrfTokenValue ||
          (string)ViewState[AntiXsrfUserNameKey] != (Context.User.Identity.Name ?? String.Empty))
       {
          throw new InvalidOperationException("防 XSRF 令牌验证失败。");
       }
    }
}
```

- 考虑在 IIS 中使用 [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)。参见[此处](https://support.microsoft.com/en-us/help/954002/how-to-add-a-custom-http-response-header-to-a-web-site-that-is-hosted)的过程。
- 以下是处理 HSTS 等问题的推荐 `web.config` 设置。

```xml
<?xml version="1.0" encoding="UTF-8"?>
 <configuration>
   <system.web>
     <httpRuntime enableVersionHeader="false"/>
   </system.web>
   <system.webServer>
     <security>
       <requestFiltering removeServerHeader="true" />
     </security>
     <staticContent>
       <clientCache cacheControlCustom="public"
            cacheControlMode="UseMaxAge"
            cacheControlMaxAge="1.00:00:00"
            setEtag="true" />
     </staticContent>
     <httpProtocol>
       <customHeaders>
         <add name="Content-Security-Policy"
            value="default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'" />
         <add name="X-Content-Type-Options" value="NOSNIFF" />
         <add name="X-Frame-Options" value="DENY" />
         <add name="X-Permitted-Cross-Domain-Policies" value="master-only"/>
         <add name="X-XSS-Protection" value="0"/>
         <remove name="X-Powered-By"/>
       </customHeaders>
     </httpProtocol>
     <rewrite>
       <rules>
         <rule name="Redirect to https">
           <match url="(.*)"/>
           <conditions>
             <add input="{HTTPS}" pattern="Off"/>
             <add input="{REQUEST_METHOD}" pattern="^get$|^head$" />
           </conditions>
           <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent"/>
         </rule>
       </rules>
       <outboundRules>
         <rule name="Add HSTS Header" enabled="true">
           <match serverVariable="RESPONSE_Strict_Transport_Security" pattern=".*" />
           <conditions>
             <add input="{HTTPS}" pattern="on" ignoreCase="true" />
           </conditions>
           <action type="Rewrite" value="max-age=15768000" />
         </rule>
       </outboundRules>
     </rewrite>
   </system.webServer>
 </configuration>
```

- 通过在 `Machine.config` 文件中添加以下行来删除版本标头：

```xml
<httpRuntime enableVersionHeader="false" />
```

- 使用代码中的 HttpContext 类也可以删除服务器标头。

```csharp
HttpContext.Current.Response.Headers.Remove("Server");
```

### HTTP 验证和编码

- 不要在 `web.config` 或页面设置中禁用 [validateRequest](http://www.asp.net/whitepapers/request-validation)。此值在 ASP.NET 中启用有限的 XSS 保护，应保持不变，因为它提供了部分防止跨站脚本攻击的功能。建议除了内置保护外，还要进行完整的请求验证。
- .NET Framework 4.5 版本包含 [AntiXssEncoder](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.antixss.antixssencoder?view=netframework-4.7.2) 库，它有一个全面的输入编码库，用于防止 XSS。请使用它。
- 每当接受用户输入时，列出可接受的值。
- 使用 [Uri.IsWellFormedUriString](https://docs.microsoft.com/en-us/dotnet/api/system.uri.iswellformeduristring) 验证 URI 的格式。

### 表单身份验证

- 尽可能使用 Cookie 进行持久化。`Cookieless` 身份验证将默认为 [UseDeviceProfile](https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookiemode?view=netframework-4.7.2)。
- 不要信任请求的 URI 用于会话或授权的持久化。它可以很容易被伪造。
- 将表单身份验证超时从默认的 *20 分钟* 减少到适合你应用程序的最短时间。如果使用 [slidingExpiration](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2)，此超时将在每次请求后重置，因此活跃用户不会受到影响。
- 如果未使用 HTTPS，应禁用 [slidingExpiration](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2)。即使使用 HTTPS，也要考虑禁用 [slidingExpiration](https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.slidingexpiration?view=netframework-4.7.2)。
- 始终实施适当的访问控制。
    - 将用户提供的用户名与 `User.Identity.Name` 进行比较。
    - 使用 `User.Identity.IsInRole` 检查角色。
- 使用 [ASP.NET 成员资格提供程序和角色提供程序](https://docs.microsoft.com/en-us/dotnet/framework/wcf/samples/membership-and-role-provider)，但要审查密码存储。默认存储使用单次迭代的 SHA-1 哈希，这相当弱。ASP.NET MVC4 模板使用 [ASP.NET Identity](http://www.asp.net/identity/overview/getting-started/introduction-to-aspnet-identity)，而不是 ASP.NET 成员资格，并且 ASP.NET Identity 默认使用 PBKDF2，这更好。有关更多信息，请查看 OWASP [密码存储备忘录](Password_Storage_Cheat_Sheet.md)。
- 明确授权资源请求。
- 利用基于角色的授权，使用 `User.Identity.IsInRole`。

## XAML 指南

- 在应用程序的 Internet 区域安全约束内工作。
- 使用 ClickOnce 部署。对于增强的权限，可以在运行时使用权限提升或在安装时使用可信应用程序部署。

## Windows Forms 指南

- 尽可能使用部分信任。部分信任的 Windows 应用程序可以减少应用程序的攻击面。管理应用程序必须使用的权限列表，以及可能使用的权限，然后在运行时以声明方式请求这些权限。
- 使用 ClickOnce 部署。对于增强的权限，可以在运行时使用权限提升或在安装时使用可信应用程序部署。

## WCF 指南

- 请记住，在 RESTful 服务中传递请求的唯一安全方式是通过启用了 TLS 的 `HTTP POST`。
使用 `HTTP GET` 需要将数据放在 URL（例如查询字符串）中，这对用户可见，并且
将被记录并存储在他们的浏览器历史记录中。
- 避免使用 [BasicHttpBinding](https://docs.microsoft.com/en-us/dotnet/api/system.servicemodel.basichttpbinding?view=netframework-4.7.2)。它没有默认的安全配置。改用 [WSHttpBinding](https://docs.microsoft.com/en-us/dotnet/api/system.servicemodel.wshttpbinding?view=netframework-4.7.2)。
- 为你的绑定使用至少两种安全模式。消息安全在标头中包含安全规定。传输安全意味着使用 SSL。[TransportWithMessageCredential](https://docs.microsoft.com/en-us/dotnet/framework/wcf/samples/ws-transport-with-message-credential) 将两者结合。
- 使用像 [ZAP](https://www.zaproxy.org/) 这样的模糊测试器测试你的 WCF 实现。
