# 服务端请求伪造（SSRF）预防备忘录

## 引言

本备忘录旨在提供关于防范[服务端请求伪造](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)（SSRF）攻击的建议。

本备忘录将从防御的角度出发，不会解释如何执行此类攻击。安全研究员 [Orange Tsai](https://twitter.com/orange_8361) 的这个[演讲](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf)以及这份[文档](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)提供了执行此类攻击的技术。

## 背景

SSRF 是一种滥用应用程序与内部/外部网络或机器本身交互的攻击向量。这一向量的主要诱因是对 URL 的错误处理，如下面的示例所示：

- 外部服务器上的图像（*例如*用户输入头像图像的 URL，供应用程序下载和使用）。
- 自定义 [WebHook](https://en.wikipedia.org/wiki/Webhook)（用户必须指定 Webhook 处理程序或回调 URL）。
- 内部请求与另一个服务交互以提供特定功能。大多数情况下，用户数据会被发送以进行处理，如果处理不当，可能执行特定的注入攻击。

## SSRF 常见流程概述

![SSRF 常见流程](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Common_Flow.png)

*注意：*

- SSRF 不仅限于 HTTP 协议。通常第一个请求是 HTTP，但在应用程序本身执行第二个请求的情况下，可能使用不同的协议（*例如* FTP、SMB、SMTP 等）和方案（*例如* `file://`、`phar://`、`gopher://`、`data://`、`dict://` 等）。
- 如果应用程序容易受到 [XML 外部实体（XXE）注入](https://portswigger.net/web-security/xxe)的攻击，则可以利用它执行 [SSRF 攻击](https://portswigger.net/web-security/xxe#exploiting-xxe-to-perform-ssrf-attacks)，请查看 [XXE 备忘录](XML_External_Entity_Prevention_Cheat_Sheet.md)以了解如何防止 XXE 暴露。

## 场景

根据应用程序的功能和需求，SSRF 可能发生在两种基本场景中：

- 应用程序只能发送请求到**已识别和可信的应用程序**：可以使用[白名单](https://en.wikipedia.org/wiki/Whitelisting)方法的情况。
- 应用程序可以发送请求到**任何外部 IP 地址或域名**：无法使用[白名单](https://en.wikipedia.org/wiki/Whitelisting)方法的情况。

由于这两种情况非常不同，本备忘录将分别描述针对它们的防御措施。

### 场景 1 - 应用程序只能发送请求到已识别和可信的应用程序

有时，应用程序需要向另一个应用程序（通常位于另一个网络）发送请求以执行特定任务。根据业务需求，需要用户输入才能使功能正常工作。

#### 示例

> 以一个接收和使用用户个人信息（如名字、姓氏、出生日期等）并在内部人力资源系统中创建配置文件的 Web 应用程序为例。根据设计，该 Web 应用程序必须使用人力资源系统能理解的协议来通信以处理这些数据。
> 基本上，用户无法直接访问人力资源系统，但是，如果负责接收用户信息的 Web 应用程序容易受到 SSRF 攻击，用户可以利用它访问人力资源系统。
> 用户利用 Web 应用程序作为人力资源系统的代理。

由于*易受攻击的应用程序*调用的内部应用程序在技术/业务流程中是明确标识的，因此白名单方法是一个可行的选择。可以明确指出，所需的调用将仅针对这些已识别和可信的应用程序。

#### 可用的防护措施

在**应用程序**和**网络**层面可以采取多种防护措施。为了应用**深度防御**原则，这两个层面都将得到加固。

##### 应用程序层

首先想到的保护是[输入验证](Input_Validation_Cheat_Sheet.md)。

基于这一点，会产生这样一个问题：*如何执行这种输入验证？*

正如 [Orange Tsai](https://twitter.com/orange_8361) 在他的[演讲](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf)中展示的，根据使用的编程语言，解析器可能会被滥用。一种可能的对策是在使用输入验证时应用[白名单方法](Input_Validation_Cheat_Sheet.md#allow-list-vs-block-list)，因为大多数情况下，从用户那里获取的信息格式是全局已知的。

发送到内部应用程序的请求将基于以下信息：

- 包含业务数据的字符串。
- IP 地址（V4 或 V6）。
- 域名。
- URL。

**注意：** 为了防止绕过本文档 `利用技巧 > 绕过限制 > 输入验证 > 不安全的重定向` 部分描述的输入验证，请在 Web 客户端中禁用[重定向](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections)支持。

###### 字符串

在 SSRF 上下文中，可以添加验证以确保输入字符串符合预期的业务/技术格式。

如果输入数据具有简单格式（*例如*令牌、邮政编码等），可以使用[正则表达式](https://www.regular-expressions.info/)来确保从安全角度看数据是有效的。否则，应使用 `string` 对象可用的库进行验证，因为复杂格式的正则表达式难以维护且极易出错。

假设用户输入是非网络相关的，由用户的个人信息组成。

示例：

```java
//对具有简单格式的数据进行正则表达式验证
if(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput)){
    //继续处理，因为输入数据有效
}else{
    //停止处理并拒绝请求
}
```

###### IP 地址

在 SSRF 上下文中，有两种可能的验证：

1. 确保提供的数据是有效的 IP V4 或 V6 地址。
2. 确保提供的 IP 地址属于已识别和可信应用程序的 IP 地址之一。

第一层验证可以使用库来确保 IP 地址格式的安全，基于所使用的技术（这里建议使用库选项，以委托 IP 地址格式的管理并利用经过充分测试的验证功能）：

> 已对所提议的库进行了验证，以防止这篇[文章](https://medium.com/@vickieli/bypassing-ssrf-protection-e111ae70727b)中描述的绕过（十六进制、八进制、双字、URL 和混合编码）。

- **JAVA：** [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/) 库中的 [InetAddressValidator.isValid](http://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/InetAddressValidator.html#isValid(java.lang.String)) 方法。
    - **不会**暴露于使用十六进制、八进制、双字、URL 和混合编码的绕过。
- **.NET**：SDK 中的 [IPAddress.TryParse](https://docs.microsoft.com/en-us/dotnet/api/system.net.ipaddress.tryparse?view=netframework-4.8) 方法。
    - 会**暴露**于使用十六进制、八进制、双字和混合编码的绕过，但**不会**暴露 URL 编码。
    - 由于这里使用白名单，任何绕过尝试都将在与允许的 IP 地址列表比较时被阻止。
- **JavaScript**：[ip-address](https://www.npmjs.com/package/ip-address) 库。
    - **不会**暴露于使用十六进制、八进制、双字、URL 和混合编码的绕过。
- **Ruby**：SDK 中的 [IPAddr](https://ruby-doc.org/stdlib-2.0.0/libdoc/ipaddr/rdoc/IPAddr.html) 类。
    - **不会**暴露于使用十六进制、八进制、双字、URL 和混合编码的绕过。

> **使用方法/库的输出值作为与白名单比较的 IP 地址。**

确保传入 IP 地址的有效性后，第二层验证将被应用。在确定已识别和可信应用程序的所有 IP 地址（v4 和 v6，以避免绕过）后，创建一个白名单。将有效的 IP 与该列表进行交叉检查，以确保与内部应用程序的通信（区分大小写的严格字符串比较）。

###### 域名

在尝试验证域名时，通过 DNS 解析来验证域名的存在似乎是一个不错的想法。但总体而言，这可能会带来安全风险，具体取决于用于域名解析的 DNS 服务器配置：

- 可能会向外部 DNS 解析器泄露信息。
- 攻击者可以将合法域名绑定到内部 IP 地址。参见此[文档](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)中的 `利用技巧 > 绕过限制 > 输入验证 > DNS 固定` 部分。
- 攻击者可以通过这种方式向内部 DNS 解析器和应用程序使用的 API（SDK 或第三方）投递恶意载荷，进而可能触发这些组件中的漏洞。

在服务器端请求伪造（SSRF）的背景下，需要执行两层验证：

1. 确保提供的数据是有效的域名。
2. 确保提供的域名属于已识别和信任的应用程序的域名之一（这里需要使用白名单）。

与 IP 地址验证类似，第一层验证可以使用确保域名格式安全的库，基于所使用的技术（这里建议使用库以委托域名格式管理并利用经过充分测试的验证函数）：

> 已验证所提议的库不执行 DNS 解析查询。

- **JAVA：** [Apache Commons Validator](http://commons.apache.org/proper/commons-validator/) 库中的 [DomainValidator.isValid](https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/DomainValidator.html#isValid(java.lang.String)) 方法。
- **.NET**：SDK 中的 [Uri.CheckHostName](https://docs.microsoft.com/en-us/dotnet/api/system.uri.checkhostname?view=netframework-4.8) 方法。
- **JavaScript**：[is-valid-domain](https://www.npmjs.com/package/is-valid-domain) 库。
- **Python**：[validators.domain](https://validators.readthedocs.io/en/latest/#module-validators.domain) 模块。
- **Ruby**：未找到有效的专用 gem。
    - 已测试 [domainator](https://github.com/mhuggins/domainator)、[public_suffix](https://github.com/weppos/publicsuffix-ruby) 和 [addressable](https://github.com/sporkmonger/addressable)，但它们都会将 `<script>alert(1)</script>.owasp.org` 视为有效域名。
    - 可以使用以下从[此处](https://stackoverflow.com/a/26987741)获取的正则表达式：`^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$`

Ruby 正则表达式执行示例：

```ruby
domain_names = ["owasp.org","owasp-test.org","doc-test.owasp.org","doc.owasp.org",
                "<script>alert(1)</script>","<script>alert(1)</script>.owasp.org"]
domain_names.each { |domain_name|
    if ( domain_name =~ /^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$/ )
        puts "[i] #{domain_name} 是有效的"
    else
        puts "[!] #{domain_name} 是无效的"
    end
}
```

```bash
$ ruby test.rb
[i] owasp.org 是有效的
[i] owasp-test.org 是有效的
[i] doc-test.owasp.org 是有效的
[i] doc.owasp.org 是有效的
[!] <script>alert(1)</script> 是无效的
[!] <script>alert(1)</script>.owasp.org 是无效的
```

确保传入域名有效后，应用第二层验证：

1. 构建一个包含所有已识别和信任应用程序域名的白名单。
2. 验证接收到的域名是否属于此白名单（区分大小写的严格字符串比较）。

遗憾的是，应用程序仍然容易受到此[文档](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)中提到的 `DNS 固定` 绕过攻击。实际上，在执行业务代码时将进行 DNS 解析。为解决此问题，除了对域名进行验证外，还必须采取以下操作：

1. 确保组织内的域名首先由内部 DNS 服务器在 DNS 解析器链中进行解析。
2. 监控域名白名单，以检测它们是否解析为：
   - 本地 IP 地址（IPv4 + IPv6）。
   - 对于非组织内域名，解析为组织内部 IP（预期在私有 IP 范围内）。

以下 Python3 脚本可用作上述监控的起点：

```python
# 依赖项：pip install ipaddress dnspython
import ipaddress
import dns.resolver

# 配置要检查的白名单
DOMAINS_ALLOWLIST = ["owasp.org", "labslinux"]

# 配置用于所有 DNS 查询的 DNS 解析器
DNS_RESOLVER = dns.resolver.Resolver()
DNS_RESOLVER.nameservers = ["1.1.1.1"]

def verify_dns_records(domain, records, type):
    """
    验证 DNS 记录是否解析到非公共 IP 地址。
    返回是否检测到错误的布尔值。
    """
    error_detected = False
    if records is not None:
        for record in records:
            value = record.to_text().strip()
            try:
                ip = ipaddress.ip_address(value)
                # 参见 https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address.is_global
                if not ip.is_global:
                    print(f"[!] DNS 记录类型 '{type}' 的域名 '{domain}' 解析到非公共 IP 地址 '{value}'！")
                    error_detected = True
            except ValueError:
                error_detected = True
                print(f"[!] '{value}' 不是有效的 IP 地址！")
    return error_detected

def check():
    """
    执行域名白名单检查。
    返回是否检测到错误的布尔值。
    """
    error_detected = False
    for domain in DOMAINS_ALLOWLIST:
        # 获取当前域名的 IP
        # 参见 https://en.wikipedia.org/wiki/List_of_DNS_record_types
        try:
            # A = IPv4 地址记录
            ip_v4_records = DNS_RESOLVER.query(domain, "A")
        except Exception as e:
            ip_v4_records = None
            print(f"[i] 无法获取域名 '{domain}' 的 A 记录：{e}\n")
        try:
            # AAAA = IPv6 地址记录
            ip_v6_records = DNS_RESOLVER.query(domain, "AAAA")
        except Exception as e:
            ip_v6_records = None
            print(f"[i] 无法获取域名 '{domain}' 的 AAAA 记录：{e}\n")
        # 验证获得的 IP
        if verify_dns_records(domain, ip_v4_records, "A") or verify_dns_records(domain, ip_v6_records, "AAAA"):
            error_detected = True
    return error_detected

if __name__== "__main__":
    if check():
        exit(1)
    else:
        exit(0)
```

###### URL

不要接受用户提供的完整 URL，因为 URL 很难验证，且解析器可能会被滥用，正如 [Orange Tsai](https://twitter.com/orange_8361) 的这个[演讲](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf)所展示的。

如果确实需要网络相关信息，则仅接受有效的 IP 地址或域名。

##### 网络层

网络层安全的目标是防止 *VulnerableApplication*（易受攻击的应用程序）向任意应用程序发起调用。只有被允许的 *路由* 将对该应用程序可用，以限制其网络访问仅限于应该通信的对象。

防火墙组件，作为特定设备或使用操作系统提供的防火墙，将在此用于定义合法的流量。

在下面的架构图中，利用防火墙组件来限制应用程序的访问，从而限制对 SSRF 漏洞的应用程序的影响：

![网络层保护案例1：我们要阻止的流量](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Case1_NetworkLayer_PreventFlow.png)

[网络隔离](https://www.mwrinfosecurity.com/our-thinking/making-the-case-for-network-segregation)（查看这组[实施建议](https://www.cyber.gov.au/acsc/view-all-content/publications/implementing-network-segmentation-and-segregation)）也可以被利用，并且**强烈建议直接在网络层阻止非法调用**。

### 案例2 - 应用程序可以向任何外部IP地址或域名发送请求

当用户可以控制指向**外部**资源的URL，且应用程序向该URL发起请求时（例如在[WebHooks](https://en.wikipedia.org/wiki/Webhook)的情况下），就会发生这种情况。这里无法使用白名单，因为IP/域名列表通常事先未知且动态变化。

在这种场景中，*外部* 指的是不属于内部网络的任何IP，并且应通过公共互联网进行访问。

因此，来自 *易受攻击应用程序* 的调用：

- **不是**针对公司全球网络内部的IP/域名
- 使用 *VulnerableApplication* 和预期的IP/域名之间定义的约定，以 *证明* 调用已合法发起

#### 在应用层阻止URL的挑战

基于上述应用程序的业务需求，白名单方法并不是一个有效的解决方案。尽管知道黑名单方法并非铜墙铁壁，但在这种场景下它是最佳解决方案。它告诉应用程序它**不应该**做什么。

以下是为什么在应用层过滤URL很困难：

- 这意味着应用程序必须能够在代码级别检测提供的IP（V4 + V6）不属于官方[私有网络范围](https://en.wikipedia.org/wiki/Private_network)，包括 *localhost* 和 *IPv4/v6 链路本地* 地址。并非每个SDK都提供这种验证的内置功能，并且将处理留给开发者理解其所有陷阱和可能的值，这使得这是一项艰巨的任务。
- 对于域名也是如此：公司必须维护所有内部域名的列表，并提供一个集中的服务，使应用程序能够验证提供的域名是否为内部域名。为了进行此验证，应用程序可以查询内部DNS解析器，但此内部DNS解析器不得解析外部域名。

#### 可用的防护措施

考虑以下[示例](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#example)中的相同假设。

##### 应用层

与[案例1](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#case-1-application-can-send-request-only-to-identified-and-trusted-applications)类似，假设需要 `IP地址` 或 `域名` 来创建将发送到 *目标应用程序* 的请求。

案例1中针对3种数据类型的第一次输入数据验证将保持不变，**但第二次验证将有所不同**。在这里，我们必须使用黑名单方法。

> **关于请求合法性的证明**：接收请求的 *目标应用程序* 必须生成一个随机令牌（例如：20个字符的字母数字），调用者需要传递这个令牌（在正文中通过应用程序本身定义的参数名称，并且只允许字符集 `[a-z]{1,10}`）以执行有效的请求。接收端点必须仅接受 HTTP POST 请求。

**验证流程（如果验证步骤中的任何一步失败，则拒绝请求）：**

1. 应用程序将接收 *目标应用程序* 的IP地址或域名，并使用本[节](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#application-layer)中提到的库/正则表达式对输入数据应用第一次验证。
2. 第二次验证将针对 *目标应用程序* 的IP地址或域名使用以下黑名单方法：
   - 对于IP地址：
     - 应用程序将验证它是公共的（请参见下一段落中的Python代码示例）。
   - 对于域名：
        1. 应用程序将尝试针对仅解析内部域名的DNS解析器解析域名，以验证它是公共的。这里，它必须返回一个响应，表明它不知道提供的域名，因为预期收到的值必须是公共域。
        2. 为防止[文档](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)中描述的 `DNS固定` 攻击，应用程序将检索提供的域名后面的所有IP地址（获取IPv4和IPv6的 *A* 和 *AAAA* 记录），并应用与IP地址相同的验证。
3. 应用程序将通过专用输入参数接收用于请求的协议，并针对允许的协议列表（`HTTP` 或 `HTTPS`）验证其值。
4. 应用程序将通过专用输入参数接收传递给 *目标应用程序* 的令牌参数名称，并且只允许字符集 `[a-z]{1,10}`。
5. 应用程序将通过专用输入参数接收令牌本身，并且只允许字符集 `[a-zA-Z0-9]{20}`。
6. 应用程序将接收并验证（从安全角度）执行有效调用所需的任何业务数据。
7. 应用程序将仅使用经过验证的信息构建 HTTP POST 请求并发送它（*不要忘记在使用的 Web 客户端中禁用[重定向](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections)支持*）。

##### 网络层

类似于以下[节](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#network-layer)。

## AWS 中的 IMDSv2

在云环境中，SSRF 常用于访问和窃取来自元数据服务的凭据和访问令牌（例如 AWS 实例元数据服务、Azure 实例元数据服务、GCP 元数据服务器）。

[IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) 是 AWS 的一种深度防御机制，可缓解部分 SSRF 实例。

要利用这种保护，请迁移到 IMDSv2 并禁用旧的 IMDSv1。查看 [AWS 文档](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)了解更多详情。

## Semgrep 规则

[Semgrep](https://semgrep.dev/) 是一个用于离线静态分析的命令行工具。使用预构建或自定义规则在代码库中强制执行代码和安全标准。
查看用于识别/调查 Java 中 SSRF 漏洞的 Semgrep 规则
[https://semgrep.dev/salecharohit:owasp_java_ssrf](https://semgrep.dev/salecharohit:owasp_java_ssrf)

## 参考文献

[SSRF 圣经](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM)的在线版本（本指南中使用的是 PDF 版本）。

关于[绕过 SSRF 保护](https://medium.com/@vickieli/bypassing-ssrf-protection-e111ae70727b)的文章。

关于 SSRF 攻击的文章：[第1部分](https://medium.com/poka-techblog/server-side-request-forgery-ssrf-attacks-part-1-the-basics-a42ba5cc244a)、[第2部分](https://medium.com/poka-techblog/server-side-request-forgery-ssrf-attacks-part-2-fun-with-ipv4-addresses-eb51971e476d)和[第3部分](https://medium.com/poka-techblog/server-side-request-forgery-ssrf-part-3-other-advanced-techniques-3f48cbcad27e)。

关于 [IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) 的文章。

## 用于架构图的工具和代码

- [Mermaid 在线编辑器](https://mermaidjs.github.io/mermaid-live-editor)和 [Mermaid 文档](https://mermaidjs.github.io/)。
- [Draw.io 在线编辑器](https://www.draw.io/)。

SSRF 常见流程的 Mermaid 代码（截图用于捕获插入到此指南中的 PNG 图像）：

```text
sequenceDiagram
    participant Attacker
    participant VulnerableApplication
    participant TargetedApplication
    Attacker->>VulnerableApplication: 精心制作的 HTTP 请求
    VulnerableApplication->>TargetedApplication: 请求（HTTP、FTP...）
    Note left of TargetedApplication: 使用包含在发送到<br>VulnerableApplication<br>的请求中的有效负载
    TargetedApplication->>VulnerableApplication: 响应
    VulnerableApplication->>Attacker: 响应
    Note left of VulnerableApplication: 包含来自<br>TargetedApplication<br>的响应
```

用于"[网络层保护案例1：我们要阻止的流量](../assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Case1_NetworkLayer_PreventFlow.xml)"架构的 Draw.io 架构 XML 代码（截图用于捕获插入到此指南中的 PNG 图像）。
