# 应用程序日志记录词汇备忘录

本文档提出了记录安全事件的标准词汇。其意图是简化监控和警报，假设开发人员捕获错误并使用此词汇记录，通过简单地关注这些术语，监控和警报将得到改进。

## 概述

每年，IBM安全部门委托Ponemon研究所对全球公司进行调查，收集与安全漏洞、缓解和相关成本有关的信息；其结果被称为"数据泄露成本报告"。

除了由于漏洞造成的数百万美元损失外，报告发现**识别漏洞的平均时间**仍徘徊在**约200天**。显然，我们监控应用程序和对异常行为发出警报的能力将改善我们识别和缓解针对应用程序的攻击的时间。

![IBM数据泄露成本报告2020](../assets/cost-of-breach-2020.png)

> IBM数据泄露研究2020年，图34，第52页，[https://www.ibm.com/security/data-breach]

这个日志记录标准旨在定义特定关键词，当在软件中一致应用时，将使团队能够简单地监控所有应用程序中的这些事件术语，并在发生攻击时快速响应。

## 假设

- 可观测性/SRE团队必须支持使用此标准并鼓励开发人员使用它
- 事件响应必须要么摄取这些数据，要么提供其他监控团队可以发送通知或警报的方式，最好是以编程方式
- 架构师必须支持、采用并为此标准做出贡献
- 开发人员必须接受此标准并开始实施（需要了解潜在攻击并在代码中捕获这些错误）

## 入门

提醒一下，日志记录的目标是能够对特定安全事件发出警报。当然，记录这些事件的第一步是良好的错误处理，如果你没有捕获事件，就没有事件可记录。

### 识别事件

为了更好地理解安全事件日志记录，对威胁建模有一个良好的高级理解会很有帮助，即使只是采用简单的方法：

1. **可能出现什么问题？**

- 订单：是否有人可以代表他人下单？
- 身份验证：我是否可以以他人身份登录？
- 授权：我是否可以查看他人的账户？

2. **如果真的发生了，会怎样？**

- 订单：我代表他人下了一个订单...到新泽西州的一个废弃仓库。糟糕了。
- 然后我在4Chan上吹嘘这件事。
- 然后我告诉纽约时报。

3. **谁可能有意这样做？**

- 黑客的有意攻击
- 员工"测试"系统工作方式
- 编码不正确的API执行作者未intended的操作

## 格式

_注意：所有日期都应以[ISO 8601](https://en.wikipedia.org/wiki/ISO_8601)格式记录，**带有** UTC偏移，以确保最大的可移植性_

```json
{
    "datetime": "2021-01-01T01:01:01-0700",
    "appid": "foobar.netportal_auth",
    "event": "AUTHN_login_success:joebob1",
    "level": "INFO",
    "description": "User joebob1 login successfully",
    "useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
    "source_ip": "165.225.50.94",
    "host_ip": "10.12.7.9",
    "hostname": "portalauth.foobar.com",
    "protocol": "https",
    "port": "440",
    "request_uri": "/api/v2/auth/",
    "request_method": "POST",
    "region": "AWS-US-WEST-2",
    "geo": "USA"
}
```

## 词汇表

接下来是应该捕获的各种事件类型。对于每种事件类型，都有一个前缀（如"authn"）和应包含的其他数据。

示例中包含了完整日志格式的部分内容，但完整的事件日志应遵循上述格式。

---

## 身份验证 [AUTHN]

### authn_login_success[:userid]

**描述**
应记录所有登录事件，包括成功的登录。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_login_success:joebob1",
    "level": "INFO",
    "description": "User joebob1 login successfully",
    ...
}
```

---

### authn_login_successafterfail[:userid,retries]

**描述**
用户在之前登录失败后成功登录。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_login_successafterfail:joebob1,2",
    "level": "INFO",
    "description": "User joebob1 login successfully",
    ...
}
```

---

### authn_login_fail[:userid]

**描述**
应记录所有登录事件，包括失败的登录。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_login_fail:joebob1",
    "level": "WARN",
    "description": "User joebob1 login failed",
    ...
}
```

---

### authn_login_fail_max[:userid,maxlimit(int)]

**描述**
应记录所有登录事件，包括失败的登录。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_login_fail_max:joebob1,3",
    "level": "WARN",
    "description": "User joebob1 reached the login fail limit of 3",
    ...
}
```

---

### authn_login_lock[:userid,reason]

**描述**
当存在在x次重试或其他条件后锁定账户的功能时，应记录锁定及相关数据。

**级别:**
WARN

**原因:**

- maxretries: 达到最大重试次数
- suspicious: 观察到账户存在可疑活动
- customer: 客户要求锁定其账户
- other: 其他

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_login_lock:joebob1,maxretries",
    "level": "WARN",
    "description": "User joebob1 login locked because maxretries exceeded",
    ...
}
```

---

### authn_password_change[:userid]

**描述**
每次密码更改都应被记录，包括更改密码的用户ID。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_password_change:joebob1",
    "level": "INFO",
    "description": "User joebob1 has successfully changed their password",
    ...
}
```

---

### authn_password_change_fail[:userid]

**描述**
密码更改尝试失败。可能还会触发其他事件，如 `authn_login_lock`。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_password_change_fail:joebob1",
    "level": "INFO",
    "description": "User joebob1 failed to changing their password",
    ...
}
```

---

### authn_impossible_travel[:userid,region1,region2]

**描述**
当用户从一个城市登录，然后突然出现在另一个距离太远、无法在合理时间内行程的城市时，这通常表明可能存在账户接管。

**级别:** 
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_impossible_travel:joebob1,US-OR,CN-SH",
    "level": "CRITICAL",
    "description": "User joebob1 has accessed the application in two distant cities at the same time",
    ...
}
```

---

### authn_token_created[:userid, entitlement(s)]

**描述**
创建服务访问令牌时应被记录。

**级别:** 
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "aws.foobar.com",
    "event": "authn_token_created:app.foobarapi.prod,create,read,update",
    "level": "INFO",
    "description": "A token has been created for app.foobarapi.prod with create,read,update",
    ...
}
```

---

### authn_token_revoked[:userid,tokenid]

**描述**
已为给定账户撤销令牌。

**级别:** 
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "aws.foobar.com",
    "event": "authn_token_revoked:app.foobarapi.prod,xyz-abc-123-gfk",
    "level": "INFO",
    "description": "Token ID: xyz-abc-123-gfk was revoked for user app.foobarapi.prod",
    ...
}
```

---

### authn_token_reuse[:userid,tokenid]

**描述**
尝试重用之前已撤销的令牌。

**级别:** 
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "aws.foobar.com",
    "event": "authn_token_reuse:app.foobarapi.prod,xyz-abc-123-gfk",
    "level": "CRITICAL",
    "description": "User app.foobarapi.prod attempted to use token ID: xyz-abc-123-gfk which was previously revoked",
    ...
}
```

---

### authn_token_delete[:appid]

**描述**
删除令牌时应被记录。

**级别:** 
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authn_token_delete:foobarapi",
    "level": "WARN",
    "description": "The token for foobarapi has been deleted",
    ...
}
```

---

## 授权 [AUTHZ]

---

### authz_fail[:userid,resource]

**描述**
尝试访问未经授权的资源。

**级别:** 
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authz_fail:joebob1,resource",
    "level": "CRITICAL",
    "description": "User joebob1 attempted to access a resource without entitlement",
    ...
}
```

---

### authz_change[:userid,from,to]

**描述**
用户或实体的权限已更改。

**级别:** 
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authz_change:joebob1,user,admin",
    "level": "WARN",
    "description": "User joebob1 access was changed from user to admin",
    ...
}
```

---

### authz_admin[:userid,event]

**描述**
应记录特权用户（如管理员）的所有活动。

**级别:** 
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "authz_admin:joebob1,user_privilege_change",
    "level": "WARN",
    "description": "Administrator joebob1 has updated privileges of user foobarapi from user to admin",
    ...
}
```

---

## 过度使用 [EXCESS]

### excess_rate_limit_exceeded[userid,max]

**描述**
应建立预期的服务限制上限，并在超出时发出警报，即使仅用于管理成本和扩展。

**级别:** 
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "excess_rate_limit_exceeded:app.foobarapi.prod,100000",
    "level": "WARN",
    "description": "User app.foobarapi.prod has exceeded max:100000 requests",
    ...
}
```

---

## 文件上传 [UPLOAD]

### upload_complete[userid,filename,type]

**描述**
在成功上传文件时，验证过程的第一步是确认上传已完成。

**级别:** 
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "upload_complete:joebob1,user_generated_content.png,PNG",
    "level": "INFO",
    "description": "User joebob1 has uploaded user_generated_content.png",
    ...
}
```

---

### upload_stored[filename,from,to]

**描述**
文件上传验证的一个步骤是移动/重命名文件，并在向最终用户提供内容时，永远不要在下载中引用原始文件名。这适用于文件系统和块存储。

**级别:** 
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "upload_stored:user_generated_content.png,kjsdhkrjhwijhsiuhdf000010202002",
    "level": "INFO",
    "description": "File user_generated_content.png was stored in the database with key abcdefghijk101010101",
    ...
}
```

---

### upload_validation[filename,(virusscan|imagemagick|...):(FAILED|incomplete|passed)]

**描述**
所有文件上传都应进行某种验证，包括正确性（是否确实是文件类型x）和安全性（是否不包含病毒）。

**级别:** 
INFO|CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "upload_validation:filename,virusscan:FAILED",
    "level": "CRITICAL",
    "description": "File user_generated_content.png FAILED virus scan and was purged",
    ...
}
```

---

### upload_delete[userid,fileid]

**描述**
当出于正常原因删除文件时应被记录。

**级别:** 
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "upload_delete:joebob1,",
    "level": "INFO",
    "description": "User joebob1 has marked file abcdefghijk101010101 for deletion.",
    ...
}
```

---

## 输入验证 [INPUT]

### input_validation_fail[:field,userid]

**描述**
当服务器端输入验证失败时，要么是因为客户端未提供足够的验证，要么是客户端验证被绕过。无论哪种情况，这都是攻击的机会，应尽快缓解。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "input_validation_fail:date_of_birth,joebob1",
    "level": "WARN",
    "description": "User joebob1 submitted data that failed validation.",
    ...
}
```

---

## 恶意行为 [MALICIOUS]

### malicious_excess_404:[userid|IP,useragent]

**描述**
当用户多次请求不存在的文件时，这通常是试图"强制浏览"可能存在的文件，常常表明存在恶意意图。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_excess404:123.456.789.101,M@l1c10us-Hax0rB0t0-v1",
    "level": "WARN",
    "description": "A user at 123.456.789.101 has generated a large number of 404 requests.",
    ...
}
```

---

### malicious_extraneous:[userid|IP,inputname,useragent]

**描述**
当用户向后端处理程序提交未预期的数据时，可能表明正在探测输入验证错误。如果后端服务收到未处理或没有输入的数据，这通常表明可能存在恶意滥用。

**级别:**
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_extraneous:dr@evil.com,creditcardnum,Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0",
    "level": "WARN",
    "description": "User dr@evil.com included field creditcardnum in the request which is not handled by this service.",
    ...
}
```

---

### 恶意攻击工具:[用户ID|IP,工具名,用户代理]

**描述**
当通过签名或用户代理识别出明显的攻击工具时，应记录这些信息。

**待办事项:** 此标准的未来版本应链接已知的攻击工具、签名和用户代理字符串。例如，"Nikto"工具默认会在其用户代理中留下类似 **_"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"_** 的字符串。

**级别:**
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_attack_tool:127.0.0.1,nikto,Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)",
    "level": "WARN",
    "description": "来自127.0.0.1的攻击流量，使用了Nikto工具",
    ...
}
```

---

### 恶意跨域请求:[用户ID|IP,用户代理,引用页]

**描述**
当从未经授权的源发出请求时，不仅应该阻止，还应尽可能记录这些请求。即使我们阻止了非法的跨域请求，但请求本身也可能是攻击的迹象。

_注意：你知道吗？"referer"在原始HTTP规范中是拼写错误的。正确的拼写应该是"referrer"，但原始的拼写错误至今仍然存在，并在此处有意使用。_

**级别:**
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_cors:127.0.0.1,Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0,attack.evil.com",
    "level": "WARN",
    "description": "来自127.0.0.1的非法跨域请求，引用页为attack.evil.com"
    ...
}
```

---

### 恶意直接引用:[用户ID|IP, 用户代理]

**描述**
针对身份验证和授权的常见攻击是在没有凭据或适当访问权限的情况下直接访问对象。未能防止这种缺陷曾经是OWASP十大安全风险中的**不安全的直接对象引用**。假设你已正确防止了这种攻击，记录这种尝试对识别恶意用户很有价值。

**级别:**
CRITICAL

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_direct:joebob1, Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0",
    "level": "WARN",
    "description": "用户joebob1尝试访问未经授权的对象",
    ...
}
```

---

## 权限变更 [PRIVILEGE]

本节重点关注对象权限变更，如读/写/执行权限，或数据库中对象的授权元信息发生变化。

用户/账户的变更在用户管理部分已涵盖。

---

### 权限变更:[用户ID,文件|对象,原权限级别,新权限级别]

**描述**
跟踪具有访问控制限制的对象的变更，可以揭示未经授权的用户试图提升这些文件的权限。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_direct:joebob1, /users/admin/some/important/path,0511,0777",
    "level": "WARN",
    "description": "用户joebob1更改了/users/admin/some/important/path的权限",
    ...
}
```

---

## 敏感数据变更 [DATA]

并非所有文件的变更都需要记录或发出警报，但对于高度敏感的文件或数据，监控和警报非常重要。

---

### 敏感数据创建:[用户ID,文件|对象]

**描述**
当创建一个新的数据并标记为敏感，或放置在存储敏感数据的目录/表/仓库中时，应记录该创建过程并定期审查。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_create:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "用户joebob1在/users/admin/some/important/path创建了新文件",
    ...
}
```

---

### 敏感数据读取:[用户ID,文件|对象]

**描述**
所有标记为敏感或放置在存储敏感数据的目录/表/仓库中的数据，其访问应被记录并定期审查。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_read:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "用户joebob1读取了文件 /users/admin/some/important/path",
    ...
}
```

---

### 敏感数据更新:[用户ID,文件|对象]

**描述**
所有标记为敏感或放置在存储敏感数据的目录/表/仓库中的数据，其更新应被记录并定期审查。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_update:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "用户joebob1修改了文件 /users/admin/some/important/path",
    ...
}
```

---

### 敏感数据删除:[用户ID,文件|对象]

**描述**
所有标记为敏感或放置在存储敏感数据的目录/表/仓库中的数据，其删除应被记录并定期审查。文件不应立即删除，而是应标记为删除，并根据法律/隐私要求保留文件归档。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_delete:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "用户joebob1标记文件 /users/admin/some/important/path 为删除",
    ...
}
```

---

## 序列错误 [SEQUENCE]

也称为**业务逻辑攻击**，如果系统中预期有特定的路径，而有人试图跳过或更改该路径的顺序，可能表明存在恶意意图。

---

### 序列失败:[用户ID]

**描述**
当用户以非顺序方式到达应用程序的某个部分时，可能表明故意滥用业务逻辑，应予以跟踪。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sequence_fail:joebob1",
    "level": "WARN",
    "description": "用户joebob1已到达应用程序正常流程之外的部分。",
    ...
}
```

---

## 会话管理 [SESSION]

### 会话创建:[用户ID]

**描述**
当创建新的经过身份验证的会话时，可以记录该会话并监控活动。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_created:joebob1",
    "level": "INFO",
    "description": "用户joebob1已开始新会话",
    ...
}
```

---

### 会话续期:[用户ID]

**描述**
当用户收到会话即将过期/撤销的警告并选择延长会话时，应记录该活动。此外，如果相关系统包含高度机密的数据，则延长会话可能需要额外的验证。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_renewed:joebob1",
    "level": "WARN",
    "description": "用户joebob1被警告会话即将过期并已延长。",
    ...
}
```

---

### 会话过期:[用户ID,原因]

**描述**
当会话过期时，尤其是对于经过身份验证的会话或涉及敏感数据的会话，应记录会话过期并包含澄清数据。原因代码可以是：注销、超时、撤销等。会话不应被删除，而是在需要撤销时应标记为过期。

**级别:**
INFO

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_expired:joebob1,revoked",
    "level": "WARN",
    "description": "由于管理员撤销，用户joebob1的会话已过期。",
    ...
}
```

---

### 过期后使用会话:[用户ID]

**描述**
如果用户尝试使用已过期的会话访问系统，记录这一行为可能很有帮助，尤其是与后续的登录失败结合时。这可能识别出恶意用户正在尝试会话劫持或直接访问他人的机器/浏览器。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_use_after_expire:joebob1",
    "level": "WARN",
    "description": "用户joebob1在会话过期后尝试访问。",
    ...
}
```

---

## 系统事件 [SYS]

### 系统启动:[用户ID]

**描述**
系统首次启动时记录启动过程可能很有价值，即使是无服务器或容器系统，尤其是在可能记录启动系统的用户时。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_startup:joebob1",
    "level": "WARN",
    "description": "用户joebob1spawned了一个新实例",
    ...
}
```

---

### 系统关闭:[用户ID]

**描述**
系统关闭时记录该事件可能很有价值，即使是无服务器或容器系统，尤其是在可能记录启动系统的用户时。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_shutdown:joebob1",
    "level": "WARN",
    "description": "用户joebob1停止了此实例",
    ...
}
```

---

### 系统重启:[用户ID]

**描述**
系统重启时记录该事件可能很有价值，即使是无服务器或容器系统，尤其是在可能记录启动系统的用户时。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_restart:joebob1",
    "level": "WARN",
    "description": "用户joebob1发起了重启",
    ...
}
```

---

### 系统崩溃[:原因]

**描述**
如果可能捕获导致系统崩溃的不稳定条件，记录该事件可能很有帮助，尤其是当事件由攻击触发时。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_crash:outofmemory",
    "level": "WARN",
    "description": "系统因内存不足错误而崩溃。",
    ...
}
```

---

### 系统监控禁用:[用户ID,监控器]

**描述**
如果系统包含负责文件完整性、资源、日志记录、病毒等的代理，了解它们被谁暂停尤其有价值。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_monitor_disabled:joebob1,crowdstrike",
    "level": "WARN",
    "description": "用户joebob1已禁用CrowdStrike",
    ...
}
```

---

### 系统监控启用:[用户ID,监控器]

**描述**
如果系统包含负责文件完整性、资源、日志记录、病毒等的代理，了解它们在停止后是否再次启动以及由谁启动尤其有价值。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_monitor_enabled:joebob1,crowdstrike",
    "level": "WARN",
    "description": "用户joebob1已启用CrowdStrike",
    ...
}
```

---

## 用户管理 [USER]

### 用户创建:[用户ID,新用户ID,属性[一,二,三]]

**描述**
创建新用户时，记录用户创建事件的具体细节很有帮助，尤其是在可以使用管理员权限创建新用户的情况下。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_created:joebob1,user1,admin:create,update,delete",
    "level": "WARN",
    "description": "用户joebob1创建了用户user1，具有admin:create,update,delete权限属性",
    ...
}
```

---

### 用户更新:[用户ID,目标用户ID,属性[一,二,三]]

**描述**
更新用户时，记录用户更新事件的具体细节很有帮助，尤其是在可以更新用户管理员权限的情况下。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_updated:joebob1,user1,admin:create,update,delete",
    "level": "WARN",
    "description": "用户joebob1更新了用户user1的admin:create,update,delete权限属性",
    ...
}
```

---

### 用户归档:[用户ID,目标用户ID]

**描述**
除非必要，否则最好归档用户而不是删除。归档用户时，记录用户归档事件的具体细节很有帮助。恶意用户可能利用此功能拒绝合法用户的服务。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_archived:joebob1,user1",
    "level": "WARN",
    "description": "用户joebob1归档了用户user1",
    ...
}
```

---

### 用户删除:[用户ID,目标用户ID]

**描述**
除非必要，否则最好归档用户而不是删除。删除用户时，记录用户删除事件的具体细节很有帮助。恶意用户可能利用此功能拒绝合法用户的服务。

**级别:**
WARN

**示例:**

```json
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_deleted:joebob1,user1",
    "level": "WARN",
    "description": "用户joebob1删除了用户user1",
    ...
}
```

---

## 排除项

与记录什么一样重要的是不记录什么。私人或秘密信息、源代码、密钥、证书等绝不应被记录。

有关应从日志中排除的项目的全面概述，请参阅 [OWASP日志作弊表](../cheatsheets/Logging_Cheat_Sheet.md#data-to-exclude)。
