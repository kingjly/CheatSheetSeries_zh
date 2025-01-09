# 应用程序日志记录词汇速查表

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

**Description**
All login events should be recorded including success.

**Level:**
INFO

**Example:**

```
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

**Description**
The user successfully logged in after previously failing.

**Level:**
INFO

**Example:**

```
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

**Description**
All login events should be recorded including failure.

**Level:**
WARN

**Example:**

```
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

**Description**
All login events should be recorded including failure.

**Level:**
WARN

**Example:**

```
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

**Description**
When the feature exists to lock an account after x retries or other condition, the lock should be logged with relevant data.

**Level:**
WARN

**Reasons:**

- maxretries: The maximum number of retries was reached
- suspicious: Suspicious activity was observed on the account
- customer: The customer requested their account be locked
- other: Other

**Example:**

```
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

**Description**
Every password change should be logged, including the userid that it was for.

**Level:**
INFO

**Example:**

```
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

**Description**
An attempt to change a password that failed. May also trigger other events such as `authn_login_lock`.

**Level:**
INFO

**Example:**

```
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

**Description**
When a user is logged in from one city and suddenly appears in another, too far away to have traveled in a reasonable timeframe, this often indicates a potential account takeover.

**Level:**: CRITICAL

**Example:**

```
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

**Description**
When a token is created for service access it should be recorded

**Level:**: INFO

**Example:**

```
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

**Description**
A token has been revoked for the given account.

**Level:**: INFO

**Example:**

```
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

**Description**
A previously revoked token was attempted to be reused.

**Level:**: CRITICAL

**Example:**

```
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

**Description**
When a token is deleted it should be recorded

**Level:**: WARN

**Example:**

```
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

## Authorization [AUTHZ]

---

### authz_fail[:userid,resource]

**Description**
An attempt was made to access a resource which was unauthorized

**Level:**: CRITICAL

**Example:**

```
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

**Description**
The user or entity entitlements was changed

**Level:**: WARN

**Example:**

```
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

**Description**
All activity by privileged users such as admin should be recorded.

**Level:**: WARN

**Example:**

```
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

## Excessive Use [EXCESS]

### excess_rate_limit_exceeded[userid,max]

**Description**
Expected service limit ceilings should be established and alerted when exceeded, even if simply for managing costs and scaling.

**Level:**: WARN

**Example:**

```
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

## File Upload [UPLOAD]

### upload_complete[userid,filename,type]

**Description**
On successful file upload the first step in the validation process is that the upload has completed.

**Level:**: INFO

**Example:**

```
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

**Description**
One step in good file upload validation is to move/rename the file and when providing the content back to end users, never reference the original filename in the download. This is true both when storing in a filesystem as well as in block storage.

**Level:**: INFO

**Example:**

```
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

**Description**
All file uploads should have some validation performed, both for correctness (is in fact of file type x), and for safety (does not contain a virus).

**Level:**: INFO|CRITICAL

**Example:**

```
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

**Description**
When a file is deleted for normal reasons it should be recorded.

**Level:**: INFO

**Example:**

```
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

## Input Validation [INPUT]

### input_validation_fail[:field,userid]

**Description**
When input validation fails on the server-side it must either be because a) sufficient validation was not provided on the client, or b) client-side validation was bypassed. In either case it's an opportunity for attack and should be mitigated quickly.

**Level:**
WARN

**Example:**

```
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

## Malicious Behavior [MALICIOUS

### malicious_excess_404:[userid|IP,useragent]

**Description**
When a user makes numerous requests for files that don't exist it often is an indicator of attempts to "force-browse" for files that could exist and is often behavior indicating malicious intent.

**Level:**
WARN

**Example:**

```
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

**Description**
When a user submits data to a backend handler that was not expected it can indicate probing for input validation errors. If your backend service receives data it does not handle or have an input for this is an indication of likely malicious abuse.

**Level:**
CRITICAL

**Example:**

```
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

### malicious_attack_tool:[userid|IP,toolname,useragent]

**Description**
When obvious attack tools are identified either by signature or by user agent they should be logged.

**TODO:** A future version of this standard should link to known attack tools, signatures and user-agent strings. For instance, the tool "Nikto" leaves behind its user agent by default with a string like **_"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"_**

**Level:**
CRITICAL

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_attack_tool:127.0.0.1,nikto,Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)",
    "level": "WARN",
    "description": "Attack traffic indicating use of Nikto coming from 127.0.0.1",
    ...
}
```

---

### malicious_cors:[userid|IP,useragent,referer]

**Description**
When attempts are made from unauthorized origins they should of course be blocked, but also logged whenever possible. Even if we block an illegal cross-origin request the fact that the request is being made could be an indication of attack.

_NOTE: Did you know that the word "referer" is misspelled in the original HTTP specification? The correct spelling should be "referrer" but the original typo persists to this day and is used here intentionally._

**Level:**
CRITICAL

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_cors:127.0.0.1,Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0,attack.evil.com",
    "level": "WARN",
    "description": "An illegal cross-origin request from 127.0.0.1 was referred from attack.evil.com"
    ...
}
```

---

### malicious_direct_reference:[userid|IP, useragent]

**Description**
A common attack against authentication and authorization is to directly access an object without credentials or appropriate access authority. Failing to prevent this flaw used to be one of the OWASP Top Ten called **Insecure Direct Object Reference**. Assuming you've correctly prevented this attack, logging the attempt is valuable to identify malicious users.

**Level:**
CRITICAL

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_direct:joebob1, Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0",
    "level": "WARN",
    "description": "User joebob1 attempted to access an object to which they are not authorized",
    ...
}
```

---

## Privilege Changes [PRIVILEGE]

This section focuses on object privilege changes such as read/write/execute permissions or objects in a database having authorization meta-information changed.

Changes to user/account are covered in the User Management section.

---

### privilege_permissions_changed:[userid,file|object,fromlevel,tolevel]

**Description**
Tracking changes to objects to which there are access control restrictions can uncover attempt to escalate privilege on those files by unauthorized users.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "malicious_direct:joebob1, /users/admin/some/important/path,0511,0777",
    "level": "WARN",
    "description": "User joebob1 changed permissions on /users/admin/some/important/path",
    ...
}
```

---

## Sensitive Data Changes [DATA]

It's not necessary to log or alert on changes to all files, but in the case of highly sensitive files or data it is important that we monitor and alert on changes.

---

### sensitive_create:[userid,file|object]

**Description**
When a new piece of data is created and marked as sensitive or placed into a directory/table/repository where sensitive data is stored, that creation should be logged and reviewed periodically.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_create:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "User joebob1 created a new file in /users/admin/some/important/path",
    ...
}
```

---

### sensitive_read:[userid,file|object]

**Description**
All data marked as sensitive or placed into a directory/table/repository where sensitive data is stored should be have access logged and reviewed periodically.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_read:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "User joebob1 read file /users/admin/some/important/path",
    ...
}
```

---

### sensitive_update:[userid,file|object]

**Description**
All data marked as sensitive or placed into a directory/table/repository where sensitive data is stored should be have updates to the data logged and reviewed periodically.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_update:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "User joebob1 modified file /users/admin/some/important/path",
    ...
}
```

---

### sensitive_delete:[userid,file|object]

**Description**
All data marked as sensitive or placed into a directory/table/repository where sensitive data is stored should have deletions of the data logged and reviewed periodically. The file should not be immediately deleted but marked for deletion and an archive of the file should be maintained according to legal/privacy requirements.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sensitive_delete:joebob1, /users/admin/some/important/path",
    "level": "WARN",
    "description": "User joebob1 marked file /users/admin/some/important/path for deletion",
    ...
}
```

---

## Sequence Errors [SEQUENCE]

Also called a **_business logic attack_**, if a specific path is expected through a system and an attempt is made to skip or change the order of that path it could indicate malicious intent.

---

### sequence_fail:[userid]

**Description**
When a user reaches a part of the application out of sequence it may indicate intentional abuse of the business logic and should be tracked.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sequence_fail:joebob1",
    "level": "WARN",
    "description": "User joebob1 has reached a part of the application out of the normal application flow.",
    ...
}
```

---

## Session Management [SESSION]

### session_created:[userid]

**Description**
When a new authenticated session is created that session may be logged and activity monitored.

**Level:**
INFO

**Example:**

```
    {
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_created:joebob1",
    "level": "INFO",
    "description": "User joebob1 has started a new session",
    ...
}
```

---

### session_renewed:[userid]

**Description**
When a user is warned of session to be expired/revoked and chooses to extend their session that activity should be logged. Also, if the system in question contains highly confidential data then extending a session may require additional verification.

**Level:**
INFO

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_renewed:joebob1",
    "level": "WARN",
    "description": "User joebob1 was warned of expiring session and extended.",
    ...
}
```

---

### session_expired:[userid,reason]

**Description**
When a session expires, especially in the case of an authenticated session or with sensitive data, then that session expiry may be logged and clarifying data included. The reason code may be any such as: logout, timeout, revoked, etc. Sessions should never be deleted but rather expired in the case of revocation requirement.

**Level:**
INFO

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_expired:joebob1,revoked",
    "level": "WARN",
    "description": "User joebob1 session expired due to administrator revocation.",
    ...
}
```

---

### session_use_after_expire:[userid]

**Description**
In the case a user attempts to access systems with an expire session it may be helpful to log, especially if combined with subsequent login failure. This could identify a case where a malicious user is attempting a session hijack or directly accessing another person's machine/browser.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "session_use_after_expire:joebob1",
    "level": "WARN",
    "description": "User joebob1 attempted access after session expired.",
    ...
}
```

---

## System Events [SYS]

### sys_startup:[userid]

**Description**
When a system is first started it can be valuable to log the startup, even if the system is serverless or a container, especially if possible to log the user that initiated the system.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_startup:joebob1",
    "level": "WARN",
    "description": "User joebob1 spawned a new instance",
    ...
}
```

---

### sys_shutdown:[userid]

**Description**
When a system is shut down it can be valuable to log the event, even if the system is serverless or a container, especially if possible to log the user that initiated the system.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_shutdown:joebob1",
    "level": "WARN",
    "description": "User joebob1 stopped this instance",
    ...
}
```

---

### sys_restart:[userid]

**Description**
When a system is restarted it can be valuable to log the event, even if the system is serverless or a container, especially if possible to log the user that initiated the system.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_restart:joebob1",
    "level": "WARN",
    "description": "User joebob1 initiated a restart",
    ...
}
```

---

### sys_crash[:reason]

**Description**
If possible to catch an unstable condition resulting in the crash of a system, logging that event could be helpful, especially if the event is triggered by an attack.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_crash:outofmemory,
    "level": "WARN",
    "description": "The system crashed due to Out of Memory error.",
    ...
}
```

---

### sys_monitor_disabled:[userid,monitor]

**Description**
If your systems contain agents responsible for file integrity, resources, logging, virus, etc. it is especially valuable to know if they are halted and by whom.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_monitor_disabled:joebob1,crowdstrike",
    "level": "WARN",
    "description": "User joebob1 has disabled CrowdStrike",
    ...
}
```

---

### sys_monitor_enabled:[userid,monitor]

**Description**
If your systems contain agents responsible for file integrity, resources, logging, virus, etc. it is especially valuable to know if they are started again after being stopped, and by whom.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "sys_monitor_enabled:joebob1,crowdstrike",
    "level": "WARN",
    "description": "User joebob1 has enabled CrowdStrike",
    ...
}
```

---

## User Management [USER]

### user_created:[userid,newuserid,attributes[one,two,three]]

**Description**
When creating new users, logging the specifics of the user creation event is helpful, especially if new users can be created with administration privileges.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_created:joebob1,user1,admin:create,update,delete",
    "level": "WARN",
    "description": "User joebob1 created user1 with admin:create,update,delete privilege attributes",
    ...
}
```

---

### user_updated:[userid,onuserid,attributes[one,two,three]]

**Description**
When updating users, logging the specifics of the user update event is helpful, especially if users can be updated with administration privileges.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_updated:joebob1,user1,admin:create,update,delete",
    "level": "WARN",
    "description": "User joebob1 updated user1 with attributes admin:create,update,delete privilege attributes",
    ...
}
```

---

### user_archived:[userid,onuserid]

**Description**
It is always best to archive users rather than deleting, except where required. When archiving users, logging the specifics of the user archive event is helpful. A malicious user could use this feature to deny service to legitimate users.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_archived:joebob1,user1",
    "level": "WARN",
    "description": "User joebob1 archived user1",
    ...
}
```

---

### user_deleted:[userid,onuserid]

**Description**
It is always best to archive users rather than deleting, except where required. When deleting users, logging the specifics of the user delete event is helpful. A malicious user could use this feature to deny service to legitimate users.

**Level:**
WARN

**Example:**

```
{
    "datetime": "2019-01-01 00:00:00,000",
    "appid": "foobar.netportal_auth",
    "event": "user_deleted:joebob1,user1",
    "level": "WARN",
    "description": "User joebob1 has deleted user1",
    ...
}
```

---

## Exclusions

As important as what you DO log is what you DON'T log. Private or secret information, source code, keys, certs, etc. should never be logged.

For comprehensive overview of items that should be excluded from logging, please see the [OWASP Logging Cheat Sheet](../cheatsheets/Logging_Cheat_Sheet.md#data-to-exclude).
