# AJAX 安全备忘录

## 引言

本文档将为 AJAX 安全提供一个起点，希望能够经常更新和扩展，以提供关于特定框架和技术的更详细信息。

### 客户端（JavaScript）

#### 使用 `.innerText` 而不是 `.innerHTML`

使用 `.innerText` 将防止大多数跨站脚本（XSS）问题，因为它会自动对文本进行编码。

#### 不要使用 `eval()`、`new Function()` 或其他代码执行工具

`eval()` 函数是有害的，永远不要使用它。需要使用 eval 通常表明设计中存在问题。

#### 对消费者规范化数据（即使用前编码）

在构建 HTML、脚本、CSS、XML、JSON 等时使用数据，确保考虑数据在字面意义上如何呈现，以保持其逻辑含义。

在使用数据之前，应正确编码以防止注入类问题，并确保保留逻辑含义。

[查看 OWASP Java 编码器项目。](https://owasp.org/www-project-java-encoder/)

#### 不要依赖客户端逻辑进行安全控制

不要忘记用户控制客户端逻辑。许多浏览器插件可以设置断点、跳过代码、更改值等。永远不要依赖客户端逻辑进行安全控制。

#### 不要依赖客户端业务逻辑

与安全性类似，确保任何重要的业务规则/逻辑在服务器端也有重复，以防止用户绕过必要的逻辑做一些愚蠢或更糟的事情。

#### 避免编写序列化代码

这很困难，即使是一个小错误也可能导致严重的安全问题。已经有很多框架提供这种功能。

查看 [JSON 页面](http://www.json.org/) 获取相关链接。

#### 避免动态构建 XML 或 JSON

就像构建 HTML 或 SQL 一样，你会引入 XML 注入漏洞，所以要远离这种做法，或者至少使用编码库或安全的 JSON 或 XML 库来保护属性和元素数据。

- [跨站脚本（XSS）预防](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [SQL 注入预防](SQL_Injection_Prevention_Cheat_Sheet.md)

#### 永不向客户端传输秘密信息

客户端知道的任何内容用户也会知道，所以请将所有秘密信息保留在服务器上。

#### 不要在客户端代码中执行加密

使用 TLS/SSL 并在服务器上加密！

#### 不要在客户端执行安全相关的逻辑

这是一个总体原则，以防我遗漏了其他细节。

### 服务器端

#### 使用 CSRF 保护

查看 [跨站请求伪造（CSRF）预防](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) 备忘录。

#### 针对旧版浏览器防范 JSON 劫持

##### 审查 AngularJS JSON 劫持防御机制

参见 AngularJS 文档中的 [JSON 漏洞保护](https://docs.angularjs.org/api/ng/service/$http#json-vulnerability-protection) 部分。

##### 始终返回带有外层对象的 JSON

对于 JSON 字符串，外层原语必须是一个对象：

**可被利用的：**

```json
[{"object": "inside an array"}]
```

**不可被利用的：**

```json
{"object": "not inside an array"}
```

**同样不可被利用的：**

```json
{"result": [{"object": "inside an array"}]}
```

#### 避免在服务器端手写序列化代码

记住引用类型和值类型！寻找已经被审查过的现有库。

#### 服务可能直接被用户调用

即使你只期望 AJAX 客户端代码调用这些服务，用户也可以直接调用。

确保验证输入，并像它们处于用户控制之下一样对待它们（因为它们确实如此！）。

#### 避免手动构建 XML 或 JSON，使用框架

使用框架以确保安全，手动操作则会引入安全问题。

#### 对 Web 服务使用 JSON 和 XML 模式

你需要使用第三方库来验证 Web 服务。
