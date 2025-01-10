# Node.js 安全备忘录

## 引言

本备忘录列出了开发人员在开发安全的 Node.js 应用程序时可以采取的行动。每个条目都有一个简要说明和特定于 Node.js 环境的解决方案。

## 背景

Node.js 应用程序数量正在增加，它们与其他框架和编程语言没有什么不同。Node.js 应用程序容易受到各种 Web 应用程序漏洞的影响。

## 目标

本备忘录旨在提供在开发 Node.js 应用程序期间应遵循的最佳实践列表。

## 建议

有几项建议可以增强 Node.js 应用程序的安全性。这些建议分为以下类别：

- **应用程序安全**
- **错误和异常处理**
- **服务器安全**
- **平台安全**

### 应用程序安全

#### 使用扁平的 Promise 链

异步回调函数是 Node.js 最强大的特性之一。然而，回调函数中嵌套层次的增加可能会成为一个问题。任何多阶段过程都可能嵌套 10 层或更深。这个问题被称为"末日金字塔"或"回调地狱"。在这种代码中，错误和结果会在回调中丢失。Promise 是编写异步代码的好方法，可以避免嵌套金字塔。Promise 通过将错误和结果传递给下一个 `.then` 函数，提供自上而下的执行。

Promise 的另一个优势是处理错误的方式。如果在 Promise 类中发生错误，它会跳过 `.then` 函数，并调用它找到的第一个 `.catch` 函数。这样，Promise 提供了更高的捕获和处理错误的保证。作为原则，您可以使所有异步代码（除了发射器）返回 Promise。需要注意的是，Promise 调用也可能变成金字塔。为了完全避免"回调地狱"，应使用扁平的 Promise 链。如果您使用的模块不支持 Promise，可以使用 `Promise.promisifyAll()` 函数将基本对象转换为 Promise。

以下代码片段是"回调地狱"的一个示例：

```JavaScript
function func1(name, callback) {
  // 需要一些时间的操作，然后调用回调
}
function func2(name, callback) {
  // 需要一些时间的操作，然后调用回调
}
function func3(name, callback) {
  // 需要一些时间的操作，然后调用回调
}
function func4(name, callback) {
  // 需要一些时间的操作，然后调用回调
}

func1("input1", function(err, result1){
   if(err){
      // 错误操作
   }
   else {
      //一些操作
      func2("input2", function(err, result2){
         if(err){
            //错误操作
         }
         else{
            //一些操作
            func3("input3", function(err, result3){
               if(err){
                  //错误操作
               }
               else{
                  // 一些操作
                  func4("input 4", function(err, result4){
                     if(err){
                        // 错误操作
                     }
                     else {
                        // 一些操作
                     }
                  });
               }
            });
         }
      });
   }
});
```

使用扁平的 Promise 链，上述代码可以安全地重写如下：

```JavaScript
function func1(name) {
  // 需要一些时间的操作，然后解析 Promise
}
function func2(name) {
  // 需要一些时间的操作，然后解析 Promise
}
function func3(name) {
  // 需要一些时间的操作，然后解析 Promise
}
function func4(name) {
  // 需要一些时间的操作，然后解析 Promise
}

func1("input1")
   .then(function (result){
      return func2("input2");
   })
   .then(function (result){
      return func3("input3");
   })
   .then(function (result){
      return func4("input4");
   })
   .catch(function (error) {
      // 错误操作
   });
```

使用 async/await：

```JavaScript
function async func1(name) {
  // 需要一些时间的操作，然后解析 Promise
}
function async func2(name) {
  // 需要一些时间的操作，然后解析 Promise
}
function async func3(name) {
  // 需要一些时间的操作，然后解析 Promise
}
function async func4(name) {
  // 需要一些时间的操作，然后解析 Promise
}

(async() => {
  try {
    let res1 = await func1("input1");
    let res2 = await func2("input2");
    let res3 = await func3("input2");
    let res4 = await func4("input2");
  } catch(err) {
    // 错误操作
  }
})();
```

#### 设置请求大小限制

缓冲和解析请求正文可能是一个资源密集型任务。如果对请求大小没有限制，攻击者可以发送大型请求正文的请求，这可能会耗尽服务器内存和/或填满磁盘空间。您可以使用 [raw-body](https://www.npmjs.com/package/raw-body) 为所有请求限制请求正文大小。

```JavaScript
const contentType = require('content-type')
const express = require('express')
const getRawBody = require('raw-body')

const app = express()

app.use(function (req, res, next) {
  if (!['POST', 'PUT', 'DELETE'].includes(req.method)) {
    next()
    return
  }

  getRawBody(req, {
    length: req.headers['content-length'],
    limit: '1kb',
    encoding: contentType.parse(req).parameters.charset
  }, function (err, string) {
    if (err) return next(err)
    req.text = string
    next()
  })
})
```

然而，为所有请求固定请求大小限制可能不是正确的行为，因为某些请求可能在请求正文中有大型有效负载，例如上传文件时。另外，JSON 类型的输入比多部分输入更危险，因为解析 JSON 是阻塞操作。因此，您应该为不同的内容类型设置请求大小限制。您可以使用 express 中间件轻松实现：

```JavaScript
app.use(express.urlencoded({ extended: true, limit: "1kb" }));
app.use(express.json({ limit: "1kb" }));
```

需要注意的是，攻击者可以更改请求的 `Content-Type` 标头并绕过请求大小限制。因此，在处理请求之前，应根据请求标头中声明的内容类型验证请求中包含的数据。如果对每个请求进行内容类型验证会严重影响性能，您可以仅验证特定内容类型或大于预定大小的请求。

#### 不要阻塞事件循环

Node.js 与使用线程的常见应用程序平台非常不同。Node.js 具有单线程事件驱动架构。通过这种架构，吞吐量变得很高，编程模型变得更简单。Node.js 围绕非阻塞 I/O 事件循环实现。使用此事件循环，没有 I/O 等待或上下文切换。事件循环寻找事件并将它们分派给处理程序函数。因此，当执行 CPU 密集型 JavaScript 操作时，事件循环会等待它们完成。这就是为什么这些操作被称为"阻塞"。为了克服这个问题，Node.js 允许为 IO 阻塞事件分配回调。这样，主应用程序不会被阻塞，回调异步运行。因此，作为一般原则，所有阻塞操作都应异步执行，以便事件循环不被阻塞。

即使您异步执行阻塞操作，您的应用程序可能仍然无法按预期服务。如果回调之外有依赖于回调内代码先运行的代码，就会发生这种情况。例如，考虑以下代码：

#### 执行输入验证

输入验证是应用程序安全的关键部分。输入验证失败可能导致多种类型的应用程序攻击。这些包括 SQL 注入、跨站脚本（XSS）、命令注入、本地/远程文件包含、拒绝服务、目录遍历、LDAP 注入和许多其他注入攻击。为避免这些攻击，应首先对应用程序的输入进行净化。最佳的输入验证技术是使用接受的输入列表。但是，如果这不可能，则应首先根据预期的输入方案检查输入，并对危险输入进行转义。为了简化 Node.js 应用程序中的输入验证，有一些模块如 [validator](https://www.npmjs.com/package/validator) 和 [express-mongo-sanitize](https://www.npmjs.com/package/express-mongo-sanitize)。

关于输入验证的详细信息，请参考 [输入验证备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)。

JavaScript 是一种动态语言，根据框架解析 URL 的方式，应用程序代码看到的数据可能采用多种形式。以下是在 express.js 中解析查询字符串后的一些示例：

| URL | 代码中 request.query.foo 的内容 |
| --- | --- |
| `?foo=bar` | `'bar'`（字符串） |
| `?foo=bar&foo=baz` | `['bar', 'baz']`（字符串数组） |
| `?foo[]=bar` | `['bar']`（字符串数组） |
| `?foo[]=bar&foo[]=baz` | `['bar', 'baz']`（字符串数组） |
| `?foo[bar]=baz` | `{ bar : 'baz' }`（带有一个键的对象） |
| `?foo[]baz=bar` | `['bar']`（字符串数组 - 后缀丢失） |
| `?foo[][baz]=bar` | `[ { baz: 'bar' } ]`（对象数组） |
| `?foo[bar][baz]=bar` | `{ foo: { bar: { baz: 'bar' } } }`（对象树） |
| `?foo[10]=bar&foo[9]=baz` | `[ 'baz', 'bar' ]`（字符串数组 - 注意顺序） |
| `?foo[toString]=bar` | `{}`（调用 `toString()` 将失败的对象） |

#### 执行输出转义

除了输入验证，还应转义应用程序通过用户显示的所有 HTML 和 JavaScript 内容，以防止跨站脚本（XSS）攻击。您可以使用 [escape-html](https://github.com/component/escape-html) 或 [node-esapi](https://github.com/ESAPI/node-esapi) 库来执行输出转义。

#### 执行应用程序活动日志记录

记录应用程序活动是一种值得鼓励的好做法。它使调试应用程序运行时遇到的任何错误变得更加容易。对于安全问题也很有用，因为它可以在事件响应期间使用。此外，这些日志可用于馈送入侵检测/防御系统（IDS/IPS）。在 Node.js 中，有诸如 [Winston](https://www.npmjs.com/package/winston)、[Bunyan](https://www.npmjs.com/package/bunyan) 或 [Pino](https://www.npmjs.com/package/pino) 等模块来执行应用程序活动日志记录。这些模块支持流式传输和查询日志，并提供处理未捕获异常的方法。

使用以下代码，您可以在控制台和所需的日志文件中记录应用程序活动：

```JavaScript
const logger = new (Winston.Logger) ({
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: 'application.log' })
    ],
    level: 'verbose'
});
```

您可以提供不同的传输，以便将错误保存到单独的日志文件，将常规应用程序日志保存到不同的日志文件。有关安全日志记录的其他信息，请参见 [日志记录备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)。

#### 监控事件循环

当您的应用程序服务器遭受大量网络流量时，可能无法为用户提供服务。这本质上是一种[拒绝服务（DoS）](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)攻击。[toobusy-js](https://www.npmjs.com/package/toobusy-js) 模块允许您监控事件循环。它跟踪响应时间，当响应时间超过某个阈值时，此模块可以指示您的服务器太忙。在这种情况下，您可以停止处理传入请求并发送 `503 服务器太忙` 消息，以使您的应用程序保持响应。以下是 [toobusy-js](https://www.npmjs.com/package/toobusy-js) 模块的示例用法：

```JavaScript
const toobusy = require('toobusy-js');
const express = require('express');
const app = express();
app.use(function(req, res, next) {
    if (toobusy()) {
        // 如果需要，记录日志
        res.status(503).send("服务器太忙");
    } else {
    next();
    }
});
```

#### 防范暴力破解

[暴力破解](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks)是所有 Web 应用程序的常见威胁。攻击者可以使用暴力破解作为密码猜测攻击来获取帐户密码。因此，应用程序开发人员应特别在登录页面防范暴力破解攻击。Node.js 有几个可用于此目的的模块。[Express-bouncer](https://libraries.io/npm/express-bouncer)、[express-brute](https://libraries.io/npm/express-brute) 和 [rate-limiter](https://libraries.io/npm/rate-limiter) 只是一些例子。根据您的需求和要求，您应选择一个或多个这些模块并相应使用。[Express-bouncer](https://libraries.io/npm/express-bouncer) 和 [express-brute](https://libraries.io/npm/express-brute) 模块的工作方式类似。它们增加每个失败请求的延迟，并可针对特定路由进行安排。这些模块可以按如下方式使用：

```JavaScript
const bouncer = require('express-bouncer');
bouncer.whitelist.push('127.0.0.1'); // 允许一个 IP 地址
// 给出自定义错误消息
bouncer.blocked = function (req, res, next, remaining) {
    res.status(429).send("已发出太多请求。请等待 " + remaining/1000 + " 秒。");
};
// 要保护的路由
app.post("/login", bouncer.block, function(req, res) {
    if (LoginFailed){  }
    else {
        bouncer.reset( req );
    }
});
```

```JavaScript
const ExpressBrute = require('express-brute');

const store = new ExpressBrute.MemoryStore(); // 本地存储状态，不要在生产中使用
const bruteforce = new ExpressBrute(store);

app.post('/auth',
    bruteforce.prevent, // 如果过于频繁地访问此路由，则返回 429 错误
    function (req, res, next) {
        res.send('成功！');
    }
);
```

除了 [express-bouncer](https://libraries.io/npm/express-bouncer) 和 [express-brute](https://libraries.io/npm/express-brute)，[rate-limiter](https://libraries.io/npm/rate-limiter) 模块还可以帮助防范暴力破解攻击。它支持指定特定 IP 地址在指定时间段内可以发出多少请求。

#### 使用防 CSRF 令牌

[跨站请求伪造（CSRF）](https://owasp.org/www-community/attacks/csrf)旨在代表经过身份验证的用户执行授权操作，而用户对此操作毫不知情。CSRF 攻击通常针对状态改变的请求，如更改密码、添加用户或下订单。[Csurf](https://www.npmjs.com/package/csurf) 是一个用于缓解 CSRF 攻击的 express 中间件。但最近在该包中发现了一个安全漏洞。该包背后的团队尚未修复已发现的漏洞，并已将该包标记为已弃用，建议使用任何其他 CSRF 保护包。

有关跨站请求伪造（CSRF）攻击和预防方法的详细信息，您可以参考 [跨站请求伪造预防](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)。

#### 删除不必要的路由

Web 应用程序不应包含用户未使用的任何页面，因为这可能会增加应用程序的攻击面。因此，应在 Node.js 应用程序中禁用所有未使用的 API 路由。这在 [Sails](https://sailsjs.com) 和 [Feathers](https://feathersjs.com) 等框架中尤为常见，因为它们会自动生成 REST API 端点。例如，在 [Sails](https://sailsjs.com) 中，如果 URL 不匹配自定义路由，它可能匹配自动路由并仍然生成响应。这种情况可能导致从信息泄露到任意命令执行的各种结果。因此，在使用此类框架和模块之前，了解它们自动生成的路由并删除或禁用这些路由很重要。

#### 防止 HTTP 参数污染

[HTTP 参数污染（HPP）](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.html)是一种攻击，攻击者发送多个同名的 HTTP 参数，导致应用程序以不可预测的方式解释它们。当发送多个参数值时，Express 会将它们放入数组中。为了解决此问题，您可以使用 [hpp](https://www.npmjs.com/package/hpp) 模块。使用时，此模块将忽略 `req.query` 和/或 `req.body` 中为参数提交的所有值，并仅选择提交的最后一个参数值。您可以按如下方式使用：

```JavaScript
const hpp = require('hpp');
app.use(hpp());
```

#### 仅返回必要的信息

应用程序用户的信息是关于应用程序最关键的信息。用户表通常包括 ID、用户名、全名、电子邮件地址、出生日期、密码，有时还包括社会安全号码。因此，在查询和使用用户对象时，您需要仅返回必要的字段，因为这可能容易导致个人信息泄露。对存储在数据库中的其他对象也是如此。如果您只需要对象的某个特定字段，则应仅返回所需的特定字段。例如，您可以使用以下函数来获取用户信息。通过这样做，您只能返回特定操作所需的字段。换句话说，如果您只需要列出可用用户的姓名，则不会额外返回他们的电子邮件地址或信用卡号码。

```JavaScript
exports.sanitizeUser = function(user) {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName
  };
};
```

#### 使用对象属性描述符

对象属性包括三个隐藏属性：`writable`（如果为 false，则无法更改属性值）、`enumerable`（如果为 false，则属性无法在 for 循环中使用）和 `configurable`（如果为 false，则无法删除属性）。通过赋值定义对象属性时，这三个隐藏属性默认设置为 true。这些属性可以按如下方式设置：

```JavaScript
const o = {};
Object.defineProperty(o, "a", {
    writable: true,
    enumerable: true,
    configurable: true,
    value: "A"
});
```

除此之外，还有一些针对对象属性的特殊函数。`Object.preventExtensions()` 可防止向对象添加新属性。

#### 使用访问控制列表

授权可防止用户在其预期权限之外行事。为此，应考虑最小特权原则来确定用户及其角色。每个用户角色只能访问必须使用的资源。对于 Node.js 应用程序，您可以使用 [acl](https://www.npmjs.com/package/acl) 模块提供 ACL（访问控制列表）实现。使用此模块，您可以创建角色并将用户分配到这些角色。

### 错误和异常处理

#### 处理未捕获的异常

Node.js 对未捕获异常的行为是打印当前堆栈跟踪，然后终止线程。但是，Node.js 允许自定义此行为。它提供了一个名为 process 的全局对象，可用于所有 Node.js 应用程序。这是一个 EventEmitter 对象，在出现未捕获的异常时，会发出 uncaughtException 事件并将其提升到主事件循环。要为未捕获的异常提供自定义行为，您可以绑定到此事件。但是，在出现此类未捕获异常后恢复应用程序可能会导致进一步的问题。因此，如果您不想错过任何未捕获的异常，应绑定到 uncaughtException 事件，并在关闭进程之前清理任何已分配的资源，如文件描述符、句柄等。强烈不建议恢复应用程序，因为应用程序将处于未知状态。需要注意的是，在出现未捕获异常时向用户显示错误消息时，不应向用户透露堆栈跟踪等详细信息。相反，应向用户显示自定义错误消息，以避免任何信息泄露。

```JavaScript
process.on("uncaughtException", function(err) {
    // 清理已分配的资源
    // 将必要的错误详细信息记录到日志文件
    process.exit(); // 退出进程以避免未知状态
});
```

#### 在使用 EventEmitter 时监听错误

使用 EventEmitter 时，错误可能在事件链的任何位置发生。通常，如果 EventEmitter 对象中发生错误，则会调用一个错误事件，并将 Error 对象作为参数。但是，如果没有附加到该错误事件的监听器，则作为参数发送的 Error 对象将被抛出并成为未捕获的异常。简而言之，如果不正确处理 EventEmitter 对象中的错误，这些未处理的错误可能会使您的应用程序崩溃。因此，在使用 EventEmitter 对象时，应始终监听错误事件。

```JavaScript
const events = require('events');
const myEventEmitter = function(){
    events.EventEmitter.call(this);
}
require('util').inherits(myEventEmitter, events.EventEmitter);
myEventEmitter.prototype.someFunction = function(param1, param2) {
    //如果出现错误
    this.emit('error', err);
}
const emitter = new myEventEmitter();
emitter.on('error', function(err){
    //在此处执行必要的错误处理
});
```

#### 处理异步调用中的错误

在异步回调中发生的错误很容易被忽略。因此，作为一般原则，异步调用的第一个参数应该是一个 Error 对象。另外，express 路由本身处理错误，但应始终记住，除非发送 Error 对象作为第一个参数，否则在 express 路由中进行的异步调用中发生的错误不会被处理。

这些回调中的错误可以被尽可能多地传播。被传播错误的每个回调都可以忽略、处理或传播错误。


### 服务器安全

#### 适当设置 Cookie 标志

通常，会话信息在 Web 应用程序中使用 Cookie 发送。然而，不当使用 HTTP Cookie 可能会使应用程序面临多种会话管理漏洞。可以为每个 Cookie 设置一些标志以防止这类攻击。`httpOnly`、`Secure` 和 `SameSite` 标志对会话 Cookie 非常重要。`httpOnly` 标志可防止客户端 JavaScript 访问 Cookie。这是针对 XSS 攻击的有效对策。`Secure` 标志仅在通信通过 HTTPS 时才允许发送 Cookie。`SameSite` 标志可防止在跨站点请求中发送 Cookie，有助于防护跨站请求伪造（CSRF）攻击。除此之外，还有域、路径和过期等其他标志。建议适当设置这些标志，但它们主要与 Cookie 范围相关，而非 Cookie 安全性。以下示例展示了这些标志的使用：

```JavaScript
const session = require('express-session');
app.use(session({
    secret: 'your-secret-key',
    name: 'cookieName',
    cookie: { secure: true, httpOnly: true, path: '/user', sameSite: true}
}));
```

#### 使用适当的安全标头

有几个 [HTTP 安全标头](https://owasp.org/www-project-secure-headers/)可以帮助您防止一些常见的攻击向量。
[helmet](https://www.npmjs.com/package/helmet) 包可以帮助设置这些标头：

```Javascript
const express = require("express");
const helmet = require("helmet");

const app = express();

app.use(helmet()); // 添加各种 HTTP 标头
```

顶级 `helmet` 函数是 14 个较小中间件的包装器。
以下是 `helmet` 中间件涵盖的 HTTP 安全标头列表：

- **[Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)**: [HTTP 严格传输安全（HSTS）](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)规定浏览器只能通过 HTTPS 连接访问应用程序。要在应用程序中使用它，请添加以下代码：

```JavaScript
app.use(helmet.hsts()); // 默认配置
app.use(
  helmet.hsts({
    maxAge: 123456,
    includeSubDomains: false,
  })
); // 自定义配置
```

- **[X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options):** 确定页面是否可以通过 `<frame>` 或 `<iframe>` 元素加载。允许页面被框架可能导致[点击劫持](https://owasp.org/www-community/attacks/Clickjacking)攻击。

```JavaScript
app.use(helmet.frameguard()); // 默认行为（SAMEORIGIN）
```

- **[X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection):** 当检测到反射型跨站脚本（XSS）攻击时，停止页面加载。此标头已被现代浏览器弃用，其使用可能在客户端引入额外的安全问题。因此，建议将标头设置为 **X-XSS-Protection: 0**，以禁用 XSS 审计器，并不允许浏览器采用默认的响应处理行为。

```JavaScript
app.use(helmet.xssFilter()); // 设置 "X-XSS-Protection: 0"
```

对于现代浏览器，建议实施强大的 **Content-Security-Policy** 策略，详见下一节。

- **[Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy):** 内容安全策略旨在降低[跨站脚本（XSS）](https://owasp.org/www-community/attacks/xss/)和[点击劫持](https://owasp.org/www-community/attacks/Clickjacking)等攻击的风险。它允许来自您决定的列表的内容。它有多个指令，每个指令禁止加载特定类型的内容。您可以参考 [内容安全策略备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)以详细解释每个指令及其使用方法。您可以在应用程序中按以下方式实施这些设置：

```JavaScript
app.use(
  helmet.contentSecurityPolicy({
    // 以下指令将合并到默认的 helmet CSP 策略中
    directives: {
      defaultSrc: ["'self'"],  // 所有缺失指令的默认值
      scriptSrc: ["'self'"],   // 有助于防止 XSS 攻击
      frameAncestors: ["'none'"],  // 有助于防止点击劫持攻击
      imgSrc: ["'self'", "'http://imgexample.com'"],
      styleSrc: ["'none'"]
    }
  })
);
```

由于此中间件执行的验证非常有限，建议依赖 CSP 检查器，如 [CSP 评估器](https://csp-evaluator.withgoogle.com/)。

- **[X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options):** 即使服务器在响应中设置了有效的 `Content-Type` 标头，浏览器也可能尝试嗅探请求资源的 MIME 类型。此标头是阻止此行为的方法，告诉浏览器不要更改 `Content-Type` 标头中指定的 MIME 类型。可以按以下方式配置：

```JavaScript
app.use(helmet.noSniff());
```

- **[Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control) 和 [Pragma](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma):** Cache-Control 标头可用于防止浏览器缓存给定的响应。对于包含有关用户或应用程序的敏感信息的页面，应执行此操作。但是，对不包含敏感信息的页面禁用缓存可能会严重影响应用程序的性能。因此，应仅对返回敏感信息的页面禁用缓存。可以使用 [nocache](https://www.npmjs.com/package/nocache) 包轻松设置适当的缓存控制和标头：

```JavaScript
const nocache = require("nocache");

app.use(nocache());
```

上述代码相应地设置 Cache-Control、Surrogate-Control、Pragma 和 Expires 标头。

- **X-Download-Options:** 此标头防止 Internet Explorer 在站点上下文中执行下载的文件。这是通过 noopen 指令实现的。您可以使用以下代码完成：

```JavaScript
app.use(helmet.ieNoOpen());
```

- **[Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT):** 证书透明性是为解决当前 SSL 基础架构中的一些结构性问题而开发的新机制。Expect-CT 标头可以强制执行证书透明性要求。可以在应用程序中按以下方式实施：

```JavaScript
const expectCt = require('expect-ct');
app.use(expectCt({ maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123, reportUri: 'http://example.com'}));
```

- **X-Powered-By:** X-Powered-By 标头用于通知服务器端使用的技术。这是一个导致信息泄露的不必要标头，因此应从应用程序中删除。为此，您可以按如下方式使用 `hidePoweredBy`：

```JavaScript
app.use(helmet.hidePoweredBy());
```

此外，您还可以对使用的技术撒谎。例如，即使您的应用程序未使用 PHP，也可以将 X-Powered-By 标头设置为看起来像是使用了 PHP。

```JavaScript
app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }));
```

### 平台安全

#### 保持包的更新

应用程序的安全性直接取决于您在应用程序中使用的第三方包的安全性。因此，保持包的更新很重要。需要注意的是，[使用存在已知漏洞的组件](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities)仍然位于 OWASP Top 10 中。您可以使用 [OWASP Dependency-Check](https://jeremylong.github.io/DependencyCheck/analyzers/nodejs.html) 查看项目中使用的包是否存在已知漏洞。此外，您可以使用 [Retire.js](https://github.com/retirejs/retire.js/) 检查具有已知漏洞的 JavaScript 库。

从版本 6 开始，`npm` 引入了 `audit`，它将警告有关易受攻击的包：

```bash
npm audit
```

`npm` 还引入了一种简单的方法来升级受影响的包：

```bash
npm audit fix
```

还有几种其他工具可用于检查依赖项。更全面的列表可以在 [易受攻击的依赖项管理备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html#tools)中找到。

#### 不要使用危险的函数

有一些 JavaScript 函数是危险的，只应在必要或不可避免的情况下使用。第一个例子是 `eval()` 函数。此函数接受一个字符串参数并将其作为任何其他 JavaScript 源代码执行。与用户输入结合使用时，这种行为本质上会导致远程代码执行漏洞。同样，调用 `child_process.exec` 也非常危险。此函数充当 bash 解释器，并将其参数发送到 /bin/sh。通过向此函数注入输入，攻击者可以在服务器上执行任意命令。

除了这些函数外，某些模块在使用时需要特别小心。例如，`fs` 模块处理文件系统操作。但是，如果将未经适当净化的用户输入输入到此模块，您的应用程序可能会变得易受文件包含和目录遍历漏洞的攻击。同样，`vm` 模块提供在 V8 虚拟机上下文中编译和运行代码的 API。由于它本质上可以执行危险操作，因此应在沙盒中使用。

说这些函数和模块完全不应使用是不公平的，但是在使用时，尤其是与用户输入一起使用时，应该非常小心。此外，还有[一些其他函数](https://github.com/wisec/domxsswiki/wiki/Direct-Execution-Sinks)可能会使您的应用程序易受攻击。

#### 远离邪恶的正则表达式

正则表达式拒绝服务（ReDoS）是一种拒绝服务攻击，它利用了大多数正则表达式实现可能达到极端情况，导致它们工作非常缓慢（与输入大小呈指数关系）。攻击者可以使用正则表达式导致程序进入这些极端情况并长时间挂起。

[正则表达式拒绝服务（ReDoS）](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)是一种使用正则表达式的拒绝服务攻击。某些正则表达式（Regex）实现会导致极端情况，使应用程序变得非常缓慢。攻击者可以使用此类 regex 实现使应用程序进入这些极端情况并长时间挂起。如果应用程序可能因精心制作的输入而卡住，则这些 regex 被称为"邪恶"。通常，这些 regex 是通过重复分组和重叠交替来利用的。例如，以下正则表达式 `^(([a-z])+.)+[A-Z]([a-z])+$` 可用于指定 Java 类名。然而，非常长的字符串（aaaa...aaaaAaaaaa...aaaa）也可以匹配此正则表达式。有一些工具可以检查 regex 是否有导致拒绝服务的潜在风险。一个例子是 [vuln-regex-detector](https://github.com/davisjam/vuln-regex-detector)。

#### 运行安全 linters

在开发代码时，记住所有安全提示可能真的很困难。同时，让所有团队成员遵守这些规则几乎是不可能的。这就是为什么有静态分析安全测试（SAST）工具。这些工具不执行您的代码，而是简单地查找可能包含安全风险的模式。由于 JavaScript 是一种动态且类型松散的语言，linting 工具在软件开发生命周期中确实至关重要。应定期审查 linting 规则，并审核发现的问题。这些工具的另一个优点是可以为您认为危险的模式添加自定义规则。[ESLint](https://eslint.org/) 和 [JSHint](http://jshint.com/) 是常用的 JavaScript linting 的 SAST 工具。

#### 使用严格模式

JavaScript 有许多不安全和危险的遗留特性，不应使用。为了删除这些特性，ES5 为开发人员引入了严格模式。使用此模式，以前静默的错误现在会被抛出。它还帮助 JavaScript 引擎进行优化。在严格模式下，以前被接受的错误语法现在会导致真正的错误。由于这些改进，您应该始终在应用程序中使用严格模式。要启用严格模式，只需在代码顶部编写 `"use strict";`。

以下代码将在控制台上生成 `ReferenceError: Can't find variable: y`，除非使用严格模式，否则不会显示：

```JavaScript
"use strict";

func();
function func() {
  y = 3.14;   // 这将导致错误（y 未定义）
}
```

#### 遵守一般应用程序安全原则

此列表主要关注 Node.js 应用程序中常见的问题，并提供建议和示例。除此之外，还有适用于 Web 应用程序的一般[安全设计原则](https://wiki.owasp.org/index.php/Security_by_Design_Principles)，无论应用程序服务器使用什么技术。在开发应用程序时，还应牢记这些原则。您随时可以参考 [OWASP 备忘录系列](https://cheatsheetseries.owasp.org/)，了解有关 Web 应用程序漏洞及其缓解技术的更多信息。

## Node.js 安全的其他资源

[Awesome Node.js 安全资源](https://github.com/lirantal/awesome-nodejs-security)
