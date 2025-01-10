# 第三方 JavaScript 管理备忘录

## 引言

标签（又称营销标签、分析标签等）是网页上的小段 JavaScript 代码。当 JavaScript 被禁用时，它们也可能是 HTML 图像元素。这些标签的目的是收集网页用户的行为和浏览上下文数据，供网页所有者用于营销。

第三方供应商 JavaScript 标签（以下简称**标签**）可分为两类：

- 用户界面标签
- 分析标签

用户界面标签必须在客户端执行，因为它们会改变 DOM；例如显示对话框、图像或更改文本等。

分析标签会将信息发送回营销信息数据库；这些信息包括用户刚刚执行的操作、浏览器元数据、位置信息、页面元数据等。分析标签的基本原理是将用户浏览器 DOM 中的数据提供给供应商，用于某种形式的营销分析。这些数据可以是 DOM 中的任何可用信息。数据用于用户导航和点击流分析、识别用户以确定要显示的进一步内容等，以及各种营销分析功能。

术语**宿主**指用户访问的原始站点，如购物或新闻网站，该站点包含或检索并执行第三方 JavaScript 标签以分析用户行为。

## 主要风险

最大的风险是第三方 JavaScript 服务器被入侵，并将恶意 JavaScript 注入原始标签 JavaScript 中。这种情况在 2018 年已经发生，并且可能更早。

在 Web 应用程序中调用第三方 JS 代码需要特别考虑 3 个风险：

1. 失去对客户端应用程序的控制
2. 在客户端系统上执行任意代码
3. 向第三方泄露或泄漏敏感信息

### 风险 1：失去对客户端应用程序的控制

这种风险源于通常无法保证第三方托管的代码将保持开发者和测试者看到的原样：第三方代码随时可能推送新功能，从而可能破坏接口或数据流，并影响应用程序对用户/客户的可用性。

典型的防御措施包括但不限于：内部脚本镜像（防止第三方更改）、子资源完整性（启用浏览器级拦截）和安全传输第三方代码（防止传输过程中被修改）。下文将详细介绍。

### 风险 2：在客户端系统上执行任意代码

这种风险源于第三方 JavaScript 代码很少在集成到网站/应用程序之前被调用方审查。当客户端访问托管网站/应用程序时，这段第三方代码会被执行，从而授予第三方与用户相同的权限（类似于 [XSS 攻击](https://owasp.org/www-community/attacks/xss/)）。

任何在进入生产环境之前进行的测试都会失去部分有效性，包括 `AST 测试`（[IAST](https://www.veracode.com/security/interactive-application-security-testing-iast)、[RAST](https://www.veracode.com/sites/default/files/pdf/resources/whitepapers/what-is-rasp.pdf)、[SAST](https://www.sqreen.com/web-application-security/what-is-sast)、[DAST](https://www.sqreen.com/web-application-security/what-is-dast) 等）。

尽管普遍认为第三方故意注入恶意代码的可能性很低，但仍有第三方服务器被入侵后在第三方代码中注入恶意代码的案例（例如：Yahoo，2014 年 1 月）。

因此，仍然需要评估这种风险，特别是当第三方没有任何文档表明其正在执行比调用组织本身更好或至少同等的安全措施时。另一个例子是托管第三方 JavaScript 代码的域名到期，因为维护它的公司破产或开发者已经放弃该项目。恶意行为者随后可以重新注册域名并发布恶意代码。

典型的防御措施包括但不限于：

- 内部脚本镜像（防止第三方更改）
- [子资源完整性](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)（启用浏览器级拦截）
- 安全传输第三方代码（防止传输过程中被修改）和各种类型的沙盒。下文将详细介绍。
- ...

### 风险 3：向第三方泄露敏感信息

当在网站/应用程序中调用第三方脚本时，浏览器直接联系第三方服务器。默认情况下，请求包括所有常规 HTTP 标头。除了浏览器的原始 IP 地址外，第三方还获取其他数据，如引用者（在非 HTTPS 请求中）以及之前由第三方设置的任何 Cookie，例如在访问另一个也调用该第三方脚本的组织的网站时。

在许多情况下，这授予第三方对组织用户/客户的主要访问权限。此外，如果第三方与其他实体共享脚本，它还会从所有其他实体收集次要数据，从而了解组织的访问者是谁，以及他们与哪些其他组织进行交互。

一个典型的案例是当前主要新闻/新闻网站调用第三方代码（通常用于广告引擎、统计和 JavaScript API）的情况：任何访问这些网站的用户都会通知第三方访问情况。在许多情况下，第三方还能知道每个用户具体点击了哪些新闻文章（通过 HTTP 引用者字段泄露），从而建立更深入的个性化档案。

典型的防御措施包括但不限于：内部脚本镜像（防止向第三方泄露 HTTP 请求）。用户可以通过在泄露的网站/应用程序（如新闻网站）上随机点击链接来减少个人资料分析。下文将详细介绍。

## 第三方 JavaScript 部署架构

**标签**有三种基本部署机制。这些机制可以相互组合。

### 页面上的供应商 JavaScript

这是供应商向宿主提供 JavaScript，而宿主将其放置在宿主页面上。为了安全，宿主公司必须审查代码是否存在 [XSS 攻击](https://owasp.org/www-community/attacks/xss/)或恶意操作，如将 DOM 中的敏感数据发送到恶意站点。这通常很困难，因为 JavaScript 通常是混淆的。

```html
<!-- 某个宿主，例如 foobar.com 的 HTML 代码 -->
<html>
<head></head>
    <body>
        ...
        <script type="text/javascript">/* 第三方供应商 javascript 在此 */</script>
    </body>
</html>
```

### 向供应商发出 JavaScript 请求

这是宿主页面上的一行或几行代码直接从供应商站点请求 JavaScript 文件或 URL。在创建宿主页面时，开发者包含供应商提供的代码行，这些代码行将请求供应商 JavaScript。每次访问页面时，都会向供应商站点发出请求以获取 JavaScript，然后在用户浏览器上执行。

```html
<!-- 某个宿主，例如 foobar.com 的 HTML 代码 -->
<html>
    <head></head>
    <body>
        ...
        <!-- 第三方供应商 javascript -->
        <script src="https://analytics.vendor.com/v1.1/script.js"></script>
        <!-- /第三方供应商 javascript -->
    </body>
</html>
```

### 通过标签管理器间接请求供应商

这是宿主页面上的一行或几行代码向标签聚合器或**标签管理器**站点（而非 JavaScript 供应商站点）请求 JavaScript 文件或 URL。标签聚合器或标签管理器站点返回宿主公司配置的第三方 JavaScript 文件。对标签管理器站点的每个文件或 URL 请求都可以返回来自多个供应商的大量其他 JavaScript 文件。

聚合器或管理器返回的实际内容（即特定的 JavaScript 文件以及它们的具体功能）可以由宿主站点员工使用托管在标签管理器站点上的图形用户界面动态更改，非技术用户（如业务营销部门）可以使用该界面。

更改可以是：

1. 为同一请求从第三方供应商获取不同的 JavaScript 文件。
2. 更改读取 DOM 对象数据的方式和时间，以发送给供应商。

标签管理器开发者用户界面将生成满足营销功能要求的代码，基本上确定从浏览器 DOM 获取哪些数据以及何时获取。标签管理器始终向浏览器返回一个**容器** JavaScript 文件，该文件基本上是一组 JavaScript 函数，由用户界面生成的代码使用，以实现所需的功能。

类似于提供函数和全局数据给开发者的 Java 框架，容器 JavaScript 在浏览器上执行，让业务用户能够使用标签管理器开发者用户界面指定高级功能，而无需了解 JavaScript。


#### 请求标签的安全问题

之前描述的机制很难确保安全，因为只有在代理请求或获得 GUI 访问权并查看配置时才能看到代码。JavaScript 通常是混淆的，即使看到它通常也没有用。它是即时可部署的，因为每个浏览器的新页面请求都会执行对聚合器的请求，聚合器从第三方供应商获取 JavaScript。因此，只要供应商上的任何 JavaScript 文件发生变化，或在聚合器上被修改，下一次从任何浏览器调用它们时都会获取已更改的 JavaScript。管理这种风险的一种方法是使用下面描述的*子资源完整性*标准。

### 服务器直接数据层

标签管理器开发者用户界面可用于创建 JavaScript，该 JavaScript 可以从浏览器 DOM 的任何位置获取数据并将其存储在页面的任何位置。这可能导致漏洞，因为该界面可用于生成代码，从 DOM（例如 URL 参数）获取未验证的数据，并将其存储在会执行 JavaScript 的某个页面位置。

使生成的代码安全的最佳方法是将其限制为仅从宿主定义的数据层获取 DOM 数据。

数据层可以是：

1. 具有营销或用户行为数据属性值的 DIV 对象，这些数据是第三方想要的
2. 具有相同数据的 JSON 对象集。每个变量或属性包含某个 DOM 元素的值或用户操作的描述。数据层是该页面所有供应商需要的完整值集。数据层由宿主开发者创建。

当发生业务定义的特定事件时，该事件的 JavaScript 处理程序直接将数据层中的值发送到标签管理器服务器。然后，标签管理器服务器将数据发送给应该接收它的任何第三方。事件处理程序代码由宿主开发者使用标签管理器开发者用户界面创建。事件处理程序代码在每次页面加载时从标签管理器服务器加载。

**这是一种安全的技术**，因为只有您的 JavaScript 在用户浏览器上执行，并且只发送您决定的数据给供应商。

这需要宿主、聚合器或标签管理器以及供应商之间的合作。

宿主开发者必须与供应商合作，以了解供应商进行分析需要什么类型的数据。然后，宿主程序员确定哪个 DOM 元素将包含该数据。

宿主开发者必须与标签管理器或聚合器合作，就向聚合器发送数据的协议达成一致：使用什么 URL、参数、格式等。

标签管理器或聚合器必须与供应商合作，就向供应商发送数据的协议达成一致：使用什么 URL、参数、格式等。供应商是否有 API？

## 安全防御考虑

### 服务器直接数据层

服务器直接机制是第三方 JavaScript 管理、部署和执行的良好安全标准。宿主页面的良好实践是创建 DOM 对象的数据层。

数据层可以对值进行任何验证，特别是来自暴露给用户的 DOM 对象的值，如 URL 参数和输入字段（如果这些是营销分析所需的）。

企业标准文档中的示例陈述是"标签 JavaScript 只能访问宿主数据层中的值。标签 JavaScript 绝不能访问 URL 参数。"

作为宿主页面开发者，您必须与第三方供应商或标签管理器就数据层中的哪个属性将具有什么值达成一致，以便他们可以创建读取该值的 JavaScript。

用户界面标签无法使用数据层架构来确保安全，因为它们的功能（或其功能之一）是在客户端更改用户界面，而不是发送关于用户操作的数据。

分析标签可以使用数据层架构来确保安全，因为唯一需要的操作是将数据层中的数据发送到第三方。只执行第一方代码；首先填充数据层（通常在页面加载时）；然后事件处理程序 JavaScript 将该页面所需的任何数据发送到第三方数据库或标签管理器。

这也是一个非常可扩展的解决方案。大型电子商务网站可以轻松拥有数十万个 URL 和参数组合，不同的 URL 和参数集包含在不同的营销分析活动中。营销逻辑可能在单个页面上有 30 或 40 个不同的供应商标签。

例如，关于特定城市、特定位置、特定日期的页面上的用户操作应发送数据层元素 1、2 和 3。关于其他城市的页面上的用户操作应仅发送数据层元素 2 和 3。由于在每个页面上发送数据层数据的事件处理程序代码由宿主开发者或使用标签管理器开发者界面的营销技术人员控制，因此关于何时以及向标签管理器服务器发送哪些数据层元素的业务逻辑可以在几分钟内更改和部署。不需要与第三方交互；他们继续获得预期的数据，但现在数据来自宿主营销技术人员选择的不同上下文。

更改第三方供应商只意味着更改标签管理器服务器上的数据传播规则，宿主代码不需要任何更改。数据也直接仅发送到标签管理器，因此执行速度很快。事件处理程序 JavaScript 不必连接到多个第三方站点。

### 间接请求

对于向提供配置 JavaScript 的 GUI 的标签管理器/聚合器站点的间接请求，他们可能还会实施：

- 技术控制，如仅允许 JavaScript 访问数据层值，不访问其他 DOM 元素
- 限制在宿主站点上部署的标签类型，例如禁用自定义 HTML 标签和 JavaScript 代码

宿主公司还应验证标签管理器站点的安全实践，如对宿主公司的标签配置的访问控制。它还可以是双因素身份验证。

让营销人员决定他们想要获取数据的位置可能导致 XSS，因为他们可能从 URL 参数获取数据并将其放入页面上可脚本化位置的变量中。

### 沙盒内容

这两个工具可以由站点用于沙盒/清理 DOM 数据。

- [DOMPurify](https://github.com/cure53/DOMPurify) 是一个快速、宽容的 HTML、MathML 和 SVG 的 XSS 清理器。DOMPurify 使用安全默认值，但提供大量可配置性和钩子。
- [MentalJS](https://github.com/hackvertor/MentalJS) 是一个 JavaScript 解析器和沙盒。它通过在变量和访问器添加"$"后缀来允许列出 JavaScript 代码。

### 子资源完整性

[子资源完整性](https://www.w3.org/TR/SRI/)将确保只执行已审查的代码。开发者为供应商 JavaScript 生成完整性元数据，并将其添加到脚本元素中，如下所示：

```javascript
<script src="https://analytics.vendor.com/v1.1/script.js"
   integrity="sha384-MBO5IDfYaE6c6Aao94oZrIOiC7CGiSNE64QUbHNPhzk8Xhm0djE6QqTpL0HzTUxk"
   crossorigin="anonymous">
</script>
```

重要的是要知道，为了使 SRI 工作，供应商主机需要启用 [CORS](https://www.w3.org/TR/cors/)。定期监控供应商 JavaScript 的变化也是个好主意。因为有时当供应商决定更新时，你可能会得到**安全**但**不工作**的第三方代码。

### 保持 JavaScript 库更新

[OWASP Top 10 2013 A9](https://wiki.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) 描述了使用具有已知漏洞的组件的问题。这包括 JavaScript 库。必须保持 JavaScript 库最新，因为早期版本可能存在已知漏洞，这可能导致站点通常容易受到[跨站脚本](https://owasp.org/www-community/attacks/xss/)攻击。有几种工具可以帮助识别此类库。其中一个工具是免费的开源工具 [RetireJS](https://retirejs.github.io)

### 使用 iframe 进行沙盒

您还可以将供应商 JavaScript 放入来自不同域（例如静态数据主机）的 iframe 中。它将作为一个"监狱"，供应商 JavaScript 将无法直接访问宿主页面 DOM 和 Cookie。

宿主主页和沙盒 iframe 可以通过 [postMessage 机制](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)相互通信。

此外，iframe 可以使用 iframe [sandbox 属性](http://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/)进行保护。

对于高风险应用程序，除了 iframe 沙盒之外，还要考虑使用[内容安全策略（CSP）](https://www.w3.org/TR/CSP2/)。CSP 使针对 XSS 的强化更加强大。

```html
<!-- 某个宿主，例如 somehost.com 的 HTML 代码 -->
 <html>
   <head></head>
     <body>
       ...
       <!-- 包含带有第三方供应商 JavaScript 的 iframe -->
       <iframe
       src="https://somehost-static.net/analytics.html"
       sandbox="allow-same-origin allow-scripts">
       </iframe>
   </body>
 </html>

<!-- somehost-static.net/analytics.html -->
 <html>
   <head></head>
     <body>
       ...
       <script>
       window.addEventListener("message", receiveMessage, false);
       function receiveMessage(event) {
         if (event.origin !== "https://somehost.com:443") {
           return;
         } else {
         // 在这里创建一些 DOM 并初始化其他
        //第三方代码所需的数据
         }
       }
       </script>
       <!-- 第三方供应商 JavaScript -->
       <script src="https://analytics.vendor.com/v1.1/script.js"></script>
       <!-- /第三方供应商 JavaScript -->
   </body>
 </html>
```

### 虚拟 iframe 隔离

这种技术创建了相对于主页异步运行的 iFrame。它还提供了自己的隔离 JavaScript，可根据营销标签要求自动动态实现受保护的 iFrame。

### 供应商协议

您可以要求与第三方的协议或建议书提供证据，证明他们已实施安全编码和总体企业服务器访问安全。但特别是，您需要确定他们对源代码的监控和控制，以防止和检测对该 JavaScript 的恶意更改。

## MarTechSec

营销技术安全

这指的是减少来自营销 JavaScript 的风险的所有方面。控制包括：

1. 风险降低的合同控制；与任何 MarTech 公司的合同应包括提供代码安全性和代码完整性监控证据的要求。
2. 风险转移的合同控制：与任何 MarTech 公司的合同可能包括提供恶意 JavaScript 的惩罚。
3. 防止恶意 JavaScript 执行的技术控制；虚拟 iFrame。
4. 识别恶意 JavaScript 的技术控制；[子资源完整性](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)。
5. 包括渗透测试要求中的客户端 JavaScript 恶意行为的技术控制。

## MarSecOps

营销安全运营

这指的是维护某些技术控制的操作要求。这涉及营销团队、MarTech 提供商和运行或运营团队之间可能的合作和信息交换，以更新页面控件中的信息（SRI 哈希更改、带有 SRI 的页面更改）、虚拟 iFrame 中的策略、标签管理器配置、数据层更改等。

对于包含非平凡营销标签的任何站点，最完整和最具预防性的控制是：

1. 调用营销服务器或标签管理器 API 的数据层，以便只有您的代码在您的页面上执行（控制反转）。

2. [子资源完整性](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)。

3. 虚拟框架隔离。

为了以营销希望的变更速度实施技术控制，或者在没有大量专门资源的情况下，MarSecOps 要求可能使数据层和子资源完整性控制变得不切实际。

## 参考资料

- [影响顶级发布商和零售商的广告网络代码中的广泛 XSS 漏洞](https://randywestergren.com/widespread-xss-vulnerabilities-ad-network-code-affecting-top-tier-publishers-retailers/)

- [深入了解 Ticketmaster：Magecart 的多重入侵](https://www.riskiq.com/blog/labs/magecart-ticketmaster-breach/)

- [Magecart - 用于从在线商店窃取支付详细信息的恶意基础设施](https://www.clearskysec.com/magecart/)

- [被入侵的电子商务网站导向"Magecart"](https://www.riskiq.com/blog/labs/magecart-keylogger-injection/)

- [Inbenta 承认被黑客入侵，为 Ticketmaster 数据泄露负责](https://www.zdnet.com/article/inbenta-blamed-for-ticketmaster-breach-says-other-sites-not-affected/)
