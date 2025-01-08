# DOM 污染防御备忘录

## 引言

[DOM 污染](https://domclob.xyz/domc_wiki/#overview)是一种代码重用的、仅基于 HTML 的注入攻击，攻击者通过注入 `id` 或 `name` 属性与安全敏感变量或浏览器 API 名称相匹配的 HTML 元素，从而混淆 Web 应用程序，并覆盖其原有值。

当无法进行脚本注入时（例如被 HTML 净化器过滤，或通过禁止或控制脚本执行来缓解），这种攻击尤其相关。在这些场景中，攻击者仍可以将非脚本的 HTML 标记注入网页，并将原本安全的标记转换为可执行代码，从而实现[跨站脚本（XSS）](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)。

**本指南是一系列防止或限制 Web 应用程序中 DOM 污染影响的指导原则、安全编码模式和实践。**

## 背景

在深入探讨 DOM 污染之前，让我们先回顾一些基本的 Web 背景知识。

当网页加载时，浏览器会创建一个表示页面结构和内容的 [DOM 树](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction)，JavaScript 代码可以读取和写入这棵树。

在创建 DOM 树时，浏览器还会在 `window` 和 `document` 对象上为（某些）具名 HTML 元素创建属性。具名 HTML 元素是指具有 `id` 或 `name` 属性的元素。例如，以下标记：

```html
<form id=x></a>
```

将导致浏览器在 `window` 和 `document` 上创建对该表单元素的引用：

```js
var obj1 = document.getElementById('x');
var obj2 = document.x;
var obj3 = document.x;
var obj4 = window.x;
var obj5 = x; // 默认情况下，对象属于全局 Window，所以 x 等同于 window.x
console.log(
 obj1 === obj2 && obj2 === obj3 &&
 obj3 === obj4 && obj4 === obj5
); // true
```

在访问 `window` 和 `document` 对象的属性时，具名 HTML 元素引用的优先级高于内置 API 和开发者在 `window` 和 `document` 上定义的其他属性的查找，这也称为[具名属性访问](https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object)。对此行为不了解的开发者可能会将 window/document 属性的内容用于敏感操作，如获取远程内容的 URL，而攻击者可以通过注入具有冲突名称的标记来利用这一点。与自定义属性/变量类似，内置浏览器 API 也可能被 DOM 污染所覆盖。

如果攻击者能够在 DOM 树中注入（非脚本）HTML 标记，就可以改变 Web 应用程序依赖的变量值，导致其功能异常、暴露敏感数据或执行攻击者控制的脚本。DOM 污染通过利用这种（遗留的）行为，在执行环境（即 `window` 和 `document` 对象）和 JavaScript 代码之间造成命名空间冲突。

### 攻击示例 1

```javascript
let redirectTo = window.redirectTo || '/profile/';
location.assign(redirectTo);
```

攻击者可以：

- 注入标记 `<a id=redirectTo href='javascript:alert(1)'` 并获得 XSS。
- 注入标记 `<a id=redirectTo href='phishing.com'` 并实现开放重定向。

### 攻击示例 2

```javascript
var script = document.createElement('script');
let src = window.config.url || 'script.js';
s.src = src;
document.body.appendChild(s);
```

攻击者可以注入标记 `<a id=config><a id=config name=url href='malicious.js'>` 以加载额外的 JavaScript 代码，从而获得任意客户端代码执行。

## 指南概要

以下是后续讨论的指南快速参考。

|    | **指南**                                                     | 描述                                                         |
|----|--------------------------------------------------------------|--------------------------------------------------------------|
| \# 1  | 使用 HTML 净化器                                            | [链接](#1-html-净化)                                         |
| \# 2  | 使用内容安全策略                                            | [链接](#2-内容安全策略)                                      |
| \# 3  | 冻结敏感的 DOM 对象                                         | [链接](#3-冻结敏感的-dom-对象)                               |
| \# 4  | 验证所有 DOM 树输入                                         | [链接](#4-验证所有-dom-树输入)                               |
| \# 5  | 使用显式变量声明                                            | [链接](#5-使用显式变量声明)                                  |
| \# 6  | 不要将文档和窗口用作全局变量                                | [链接](#6-不要将文档和窗口用作全局变量)                      |
| \# 7  | 不要在验证前信任文档内置 API                                | [链接](#7-不要在验证前信任文档内置-api)                      |
| \# 8  | 强制类型检查                                                | [链接](#8-强制类型检查)                                      |
| \# 9  | 使用严格模式                                                | [链接](#9-使用严格模式)                                      |
| \# 10 | 应用浏览器特性检测                                          | [链接](#10-应用浏览器特性检测)                               |
| \# 11 | 将变量限制在局部作用域                                      | [链接](#11-将变量限制在局部作用域)                           |
| \# 12 | 在生产环境中使用唯一的变量名                                | [链接](#12-在生产环境中使用唯一的变量名)                     |
| \# 13 | 使用面向对象编程技术，如封装                                | [链接](#13-使用面向对象编程技术如封装)                       |

## 缓解技术

### \#1: HTML 净化

强大的 HTML 净化器可以防止或限制 DOM 污染的风险。它们可以通过多种方式实现：

- 完全移除 `id` 和 `name` 等具名属性。虽然有效，但可能会在需要具名属性进行合法功能时阻碍可用性。
- 命名空间隔离，例如为具名属性的值添加常量字符串前缀，以限制命名冲突的风险。
- 动态检查输入标记的具名属性是否与现有 DOM 树存在冲突，如果是，则移除输入标记的具名属性。

OWASP 推荐使用 [DOMPurify](https://github.com/cure53/DOMPurify) 或 [Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) 进行 HTML 净化。

#### DOMPurify 净化器

默认情况下，DOMPurify 会移除与**内置** API 和属性的所有污染冲突（使用默认启用的 `SANITIZE_DOM` 配置选项）。

要防止自定义变量和属性的污染，需要启用 `SANITIZE_NAMED_PROPS` 配置：

```js
var clean = DOMPurify.sanitize(dirty, {SANITIZE_NAMED_PROPS: true});
```

这将通过在具名属性和 JavaScript 变量前添加 `user-content-` 字符串来隔离其命名空间。

#### Sanitizer API

新的浏览器内置 [Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API) 在[默认设置](https://wicg.github.io/sanitizer-api/#dom-clobbering)下不能防止 DOM 污染，但可以配置为移除具名属性：

```js
const sanitizerInstance = new Sanitizer({
  blockAttributes: [
    {'name': 'id', elements: '*'},
    {'name': 'name', elements: '*'}
  ]
});
containerDOMElement.setHTML(input, {sanitizer: sanitizerInstance});
```

### \#2: 内容安全策略

[内容安全策略（CSP）](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)是一组规则，告诉浏览器允许在网页上加载哪些资源。通过限制 JavaScript 文件的来源（例如使用 [script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src) 指令），CSP 可以防止恶意代码被注入页面。

**注意：** CSP 只能缓解 DOM 污染攻击的**部分变体**，例如当攻击者试图通过污染脚本源加载新脚本时，但对于已存在的可被滥用于代码执行的代码（如污染 `eval()` 等代码评估构造的参数）则无法防范。

### \#3: 冻结敏感的 DOM 对象

针对单个对象缓解 DOM 污染的简单方法是冻结敏感的 DOM 对象及其属性，例如通过 [Object.freeze()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/freeze) 方法。

**注意：** 冻结对象属性可以防止它们被具名 DOM 元素覆盖。但是，确定需要冻结的所有对象和对象属性可能并不容易，这限制了这种方法的实用性。

## 安全编码指南

通过防御性编程和遵循几种编码模式和指南，可以避免 DOM 污染。

### \#4: 验证所有 DOM 树输入

在将任何标记插入网页的 DOM 树之前，对 `id` 和 `name` 属性进行净化（参见 [HTML 净化](#html-净化)）。

### \#5: 使用显式变量声明

初始化变量时，始终使用 `var`、`let` 或 `const` 等变量声明器，这可以防止变量被污染。

**注意：** 使用 `let` 声明变量不会在 `window` 上创建属性，与 `var` 不同。因此，`window.VARNAME` 仍然可能被污染（假设 `VARNAME` 是变量名）。

### \#6: 不要将文档和窗口用作全局变量

避免使用 `document` 和 `window` 等对象存储全局变量，因为它们很容易被操纵（参见[此处](https://domclob.xyz/domc_wiki/indicators/patterns.html#do-not-use-document-for-global-variables)）。

### \#7: 不要在验证前信任文档内置 API

文档属性，包括内置属性，始终可以被 DOM 污染覆盖，即使在赋值后立即使用。

**提示：** 这是由所谓的[具名属性可见性算法](https://webidl.spec.whatwg.org/#legacy-platform-object-abstract-ops)造成的，其中具名 HTML 元素引用的优先级高于 `document` 上的内置 API 和其他属性的查找。

### \#8: 强制类型检查

在敏感操作中使用 `document` 和 `window` 属性之前，始终检查其类型，例如使用 [`instanceof`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/instanceof) 运算符。

**提示：** 当对象被污染时，它将引用 [`Element`](https://developer.mozilla.org/en-US/docs/Web/API/Element) 实例，这可能不是预期的类型。

### \#9: 使用严格模式

使用 `strict` 模式可以防止意外创建全局变量，并在尝试覆盖只读属性时[引发错误](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Read-only)。

### \#10: 应用浏览器特性检测

不要依赖特定于浏览器的特性或属性，而是使用特性检测来确定是否支持某个特性，然后再使用它。这可以帮助防止在不支持的浏览器中使用这些特性时可能出现的错误和 DOM 污染。

**提示：** 在不支持的浏览器中，不支持的特性 API 可能表现为未定义的变量/属性，使其容易被污染。

### \#11: 将变量限制在局部作用域

全局变量更容易被 DOM 污染覆盖。尽可能使用局部变量和对象属性。

### \#12: 在生产环境中使用唯一的变量名

使用唯一的变量名可以帮助防止可能导致意外覆盖的命名冲突。

### \#13: 使用面向对象编程技术，如封装

将变量和函数封装在对象或类中可以帮助防止它们被覆盖。通过使它们私有，它们无法从对象外部访问，从而使它们不太容易受到 DOM 污染的影响。

## 参考文献

- [domclob.xyz](https://domclob.xyz)
- [PortSwigger: DOM 污染再袭](https://portswigger.net/research/dom-clobbering-strikes-back)
- [博客文章：GMail 的 AMP4Email 中的 XSS](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)
- [HackTricks: DOM 污染](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [HTMLHell: DOM 污染](https://www.htmhell.dev/adventcalendar/2022/12/)
