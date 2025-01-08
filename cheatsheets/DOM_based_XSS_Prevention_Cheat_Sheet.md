# 基于 DOM 的 XSS 防御备忘录

## 引言

在研究 XSS（跨站脚本）时，通常认为存在三种形式的 [XSS](https://owasp.org/www-community/attacks/xss/)：

- [反射型或存储型](https://owasp.org/www-community/attacks/xss/#stored-and-reflected-xss-attacks)
- [基于 DOM 的 XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

[XSS 防御备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)在处理反射型和存储型 XSS 方面做得非常出色。本备忘录专注于基于 DOM（文档对象模型）的 XSS，是 [XSS 防御备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)的扩展（并假定读者已理解原文）。

为了理解基于 DOM 的 XSS，需要了解反射型/存储型 XSS 与基于 DOM 的 XSS 之间的根本区别。主要区别在于攻击被注入应用程序的位置。

反射型和存储型 XSS 是服务器端注入问题，而基于 DOM 的 XSS 是客户端（浏览器）侧注入问题。

所有这些代码都源自服务器，这意味着应用程序所有者有责任使其免受 XSS 攻击，无论是哪种类型的 XSS 漏洞。同时，XSS 攻击始终在**浏览器中执行**。

反射型/存储型 XSS 与基于 DOM 的 XSS 的区别在于攻击被添加或注入应用程序的位置。对于反射型/存储型 XSS，攻击在服务器端处理请求期间被注入，其中不可信的输入被动态添加到 HTML 中。对于 DOM XSS，攻击直接在客户端运行时被注入到应用程序中。

当浏览器渲染 HTML 以及 CSS 或 JavaScript 等相关内容时，它会识别不同类型输入的各种渲染上下文，并为每个上下文遵循不同的规则。渲染上下文与 HTML 标签及其属性的解析相关联。

- 渲染上下文的 HTML 解析器决定数据如何在页面上呈现和布局，并可进一步细分为 HTML、HTML 属性、URL 和 CSS 的标准上下文。
- 执行上下文的 JavaScript 或 VBScript 解析器与脚本代码的解析和执行相关。每个解析器在可能执行脚本代码的方式上都有不同且独立的语义，这使得在各种上下文中缓解漏洞的一致规则变得困难。这种复杂性因执行上下文中每个子上下文（HTML、HTML 属性、URL 和 CSS）内编码值的不同含义和处理方式而加剧。

就本文而言，我们将 HTML、HTML 属性、URL 和 CSS 上下文称为子上下文，因为这些上下文中的每一个都可以在 JavaScript 执行上下文中被访问和设置。

在 JavaScript 代码中，主要上下文是 JavaScript，但通过适当的标签和上下文闭合字符，攻击者可以尝试使用等效的 JavaScript DOM 方法攻击其他 4 个解析上下文。  

以下是在 JavaScript 解析上下文和 HTML 解析上下文中发生的漏洞示例：  

```html
 <script>
 var x = '<%= taintedVar %>';
 var d = document.createElement('div');
 d.innerHTML = x;
 document.body.appendChild(d);
 </script>
```

接下来，我们将依次查看不同的解析上下文。

## 规则 \#1 - 在将不可信数据插入执行上下文中的 HTML 解析上下文之前进行 HTML 转义和 JavaScript 转义

有几种方法和属性可以直接在 JavaScript 中渲染 HTML 内容。这些方法构成了执行上下文中的 HTML 解析上下文。如果这些方法使用不可信的输入，则可能导致 XSS 漏洞。例如：

### 危险的 HTML 方法示例

#### 属性

```javascript
 element.innerHTML = "<HTML> 标签和标记";
 element.outerHTML = "<HTML> 标签和标记";
```

#### 方法

```javascript
 document.write("<HTML> 标签和标记");
 document.writeln("<HTML> 标签和标记");
```

### 指南

为了安全地动态更新 DOM 中的 HTML，我们建议：

 1. HTML 编码，然后
 2. JavaScript 编码所有不可信的输入，如下例所示：

```javascript
 var ESAPI = require('node-esapi');
 element.innerHTML = "<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>";
 element.outerHTML = "<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>";
```

```javascript
 var ESAPI = require('node-esapi');
 document.write("<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>");
 document.writeln("<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>");
```

## 规则 \#2 - 在将不可信数据插入执行上下文中的 HTML 属性解析上下文之前进行 JavaScript 转义

执行上下文中的 HTML 属性解析上下文与标准编码规则不同。这是因为在 HTML 属性渲染上下文中进行 HTML 属性编码是为了缓解试图退出 HTML 属性或添加可能导致 XSS 的额外属性的攻击。

在 DOM 执行上下文中，您只需要对不执行代码的 HTML 属性（事件处理程序、CSS 和 URL 属性除外）进行 JavaScript 编码。

例如，一般规则是对放置在 HTML 属性中的不可信数据（来自数据库、HTTP 请求、用户、后端系统等）进行 HTML 属性编码。这是在渲染上下文中输出数据时的适当步骤，但在执行上下文中使用 HTML 属性编码会破坏应用程序的数据显示。

## 规则 \#3 - 在执行上下文中将不可信数据插入事件处理程序和 JavaScript 代码解析上下文时要小心

在 JavaScript 代码中放置动态数据特别危险，因为与其他编码相比，JavaScript 编码对 JavaScript 编码数据有不同的语义。在许多情况下，JavaScript 编码无法阻止执行上下文中的攻击。例如，即使经过 JavaScript 编码，编码后的字符串仍然会执行。

因此，主要建议是**避免在此上下文中包含不可信数据**。如果必须使用，以下示例描述了一些可行和不可行的方法。

```javascript
var x = document.createElement("a");
x.href="#";
// 下面代码行中，右侧编码的数据（setAttribute 的第二个参数）
// 是一个经过正确 JavaScript 编码但仍然执行的不可信数据示例
x.setAttribute("onclick", "\u0061\u006c\u0065\u0072\u0074\u0028\u0032\u0032\u0029");
var y = document.createTextNode("点击测试");
x.appendChild(y);
document.body.appendChild(x);
```

`setAttribute(name_string,value_string)` 方法很危险，因为它隐式地将 *value_string* 强制转换为 *name_string* 的 DOM 属性数据类型。

在上面的情况中，属性名是一个 JavaScript 事件处理程序，所以属性值被隐式转换为 JavaScript 代码并执行。在这种情况下，JavaScript 编码无法缓解基于 DOM 的 XSS。

其他以字符串类型接受代码的 JavaScript 方法也会出现类似问题（`setTimeout`、`setInterval`、`new Function` 等）。这与 HTML 标签的事件处理程序属性中的 JavaScript 编码（HTML 解析器）形成鲜明对比，后者可以缓解 XSS。

```html
<!-- 不起作用 -->
<a id="bb" href="#" onclick="\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029"> 测试我</a>
```

使用 `Element.setAttribute(...)` 设置 DOM 属性的替代方法是直接设置属性。直接设置事件处理程序属性将允许 JavaScript 编码缓解基于 DOM 的 XSS。请注意，将不可信数据直接放入命令执行上下文始终是危险的设计。

``` html
<a id="bb" href="#"> 测试我</a>
```

``` javascript
// 以下不起作用，因为事件处理程序被设置为字符串。
// "alert(7)" 已进行 JavaScript 编码。
document.getElementById("bb").onclick = "\u0061\u006c\u0065\u0072\u0074\u0028\u0037\u0029";

// 以下不起作用，因为事件处理程序被设置为字符串。
document.getElementById("bb").onmouseover = "testIt";

// 以下不起作用，因为 "(" 和 ")" 已编码。
// "alert(77)" 已进行 JavaScript 编码。
document.getElementById("bb").onmouseover = \u0061\u006c\u0065\u0072\u0074\u0028\u0037\u0037\u0029;

// 以下不起作用，因为 ";" 已编码。
// "testIt;testIt" 已进行 JavaScript 编码。
document.getElementById("bb").onmouseover = \u0074\u0065\u0073\u0074\u0049\u0074\u003b\u0074\u0065\u0073
                                            \u0074\u0049\u0074;

// 以下起作用，因为编码值是有效的变量名或函数引用。
// "testIt" 已进行 JavaScript 编码
document.getElementById("bb").onmouseover = \u0074\u0065\u0073\u0074\u0049\u0074;

function testIt() {
   alert("我被调用了。");
}
```

JavaScript 中还有其他地方接受 JavaScript 编码为有效的可执行代码。

```javascript
 for(var \u0062=0; \u0062 < 10; \u0062++){
     \u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074
     .\u0077\u0072\u0069\u0074\u0065\u006c\u006e
     ("\u0048\u0065\u006c\u006c\u006f\u0020\u0057\u006f\u0072\u006c\u0064");
 }
 \u0077\u0069\u006e\u0064\u006f\u0077
 .\u0065\u0076\u0061\u006c
 \u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074
 .\u0077\u0072\u0069\u0074\u0065(111111111);
```

或者

```javascript
 var s = "\u0065\u0076\u0061\u006c";
 var t = "\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0031\u0029";
 window[s](t);
```

因为 JavaScript 基于国际标准（ECMAScript），JavaScript 编码支持编程构造和变量中的国际字符，以及替代的字符串表示（字符串转义）。

然而，HTML 编码则相反。HTML 标签元素是明确定义的，不支持同一标签的替代表示。因此，HTML 编码不能让开发者拥有 `<a>` 标签的替代表示。

## HTML 编码的中和性质

通常，HTML 编码用于中和放置在 HTML 和 HTML 属性上下文中的 HTML 标签。工作示例（无 HTML 编码）：

```html
<a href="..." >
```

通常编码的示例（不起作用 - DNW）：

```html
&#x3c;a href=... &#x3e;
```

HTML 编码示例，突出显示与 JavaScript 编码值的根本区别（DNW）：

```html
<&#x61; href=...>
```

如果 HTML 编码遵循与 JavaScript 编码相同的语义，上面的行可能可以渲染链接。这种差异使得 JavaScript 编码在对抗 XSS 的斗争中不太可靠。

## 规则 \#4 - 在将不可信数据插入执行上下文中的 CSS 属性解析上下文之前进行 JavaScript 转义

通常，从 CSS 上下文执行 JavaScript 需要将 `javascript:attackCode()` 传递给 CSS `url()` 方法，或调用 CSS `expression()` 方法传递要直接执行的 JavaScript 代码。

根据我的经验，从执行上下文（JavaScript）调用 `expression()` 函数已被禁用。为了缓解 CSS `url()` 方法，请确保对传递给 CSS `url()` 方法的数据进行 URL 编码。

```javascript
var ESAPI = require('node-esapi');
document.body.style.backgroundImage = "url(<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForURL(companyName))%>)";
```

## 规则 \#5 - URL 转义后再 JavaScript 转义，在将不可信数据插入执行上下文中的 URL 属性解析上下文之前

解析执行和渲染上下文中的 URL 的逻辑看起来是相同的。因此，执行（DOM）上下文中 URL 属性的编码规则变化不大。

```javascript
var ESAPI = require('node-esapi');
var x = document.createElement("a");
x.setAttribute("href", '<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForURL(userRelativePath))%>');
var y = document.createTextElement("点击测试");
x.appendChild(y);
document.body.appendChild(x);
```

如果使用完全限定的 URL，这将破坏链接，因为协议标识符中的冒号（`http:` 或 `javascript:`）将被 URL 编码，阻止调用 `http` 和 `javascript` 协议。

## 规则 \#6 - 使用安全的 JavaScript 函数或属性填充 DOM

使用不可信数据填充 DOM 最基本的安全方法是使用安全的赋值属性 `textContent`。

以下是安全使用的示例：

```html
<script>
element.textContent = untrustedData;  // 不执行代码
</script>
```

## 规则 \#7 - 修复 DOM 跨站脚本漏洞

修复基于 DOM 的跨站脚本的最佳方法是使用正确的输出方法（接收器）。例如，如果要使用用户输入写入 `div` 标签元素，不要使用 `innerHtml`，而是使用 `innerText` 或 `textContent`。这将解决问题，并且是修复基于 DOM 的 XSS 漏洞的正确方法。

**在诸如 eval 之类的危险来源中使用用户控制的输入始终是一个坏主意。99% 的情况下，这表明编程实践糟糕或懒惰，所以根本不要这样做，而不是尝试净化输入。**

最后，要修复我们最初代码中的问题，与其尝试正确编码输出（这很麻烦且容易出错），不如简单地使用 `element.textContent` 像这样写入内容：

```html
<b>当前 URL：</b> <span id="contentholder"></span>
...
<script>
document.getElementById("contentholder").textContent = document.baseURI;
</script>
```

它做了相同的事情，但这次不会受到基于 DOM 的跨站脚本漏洞的影响。

## 开发安全 JavaScript 应用程序的指南

基于 DOM 的 XSS 极难缓解，因为其攻击面广泛，且浏览器间缺乏标准化。

以下指南旨在为开发基于 Web 的 JavaScript 应用程序（Web 2.0）的开发者提供指导，以避免 XSS。

### 指南 \#1 - 不可信数据应仅被视为可显示文本

避免在 JavaScript 代码中将不可信数据视为代码或标记。

### 指南 \#2 - 在构建模板化 JavaScript 时，始终对不可信数据进行 JavaScript 编码并用引号分隔

始终对不可信数据进行 JavaScript 编码并用引号分隔，如下例所示：

```javascript
var x = "<%= Encode.forJavaScript(untrustedData) %>";
```

### 指南 \#3 - 使用 `document.createElement("...")`, `element.setAttribute("...","value")`, `element.appendChild(...)` 等构建动态接口

`document.createElement("...")`, `element.setAttribute("...","value")`, `element.appendChild(...)` 等是构建动态接口的安全方法。

请注意，`element.setAttribute` 仅对有限数量的属性是安全的。

危险属性包括任何命令执行上下文的属性，如 `onclick` 或 `onblur`。

安全属性的示例包括：`align`, `alink`, `alt`, `bgcolor`, `border`, `cellpadding`, `cellspacing`, `class`, `color`, `cols`, `colspan`, `coords`, `dir`, `face`, `height`, `hspace`, `ismap`, `lang`, `marginheight`, `marginwidth`, `multiple`, `nohref`, `noresize`, `noshade`, `nowrap`, `ref`, `rel`, `rev`, `rows`, `rowspan`, `scrolling`, `shape`, `span`, `summary`, `tabindex`, `title`, `usemap`, `valign`, `value`, `vlink`, `vspace`, `width`。

### 指南 \#4 - 避免将不可信数据发送到 HTML 渲染方法

避免使用不可信数据填充以下方法：

1. `element.innerHTML = "...";`
2. `element.outerHTML = "...";`
3. `document.write(...);`
4. `document.writeln(...);`

### 指南 \#5 - 避免隐式 `eval()` 传递给它的数据的众多方法

必须避免众多隐式 `eval()` 传递给它的数据的方法。

确保传递给这些方法的任何不可信数据：

1. 用字符串分隔符分隔
2. 封装在闭包中或根据使用情况进行 N 级 JavaScript 编码
3. 包装在自定义函数中

确保遵循上述第 3 步，以确保不可信数据不会在自定义函数中发送到危险方法，或通过添加额外的编码层来处理。

## DOM 基于 XSS 的常见问题

### 复杂的上下文

在许多情况下，上下文并不总是直接明了。

```html
<a href="javascript:myFunction('<%=untrustedData%>', 'test');">点击我</a>
 ...
<script>
Function myFunction (url,name) {
    window.location = url;
}
</script>
```

在上面的示例中，不可信数据从渲染 URL 上下文（`a` 标签的 `href` 属性）开始，然后变为 JavaScript 执行上下文（`javascript:` 协议处理程序），并将不可信数据传递给执行 URL 子上下文（`myFunction` 的 `window.location`）。

因为数据是在 JavaScript 代码中引入并传递到 URL 子上下文，所以适当的服务器端编码应该是以下形式：

```html
<a href="javascript:myFunction('<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForURL(untrustedData)) %>', 'test');">
点击我</a>
 ...
```

或者，如果您使用带有不可变 JavaScript 客户端编码库的 ECMAScript 5，则可以执行以下操作：

```html
<!-- 服务器端 URL 编码已删除。现在仅在服务器端进行 JavaScript 编码。 -->
<a href="javascript:myFunction('<%=ESAPI.encoder().encodeForJavascript(untrustedData)%>', 'test');">点击我</a>
 ...
<script>
Function myFunction (url,name) {
    var encodedURL = ESAPI.encoder().encodeForURL(url);  // 使用客户端脚本进行 URL 编码
    window.location = encodedURL;
}
</script>
```

### 编码库的不一致性

市面上有许多开源编码库：

1. OWASP [ESAPI](https://owasp.org/www-project-enterprise-security-api/)
2. OWASP [Java Encoder](https://owasp.org/www-project-java-encoder/)
3. Apache Commons Text [StringEscapeUtils](https://commons.apache.org/proper/commons-text/javadocs/api-release/org/apache/commons/text/StringEscapeUtils.html)，替换 [Apache Commons Lang3](https://commons.apache.org/proper/commons-lang/apidocs/org/apache/commons/lang3/StringEscapeUtils.html) 中的
4. [Jtidy](http://jtidy.sourceforge.net/)
5. 公司的自定义实现。

有些基于拒绝列表工作，而其他一些则忽略重要字符如 "&lt;" 和 "&gt;"。

Java Encoder 是一个活跃的项目，提供 HTML、CSS 和 JavaScript 编码支持。

ESAPI 是少数几个基于允许列表并对所有非字母数字字符进行编码的库之一。使用一个能理解在各自上下文中可用于利用漏洞的字符的编码库非常重要。关于所需的正确编码存在许多误解。

### 编码误解

许多安全培训课程和论文提倡盲目使用 HTML 编码来解决 XSS。

从逻辑上看，这似乎是明智的建议，因为 JavaScript 解析器不理解 HTML 编码。

然而，如果从 Web 应用程序返回的页面使用 `text/xhtml` 内容类型或 `*.xhtml` 文件类型扩展名，则 HTML 编码可能无法缓解 XSS。

例如：

```html
<script>
&#x61;lert(1);
</script>
```

上面的 HTML 编码值仍然是可执行的。如果这还不够让人记住，您还必须记住，当使用 DOM 元素的 value 属性检索编码时，编码会丢失。

让我们看看示例页面和脚本：

```html
<form name="myForm" ...>
  <input type="text" name="lName" value="<%=ESAPI.encoder().encodeForHTML(last_name)%>">
 ...
</form>
<script>
  var x = document.myForm.lName.value;  // 检索值时编码被还原
  document.writeln(x);  // 现在可以执行传入 lName 的任何代码。
</script>
```

最后，还有一个问题是 JavaScript 中通常安全的某些方法在某些上下文中可能不安全。

### 通常被认为安全的方法

一个被认为安全的属性示例是 `innerText`。

一些论文或指南建议使用它作为缓解 `innerHTML` 中 XSS 的替代方案。然而，根据应用 `innerText` 的标签，代码仍可能被执行。

```html
<script>
 var tag = document.createElement("script");
 tag.innerText = "<%=untrustedData%>";  // 执行代码
</script>
```

`innerText` 功能最初由 Internet Explorer 引入，并在 2016 年在所有主要浏览器供应商采用后正式纳入 HTML 标准。

### 使用变体分析检测 DOM XSS

**易受攻击的代码：**

```javascript
<script>
var x = location.hash.split("#")[1];
document.write(x);
</script>
```

用于识别上述 DOM XSS 的 Semgrep 规则 [链接](https://semgrep.dev/s/we30)。
