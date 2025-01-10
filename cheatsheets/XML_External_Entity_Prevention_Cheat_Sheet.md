# XML 外部实体防护备忘录

## 引言

*XML 外部实体注入*（XXE）现已成为 [OWASP Top 10](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_%28XXE%29) 中的 **A4** 点，是针对解析 XML 输入的应用程序的攻击。这个问题在 [通用弱点枚举](https://cwe.mitre.org/index.html) 参考中以 ID [611](https://cwe.mitre.org/data/definitions/611.html) 被引用。当**未经信任的 XML 输入中包含对外部实体的引用，并被配置不当的 XML 解析器处理时**，就会发生 XXE 攻击，这种攻击可用于发起多种事件，包括：

- 对系统的拒绝服务攻击
- [服务器端请求伪造](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)（SSRF）攻击
- 扫描解析器所在机器的端口的能力
- 其他系统影响。

本备忘录将帮助您防止这种漏洞。

有关 XXE 的更多信息，请访问 [XML 外部实体（XXE）攻击](https://en.wikipedia.org/wiki/XML_external_entity_attack)。

## 总体指导

**预防 XXE 最安全的方法是完全禁用 DTD（外部实体）。** 根据解析器的不同，方法应类似于以下：

``` java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

禁用 [DTD](https://www.w3schools.com/xml/xml_dtd.asp) 还可以防止解析器遭受拒绝服务（DOS）攻击，如[十亿笑声攻击](https://en.wikipedia.org/wiki/Billion_laughs_attack)。**如果无法完全禁用 DTD，则必须按照每个解析器特定的方式禁用外部实体和外部文档类型声明。**

**下面为多种语言（C++、Cold Fusion、Java、.NET、iOS、PHP、Python、Semgrep 规则）及其常用 XML 解析器提供详细的 XXE 预防指导。**

## C/C++

### libxml2

[xmlParserOption](http://xmlsoft.org/html/libxml-parser.html#xmlParserOption) 枚举不应定义以下选项：

- `XML_PARSE_NOENT`：展开实体并用替换文本替换
- `XML_PARSE_DTDLOAD`：加载外部 DTD

注意：

根据[这篇文章](https://mail.gnome.org/archives/xml/2012-October/msg00045.html)，从 libxml2 2.9 版本开始，XXE 已默认禁用，通过以下[补丁](https://gitlab.gnome.org/GNOME/libxml2/commit/4629ee02ac649c27f9c0cf98ba017c6b5526070f)提交。

搜索是否使用了以下 API，并确保参数中未定义 `XML_PARSE_NOENT` 和 `XML_PARSE_DTDLOAD`：

- `xmlCtxtReadDoc`
- `xmlCtxtReadFd`
- `xmlCtxtReadFile`
- `xmlCtxtReadIO`
- `xmlCtxtReadMemory`
- `xmlCtxtUseOptions`
- `xmlParseInNodeContext`
- `xmlReadDoc`
- `xmlReadFd`
- `xmlReadFile`
- `xmlReadIO`
- `xmlReadMemory`

### libxerces-c

使用 `XercesDOMParser` 防止 XXE：

``` cpp
XercesDOMParser *parser = new XercesDOMParser;
parser->setCreateEntityReferenceNodes(true);
parser->setDisableDefaultEntityResolution(true);
```

使用 SAXParser 防止 XXE：

``` cpp
SAXParser* parser = new SAXParser;
parser->setDisableDefaultEntityResolution(true);
```

使用 SAX2XMLReader 防止 XXE：

``` cpp
SAX2XMLReader* reader = XMLReaderFactory::createXMLReader();
parser->setFeature(XMLUni::fgXercesDisableDefaultEntityResolution, true);
```

## ColdFusion

根据[这篇博客文章](https://hoyahaxa.blogspot.com/2022/11/on-coldfusion-xxe-and-other-xml-attacks.html)，Adobe ColdFusion 和 Lucee 都有内置机制来禁用外部 XML 实体支持。

### Adobe ColdFusion

从 ColdFusion 2018 Update 14 和 ColdFusion 2021 Update 4 开始，所有处理 XML 的原生 ColdFusion 函数都有一个 XML 解析器参数，可以禁用外部 XML 实体支持。由于没有全局设置可以禁用外部实体，开发人员必须确保每个 XML 函数调用都使用正确的安全选项。

从 [XmlParse() 函数文档](https://helpx.adobe.com/coldfusion/cfml-reference/coldfusion-functions/functions-t-z/xmlparse.html)，您可以使用以下代码禁用 XXE：

```
<cfset parseroptions = structnew()>
<cfset parseroptions.ALLOWEXTERNALENTITIES = false>
<cfscript>
a = XmlParse("xml.xml", false, parseroptions);
writeDump(a);
</cfscript>
```

您可以使用上面显示的 "parseroptions" 结构作为参数来保护其他处理 XML 的函数，例如：

```
XxmlSearch(xmldoc, xpath,parseroptions);

XmlTransform(xmldoc,xslt,parseroptions);

isXML(xmldoc,parseroptions);
```

### Lucee

从 Lucee 5.3.4.51 及更高版本，您可以通过在 Application.cfc 中添加以下内容来禁用 XML 外部实体支持：

```
this.xmlFeatures = {
     externalGeneralEntities: false,
     secure: true,
     disallowDoctypeDecl: true
};
```

从 Lucee 5.4.2.10 和 Lucee 6.0.0.514 开始，默认禁用外部 XML 实体支持。

## Java

**由于大多数 Java XML 解析器默认启用 XXE，因此这种语言特别容易遭受 XXE 攻击，所以必须显式禁用 XXE 才能安全使用这些解析器。** 本节描述如何在最常用的 Java XML 解析器中禁用 XXE。

### JAXP DocumentBuilderFactory、SAXParserFactory 和 DOM4J

`DocumentBuilderFactory`、`SAXParserFactory` 和 `DOM4J` `XML` 解析器可以使用相同的技术防止 XXE 攻击。

**为简洁起见，我们仅展示如何保护 `DocumentBuilderFactory` 解析器。保护此解析器的其他说明已嵌入示例代码中**

JAXP `DocumentBuilderFactory` [setFeature](https://docs.oracle.com/javase/7/docs/api/javax/xml/parsers/DocumentBuilderFactory.html#setFeature(java.lang.String,%20boolean)) 方法允许开发者控制启用或禁用哪些特定于实现的 XML 处理器功能。

这些功能可以在工厂上设置，也可以在底层 `XMLReader` [setFeature](https://docs.oracle.com/javase/7/docs/api/org/xml/sax/XMLReader.html#setFeature%28java.lang.String,%20boolean%29) 方法上设置。

**每个 XML 处理器实现都有自己的功能，用于管理 DTD 和外部实体的处理。通过完全禁用 DTD 处理，可以避免大多数 XXE 攻击，尽管还需要禁用或验证 XInclude 未启用。**

**自 JDK 6 以来，可以使用 [FEATURE_SECURE_PROCESSING](https://docs.oracle.com/javase/6/docs/api/javax/xml/XMLConstants.html#FEATURE_SECURE_PROCESSING) 标志指示解析器安全处理 XML**。其行为取决于具体实现。它可能有助于防止资源耗尽，但可能无法始终缓解实体扩展。关于此标志的更多详细信息可以在[此处](https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-88B04BE2-35EF-4F61-B4FA-57A0E9102342)找到。

使用 `SAXParserFactory` 的语法高亮代码片段可以在[此处](https://gist.github.com/asudhakar02/45e2e6fd8bcdfb4bc3b2)查看。

完全禁用 DTD（文档类型）的示例代码：

``` java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException; // catching unsupported features
import javax.xml.XMLConstants;

...

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
String FEATURE = null;
try {
    // 这是主要防御。如果禁止 DTD（文档类型），几乎所有 XML 实体攻击都可以防止
    // 仅限 Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
    FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
    dbf.setFeature(FEATURE, true);

    // 根据 Timothy Morgan 2014 年的论文："XML 架构、DTD 和实体攻击"
    dbf.setXIncludeAware(false);

    // 剩余的解析器逻辑
    ...
} catch (ParserConfigurationException e) {
    // 这应该捕获失败的 setFeature 功能
    // 注意：每次调用 setFeature() 都应该在其自己的 try/catch 中，否则后续调用将被跳过。
    // 这仅在为多提供者支持忽略错误时很重要。
    logger.info("ParserConfigurationException 被抛出。您的 XML 处理器不支持功能 '" + FEATURE + "'。");
    ...
} catch (SAXException e) {
    // 在 Apache 上，当禁止 DOCTYPE 时应抛出此异常
    logger.warning("XML 文档中传入了 DOCTYPE");
    ...
} catch (IOException e) {
    // 指向不存在文件的 XXE
    logger.error("发生 IOException，XXE 仍可能存在：" + e.getMessage());
    ...
}

// 使用防 XXE 配置的解析器加载 XML 文件或流...
DocumentBuilder safebuilder = dbf.newDocumentBuilder();
```

如果无法完全禁用 DTD：

``` java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException; // catching unsupported features
import javax.xml.XMLConstants;

...

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

String[] featuresToDisable = {
    // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
    // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
    // JDK7+ - http://xml.org/sax/features/external-general-entities
    // 必须与下面的功能一起使用，否则无法确保防止 XXE
    "http://xml.org/sax/features/external-general-entities",

    // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
    // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
    // JDK7+ - http://xml.org/sax/features/external-parameter-entities
    // 必须与前面的功能一起使用，否则无法确保防止 XXE
    "http://xml.org/sax/features/external-parameter-entities",

    // 同时禁用外部 DTD
    "http://apache.org/xml/features/nonvalidating/load-external-dtd"
}

for (String feature : featuresToDisable) {
    try {    
        dbf.setFeature(FEATURE, false); 
    } catch (ParserConfigurationException e) {
        // 这应该捕获失败的 setFeature 功能
        logger.info("ParserConfigurationException 被抛出。您的 XML 处理器可能不支持功能 '" + feature + "'。");
        ...
    }
}

try {
    // 根据 Timothy Morgan 2014 年的论文："XML 架构、DTD 和实体攻击"
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
        
    // 如文档所述，"安全处理功能（FSP）"是帮助您保护 XML 处理的中心机制。
    // 它指示 XML 处理器（如解析器、验证器和转换器）尝试安全处理 XML，
    // 并且 FSP 可以用作 dbf.setExpandEntityReferences(false) 的替代方案，
    // 以允许某些安全级别的实体扩展
    // 从 JDK6 开始存在。
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

    // 根据 Timothy Morgan："如果出于某些原因需要支持内联 DOCTYPE，
    // 则确保禁用实体设置（如上所示），并注意 SSRF 攻击
    // (http://cwe.mitre.org/data/definitions/918.html) 和拒绝服务攻击
    // （如十亿笑声或通过"jar:"进行的解压缩炸弹）是一种风险。"

    // 剩余的解析器逻辑
    ...
} catch (ParserConfigurationException e) {
    // 这应该捕获失败的 setFeature 功能
    logger.info("ParserConfigurationException 被抛出。您的 XML 处理器可能不支持功能 'XMLConstants.FEATURE_SECURE_PROCESSING'。");
    ...
} catch (SAXException e) {
    // 在 Apache 上，当禁止 DOCTYPE 时应抛出此异常
    logger.warning("XML 文档中传入了 DOCTYPE");
    ...
} catch (IOException e) {
    // 指向不存在文件的 XXE
    logger.error("发生 IOException，XXE 仍可能存在：" + e.getMessage());
    ...
}

// 使用防 XXE 配置的解析器加载 XML 文件或流...
DocumentBuilder safebuilder = dbf.newDocumentBuilder();
```

### Xerces 1 功能

- 通过将[此功能](https://xerces.apache.org/xerces-j/features.html#external-general-entities)设置为 `false` 来不包含外部实体。
- 通过将[此功能](https://xerces.apache.org/xerces-j/features.html#external-parameter-entities)设置为 `false` 来不包含参数实体。
- 通过将[此功能](https://xerces.apache.org/xerces-j/features.html#load-external-dtd)设置为 `false` 来不包含外部 DTD。

### Xerces 2 功能

- 通过将[此功能](https://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl)设置为 `true` 来禁止内联 DTD。
- 通过将[此功能](https://xerces.apache.org/xerces2-j/features.html#external-general-entities)设置为 `false` 来不包含外部实体。
- 通过将[此功能](https://xerces.apache.org/xerces2-j/features.html#external-parameter-entities)设置为 `false` 来不包含参数实体。
- 通过将[此功能](https://xerces.apache.org/xerces-j/features.html#load-external-dtd)设置为 `false` 来不包含外部 DTD。

**注意：** 上述防御措施需要 Java 7 更新 67、Java 8 更新 20 或更高版本，因为在早期 Java 版本中，`DocumentBuilderFactory` 和 SAXParserFactory 的对策是损坏的，参见：[CVE-2014-6517](http://www.cvedetails.com/cve/CVE-2014-6517/)。

### XMLInputFactory（StAX 解析器）

[StAX](http://en.wikipedia.org/wiki/StAX) 解析器（如 [`XMLInputFactory`](http://docs.oracle.com/javase/7/docs/api/javax/xml/stream/XMLInputFactory.html)）允许设置各种属性和功能。

要保护 Java `XMLInputFactory` 免受 XXE 攻击，请完全禁用 DTD（文档类型）：

``` java
// 这将完全禁用该工厂的 DTD
xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

或者如果无法完全禁用 DTD：

``` java
// 如果访问外部 DTD，这将导致抛出 XMLStreamException。
xmlInputFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
// 禁用外部实体
xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
```

设置 `xmlInputFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");` 不是必需的，因为 XMLInputFactory 依赖于 Validator 对照架构执行 XML 验证。请查看 [Validator](#Validator) 部分以获取具体配置。

### Oracle DOM 解析器

遵循 [Oracle 建议](https://docs.oracle.com/en/database/oracle/oracle-database/18/adxdk/security-considerations-oracle-xml-developers-kit.html#GUID-45303542-41DE-4455-93B3-854A826EF8BB)，例如：

``` java
    // 扩展 oracle.xml.parser.v2.XMLParser
    DOMParser domParser = new DOMParser();

    // 不展开实体引用
    domParser.setAttribute(DOMParser.EXPAND_ENTITYREF, false);

    // dtdObj 是 oracle.xml.parser.v2.DTD 的一个实例
    domParser.setAttribute(DOMParser.DTD_OBJECT, dtdObj);

    // 不允许超过 11 级的实体扩展
    domParser.setAttribute(DOMParser.ENTITY_EXPANSION_DEPTH, 12);
```

### TransformerFactory

要保护 `javax.xml.transform.TransformerFactory` 免受 XXE 攻击，请执行以下操作：

``` java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

### Validator

要保护 `javax.xml.validation.Validator` 免受 XXE 攻击，请执行以下操作：

``` java
SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
Schema schema = factory.newSchema();
Validator validator = schema.newValidator();
validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

### SchemaFactory

要保护 `javax.xml.validation.SchemaFactory` 免受 XXE 攻击，请执行以下操作：

``` java
SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
Schema schema = factory.newSchema(Source);
```

### SAXTransformerFactory

要保护 `javax.xml.transform.sax.SAXTransformerFactory` 免受 XXE 攻击，请执行以下操作：

``` java
SAXTransformerFactory sf = SAXTransformerFactory.newInstance();
sf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
sf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
sf.newXMLFilter(Source);
```

**注意：使用以下 `XMLConstants` 需要 JAXP 1.5，该版本已添加到 Java 7u40 和 Java 8 中：**

- `javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD`
- `javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA`
- `javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET`

### XMLReader

要保护 Java `org.xml.sax.XMLReader` 免受 XXE 攻击，请执行以下操作：

``` java
XMLReader reader = XMLReaderFactory.createXMLReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 根据前一行，这可能不是严格必需的，因为已经完全不允许 DTD。
reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### SAXReader

要保护 Java `org.dom4j.io.SAXReader` 免受 XXE 攻击，请执行以下操作：

``` java
saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
saxReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
saxReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

如果您的代码中没有所有这些行，则可能容易遭受 XXE 攻击。

### SAXBuilder

要保护 Java `org.jdom2.input.SAXBuilder` 免受 XXE 攻击，请完全禁止 DTD（文档类型）：

``` java
SAXBuilder builder = new SAXBuilder();
builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
Document doc = builder.build(new File(fileName));
```

或者，如果无法完全禁用 DTD，请禁用外部实体和实体扩展：

``` java
SAXBuilder builder = new SAXBuilder();
builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
builder.setExpandEntities(false);
Document doc = builder.build(new File(fileName));
```

### 无操作 EntityResolver

对于接受 `EntityResolver` 的 API，您可以通过[提供无操作实现](https://wiki.sei.cmu.edu/confluence/display/java/IDS17-J.+Prevent+XML+External+Entity+Attacks)来中和 XML 解析器解析实体的能力：

```java
public final class NoOpEntityResolver implements EntityResolver {
    public InputSource resolveEntity(String publicId, String systemId) {
        return new InputSource(new StringReader(""));
    }
}

// ...

xmlReader.setEntityResolver(new NoOpEntityResolver());
documentBuilder.setEntityResolver(new NoOpEntityResolver());
```

或更简单地：

```java
EntityResolver noop = (publicId, systemId) -> new InputSource(new StringReader(""));
xmlReader.setEntityResolver(noop);
documentBuilder.setEntityResolver(noop);
```

### JAXB Unmarshaller

**由于 `javax.xml.bind.Unmarshaller` 解析 XML 但不支持任何禁用 XXE 的标志，必须先通过可配置的安全解析器解析不可信的 XML，生成源对象，然后将源对象传递给 Unmarshaller。** 例如：

``` java
SAXParserFactory spf = SAXParserFactory.newInstance();

//选项1：这是防止 XXE 的主要防御
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
spf.setXIncludeAware(false);

//选项2：如果无法禁用文档类型
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
spf.setXIncludeAware(false);

//执行反编组操作
Source xmlSource = new SAXSource(spf.newSAXParser().getXMLReader(),
                                new InputSource(new StringReader(xml)));
JAXBContext jc = JAXBContext.newInstance(Object.class);
Unmarshaller um = jc.createUnmarshaller();
um.unmarshal(xmlSource);
```

### XPathExpression

**由于 `javax.xml.xpath.XPathExpression` 本身无法安全配置，必须先通过另一个可安全配置的 XML 解析器解析不可信数据。**

例如：

``` java
DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
df.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
df.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
DocumentBuilder builder = df.newDocumentBuilder();
String result = new XPathExpression().evaluate( builder.parse(
                            new ByteArrayInputStream(xml.getBytes())) );
```

### java.beans.XMLDecoder

**[readObject()](https://docs.oracle.com/javase/8/docs/api/java/beans/XMLDecoder.html#readObject--) 方法本质上是不安全的。**

**不仅它解析的 XML 容易受到 XXE 攻击，而且该方法可用于构造任何 Java 对象，并且[可以执行任意代码，如此处所述](http://stackoverflow.com/questions/14307442/is-it-safe-to-use-xmldecoder-to-read-document-files)。**

**除了信任或正确验证传入的输入外，没有办法使这个类变得安全。**

**因此，我们强烈建议完全避免使用此类，并将其替换为本备忘录中描述的安全或正确配置的 XML 解析器。**

### 其他 XML 解析器

**有许多第三方库直接或通过使用其他库来解析 XML。请测试并验证其 XML 解析器默认是否安全防止 XXE。** 如果解析器默认不安全，请寻找解析器支持的标志以禁用所有可能的外部资源包含，如上面给出的示例。如果没有暴露外部控制，请确保先通过安全解析器传递不可信内容，然后再传递给不安全的第三方解析器，类似于保护 Unmarshaller 的方式。

#### Spring Framework MVC/OXM XXE 漏洞

**在 [Spring OXM](https://pivotal.io/security/cve-2013-4152) 和 [Spring MVC](https://pivotal.io/security/cve-2013-7315) 中发现了一些 XXE 漏洞。以下版本的 Spring Framework 容易受到 XXE 攻击：**

- **3.0.0** 到 **3.2.3**（Spring OXM & Spring MVC）
- **4.0.0.M1**（Spring OXM）
- **4.0.0.M1-4.0.0.M2**（Spring MVC）

还有其他后来修复的问题，因此为了完全解决这些问题，Spring 建议您升级到 Spring Framework 3.2.8+ 或 4.0.2+。

对于 Spring OXM，这是指使用 org.springframework.oxm.jaxb.Jaxb2Marshaller。**请注意，Spring OXM 的 CVE 特别指出，两种 XML 解析情况需要开发者正确处理，而另外两种是 Spring 的责任，并已修复以解决此 CVE。**

他们是这样说的：

开发者必须处理的两种情况：

- 对于 `DOMSource`，XML 已由用户代码解析，该代码负责防止 XXE。
- 对于 `StAXSource`，XMLStreamReader 已由用户代码创建，该代码负责防止 XXE。

Spring 修复的问题：

对于 SAXSource 和 StreamSource 实例，Spring 默认处理外部实体，从而创建了这个漏洞。

以下是使用曾经易受攻击但现在安全的 StreamSource 的示例，前提是使用修复版本的 Spring OXM 或 Spring MVC：

``` java
import org.springframework.oxm.Jaxb2Marshaller;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
// 必须将返回的 Object 强制转换为您正在反编组的类型
marshaller.unmarshal(new StreamSource(new StringReader(some_string_containing_XML));
```

因此，根据 [Spring OXM CVE 写作](https://pivotal.io/security/cve-2013-4152)，上述代码现在是安全的。但如果使用 DOMSource 或 StAXSource，则需要您自行配置这些源以防止 XXE。

#### Castor

**Castor 是一个 Java 数据绑定框架。它允许在 Java 对象、XML 和关系表之间进行转换。Castor 1.3.3 版本之前的 XML 功能容易受到 XXE 攻击，应升级到最新版本。** 欲了解更多信息，请查看官方 [XML 配置文件](https://castor-data-binding.github.io/castor/reference-guide/reference/xml/xml-properties.html)

## .NET

**关于 .NET 中的 XXE 注入的最新信息直接来自 Dean Fleming 的[单元测试 Web 应用程序](https://github.com/deanf1/dotnet-security-unit-tests)，该应用程序涵盖了所有当前支持的 .NET XML 解析器，并提供了测试用例，展示了它们何时免受 XXE 注入，何时不免受攻击，但这些测试仅针对文件注入，而非直接 DTD（用于 DoS 攻击）。**

对于使用直接 DTD 的 DoS 攻击（如[十亿笑攻击](https://en.wikipedia.org/wiki/Billion_laughs_attack)），Bounce Security 的 Josh Grossman 创建了[一个单独的测试应用程序](https://github.com/BounceSecurity/BillionLaughsTester)，以验证 .NET ≥4.5.2 对这些攻击是安全的。

以前，这些信息基于一些可能不完全准确的旧文章，包括：

- [James Jardine 关于 .NET XXE 的优秀文章](https://www.jardinesoftware.net/2016/05/26/xxe-and-net/)。
- [微软关于如何在 .NET 中防止 XXE 和 XML 拒绝服务的指导](http://msdn.microsoft.com/en-us/magazine/ee335713.aspx)。

### .NET 解析器安全级别概述

**下面是所有支持的 .NET XML 解析器及其默认安全级别的概述。此列表后面将包含每个解析器的更多详细信息。**

**XDocument（Linq to XML）**

在 .NET Framework 4.5.2 版本中，此解析器受外部实体保护，在 4.5.2 或更高版本中受十亿笑攻击保护，但在 4.5.2 版本之前是否受十亿笑攻击保护尚不确定。

#### XmlDocument、XmlTextReader、XPathNavigator 默认安全级别

这些解析器在 4.5.2 版本以下容易受到外部实体攻击和十亿笑攻击，但在 4.5.2 或更高版本中受到保护。

#### XmlDictionaryReader、XmlNodeReader、XmlReader 默认安全级别

这些解析器在 4.5.2 版本之前和之后都不容易受到外部实体攻击或十亿笑攻击。而且在 4.5.2 或更高版本中，这些库默认甚至不会处理内联 DTD。即使您将默认设置更改为允许处理 DTD，如果执行 DoS 攻击，仍将抛出异常，如上文所述。

### ASP.NET

ASP.NET 应用程序 ≥ .NET 4.5.2 还必须确保在其 `Web.config` 中将 `<httpRuntime targetFramework="..." />` 设置为 ≥4.5.2，否则无论实际的 .NET 版本如何都可能容易受到攻击。省略此标记也将导致默认不安全的行为。

为了理解上表，ASP.NET 应用程序的 `.NET Framework 版本` 是应用程序构建时的 .NET 版本或 httpRuntime 的 `targetFramework`（Web.config），**以较低者为准**。

此配置标记不应与类似的配置标记混淆：`<compilation targetFramework="..." />` 或程序集/项目的 targetFramework，这些**不**足以实现上表中宣传的默认安全行为。

### LINQ to XML

**`System.Xml.Linq` 库中的 `XElement` 和 `XDocument` 对象默认情况下免受来自外部文件的 XXE 注入和 DoS 攻击。** `XElement` 仅解析 XML 文件中的元素，因此完全忽略 DTD。`XDocument` 默认[禁用了 XmlResolver](https://docs.microsoft.com/en-us/dotnet/standard/linq/linq-xml-security)，因此免受 SSRF。虽然 DTD 默认[已启用](https://referencesource.microsoft.com/#System.Xml.Linq/System/Xml/Linq/XLinq.cs,71f4626a3d6f9bad)，但从 Framework 版本 ≥4.5.2 开始，它**不**容易受到 DoS 攻击，但在早期 Framework 版本中可能容易受到攻击。更多信息请参见[微软关于如何在 .NET 中防止 XXE 和 XML 拒绝服务的指导](http://msdn.microsoft.com/en-us/magazine/ee335713.aspx)

### XmlDictionaryReader

**`System.Xml.XmlDictionaryReader` 默认是安全的，因为在尝试解析 DTD 时，编译器会抛出异常，提示"CData 元素在 XML 文档的顶层无效"。如果使用不同的不安全 XML 解析器构造，则会变得不安全。**

### XmlDocument

**在 .NET Framework 4.5.2 版本之前，`System.Xml.XmlDocument` 默认是不安全的。`XmlDocument` 对象内部有一个 `XmlResolver` 对象，在 4.5.2 版本之前需要将其设置为 null。在 4.5.2 及更高版本中，此 `XmlResolver` 默认设置为 null。**

下面的示例展示了如何使其安全：

``` csharp
 static void LoadXML()
 {
   string xxePayload = "<!DOCTYPE doc [<!ENTITY win SYSTEM 'file:///C:/Users/testdata2.txt'>]>"
                     + "<doc>&win;</doc>";
   string xml = "<?xml version='1.0' ?>" + xxePayload;

   XmlDocument xmlDoc = new XmlDocument();
   // 将此设置为 NULL 可禁用 DTD - 默认情况下不是 null
   xmlDoc.XmlResolver = null;
   xmlDoc.LoadXml(xml);
   Console.WriteLine(xmlDoc.InnerText);
   Console.ReadLine();
 }
```

**对于 .NET Framework 版本 ≥4.5.2，默认情况下是安全的**。

如果创建具有默认或不安全设置的非空 `XmlResolver`，`XmlDocument` 可能变得不安全。如果需要启用 DTD 处理，[引用的 MSDN 文章](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx)中详细描述了如何安全地执行此操作。

### XmlNodeReader

`System.Xml.XmlNodeReader` 对象默认是安全的，即使使用不安全的解析器构造或包装在另一个不安全的解析器中，也会忽略 DTD。

### XmlReader

`System.Xml.XmlReader` 对象默认是安全的。

在 .NET Framework 4.0 及更早版本中，默认将其 ProhibitDtd 属性设置为 false，或在 .NET 4.0 及更高版本中将 `DtdProcessing` 属性设置为 Prohibit。

此外，在 .NET 4.5.2 及更高版本中，属于 `XmlReader` 的 `XmlReaderSettings` 默认将其 `XmlResolver` 设置为 null，提供了额外的安全层。

因此，`XmlReader` 对象仅在 4.5.2 及更高版本中变得不安全，前提是 `DtdProcessing` 属性设置为 Parse，且 `XmlReaderSetting` 的 `XmlResolver` 设置为具有默认或不安全设置的非空 XmlResolver。如果需要启用 DTD 处理，[引用的 MSDN 文章](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx)中详细描述了如何安全地执行此操作。

### XmlTextReader

在 .NET Framework 4.5.2 之前的版本中，`System.Xml.XmlTextReader` **默认是不安全的**。以下是在各种 .NET 版本中使其安全的方法：

#### .NET 4.0 之前

在 .NET Framework 4.0 之前的版本中，`XmlTextReader` 等 `XmlReader` 对象的 DTD 解析行为由 `System.Xml.XmlReaderSettings` 和 `System.Xml.XmlTextReader` 类中的布尔 `ProhibitDtd` 属性控制。

将这些值设置为 true 可完全禁用内联 DTD。

``` csharp
XmlTextReader reader = new XmlTextReader(stream);
// 需要这样做，因为默认值是 FALSE!!
reader.ProhibitDtd = true;  
```

#### .NET 4.0 - .NET 4.5.2

**在 .NET Framework 4.0 版本中，DTD 解析行为已更改。`ProhibitDtd` 属性已被弃用，取而代之的是新的 `DtdProcessing` 属性。**

**然而，他们没有更改默认设置，因此 `XmlTextReader` 默认仍然容易受到 XXE 攻击。**

**将 `DtdProcessing` 设置为 `Prohibit` 会导致运行时在 XML 中存在 `<!DOCTYPE>` 元素时抛出异常。**

要自行设置此值，代码如下：

``` csharp
XmlTextReader reader = new XmlTextReader(stream);
// 需要这样做，因为默认值是 Parse!!
reader.DtdProcessing = DtdProcessing.Prohibit;  
```

或者，您可以将 `DtdProcessing` 属性设置为 `Ignore`，这将不会在遇到 `<!DOCTYPE>` 元素时抛出异常，而是简单地跳过它并不处理。最后，如果确实想允许和处理内联 DTD，可以将 `DtdProcessing` 设置为 `Parse`。

#### .NET 4.5.2 及更高版本

在 .NET Framework 4.5.2 及更高版本中，`XmlTextReader` 的内部 `XmlResolver` 默认设置为 null，使 `XmlTextReader` 默认忽略 DTD。如果创建具有默认或不安全设置的非空 `XmlResolver`，`XmlTextReader` 可能变得不安全。

### XPathNavigator

在 .NET Framework 4.5.2 之前的版本中，`System.Xml.XPath.XPathNavigator` **默认是不安全的**。

这是因为它实现了 `IXPathNavigable` 对象，如 `XmlDocument`，在 4.5.2 之前的版本中也默认不安全。

您可以通过在 `XPathDocument` 的构造函数中给它一个安全的解析器（如默认安全的 `XmlReader`）来使 `XPathNavigator` 安全。

以下是一个示例：

``` csharp
XmlReader reader = XmlReader.Create("example.xml");
XPathDocument doc = new XPathDocument(reader);
XPathNavigator nav = doc.CreateNavigator();
string xml = nav.InnerXml.ToString();
```

对于 .NET Framework 版本 ≥4.5.2，XPathNavigator **默认是安全的**。

### XslCompiledTransform

只要给定的解析器是安全的，`System.Xml.Xsl.XslCompiledTransform`（XML 转换器）默认是安全的。

它默认是安全的，因为 `Transform()` 方法的默认解析器是 `XmlReader`，默认情况下是安全的（如上所述）。

[此方法的源代码在此](http://www.dotnetframework.org/default.aspx/4@0/4@0/DEVDIV_TFS/Dev10/Releases/RTMRel/ndp/fx/src/Xml/System/Xml/Xslt/XslCompiledTransform@cs/1305376/XslCompiledTransform@cs)。

一些 `Transform()` 方法接受 `XmlReader` 或 `IXPathNavigable`（例如 `XmlDocument`）作为输入，如果传入不安全的 XML 解析器，则 `Transform` 也将不安全。

## iOS

### libxml2

**iOS 包含上述描述的 C/C++ libxml2 库，因此如果直接使用 libxml2，则适用上述指导。**

**但是，直到 iOS6 的 libxml2 版本早于 libxml2 2.9 版本（默认情况下可防止 XXE）。**

### NSXMLDocument

**iOS 还提供了 `NSXMLDocument` 类型，它建立在 libxml2 之上。**

**然而，`NSXMLDocument` 提供了一些 libxml2 直接不可用的额外 XXE 保护。**

根据此[页面](https://developer.apple.com/library/archive/releasenotes/Foundation/RN-Foundation-iOS/Foundation_iOS5.html)的"NSXMLDocument 外部实体限制 API"部分：

- iOS4 及更早版本：默认加载所有外部实体。
- iOS5 及更高版本：仅加载不需要网络访问的实体。（更安全）

**但是，要在任何版本的 iOS 中完全禁用 `NSXMLDocument` 中的 XXE，只需在创建 `NSXMLDocument` 时指定 `NSXMLNodeLoadExternalEntitiesNever`。**

## PHP

**使用默认 XML 解析器（基于 libxml2）时，PHP 8.0 及更新版本[默认防止 XXE](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php)。**

**对于 8.0 之前的 PHP 版本，根据 [PHP 文档](https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php)，使用默认 PHP XML 解析器时应设置以下内容以防止 XXE：**

``` php
libxml_set_external_entity_loader(null);
```

关于如何在 PHP 中滥用这一点的描述，可参见 SensePost 的一篇[文章](https://www.sensepost.com/blog/2014/revisting-xxe-and-abusing-protocols/)，该文描述了一个在 Facebook 中修复的有趣的 PHP XXE 漏洞。

## Python

Python 3 官方文档包含关于 [XML 漏洞](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)的部分。截至 2020 年 1 月 1 日，Python 2 不再受支持，但 Python 网站仍然包含[一些遗留文档](https://docs.Python.org/2/library/xml.html#xml-vulnerabilities)。

下表显示了 Python 3 中各种 XML 解析模块对某些 XXE 攻击的脆弱性。

| 攻击类型               | sax        | etree      | minidom    | pulldom    | xmlrpc     |
|------------------------|------------|------------|------------|------------|------------|
| 十亿笑攻击            | 易受攻击   | 易受攻击   | 易受攻击   | 易受攻击   | 易受攻击   |
| 二次爆炸              | 易受攻击   | 易受攻击   | 易受攻击   | 易受攻击   | 易受攻击   |
| 外部实体扩展          | 安全       | 安全       | 安全       | 安全       | 安全       |
| DTD 检索               | 安全       | 安全       | 安全       | 安全       | 安全       |
| 解压炸弹              | 安全       | 安全       | 安全       | 安全       | 易受攻击   |

为了保护您的应用程序免受适用的攻击，存在[两个包](https://docs.python.org/3/library/xml.html#the-defusedxml-and-defusedexpat-packages)来帮助您净化输入并保护应用程序免受 DDoS 和远程攻击。

## Semgrep 规则

[Semgrep](https://semgrep.dev/) 是一个用于离线静态分析的命令行工具。使用预建或自定义规则来强制执行代码和安全标准。

### Java

以下是 Java 中不同 XML 解析器的规则

#### Digester

识别 `org.apache.commons.digester3.Digester` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-Digester](https://semgrep.dev/s/salecharohit:xxe-Digester)

#### DocumentBuilderFactory

识别 `javax.xml.parsers.DocumentBuilderFactory` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-dbf](https://semgrep.dev/s/salecharohit:xxe-dbf)

#### SAXBuilder

识别 `org.jdom2.input.SAXBuilder` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-saxbuilder](https://semgrep.dev/s/salecharohit:xxe-saxbuilder)

#### SAXParserFactory

识别 `javax.xml.parsers.SAXParserFactory` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-SAXParserFactory](https://semgrep.dev/s/salecharohit:xxe-SAXParserFactory)

#### SAXReader

识别 `org.dom4j.io.SAXReader` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-SAXReader](https://semgrep.dev/s/salecharohit:xxe-SAXReader)

#### XMLInputFactory

识别 `javax.xml.stream.XMLInputFactory` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-XMLInputFactory](https://semgrep.dev/s/salecharohit:xxe-XMLInputFactory)

#### XMLReader

识别 `org.xml.sax.XMLReader` 库中的 XXE 漏洞
规则可在此处测试 [https://semgrep.dev/s/salecharohit:xxe-XMLReader](https://semgrep.dev/s/salecharohit:xxe-XMLReader)

## 参考文献

- [InfoSecInstitute 的 XXE](https://resources.infosecinstitute.com/identify-mitigate-xxe-vulnerabilities/)
- [OWASP Top 10-2017 A4: XML 外部实体（XXE）](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_%28XXE%29)
- [Timothy Morgan 2014 年论文："XML Schema、DTD 和实体攻击"](https://vsecurity.com//download/papers/XMLDTDEntityAttacks.pdf)
- [FindSecBugs XXE 检测](https://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER)
- [XXEbugFind 工具](https://github.com/ssexxe/XXEBugFind)
- [测试 XML 注入](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection.html)
