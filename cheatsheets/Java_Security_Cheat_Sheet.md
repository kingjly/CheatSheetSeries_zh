# Java 安全备忘录

## Java 中的注入防护

本节旨在提供处理 Java 应用程序代码中*注入*问题的技巧。

示例代码位于[此处](https://github.com/righettod/injection-cheat-sheets)。

### 什么是注入

在 OWASP Top 10 中，[注入](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)被定义如下：

*考虑可以向系统发送不可信数据的任何人，包括外部用户、内部用户和管理员。*

### 防止注入的一般建议

以下几点可以普遍应用于防止*注入*问题：

1. 对用户输入/输出应用**输入验证**（使用白名单方法）结合**输出净化+转义**。
2. 如需与系统交互，尽量使用技术栈（Java / .Net / PHP...）提供的 API 功能，而不是自行构建命令。

关于此方面的其他建议，请参见[备忘录](Input_Validation_Cheat_Sheet.md)。

## 特定的注入类型

*本节的示例将使用 Java 技术（请参见关联的 Maven 项目），但建议同样适用于其他技术，如 .Net / PHP / Ruby / Python...*

### SQL 注入

#### 症状

当应用程序使用不可信的用户输入通过字符串构建 SQL 查询并执行时，会发生此类注入。

#### 如何防护

使用*查询参数化*以防止注入。

#### 示例

``` java
/*此处未使用数据库框架，以展示 Java API 中 Prepared Statement 的实际使用*/
/*打开与 H2 数据库的连接并使用*/
Class.forName("org.h2.Driver");
String jdbcUrl = "jdbc:h2:file:" + new File(".").getAbsolutePath() + "/target/db";
try (Connection con = DriverManager.getConnection(jdbcUrl)) {

    /* 示例 A：使用 Prepared Statement 选择数据*/
    String query = "select * from color where friendly_name = ?";
    List<String> colors = new ArrayList<>();
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setString(1, "yellow");
        try (ResultSet rSet = pStatement.executeQuery()) {
            while (rSet.next()) {
                colors.add(rSet.getString(1));
            }
        }
    }

    /* 示例 B：使用 Prepared Statement 插入数据*/
    query = "insert into color(friendly_name, red, green, blue) values(?, ?, ?, ?)";
    int insertedRecordCount;
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setString(1, "orange");
        pStatement.setInt(2, 239);
        pStatement.setInt(3, 125);
        pStatement.setInt(4, 11);
        insertedRecordCount = pStatement.executeUpdate();
    }

   /* 示例 C：使用 Prepared Statement 更新数据*/
    query = "update color set blue = ? where friendly_name = ?";
    int updatedRecordCount;
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setInt(1, 10);
        pStatement.setString(2, "orange");
        updatedRecordCount = pStatement.executeUpdate();
    }

   /* 示例 D：使用 Prepared Statement 删除数据*/
    query = "delete from color where friendly_name = ?";
    int deletedRecordCount;
    try (PreparedStatement pStatement = con.prepareStatement(query)) {
        pStatement.setString(1, "orange");
        deletedRecordCount = pStatement.executeUpdate();
    }

}
```

#### 参考资料

- [SQL 注入防护备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)

### JPA 注入

#### 症状

当应用程序使用不可信的用户输入通过字符串构建 JPA 查询并执行时，会发生此类注入。这与 SQL 注入非常相似，但这里被篡改的语言不是 SQL，而是 JPA QL。

#### 如何防护

使用 Java 持久化查询语言的**查询参数化**以防止注入。

#### 示例

``` java
EntityManager entityManager = null;
try {
    /* 获取 EntityManager 引用以访问数据库 */
    entityManager = Persistence.createEntityManagerFactory("testJPA").createEntityManager();

    /* 使用命名参数定义参数化查询原型以提高可读性 */
    String queryPrototype = "select c from Color c where c.friendlyName = :colorName";

    /* 创建查询，设置命名参数并执行查询 */
    Query queryObject = entityManager.createQuery(queryPrototype);
    Color c = (Color) queryObject.setParameter("colorName", "yellow").getSingleResult();

} finally {
    if (entityManager != null && entityManager.isOpen()) {
        entityManager.close();
    }
}
```

#### 参考资料

- [SQLi 和 JPA](https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-persistence-api-jpa)

### 操作系统命令注入

#### 症状

当应用程序使用不可信的用户输入通过字符串构建操作系统命令并执行时，会发生此类注入。

#### 如何防护

使用技术栈的 **API** 以防止注入。

#### 示例

``` java
/* 上下文示例是对计算机执行 PING 操作。
* 防护方法是使用 Java API 提供的功能，而不是构建字符串形式的系统命令并执行 */
InetAddress host = InetAddress.getByName("localhost");
var reachable = host.isReachable(5000);
```

#### 参考资料

- [命令注入](https://owasp.org/www-community/attacks/Command_Injection)

### XML：XPath 注入

#### 症状

当应用程序使用不可信的用户输入通过字符串构建 XPath 查询并执行时，会发生此类注入。

#### 如何防护

使用 **XPath 变量解析器**以防止注入。

#### 变量解析器

**变量解析器**的实现。

``` java
/**
 * 用于为 XPATH 表达式定义参数的解析器。
 *
 */
public class SimpleVariableResolver implements XPathVariableResolver {

    private final Map<QName, Object> vars = new HashMap<QName, Object>();

    /**
     * 添加参数的外部方法
     *
     * @param name 参数名称
     * @param value 参数值
     */
    public void addVariable(QName name, Object value) {
        vars.put(name, value);
    }

    /**
     * {@inheritDoc}
     *
     * @see javax.xml.xpath.XPathVariableResolver#resolveVariable(javax.xml.namespace.QName)
     */
    public Object resolveVariable(QName variableName) {
        return vars.get(variableName);
    }
}
```

使用它执行 XPath 查询的代码。

``` java
/*创建 XML 文档构建器工厂*/
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

/*禁用外部实体解析，针对不同情况*/
//此处未执行，以便专注于变量解析器代码
//但在生产代码中必须执行！

/*加载 XML 文件*/
DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(new File("src/test/resources/SampleXPath.xml"));

/* 创建并配置参数解析器 */
String bid = "bk102";
SimpleVariableResolver variableResolver = new SimpleVariableResolver();
variableResolver.addVariable(new QName("bookId"), bid);

/*创建并配置 XPATH 表达式*/
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(variableResolver);
XPathExpression xPathExpression = xpath.compile("//book[@id=$bookId]");

/* 在 XML 文档上应用表达式 */
Object nodes = xPathExpression.evaluate(doc, XPathConstants.NODESET);
NodeList nodesList = (NodeList) nodes;
Element book = (Element)nodesList.item(0);
var containsRalls = book.getTextContent().contains("Ralls, Kim");
```

#### 参考文献

- [XPATH 注入](https://owasp.org/www-community/attacks/XPATH_Injection)

### HTML/JavaScript/CSS

#### 症状

当应用程序使用不可信的用户输入构建 HTTP 响应并将其发送到浏览器时，会发生此类注入。

#### 如何预防

要么应用严格的输入验证（白名单方法），要么在无法进行输入验证时使用输出消毒和转义（如果可能，始终结合两种方法）。

#### 示例

``` java
/*
输入方式：从用户接收数据
建议使用严格的输入验证，采用白名单方法。
确保输入只包含允许的字符。
*/

String userInput = "You user login is owasp-user01";

/* 首先检查值是否仅包含预期字符*/
if (!Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput))
{
    return false;
}

/* 如果第一次检查通过，则确保为业务需求允许的潜在危险字符不会以危险方式使用。
例如，我们已允许字符 '-'，这可能用于 SQL 注入，
因此我们确保此字符不会连续使用。
使用 COMMONS LANG v3 API 帮助字符串分析...
*/
If (0 != StringUtils.countMatches(userInput.replace(" ", ""), "--"))
{
    return false;
}

/*
输出方式：向用户发送数据
在这里对发送给用户的任何数据进行转义和消毒
使用 OWASP Java HTML 消毒器 API 处理消毒
使用 OWASP Java 编码器 API 处理 HTML 标签编码（转义）
*/

String outputToUser = "You <p>user login</p> is <strong>owasp-user01</strong>";
outputToUser += "<script>alert(22);</script><img src='#' onload='javascript:alert(23);'>";

/* 创建仅允许标签 '<p>' 和 '<strong>' 的消毒策略*/
PolicyFactory policy = new HtmlPolicyBuilder().allowElements("p", "strong").toFactory();

/* 消毒将发送给用户的输出*/
String safeOutput = policy.sanitize(outputToUser);

/* 编码 HTML 标签*/
safeOutput = Encode.forHtml(safeOutput);
String finalSafeOutputExpected = "You <p>user login</p> is <strong>owasp-user01</strong>";
if (!finalSafeOutputExpected.equals(safeOutput))
{
    return false;
}
```

#### 参考文献

- [跨站脚本攻击（XSS）](https://owasp.org/www-community/attacks/xss/)
- [OWASP Java HTML 消毒器](https://github.com/owasp/java-html-sanitizer)
- [OWASP Java 编码器](https://github.com/owasp/owasp-java-encoder)
- [Java 正则表达式](https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html)

### LDAP

已创建专门的[速查表](LDAP_Injection_Prevention_Cheat_Sheet.md)。

### NoSQL

#### 症状

当应用程序使用不可信的用户输入构建 NoSQL API 调用表达式时，会发生此类注入。

#### 如何预防

由于存在多种 NoSQL 数据库系统，每个系统使用不同的 API 调用，因此确保接收并用于构建 API 调用表达式的用户输入不包含目标 API 语法中具有特殊含义的字符非常重要。这是为了避免输入被用于转义初始调用表达式，从而创建基于精心构造的用户输入的另一个表达式。同时，重要的是不要使用字符串拼接来构建 API 调用表达式，而是使用 API 创建表达式。

#### 示例 - MongoDB

``` java
 /* 使用 MongoDB 作为目标 NoSQL 数据库 */
String userInput = "Brooklyn";

/* 首先确保输入不包含当前 NoSQL 数据库调用 API 的任何特殊字符
这些特殊字符包括：' " \ ; { } $
*/
//这次避免使用正则表达式，以使验证代码更易读和理解...
ArrayList < String > specialCharsList = new ArrayList < String > () {
    {
        add("'");
        add("\"");
        add("\\");
        add(";");
        add("{");
        add("}");
        add("$");
    }
};

for (String specChar: specialCharsList) {
    if (userInput.contains(specChar)) {
        return false;
    }
}

//另外检查输入的最大长度
if (!userInput.length() <= 50)
{
    return false;
}

/* 然后使用 API 构建表达式执行数据库查询 */
//连接到本地 MongoDB 实例
try(MongoClient mongoClient = new MongoClient()){
    MongoDatabase db = mongoClient.getDatabase("test");
    //使用 API 查询构建器创建调用表达式
    //创建表达式
    Bson expression = eq("borough", userInput);
    //执行调用
    FindIterable<org.bson.Document> restaurants = db.getCollection("restaurants").find(expression);
    //验证结果一致性
    restaurants.forEach(new Block<org.bson.Document>() {
        @Override
        public void apply(final org.bson.Document doc) {
            String restBorough = (String)doc.get("borough");
            if (!"Brooklyn".equals(restBorough))
            {
                return false;
            }
        }
    });
}
```

#### 参考文献

- [测试 NoSQL 注入](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html)
- [SQL 和 NoSQL 注入](https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html)
- [没有 SQL，就没有注入？](https://arxiv.org/ftp/arxiv/papers/1506/1506.04082.pdf)

### 日志注入

#### 症状

[日志注入](https://owasp.org/www-community/attacks/Log_Injection)发生在应用程序在日志消息中包含不可信数据时（例如，如果攻击者可以在不可信数据中注入 CRLF 字符，他们可以导致看起来像来自完全不同用户的额外日志条目）。关于此攻击的更多信息可在 OWASP [日志注入](https://owasp.org/www-community/attacks/Log_Injection)页面找到。

#### 如何预防

为防止攻击者将恶意内容写入应用程序日志，请采用以下防御措施：

- 使用结构化日志格式，如 JSON，而不是非结构化文本格式。
  非结构化格式容易受到**回车**（CR）和**换行**（LF）注入的影响（参见 [CWE-93](https://cwe.mitre.org/data/definitions/93.html)）。
- 限制用于创建日志消息的用户输入值的大小。
- 确保在网页浏览器中查看日志文件时应用所有 [XSS 防御措施](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)。

#### 使用 Log4j Core 2 的示例

生产环境的推荐日志策略是使用在 [Log4j 2.14.0](https://logging.apache.org/log4j/2.x/release-notes.html#release-notes-2-14-0) 中引入的结构化 [JSON 模板布局](https://logging.apache.org/log4j/2.x/manual/json-template-layout.html)将日志发送到网络套接字，并使用 [`maxStringLength` 配置属性](https://logging.apache.org/log4j/2.x/manual/json-template-layout.html#plugin-attr-maxStringLength)将字符串大小限制为 500 字节：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration xmlns="https://logging.apache.org/xml/ns"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xsi:schemaLocation="
                   https://logging.apache.org/xml/ns
                   https://logging.apache.org/xml/ns/log4j-config-2.xsd">
  <Appenders>
    <Socket name="SOCKET"
            host="localhost"
            port="12345">
      <!-- 将生成的 JSON 文档中任何字符串字段的大小限制为 500 字节 -->
      <JsonTemplateLayout maxStringLength="500"
                          nullEventDelimiterEnabled="true"/>
    </Socket>
  </Appenders>
  <Loggers>
    <Root level="DEBUG">
      <AppenderRef ref="SOCKET"/>
    </Root>
  </Loggers>
</Configuration>
```

请参阅 [Log4j 网站](https://logging.apache.org/log4j/2.x/index.html)上的[面向服务架构的集成](https://logging.apache.org/log4j/2.x/soa.html)以获取更多提示。

代码级别的日志记录使用：

``` java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
...
// 声明日志记录器的最常见方式
private static final LOGGER = LogManager.getLogger();
// 好的做法！
//
// 使用参数化日志记录向消息添加用户数据
// 模式应该是编译时常量
logger.warn("登录用户 {} 失败。", username);
// 不好的做法！
//
// 不要混合字符串拼接和参数
// 如果 `username` 包含 `{}`，异常将泄漏到消息中
logger.warn("用户 " + username + " 和角色 {} 的失败。", role, ex);
...
```

请参阅 [Log4j API 最佳实践](https://logging.apache.org/log4j/2.x/manual/api.html#best-practice)以获取更多信息。

#### 使用 Logback 的示例

生产环境的推荐日志策略是使用在 [Logback 1.3.8](https://logback.qos.ch/news.html#1.3.8) 中引入的结构化 [JsonEncoder](https://logback.qos.ch/manual/encoders.html#JsonEncoder)。
在下面的示例中，Logback 配置为滚动 10 个每个 5 MiB 的日志文件：

``` xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE configuration>
<configuration>
  <import class="ch.qos.logback.classic.encoder.JsonEncoder"/>
  <import class="ch.qos.logback.core.rolling.FixedWindowRollingPolicy"/>
  <import class="ch.qos.logback.core.rolling.RollingFileAppender"/>
  <import class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy"/>

  <appender name="RollingFile" class="RollingFileAppender">
    <file>app.log</file>
    <rollingPolicy class="FixedWindowRollingPolicy">
      <fileNamePattern>app-%i.log</fileNamePattern>
      <minIndex>1</minIndex>
      <maxIndex>10</maxIndex>
    </rollingPolicy>
    <triggeringPolicy class="SizeBasedTriggeringPolicy">
      <maxFileSize>5MB</maxFileSize>
    </triggeringPolicy>
    <encoder class="JsonEncoder"/>
  </appender>

  <root level="DEBUG">
    <appender-ref ref="SOCKET"/>
  </root>
</configuration>
```

代码级别的日志记录使用：

``` java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
...
// 声明日志记录器的最常见方式
Logger logger = LoggerFactory.getLogger(MyClass.class);
// 好的做法！
//
// 使用参数化日志记录向消息添加用户数据
// 模式应该是编译时常量
logger.warn("登录用户 {} 失败。", username);
// 不好的做法！
//
// 不要混合字符串拼接和参数
// 如果 `username` 包含 `{}`，异常将泄漏到消息中
logger.warn("用户 " + username + " 和角色 {} 的失败。", role, ex);
...
```

#### 参考文献

- [Log4j Core 配置文件](https://logging.apache.org/log4j/2.x/manual/configuration.html)
- [Log4j JSON 模板布局](https://logging.apache.org/log4j/2.x/manual/json-template-layout.html)
- [Log4j 附加程序](https://logging.apache.org/log4j/2.x/manual/appenders.html)
- [Logback 配置文件](https://logback.qos.ch/manual/configuration.html)
- [Logback JsonEncoder](https://logback.qos.ch/manual/encoders.html#JsonEncoder)
- [Logback 附加程序](https://logback.qos.ch/manual/appenders.html)

## 密码学

### 通用密码学指导

- **绝对不要编写自己的密码学函数。**
- 尽可能避免编写任何密码学代码。相反，尝试使用现有的秘密管理解决方案或云提供商提供的秘密管理解决方案。更多信息，请参见 [OWASP 秘密管理速查表](Secrets_Management_Cheat_Sheet.md)。
- 如果无法使用现有的秘密管理解决方案，请尝试使用可信且众所周知的实现库，而不是使用 JCA/JCE 内置的库，因为使用它们很容易犯密码学错误。
- 确保您的应用程序或协议可以轻松支持未来更改密码学算法。
- 尽可能使用包管理器保持所有包的最新状态。关注开发设置的更新，并相应地规划应用程序更新。
- 下面我们将展示基于 Google Tink 的示例，这是由密码学专家创建的库，用于安全地使用密码学（即最大限度地减少使用标准密码学库时常见的错误）。

### 存储加密

遵循 [OWASP 加密存储速查表](Cryptographic_Storage_Cheat_Sheet.md#algorithms)中的算法指导。

#### 使用 Google Tink 的对称加密示例

Google Tink 有关于执行常见任务的文档。

例如，此页面（来自 Google 网站）展示了[如何执行简单的对称加密](https://developers.google.com/tink/encrypt-data)。

以下代码片段展示了这个功能的封装使用：

<details>
  <summary>点击查看"Tink 对称加密"代码片段。</summary>

``` java
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

// AesGcmSimpleTest
public class App {

    // 基于以下示例：
    // https://github.com/tink-crypto/tink-java/tree/main/examples/aead

    public static void main(String[] args) throws Exception {

        // 使用以下方式安全生成密钥：
        // tinkey create-keyset --key-template AES128_GCM --out-format JSON --out aead_test_keyset.json



        // 向 Tink 运行时注册所有 AEAD 密钥类型。
        AeadConfig.register();

        // 将密钥集读入 KeysetHandle。
        KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes( Paths.get("/home/fredbloggs/aead_test_keyset.json")), UTF_8), InsecureSecretKeyAccess.get());

        String message = "这是要加密的消息";
        System.out.println(message);

        // 添加一些关于加密数据的相关上下文，这些上下文应在解密时验证
        String metadata = "发送者：fredbloggs@example.com";

        // 加密消息
        byte[] cipherText = AesGcmSimple.encrypt(message, metadata, handle);
        System.out.println(Base64.getEncoder().encodeToString(cipherText));

        // 解密消息
        String message2 = AesGcmSimple.decrypt(cipherText, metadata, handle);
        System.out.println(message2);
    }
}

class AesGcmSimple {

    public static byte[] encrypt(String plaintext, String metadata, KeysetHandle handle) throws Exception {
        // 获取原语。
        Aead aead = handle.getPrimitive(Aead.class);
        return aead.encrypt(plaintext.getBytes(UTF_8), metadata.getBytes(UTF_8));
    }

    public static String decrypt(byte[] ciphertext, String metadata, KeysetHandle handle) throws Exception {
        // 获取原语。
        Aead aead = handle.getPrimitive(Aead.class);
        return new String(aead.decrypt(ciphertext, metadata.getBytes(UTF_8)),UTF_8);
    }

}

```

</details>

#### 使用内置 JCA/JCE 类的对称加密示例

如果绝对无法使用独立库，仍然可以使用内置的 JCA/JCE 类，但强烈建议让密码学专家审查完整的设计和代码，因为即使是最微不足道的错误也可能严重削弱您的加密。

以下代码片段展示了使用 AES-GCM 执行数据加密/解密的示例。

关于此代码的一些约束和陷阱：

- 它没有考虑密钥轮换或管理，这本身就是一个完整的主题。
- 对于每次加密操作，使用不同的随机数非常重要，尤其是在使用相同密钥的情况下。更多信息，请参见 [Cryptography Stack Exchange 上的这个答案](https://crypto.stackexchange.com/a/66500)。
- 密钥需要安全存储。

<details>
  <summary>点击查看"JCA/JCE 对称加密"代码片段。</summary>

```java
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.spec.*;
import javax.crypto.*;
import java.util.Base64;


// AesGcmSimpleTest
class Main {

    public static void main(String[] args) throws Exception {
        // 32字节/256位的 AES 密钥
        KeyGenerator keyGen = KeyGenerator.getInstance(AesGcmSimple.ALGORITHM);
        keyGen.init(AesGcmSimple.KEY_SIZE, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();

        // 12字节/96位的随机数，并且始终应使用此大小。
        // 对于 AES-GCM 来说，每次加密操作使用唯一的随机数至关重要。
        byte[] nonce = new byte[AesGcmSimple.IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        var message = "这是要加密的消息";
        System.out.println(message);

        // 加密消息
        byte[] cipherText = AesGcmSimple.encrypt(message, nonce, secretKey);
        System.out.println(Base64.getEncoder().encodeToString(cipherText));

        // 解密消息
        var message2 = AesGcmSimple.decrypt(cipherText, nonce, secretKey);
        System.out.println(message2);
    }
}

class AesGcmSimple {

    public static final String ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    public static final int KEY_SIZE = 256;
    public static final int TAG_LENGTH = 128;
    public static final int IV_LENGTH = 12;

    public static byte[] encrypt(String plaintext, byte[] nonce, SecretKey secretKey) throws Exception {
        return cryptoOperation(plaintext.getBytes(StandardCharsets.UTF_8), nonce, secretKey, Cipher.ENCRYPT_MODE);
    }

    public static String decrypt(byte[] ciphertext, byte[] nonce, SecretKey secretKey) throws Exception {
        return new String(cryptoOperation(ciphertext, nonce, secretKey, Cipher.DECRYPT_MODE), StandardCharsets.UTF_8);
    }

    private static byte[] cryptoOperation(byte[] text, byte[] nonce, SecretKey secretKey, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        cipher.init(mode, secretKey, gcmParameterSpec);
        return cipher.doFinal(text);
    }

}
```

</details>

### 传输加密

再次遵循 [OWASP 加密存储速查表](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#algorithms) 中的算法指导。

#### 使用 Google Tink 的非对称加密示例

Google Tink 有关于执行常见任务的文档。

例如，此页面（来自 Google 网站）展示了[如何执行混合加密过程](https://developers.google.com/tink/exchange-data)，其中两方希望基于其非对称密钥对共享数据。

以下代码片段展示了如何使用此功能在 Alice 和 Bob 之间共享秘密：

<details>
  <summary>点击查看"Tink 混合加密"代码片段。</summary>

``` java
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HybridConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

// HybridReplaceTest
class App {
    public static void main(String[] args) throws Exception {
        /*

        使用以下 tinkey 命令为 Bob 和 Alice 生成公钥/私钥对：

        ./tinkey create-keyset \
        --key-template DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM \
        --out-format JSON --out alice_private_keyset.json

        ./tinkey create-keyset \
        --key-template DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM \
        --out-format JSON --out bob_private_keyset.json

        ./tinkey create-public-keyset --in alice_private_keyset.json \
        --in-format JSON --out-format JSON --out alice_public_keyset.json

        ./tinkey create-public-keyset --in bob_private_keyset.json \
        --in-format JSON --out-format JSON --out bob_public_keyset.json
        */

        HybridConfig.register();

        // 为 Alice 生成 ECC 密钥对
        var alice = new HybridSimple(
                getKeysetHandle("/home/alicesmith/private_keyset.json"),
                getKeysetHandle("/home/alicesmith/public_keyset.json")

        );

        KeysetHandle alicePublicKey = alice.getPublicKey();

        // 为 Bob 生成 ECC 密钥对
        var bob = new HybridSimple(
                getKeysetHandle("/home/bobjones/private_keyset.json"),
                getKeysetHandle("/home/bobjones/public_keyset.json")

        );

        KeysetHandle bobPublicKey = bob.getPublicKey();

        // 应定期重新执行此密钥对生成，以获取新的共享密钥，避免长期使用共享密钥。

        // Alice 加密要发送给 Bob 的消息
        String plaintext = "你好，Bob！";

        // 添加关于加密数据的相关上下文，这些上下文应在解密时验证
        String metadata = "发送者：alicesmith@example.com";

        System.out.println("从 Alice 发送给 Bob 的秘密：" + plaintext);
        var cipherText = alice.encrypt(bobPublicKey, plaintext, metadata);
        System.out.println("从 Alice 发送给 Bob 的密文：" + Base64.getEncoder().encodeToString(cipherText));


        // Bob 解密消息
        var decrypted = bob.decrypt(cipherText, metadata);
        System.out.println("Bob 从 Alice 收到的秘密：" + decrypted);
        System.out.println();

        // Bob 加密要发送给 Alice 的消息
        String plaintext2 = "你好，Alice！";

        // 添加关于加密数据的相关上下文，这些上下文应在解密时验证
        String metadata2 = "发送者：bobjones@example.com";

        System.out.println("从 Bob 发送给 Alice 的秘密：" + plaintext2);
        var cipherText2 = bob.encrypt(alicePublicKey, plaintext2, metadata2);
        System.out.println("从 Bob 发送给 Alice 的密文：" + Base64.getEncoder().encodeToString(cipherText2));

        // Alice 解密消息
        var decrypted2 = alice.decrypt(cipherText2, metadata2);
        System.out.println("Alice 从 Bob 收到的秘密：" + decrypted2);
    }

    private static KeysetHandle getKeysetHandle(String filename) throws Exception
    {
        return TinkJsonProtoKeysetFormat.parseKeyset(
                new String(Files.readAllBytes( Paths.get(filename)), UTF_8), InsecureSecretKeyAccess.get());
    }
}
class HybridSimple {

    private KeysetHandle privateKey;
    private KeysetHandle publicKey;


    public HybridSimple(KeysetHandle privateKeyIn, KeysetHandle publicKeyIn) throws Exception {
        privateKey = privateKeyIn;
        publicKey = publicKeyIn;
    }

    public KeysetHandle getPublicKey() {
        return publicKey;
    }

    public byte[] encrypt(KeysetHandle partnerPublicKey, String message, String metadata) throws Exception {

        HybridEncrypt encryptor = partnerPublicKey.getPrimitive(HybridEncrypt.class);

        // 返回加密值
        return encryptor.encrypt(message.getBytes(UTF_8), metadata.getBytes(UTF_8));
    }
    public String decrypt(byte[] ciphertext, String metadata) throws Exception {

        HybridDecrypt decryptor = privateKey.getPrimitive(HybridDecrypt.class);

        // 返回解密值
        return new String(decryptor.decrypt(ciphertext, metadata.getBytes(UTF_8)),UTF_8);
    }


}
```

</details>

#### 使用内置 JCA/JCE 类的非对称加密示例

如果绝对无法使用独立库，仍然可以使用内置的 JCA/JCE 类，但强烈建议让密码学专家审查完整的设计和代码，因为即使是最微不足道的错误也可能严重削弱您的加密。

以下代码片段展示了使用椭圆曲线/迪菲-赫尔曼（ECDH）结合 AES-GCM 在两个不同方之间执行数据加密/解密的示例，无需在两方之间传输对称密钥。相反，双方交换公钥，然后可以使用 ECDH 生成可用于对称加密的共享密钥。

请注意，此代码示例依赖于[前一节](#使用内置-jcajce-类的对称加密示例)中的 AesGcmSimple 类。

关于此代码的一些约束和陷阱：

- 它没有考虑密钥轮换或管理，这本身就是一个完整的主题。
- 代码故意为每次加密操作强制使用新的随机数，但必须将其作为密文旁边的单独数据项进行管理。
- 私钥需要安全存储。
- 代码没有考虑在使用前验证公钥。
- 总体而言，双方之间没有真实性验证。

<details>
  <summary>点击查看"JCA/JCE 混合加密"代码片段。</summary>

```java
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.spec.*;
import javax.crypto.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

// ECDHSimpleTest
class Main {
    public static void main(String[] args) throws Exception {

        // 为 Alice 生成 ECC 密钥对
        var alice = new ECDHSimple();
        Key alicePublicKey = alice.getPublicKey();

        // 为 Bob 生成 ECC 密钥对
        var bob = new ECDHSimple();
        Key bobPublicKey = bob.getPublicKey();

        // 应定期重新执行此密钥对生成，以获取新的共享密钥，避免长期使用共享密钥。

        // Alice 加密要发送给 Bob 的消息
        String plaintext = "你好"; //, Bob!";
        System.out.println("从 Alice 发送给 Bob 的秘密：" + plaintext);

        var retPair = alice.encrypt(bobPublicKey, plaintext);
        var nonce = retPair.getKey();
        var cipherText = retPair.getValue();

        System.out.println("从 Alice 发送给 Bob 的密文和随机数：" + Base64.getEncoder().encodeToString(cipherText) + " " + Base64.getEncoder().encodeToString(nonce));


        // Bob 解密消息
        var decrypted = bob.decrypt(alicePublicKey, cipherText, nonce);
        System.out.println("Bob 从 Alice 收到的秘密：" + decrypted);
        System.out.println();

        // Bob 加密要发送给 Alice 的消息
        String plaintext2 = "你好"; //, Alice!";
        System.out.println("从 Bob 发送给 Alice 的秘密：" + plaintext2);

        var retPair2 = bob.encrypt(alicePublicKey, plaintext2);
        var nonce2 = retPair2.getKey();
        var cipherText2 = retPair2.getValue();
        System.out.println("从 Bob 发送给 Alice 的密文和随机数：" + Base64.getEncoder().encodeToString(cipherText2) + " " + Base64.getEncoder().encodeToString(nonce2));

        // Alice 解密消息
        var decrypted2 = alice.decrypt(bobPublicKey, cipherText2, nonce2);
        System.out.println("Alice 从 Bob 收到的秘密：" + decrypted2);
    }
}
class ECDHSimple {
    private KeyPair keyPair;

    public class AesKeyNonce {
        public SecretKey Key;
        public byte[] Nonce;
    }

    public ECDHSimple() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // 使用 secp256r1 曲线
        keyPairGenerator.initialize(ecSpec);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public Key getPublicKey() {
        return keyPair.getPublic();
    }

    public AbstractMap.SimpleEntry<byte[], byte[]> encrypt(Key partnerPublicKey, String message) throws Exception {

        // 生成 AES 密钥和随机数
        AesKeyNonce aesParams = generateAESParams(partnerPublicKey);

        // 返回加密值
        return new AbstractMap.SimpleEntry<>(
            aesParams.Nonce,
            AesGcmSimple.encrypt(message, aesParams.Nonce, aesParams.Key)
            );
    }
    public String decrypt(Key partnerPublicKey, byte[] ciphertext, byte[] nonce) throws Exception {

        // 生成 AES 密钥和随机数
        AesKeyNonce aesParams = generateAESParams(partnerPublicKey, nonce);

        // 返回解密值
        return AesGcmSimple.decrypt(ciphertext, aesParams.Nonce, aesParams.Key);
    }

    private AesKeyNonce generateAESParams(Key partnerPublicKey, byte[] nonce) throws Exception {

        // 基于此方的私钥和另一方的公钥推导密钥
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(partnerPublicKey, true);
        byte[] secret = keyAgreement.generateSecret();

        AesKeyNonce aesKeyNonce = new AesKeyNonce();

        // 复制前 32 字节作为密钥
        byte[] key = Arrays.copyOfRange(secret, 0, (AesGcmSimple.KEY_SIZE / 8));
        aesKeyNonce.Key = new SecretKeySpec(key, 0, key.length, "AES");

        // 使用传入的随机数
        aesKeyNonce.Nonce = nonce;
        return aesKeyNonce;

    }

    private AesKeyNonce generateAESParams(Key partnerPublicKey) throws Exception {

        // 12字节/96位的随机数，并且始终应使用此大小。
        // 对于 AES-GCM 来说，每次加密操作使用唯一的随机数至关重要。
        // 因此这不是从共享密钥生成的
        byte[] nonce = new byte[AesGcmSimple.IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        return generateAESParams(partnerPublicKey, nonce);

    }
}
```

</details>
