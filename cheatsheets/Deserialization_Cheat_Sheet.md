# 反序列化备忘录

## 引言

本文旨在为在应用程序中安全地反序列化不可信数据提供清晰、可操作的指导。

## 什么是反序列化

**序列化**是将某个对象转换为可以稍后恢复的数据格式的过程。人们通常会序列化对象以便保存它们进行存储，或作为通信的一部分发送。

**反序列化**是这个过程的逆向操作，即将某种格式的数据结构重新构建为对象。如今，用于序列化数据最流行的格式是 JSON。在此之前，是 XML。

然而，许多编程语言都有原生的对象序列化方式。这些原生格式通常比 JSON 或 XML 提供更多功能，包括序列化过程的自定义。

不幸的是，当处理不可信数据时，这些原生反序列化机制的特性有时可能会被恶意利用。针对反序列化器的攻击已被发现可以实现拒绝服务、访问控制或远程代码执行（RCE）攻击。

## 安全反序列化对象的指导

以下是针对不可信数据的反序列化的语言特定指导。

### PHP

#### 白盒审查

检查 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) 函数的使用，并审查外部参数的接受方式。如果需要向用户传递序列化数据，请使用安全的标准数据交换格式，如 JSON（通过 `json_decode()` 和 `json_encode()`）。

### Python

#### 黑盒审查

如果流量数据在末尾包含点符号 `.`，很可能数据是以序列化形式发送的。仅当数据未使用 Base64 或十六进制编码时才成立。如果数据已编码，最好通过查看参数值的起始字符来检查序列化是否可能发生。例如，如果数据是 Base64 编码，则很可能以 `gASV` 开头。

#### 白盒审查

Python 中以下 API 容易遭受序列化攻击。搜索代码中的以下模式：

1. 使用 `pickle/c_pickle/_pickle` 的 `load/loads`：

```python
import pickle
data = """ cos.system(S'dir')tR. """
pickle.loads(data)
```

2. 使用 `PyYAML` 的 `load`：

```python
import yaml
document = "!!python/object/apply:os.system ['ipconfig']"
print(yaml.load(document))
```

3. 使用 `jsonpickle` 的 `encode` 或 `store` 方法。

### Java

以下技术都适用于防范针对 [Java 的 Serializable 格式](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html) 的反序列化攻击。

实施建议：

- 在代码中，重写 `ObjectInputStream#resolveClass()` 方法以防止反序列化任意类。这种安全行为可以封装在像 [SerialKiller](https://github.com/ikkisoft/SerialKiller) 这样的库中。
- 使用安全的替代方法替代通用的 `readObject()` 方法。请注意，这通过检查输入长度和反序列化对象的数量来解决"[十亿笑声](https://en.wikipedia.org/wiki/Billion_laughs_attack)"类型的攻击。

#### 白盒审查

注意以下 Java API 的使用可能存在序列化漏洞：

1. 带有外部用户定义参数的 `XMLdecoder`

2. 使用 `fromXML` 方法的 `XStream`（xstream 版本 <= v1.4.6 容易受到序列化问题的影响）

3. 带有 `readObject` 的 `ObjectInputStream`

4. 使用 `readObject`、`readObjectNoData`、`readResolve` 或 `readExternal`

5. `ObjectInputStream.readUnshared`

6. `Serializable`

#### 黑盒审查

如果捕获的流量数据包含以下模式，可能表明数据是以 Java 序列化流的形式发送：

- 十六进制中的 `AC ED 00 05`
- Base64 中的 `rO0`
- HTTP 响应的 `Content-type` 标头设置为 `application/x-java-serialized-object`

#### 防止数据泄露和受信任字段覆盖

如果对象的数据成员在反序列化期间不应由最终用户控制，或在序列化期间不应暴露给用户，则应声明为 [`transient` 关键字](https://docs.oracle.com/javase/7/docs/platform/serialization/spec/serial-arch.html#7231)（*保护敏感信息*部分）。

对于定义为 Serializable 的类，敏感信息变量应声明为 `private transient`。

例如，在 `myAccount` 类中，变量 'profit' 和 'margin' 被声明为 transient 以防止它们被序列化。

```java
public class myAccount implements Serializable
{
    private transient double profit; // 声明为 transient

    private transient double margin; // 声明为 transient
    ....
```

#### 防止域对象的反序列化

由于层次结构的原因，您的某些应用程序对象可能被强制实现 `Serializable`。为了确保应用程序对象无法被反序列化，应声明一个 `readObject()` 方法（使用 `final` 修饰符），该方法始终抛出异常：

```java
private final void readObject(ObjectInputStream in) throws java.io.IOException {
    throw new java.io.IOException("Cannot be deserialized");
}
```

#### 强化自定义的 java.io.ObjectInputStream

`java.io.ObjectInputStream` 类用于反序列化对象。通过对其进行子类化，可以强化其行为。如果满足以下条件，这是最佳解决方案：

- 您可以更改执行反序列化的代码；
- 您知道期望反序列化的类。

其基本思路是重写 [`ObjectInputStream.html#resolveClass()`](http://docs.oracle.com/javase/7/docs/api/java/io/ObjectInputStream.html#resolveClass(java.io.ObjectStreamClass)) 以限制允许反序列化的类。

由于此调用发生在调用 `readObject()` 之前，您可以确保除了允许的类型外，不会发生任何反序列化活动。

下面是一个简单的示例，其中 `LookAheadObjectInputStream` 类保证**不**反序列化 `Bicycle` 类以外的任何类型：

```java
public class LookAheadObjectInputStream extends ObjectInputStream {

    public LookAheadObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    /**
    * 仅反序列化预期的 Bicycle 类的实例
    */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!desc.getName().equals(Bicycle.class.getName())) {
            throw new InvalidClassException("未授权的反序列化尝试", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

社区成员提出了更完整的实现方案：

- [NibbleSec](https://github.com/ikkisoft/SerialKiller) - 一个允许创建可反序列化类列表的库
- [IBM](https://www.ibm.com/developerworks/library/se-lookahead/) - 在最严重的利用场景被设想之前多年就已编写的基础保护
- [Apache Commons IO 类](https://commons.apache.org/proper/commons-io/javadocs/api-2.5/org/apache/commons/io/serialization/ValidatingObjectInputStream.html)

#### 使用代理强化所有 java.io.ObjectInputStream 的使用

如前所述，`java.io.ObjectInputStream` 类用于反序列化对象。通过对其进行子类化可以强化其行为。但是，如果您不拥有代码或无法等待补丁，使用代理将强化功能编织到 `java.io.ObjectInputStream` 中是最佳解决方案。

全局更改 `ObjectInputStream` 仅对阻止已知的恶意类型是安全的，因为不可能知道所有应用程序中期望反序列化的类。幸运的是，现在只需要很少的类在拒绝列表中就可以防范所有已知的攻击向量。

不可避免地会发现更多可被滥用的"小工具"类。然而，目前有大量需要修复的易受攻击的软件。在某些情况下，"修复"漏洞可能涉及重新设计消息系统并打破向后兼容性，因为开发人员转向不接受序列化对象。

要启用这些代理，只需添加一个新的 JVM 参数：

```text
-javaagent:name-of-agent.jar
```

社区成员发布了采用这种方法的代理：

- [rO0 by Contrast Security](https://github.com/Contrast-Security-OSS/contrast-rO0)

类似但可扩展性较低的方法是手动修补和引导 JVM 的 ObjectInputStream。关于这种方法的指导可在[此处](https://github.com/wsargent/paranoid-java-serialization)找到。

#### 其他反序列化库和格式

虽然上述建议侧重于 [Java 的 Serializable 格式](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html)，但还有许多其他库使用不同的格式进行反序列化。如果配置不正确，这些库可能存在类似的安全问题。本节列出了一些库及推荐的配置选项，以避免在反序列化不可信数据时出现安全问题：

**默认配置下可安全使用：**

以下库在默认配置下可安全使用：

- **[fastjson2](https://github.com/alibaba/fastjson2)** (JSON) - 只要不开启 [**autotype**](https://github.com/alibaba/fastjson2/wiki/fastjson2_autotype_cn) 选项就可安全使用
- **[jackson-databind](https://github.com/FasterXML/jackson-databind)** (JSON) - 只要不使用多态性就可安全使用（[参见博客文章](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062)）
- **[Kryo v5.0.0+](https://github.com/EsotericSoftware/kryo)** (自定义格式) - 只要不关闭类注册就可安全使用（[参见文档](https://github.com/EsotericSoftware/kryo#optional-registration)和[此问题](https://github.com/EsotericSoftware/kryo/issues/929)）
- **[YamlBeans v1.16+](https://github.com/EsotericSoftware/yamlbeans)** (YAML) - 只要不使用 **UnsafeYamlConfig** 类就可安全使用（参见[此提交](https://github.com/EsotericSoftware/yamlbeans/commit/b1122588e7610ae4e0d516c50d08c94ee87946e6)）
    - _注意：因为这些版本在 Maven Central 中不可用，[存在一个分支](https://github.com/Contrast-Security-OSS/yamlbeans)可以使用_
- **[XStream v1.4.17+](https://x-stream.github.io/)** (JSON 和 XML) - 只要不放松允许列表和其他安全控制就可安全使用（[参见文档](https://x-stream.github.io/security.html)）

**需要配置后才能安全使用：**

以下库需要设置配置选项后才能安全使用：

- **[fastjson v1.2.68+](https://github.com/alibaba/fastjson)** (JSON) - 除非开启 [**safemode**](https://github.com/alibaba/fastjson/wiki/fastjson_safemode_en) 选项（禁用任何类的反序列化），否则无法安全使用（[参见文档](https://github.com/alibaba/fastjson/wiki/enable_autotype)）。早期版本不安全。
- **[json-io](https://github.com/jdereg/json-io)** (JSON) - 由于 JSON 中的 **@type** 属性允许反序列化任何类，因此无法安全使用。仅在以下情况下可安全使用：
    - 在[非类型模式](https://github.com/jdereg/json-io/blob/master/user-guide.md#non-typed-usage)下使用 **JsonReader.USE_MAPS** 设置，关闭通用对象反序列化
    - [使用自定义反序列化器](https://github.com/jdereg/json-io/blob/master/user-guide.md#customization-technique-4-custom-serializer)控制要反序列化的类
- **[Kryo < v5.0.0](https://github.com/EsotericSoftware/kryo)** (自定义格式) - 除非开启类注册（禁用任何类的反序列化），否则无法安全使用（[参见文档](https://github.com/EsotericSoftware/kryo#optional-registration)和[此问题](https://github.com/EsotericSoftware/kryo/issues/929)）
    - _注意：Kryo 周围存在其他包装器，如 [Chill](https://github.com/twitter/chill)，无论使用的底层 Kryo 版本如何，可能都不需要默认类注册_
- **[SnakeYAML](https://bitbucket.org/snakeyaml/snakeyaml/src)** (YAML) - 除非使用 **org.yaml.snakeyaml.constructor.SafeConstructor** 类（禁用任何类的反序列化），否则无法安全使用（[参见文档](https://bitbucket.org/snakeyaml/snakeyaml/wiki/CVE-2022-1471)）

**无法安全使用：**

以下库要么不再维护，要么无法安全地处理不可信的输入：

- **[Castor](https://github.com/castor-data-binding/castor)** (XML) - 似乎已被放弃，自 2016 年以来没有提交
- **[fastjson < v1.2.68](https://github.com/alibaba/fastjson)** (JSON) - 这些版本允许反序列化任何类（[参见文档](https://github.com/alibaba/fastjson/wiki/enable_autotype)）
- **[JDK 中的 XMLDecoder](https://docs.oracle.com/javase/8/docs/api/java/beans/XMLDecoder.html)** (XML) - _"从不可信输入中安全地反序列化 Java 对象几乎是不可能的"_
（"Red Hat 防御性编码指南"，[第 2.6.5 节末尾](https://redhat-crypto.gitlab.io/defensive-coding-guide/#sect-Defensive_Coding-Tasks-Serialization-XML)）
- **[XStream < v1.4.17](https://x-stream.github.io/)** (JSON 和 XML) - 这些版本允许反序列化任何类（[参见文档](https://x-stream.github.io/security.html#explicit)）
- **[YamlBeans < v1.16](https://github.com/EsotericSoftware/yamlbeans)** (YAML) - 这些版本允许反序列化任何类（[参见此文档](https://github.com/Contrast-Security-OSS/yamlbeans/blob/main/SECURITY.md)）

### .Net CSharp

#### 黑盒审查

搜索源代码中的以下术语：

1. `TypeNameHandling`
2. `JavaScriptTypeResolver`

查找任何类型由用户控制变量设置的序列化器。

#### 不透明盒审查

搜索以下 base64 编码的内容，以 `AAEAAAD/////` 开头：

```text
AAEAAAD/////
```

搜索包含以下文本的内容：

1. `TypeObject`
2. `$type:`

#### 一般预防措施

微软已声明 `BinaryFormatter` 类型是危险的且无法安全保护。因此，不应使用它。完整细节请参见 [BinaryFormatter 安全指南](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)。

不要允许数据流定义将要反序列化的对象类型。如果可能，可以通过使用 `DataContractSerializer` 或 `XmlSerializer` 来防止这一点。

使用 `JSON.Net` 时，确保 `TypeNameHandling` 仅设置为 `None`。

```csharp
TypeNameHandling = TypeNameHandling.None
```

如果要使用 `JavaScriptSerializer`，则不要与 `JavaScriptTypeResolver` 一起使用。

如果必须反序列化定义自身类型的数据流，则限制允许反序列化的类型。应注意，这仍然存在风险，因为许多本机 .Net 类型本身可能是危险的。例如：

```csharp
System.IO.FileInfo
```

反序列化时引用服务器上实际文件的 `FileInfo` 对象可以更改这些文件的属性（例如设为只读），从而创建潜在的拒绝服务攻击。

即使您已限制可反序列化的类型，请记住某些类型的属性仍可能存在风险。例如，`System.ComponentModel.DataAnnotations.ValidationException` 有一个 `Object` 类型的 `Value` 属性。如果允许反序列化此类型，攻击者可以将 `Value` 属性设置为他们选择的任何对象类型。

应阻止攻击者引导将要实例化的类型。如果这是可能的，即使 `DataContractSerializer` 或 `XmlSerializer` 也可能被破坏，例如：

```csharp
// 如果攻击者可以更改数据库中的数据，下面的操作是危险的
var typename = GetTransactionTypeFromDatabase();

var serializer = new DataContractJsonSerializer(Type.GetType(typename));

var obj = serializer.ReadObject(ms);
```

在反序列化期间，某些 .Net 类型可能会执行代码。下面所示的控制是无效的：

```csharp
var suspectObject = myBinaryFormatter.Deserialize(untrustedData);

// 检查已经太晚！执行可能已经发生
if (suspectObject is SomeDangerousObjectType)
{
    // 生成警告并处理 suspectObject
}
```

对于 `JSON.Net`，可以使用自定义 `SerializationBinder` 创建更安全的允许列表控制。

尽量了解已知的 .Net 不安全反序列化小工具（gadgets），并特别关注可以通过反序列化过程创建此类类型的地方。**反序列化器只能实例化它所知道的类型**。

尽量将可能创建潜在小工具的代码与具有互联网连接的代码分开。例如，在 WPF 应用程序中使用的 `System.Windows.Data.ObjectDataProvider` 是一个已知的小工具，允许任意方法调用。在反序列化不可信数据的 REST 服务项目中引用此程序集是有风险的。

#### 已知的 .NET RCE 小工具

- `System.Configuration.Install.AssemblyInstaller`
- `System.Activities.Presentation.WorkflowDesigner`
- `System.Windows.ResourceDictionary`
- `System.Windows.Data.ObjectDataProvider`
- `System.Windows.Forms.BindingSource`
- `Microsoft.Exchange.Management.SystemManager.WinForms.ExchangeSettingsProvider`
- `System.Data.DataViewManager, System.Xml.XmlDocument/XmlDataDocument`
- `System.Management.Automation.PSObject`

## 语言无关的安全反序列化方法

### 使用替代数据格式

通过避免原生（反）序列化格式，可以大大降低风险。通过切换到纯数据格式（如 JSON 或 XML），可以减少自定义反序列化逻辑被恶意重新利用的机会。

许多应用程序依赖于[数据传输对象模式](https://en.wikipedia.org/wiki/Data_transfer_object)，该模式涉及创建一个专门用于数据传输的独立对象域。当然，在解析纯数据对象后，应用程序仍可能犯安全错误。

### 仅反序列化签名数据

如果应用程序在反序列化之前知道需要处理哪些消息，则可以在序列化过程中对其进行签名。然后，应用程序可以选择不反序列化任何没有经过身份验证签名的消息。

## 缓解工具/库

- [Java 安全反序列化库](https://github.com/ikkisoft/SerialKiller)
- [SWAT - 创建允许列表的工具](https://github.com/cschneider4711/SWAT)
- [NotSoSerial](https://github.com/kantega/notsoserial)

## 检测工具

- [面向渗透测试者的 Java 反序列化备忘单](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [用于生成利用不安全 Java 对象反序列化的有效载荷的概念验证工具](https://github.com/frohoff/ysoserial)
- [Java 反序列化工具包](https://github.com/brianwrf/hackUtils)
- [Java 反序列化工具](https://github.com/frohoff/ysoserial)
- [.Net 有效载荷生成器](https://github.com/pwntester/ysoserial.net)
- [Burp Suite 扩展](https://github.com/federicodotta/Java-Deserialization-Scanner/releases)
- [Java 安全反序列化库](https://github.com/ikkisoft/SerialKiller)
- [Serianalyzer - 用于反序列化的静态字节码分析器](https://github.com/mbechler/serianalyzer)
- [有效载荷生成器](https://github.com/mbechler/marshalsec)
- [Android Java 反序列化漏洞测试器](https://github.com/modzero/modjoda)
- Burp Suite 扩展
    - [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
    - [Java 反序列化扫描器](https://github.com/federicodotta/Java-Deserialization-Scanner)
    - [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
    - [SuperSerial](https://github.com/DirectDefense/SuperSerial)
    - [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

## 参考资料

- [Java-反序列化-备忘单](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [不可信数据的反序列化](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [Java 反序列化攻击 - 德国 OWASP Day 2016](../assets/Deserialization_Cheat_Sheet_GOD16Deserialization.pdf)
- [AppSecCali 2015 - 编组 Pickles](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [FoxGlove 安全 - 漏洞公告](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#websphere)
- [面向渗透测试者的 Java 反序列化备忘单](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [用于生成利用不安全 Java 对象反序列化的有效载荷的概念验证工具](https://github.com/frohoff/ysoserial)
- [Java 反序列化工具包](https://github.com/brianwrf/hackUtils)
- [Java 反序列化工具](https://github.com/frohoff/ysoserial)
- [Burp Suite 扩展](https://github.com/federicodotta/Java-Deserialization-Scanner/releases)
- [Java 安全反序列化库](https://github.com/ikkisoft/SerialKiller)
- [Serianalyzer - 用于反序列化的静态字节码分析器](https://github.com/mbechler/serianalyzer)
- [有效载荷生成器](https://github.com/mbechler/marshalsec)
- [Android Java 反序列化漏洞测试器](https://github.com/modzero/modjoda)
- Burp Suite 扩展
    - [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
    - [Java 反序列化扫描器](https://github.com/federicodotta/Java-Deserialization-Scanner)
    - [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
    - [SuperSerial](https://github.com/DirectDefense/SuperSerial)
    - [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)
- .Net
    - [Alvaro Muñoz：.NET 序列化：检测和防御易受攻击的端点](https://www.youtube.com/watch?v=qDoBlLwREYk)
    - [James Forshaw - 黑帽美国 2012 - 我是你的类型吗？通过序列化破坏 .net 沙盒](https://www.youtube.com/watch?v=Xfbu-pQ1tIc)
    - [Jonathan Birch BlueHat v17 - 危险内容 - 保护 .Net 反序列化](https://www.youtube.com/watch?v=oxlD8VWWHE8)
    - [Alvaro Muñoz & Oleksandr Mirosh - 13号星期五：攻击 JSON - AppSecUSA 2017](https://www.youtube.com/watch?v=NqHsaVhlxAQ)
- Python
    - [在野外发现的不安全反序列化漏洞利用（Python Pickles）](https://macrosec.tech/index.php/2021/06/29/exploiting-insecuredeserialization-bugs-found-in-the-wild-python-pickles.)
