# 加密存储备忘录

## 引言

本文提供了在实施保护静态数据解决方案时可遵循的简单模型。

密码不应使用可逆加密存储 - 应改用安全的密码哈希算法。[密码存储备忘录](Password_Storage_Cheat_Sheet.md)包含有关存储密码的进一步指导。

## 架构设计

设计任何应用程序的第一步是考虑系统的整体架构，因为这将对技术实施产生巨大影响。

这个过程应从考虑应用程序的[威胁模型](Threat_Modeling_Cheat_Sheet.md)开始（即，你试图保护数据免受谁的攻击）。

使用专用的秘密或密钥管理系统可以提供额外的安全保护，并使秘密管理变得更加容易 - 但代价是增加了复杂性和管理开销 - 因此并非对所有应用程序都可行。请注意，许多云环境都提供这些服务，因此应尽可能利用这些服务。[秘密管理速查表](Secrets_Management_Cheat_Sheet.md)包含有关此主题的进一步指导。

### 在何处执行加密

加密可以在应用程序堆栈的多个层级执行，例如：

- 应用程序级别
- 数据库级别（例如，[SQL Server TDE](https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption?view=sql-server-ver15)）
- 文件系统级别（例如，BitLocker 或 LUKS）
- 硬件级别（例如，加密的 RAID 卡或 SSD）

哪些层级最合适将取决于威胁模型。例如，硬件级加密对防止服务器物理盗窃很有效，但如果攻击者能够远程入侵服务器，则无法提供保护。

### 最小化敏感信息存储

保护敏感信息的最佳方法是一开始就不存储它。虽然这适用于所有类型的信息，但最常见的是信用卡详细信息，因为它们对攻击者非常有吸引力，并且 PCI DSS 对其存储方式有严格的要求。在可能的情况下，应避免存储敏感信息。

## 算法

对于对称加密，应使用 **AES**，密钥至少 **128 位**（理想情况下 **256 位**），并使用安全的[模式](#密码模式)。

对于非对称加密，使用椭圆曲线密码学（ECC）和安全曲线，如 **Curve25519** 作为首选算法。如果 ECC 不可用且必须使用 **RSA**，则确保密钥至少为 **2048 位**。

还有许多其他对称和非对称算法，它们各有优缺点，在特定用例中可能比 AES 或 Curve25519 更好或更差。在考虑这些算法时，应考虑以下因素：

- 密钥大小
- 算法的已知攻击和弱点
- 算法的成熟度
- 第三方（如 [NIST 算法验证程序](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)）的批准
- 性能（加密和解密）
- 可用库的质量
- 算法的可移植性（即支持程度）

在某些情况下，可能有限制可使用算法的监管要求，如 [FIPS 140-2](https://csrc.nist.gov/csrc/media/publications/fips/140/2/final/documents/fips1402annexa.pdf) 或 [PCI DSS](https://www.pcisecuritystandards.org/pci_security/glossary#Strong%20Cryptography)。

### 自定义算法

不要这样做。

### 密码模式

有各种[模式](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)可用于允许分组密码（如 AES）加密任意数量的数据，就像流密码一样。这些模式具有不同的安全性和性能特征，对它们的全面讨论超出了本速查表的范围。某些模式要求生成安全的初始化向量（IV）和其他属性，但这些应由库自动处理。

在可用的情况下，应始终使用经过身份验证的模式。这些模式提供数据的完整性和真实性以及机密性的保证。最常用的经过身份验证的模式是 **[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)** 和 **[CCM](https://en.wikipedia.org/wiki/CCM_mode)**，应作为首选。

如果 GCM 或 CCM 不可用，则应使用 [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_%28CTR%29) 模式或 [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_%28CBC%29) 模式。由于这些模式不提供关于数据真实性的任何保证，应实施单独的身份验证，例如使用 [Encrypt-then-MAC](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_%28EtM%29) 技术。使用此方法时需要注意[可变长度消息](https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages)。

[ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB) 不应在非常特定的情况外使用。

### 随机填充

对于 RSA，启用随机填充至关重要。随机填充也称为 OAEP 或最优非对称加密填充。这类防御通过在有效载荷开头添加随机性来防止已知明文攻击。

在这种情况下，通常使用 [PKCS#1](https://wikipedia.org/wiki/RSA_(cryptosystem)#Padding_schemes) 填充方案。

### 安全随机数生成

在各种安全关键功能中需要随机数（或字符串），如生成加密密钥、IV、会话 ID、CSRF 令牌或密码重置令牌。因此，重要的是这些随机数应安全生成，并且攻击者无法猜测和预测它们。

通常，计算机无法生成真正的随机数（没有特殊硬件），因此大多数系统和语言提供两种不同类型的随机性。

伪随机数生成器（PRNG）提供低质量的随机性，速度更快，可用于非安全相关的功能（如对页面结果排序或随机化 UI 元素）。但是，它们**绝不**能用于任何安全关键功能，因为攻击者通常可以猜测或预测输出。

密码学安全伪随机数生成器（CSPRNG）旨在产生更高质量的随机性（更严格地说，是更多的熵），使其可安全用于安全敏感的功能。但是，它们速度较慢，CPU 密集，在请求大量随机数据时可能会阻塞。因此，如果需要大量非安全相关的随机性，它们可能不合适。

下表显示了每种语言推荐的算法，以及不应使用的不安全函数。

| 语言       | 不安全函数                                                                                                                         | 密码学安全函数                                                                                                                                                                                                                                                                                                                                                             |
|------------|------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| C          | `random()`, `rand()`                                                                                                               | [getrandom(2)](http://man7.org/linux/man-pages/man2/getrandom.2.html) |
| Java       | `Math.random()`, `StrictMath.random()`, `java.util.Random`, `java.util.SplittableRandom`, `java.util.concurrent.ThreadLocalRandom` | [java.security.SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html), [java.util.UUID.randomUUID()](https://docs.oracle.com/javase/8/docs/api/java/util/UUID.html#randomUUID--) |
| PHP        | `array_rand()`, `lcg_value()`, `mt_rand()`, `rand()`, `uniqid()`                                                                   | [random_bytes()](https://www.php.net/manual/en/function.random-bytes.php), [Random\Engine\Secure](https://www.php.net/manual/en/class.random-engine-secure.php) in PHP 8, [random_int()](https://www.php.net/manual/en/function.random-int.php) in PHP 7, [openssl_random_pseudo_bytes()](https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php) in PHP 5 |
| .NET/C#    | `Random()`                                                                                                                         | [RandomNumberGenerator](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-6.0) |
| Objective-C| `arc4random()`/`arc4random_uniform()` (使用 RC4 密码), `GKRandomSource` 的子类, `rand()`, `random()`                                | [SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc) |
| Python     | `random()`                                                                                                                         | [secrets()](https://docs.python.org/3/library/secrets.html#module-secrets) |
| Ruby       | `rand()`, `Random`                                                                                                                 | [SecureRandom](https://ruby-doc.org/stdlib-2.5.1/libdoc/securerandom/rdoc/SecureRandom.html) |
| Go         | 使用 `math/rand` 包的 `rand`                                                                                                       | [crypto.rand](https://golang.org/pkg/crypto/rand/) 包 |
| Rust       | `rand::prng::XorShiftRng`                                                                                                          | [rand::prng::chacha::ChaChaRng](https://docs.rs/rand/0.5.0/rand/prng/chacha/struct.ChaChaRng.html) 和 Rust 库的其余 [CSPRNGs](https://docs.rs/rand/0.5.0/rand/prng/index.html#cryptographically-secure-pseudo-random-number-generators-csprngs) |
| Node.js    | `Math.random()`                                                                                                                    | [crypto.randomBytes()](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback), [crypto.randomInt()](https://nodejs.org/api/crypto.html#cryptorandomintmin-max-callback), [crypto.randomUUID()](https://nodejs.org/api/crypto.html#cryptorandomuuidoptions) |

#### UUID 和 GUID

通用唯一标识符（UUID 或 GUID）有时被用作快速生成随机字符串的方法。尽管它们可以提供合理的随机性来源，但这取决于所创建的 UUID 的[类型或版本](https://en.wikipedia.org/wiki/Universally_unique_identifier#Versions)。

具体来说，第 1 版 UUID 由高精度时间戳和生成它们的系统的 MAC 地址组成，因此**不是随机的**（尽管考虑到时间戳精确到最近的 100ns，可能很难猜测）。第 4 版 UUID 是随机生成的，尽管这是否使用 CSPRNG 取决于具体实现。除非在特定语言或框架中已知是安全的，否则不应依赖 UUID 的随机性。

### 纵深防御

即使加密控制失败，应用程序也应设计为仍然安全。任何以加密形式存储的信息都应受到额外的安全层保护。应用程序也不应依赖加密 URL 参数的安全性，并应强制执行严格的访问控制以防止未经授权访问信息。

## 密钥管理

### 流程

应实施（并测试）正式流程，涵盖密钥管理的所有方面，包括：

- 生成和存储新密钥
- 将密钥分发给所需方
- 将密钥部署到应用程序服务器
- 轮换和退役旧密钥

### 密钥生成

应使用密码学安全函数随机生成密钥，如[安全随机数生成](#安全随机数生成)部分所讨论。密钥**不应**基于常用词或短语，或通过乱敲键盘生成的"随机"字符。

在使用多个密钥（如单独的数据加密密钥和密钥加密密钥）时，它们应完全彼此独立。

### 密钥生命周期和轮换

应根据多个不同标准更改（或轮换）加密密钥：

- 如果先前的密钥已知（或怀疑）被泄露
    - 这也可能由拥有密钥访问权的人离开组织引起
- 经过指定的时间段（称为加密周期）
    - 影响适当加密周期的因素很多，包括密钥大小、数据敏感性和系统的威胁模型。有关进一步指导，请参见 [NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf) 第 5.3 节
- 在使用密钥加密特定数量的数据后
    - 对于 64 位密钥通常是 `2^35` 字节（~34GB），对于 128 位块大小则是 `2^68` 字节（~295 艾字节）
- 如果算法提供的安全性发生重大变化（如宣布新的攻击）

满足这些标准之一后，应生成新密钥并用于加密任何新数据。对于如何处理使用旧密钥加密的现有数据，主要有两种方法：

1. 解密并使用新密钥重新加密。
2. 使用加密该数据的密钥的 ID 标记每个项目，并存储多个密钥以允许解密旧数据。

通常应优先选择第一种方案，因为它极大地简化了应用程序代码和密钥管理流程；但并非总是可行。请注意，通常应在退役后保留旧密钥一段时间，以防需要解密旧备份或数据副本。

重要的是，在需要之前就已准备好用于轮换密钥的代码和流程，以便在发生泄露时可以快速轮换密钥。此外，还应实施流程以允许更改加密算法或库，以防在算法或实现中发现新的漏洞。

## 密钥存储

安全存储加密密钥是最难解决的问题之一，因为应用程序总是需要某种程度的密钥访问权限才能解密数据。虽然可能无法完全保护已完全入侵应用程序的攻击者获取密钥，但可以采取多个步骤使其更难获取密钥。

在可用的情况下，应使用操作系统、框架或云服务提供商提供的安全存储机制。这些包括：

- 物理硬件安全模块（HSM）
- 虚拟 HSM
- 密钥保险库，如 [Amazon KMS](https://aws.amazon.com/kms/) 或 [Azure Key Vault](https://azure.microsoft.com/en-gb/services/key-vault/)
- 外部秘密管理服务，如 [Conjur](https://github.com/cyberark/conjur) 或 [HashiCorp Vault](https://github.com/hashicorp/vault)
- .NET 框架中 [ProtectedData](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?redirectedfrom=MSDN&view=netframework-4.8) 类提供的安全存储 API

与简单地将密钥放在配置文件中相比，使用这些类型的安全存储有许多优势。具体优势取决于所使用的解决方案，但包括：

- 在容器化环境中集中管理密钥
- 轻松轮换和替换密钥
- 安全的密钥生成
- 简化遵守 FIPS 140 或 PCI DSS 等监管标准
- 使攻击者更难导出或窃取密钥

在某些情况下，如共享托管环境，这些方法都不可用，意味着无法为任何加密密钥获得高度保护。但仍可遵循以下基本规则：

- 不要将密钥硬编码到应用程序源代码中
- 不要将密钥签入版本控制系统
- 使用限制性权限保护包含密钥的配置文件
- 避免将密钥存储在环境变量中，因为它们可能通过 [phpinfo()](https://www.php.net/manual/en/function.phpinfo.php) 等函数或 `/proc/self/environ` 文件意外暴露

[秘密管理速查表](Secrets_Management_Cheat_Sheet.md)提供了有关安全存储秘密的更多详细信息。

### 密钥和数据分离

在可能的情况下，加密密钥应存储在与加密数据不同的位置。例如，如果数据存储在数据库中，则密钥应存储在文件系统中。这意味着如果攻击者只能访问其中一个（例如通过目录遍历或 SQL 注入），他们就无法同时访问密钥和数据。

根据环境架构，可能可以将密钥和数据存储在不同的系统上，这将提供更高程度的隔离。

### 加密存储的密钥

在可能的情况下，加密密钥本身应以加密形式存储。至少需要两个单独的密钥：

- 数据加密密钥（DEK）用于加密数据
- 密钥加密密钥（KEK）用于加密 DEK

要使其有效，KEK 必须与 DEK 分开存储。加密的 DEK 可以与数据一起存储，但只有在攻击者能够同时获取 KEK（存储在另一个系统上）时才可用。

KEK 应至少与 DEK 一样强。Google 的[信封加密](https://cloud.google.com/kms/docs/envelope-encryption)指南包含有关如何管理 DEK 和 KEK 的更多详细信息。

在更简单的应用程序架构（如共享托管环境）中，无法单独存储 KEK 和 DEK，这种方法的价值有限，因为攻击者可能同时获取两个密钥。但是，它可以为非熟练的攻击者提供额外的屏障。

可以使用密钥派生函数（KDF）从用户提供的输入（如密码）生成 KEK，然后用于加密随机生成的 DEK。这允许 KEK 易于更改（当用户更改其密码时），而无需重新加密数据（因为 DEK 保持不变）。
