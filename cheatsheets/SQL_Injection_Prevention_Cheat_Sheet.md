# SQL注入防御备忘录

## 引言

本备忘录将帮助您防止应用程序中的SQL注入漏洞。它将定义什么是SQL注入，解释这些漏洞发生的位置，并提供四种防御SQL注入攻击的选项。[SQL注入](https://owasp.org/www-community/attacks/SQL_Injection)攻击很常见，原因是：

1. SQL注入漏洞非常普遍，
2. 应用程序的数据库通常是攻击者的频繁目标，因为它通常包含有趣或关键的数据。

## 什么是SQL注入攻击？

如果应用程序使用字符串拼接和用户提供的输入的动态数据库查询，攻击者就可以对其进行SQL注入。为避免SQL注入漏洞，开发者需要：

1. 停止使用字符串拼接编写动态查询，或
2. 防止恶意SQL输入被包含在执行的查询中。

有简单的技术可以防止SQL注入漏洞，这些技术几乎可以与任何编程语言和任何类型的数据库一起使用。虽然XML数据库可能存在类似问题（如XPath和XQuery注入），但这些技术也可用于保护它们。

## 典型SQL注入漏洞的剖析

下面是Java中常见的SQL注入缺陷。因为未经验证的"customerName"参数简单地附加到查询中，攻击者可以在该查询中输入SQL代码，应用程序会获取攻击者的代码并在数据库上执行。

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = "
             + request.getParameter("customerName");
try {
    Statement statement = connection.createStatement( ... );
    ResultSet results = statement.executeQuery( query );
}

...
```

## 主要防御策略

- **选项1：使用预编译语句（参数化查询）**
- **选项2：使用正确构建的存储过程**
- **选项3：白名单输入验证**
- **选项4：强烈不建议：转义所有用户提供的输入**

### 防御选项1：预编译语句（参数化查询）

当教导开发者如何编写数据库查询时，应该告诉他们使用带变量绑定的预编译语句（即参数化查询）。预编译语句易于编写且比动态查询更容易理解，参数化查询强制开发者先定义所有SQL代码，然后再将每个参数传递给查询。

如果数据库查询使用这种编码风格，无论用户输入是什么，数据库都将始终区分代码和数据。此外，预编译语句确保攻击者即使插入SQL命令也无法改变查询的意图。

#### 安全的Java预编译语句示例

在下面的安全Java示例中，如果攻击者输入用户ID为 `tom' or '1'='1`，参数化查询将查找完全匹配整个字符串 `tom' or '1'='1` 的用户名。因此，数据库将免受恶意SQL代码注入的攻击。

以下代码示例使用 `PreparedStatement`（Java中参数化查询的实现）执行相同的数据库查询。

```java
// 这里也应该进行验证
String custname = request.getParameter("customerName");
// 执行输入验证以检测攻击
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname);
ResultSet results = pstmt.executeQuery( );
```

#### 安全的C# .NET预编译语句示例

在.NET中，查询的创建和执行不会改变。只需使用 `Parameters.Add()` 调用将参数传递给查询，如下所示。

```csharp
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
try {
  OleDbCommand command = new OleDbCommand(query, connection);
  command.Parameters.Add(new OleDbParameter("customerName", CustomerName Name.Text));
  OleDbDataReader reader = command.ExecuteReader();
  // …
} catch (OleDbException se) {
  // 错误处理
}
```

虽然我们展示了Java和.NET的示例，但几乎所有其他语言（包括Cold Fusion和Classic ASP）都支持参数化查询接口。甚至SQL抽象层，如[Hibernate查询语言](http://hibernate.org/)（HQL），也有类似的注入问题（称为[HQL注入](http://cwe.mitre.org/data/definitions/564.html)），同样支持参数化查询：

#### Hibernate查询语言（HQL）预编译语句（命名参数）示例

```java
// 这是一个不安全的HQL语句
Query unsafeHQLQuery = session.createQuery("from Inventory where productID='"+userSuppliedParameter+"'");
// 这是使用命名参数的安全版本查询
Query safeHQLQuery = session.createQuery("from Inventory where productID=:productid");
safeHQLQuery.setParameter("productid", userSuppliedParameter);
```

#### 其他安全预编译语句示例

如需包括Ruby、PHP、Cold Fusion、Perl和Rust在内的参数化查询语言的示例，请参见[查询参数化备忘录](Query_Parameterization_Cheat_Sheet.md)或[这个网站](http://bobby-tables.com/)。

通常，开发者喜欢预编译语句，因为所有SQL代码都保留在应用程序中，这使得应用程序相对于数据库是独立的。

### 防御选项2：存储过程

尽管存储过程并非总是免于SQL注入，但开发者可以使用某些标准存储过程编程结构。只要安全地实现存储过程（这对于大多数存储过程语言来说是常态），这种方法与使用参数化查询的效果相同。

#### 存储过程的安全方法

如果需要存储过程，最安全的方法要求开发者使用自动参数化的参数构建SQL语句，除非开发者做一些非常规的事情。预编译语句和安全存储过程在防止SQL注入方面同样有效，因此您的组织应选择最适合自身的方法。

#### 存储过程可能增加风险的情况

在某些情况下，存储过程可能会在系统受到攻击时增加风险。例如，在MS SQL Server上，你有三个主要默认角色：`db_datareader`、`db_datawriter` 和 `db_owner`。在存储过程使用之前，数据库管理员会根据需求给Web服务用户 `db_datareader` 或 `db_datawriter` 权限。

然而，存储过程需要执行权限，这是默认不可用的角色。在一些用户管理集中但仅限于这三个角色的设置中，Web应用程序必须以 `db_owner` 身份运行，以便存储过程能够工作。自然地，这意味着如果服务器被攻破，攻击者将拥有对数据库的完全权限，而之前他们可能只有读取权限。

#### 安全的Java存储过程示例

下面的代码示例使用Java的存储过程接口实现（`CallableStatement`）来执行相同的数据库查询。`sp_getAccountBalance`存储过程必须预先在数据库中定义，并使用与上面查询相同的功能。

```java
// 这里应该进行验证
String custname = request.getParameter("customerName");
try {
  CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
  cs.setString(1, custname);
  ResultSet results = cs.executeQuery();
  // … 结果集处理
} catch (SQLException se) {
  // … 日志记录和错误处理
}
```

#### 安全的VB .NET存储过程示例

下面的代码示例使用`SqlCommand`（.NET的存储过程接口实现）执行相同的数据库查询。`sp_getAccountBalance`存储过程必须预先在数据库中定义，并使用与上面定义的查询相同的功能。

```vbnet
 Try
   Dim command As SqlCommand = new SqlCommand("sp_getAccountBalance", connection)
   command.CommandType = CommandType.StoredProcedure
   command.Parameters.Add(new SqlParameter("@CustomerName", CustomerName.Text))
   Dim reader As SqlDataReader = command.ExecuteReader()
   '...
 Catch se As SqlException
   '错误处理
 End Try
```

### 防御选项3：白名单输入验证

如果遇到无法使用绑定变量的SQL查询部分，如表名、列名或排序指示符（ASC或DESC），输入验证或查询重新设计是最合适的防御。当需要表名或列名时，理想情况下这些值应该来自代码，而不是用户参数。

#### 安全表名验证示例

警告：使用用户参数值作为表或列名的目标是设计不良的症状，如果时间允许，应考虑完全重写。如果不可能，开发者应将参数值映射到合法/预期的表或列名，以确保未经验证的用户输入不会出现在查询中。

在下面的示例中，由于`tableName`被识别为此查询中表名的合法和预期值之一，因此可以直接附加到SQL查询中。请记住，通用表验证函数可能导致数据丢失，如果在不期望的查询中使用表名。

```text
String tableName;
switch(PARAM):
  case "Value1": tableName = "fooTable";
                 break;
  case "Value2": tableName = "barTable";
                 break;
  ...
  default      : throw new InputValidationException("提供了意外的表名值");
```

#### 最安全的动态SQL生成（不推荐）

当我们说存储过程"安全实现"时，意味着它不包含任何不安全的动态SQL生成。开发者通常不会在存储过程内生成动态SQL。但是，如果无法避免，存储过程必须使用输入验证或适当的转义，以确保传递给存储过程的所有用户提供的输入不能用于将SQL代码注入动态生成的查询。审核员应始终查找SQL Server存储过程中`sp_execute`、`execute`或`exec`的使用。对于其他供应商的类似函数，也需要类似的审核指南。

#### 更安全的动态查询生成示例（不推荐）

对于像排序顺序这样简单的情况，最好将用户提供的输入转换为布尔值，然后使用该布尔值选择要附加到查询的安全值。这是动态查询创建中非常标准的需求。

例如：

```java
public String someMethod(boolean sortOrder) {
 String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");`
 ...
```

任何时候，在将用户输入附加到查询或用于选择要附加到查询的值之前，如果可以将其转换为非字符串类型（如日期、数字、布尔、枚举类型等），这就确保了这样做是安全的。

即使使用绑定变量，仍建议在所有情况下进行输入验证作为次要防御。关于如何实施强大的输入验证的更多技术，请参见[输入验证备忘录](Input_Validation_Cheat_Sheet.md)。

### 防御选项4：强烈不建议：转义所有用户提供的输入

在这种方法中，开发者在将输入放入查询之前转义所有用户输入。这种实现非常依赖于特定数据库。与其他防御相比，这种方法很脆弱，我们无法保证在所有情况下都能防止SQL注入。

如果应用程序是从头开始构建或需要低风险容忍度，它应该使用参数化查询、存储过程或某种为您构建查询的对象关系映射器（ORM）来构建或重写。

## 额外防御

除了采用四种主要防御之外，我们还建议采用所有这些额外防御以提供深度防御。这些额外防御包括：

- **最小权限**
- **白名单输入验证**

### 最小权限

为了最大限度地减少成功SQL注入攻击的潜在损害，您应该最大限度地减少环境中每个数据库帐户分配的权限。从头开始确定应用程序帐户所需的访问权限，而不是试图确定需要取消的访问权限。

确保只需要读取访问权限的帐户仅被授予对其需要访问的表的读取权限。不要为您的应用程序帐户分配DBA或管理员类型的访问权限。我们理解这样做很容易，而且一切看起来都能"正常工作"，但这非常危险。

#### 最小化应用程序和操作系统权限

SQL注入并不是对数据库数据的唯一威胁。攻击者可以简单地将参数值从他们被呈现的合法值之一更改为对他们未经授权但应用程序本身可能有权访问的值。因此，最大限度地减少授予应用程序的权限将降低此类未经授权的访问尝试的可能性，即使攻击者不试图将SQL注入作为其攻击的一部分。

在此过程中，您还应该最大限度地减少DBMS运行的操作系统帐户的权限。不要以root或system身份运行DBMS！大多数DBMS开箱即用时使用非常强大的系统帐户。例如，MySQL默认在Windows上以系统身份运行！将DBMS的操作系统帐户更改为更合适的、权限受限的帐户。

#### 开发时的最小权限细节

如果帐户只需要访问表的一部分，请考虑创建一个限制对该部分数据的访问的视图，并将帐户的访问权限分配给该视图，而不是底层表。很少（如果有的话）授予数据库帐户创建或删除的权限。

如果您采用在任何地方使用存储过程的策略，并且不允许应用程序帐户直接执行自己的查询，那么将这些帐户限制为只能执行他们需要的存储过程。不要直接授予他们对数据库中表的任何权限。

#### 多个数据库的最小管理权限

Web应用程序的设计者应避免使用相同的所有者/管理员帐户连接到数据库。不同的数据库用户应用于不同的Web应用程序。

通常，每个需要访问数据库的单独Web应用程序都应该有一个指定的数据库用户帐户，应用程序将使用该帐户连接到数据库。这样，应用程序的设计者可以在访问控制方面具有良好的粒度，从而尽可能减少权限。然后，每个数据库用户将只对其需要的内容具有选择访问权，并根据需要具有写入访问权。

作为一个例子，登录页面需要对表的用户名和密码字段具有读取访问权，但没有任何形式的写入访问权（无插入、更新或删除）。然而，注册页面肯定需要对该表具有插入权限；只有当这些Web应用程序使用不同的数据库用户连接到数据库时，才能强制执行这种限制。

#### 使用SQL视图增强最小权限

您可以使用SQL视图通过限制对表的特定字段或表连接的读取访问来进一步增加访问的粒度。这可能还有额外的好处。

例如，如果系统需要（可能是由于某些特定的法律要求）存储用户的密码，而不是盐哈希密码，设计者可以使用视图来弥补这一限制。他们可以撤销除所有者/管理员之外的所有数据库用户对表的所有访问权，并创建一个输出密码字段哈希值而不是字段本身的视图。

任何成功窃取数据库信息的SQL注入攻击都将被限制为窃取密码的哈希值（甚至可能是带密钥的哈希），因为没有任何Web应用程序的数据库用户可以直接访问表本身。

### 白名单输入验证

除了在没有其他方法时作为主要防御（例如，当绑定变量不合法时），输入验证还可以作为次要防御，用于在将输入传递到SQL查询之前检测未经授权的输入。有关更多信息，请参见[输入验证备忘录](Input_Validation_Cheat_Sheet.md)。在这里要谨慎行事。经过验证的数据不一定可以通过字符串构建安全地插入SQL查询。

## 相关文章

**SQL注入攻击备忘录**：

以下文章描述了如何在各种平台上利用不同类型的SQL注入漏洞（本文旨在帮助您避免这些漏洞）：

- [SQL注入备忘录](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
- 绕过WAF的SQL注入 - [SQL注入绕过WAF](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF)

**SQL注入漏洞描述**：

- OWASP关于[SQL注入](https://owasp.org/www-community/attacks/SQL_Injection)漏洞的文章
- OWASP关于[盲SQL注入](https://owasp.org/www-community/attacks/Blind_SQL_Injection)漏洞的文章

**如何避免SQL注入漏洞**：

- [OWASP开发者指南](https://github.com/OWASP/DevGuide)关于如何避免SQL注入漏洞的文章
- OWASP备忘录，提供使用预编译语句和存储过程的[多种语言特定参数化查询示例](Query_Parameterization_Cheat_Sheet.md)
- [Bobby Tables网站（受XKCD网络漫画启发）提供不同语言中参数化预编译语句和存储过程的众多示例](http://bobby-tables.com/)

**如何审查SQL注入漏洞的代码**：

- [OWASP代码审查指南](https://wiki.owasp.org/index.php/Category:OWASP_Code_Review_Project)关于如何[审查SQL注入](https://wiki.owasp.org/index.php/Reviewing_Code_for_SQL_Injection)漏洞的文章

**如何测试SQL注入漏洞**：

- [OWASP测试指南](https://owasp.org/www-project-web-security-testing-guide)关于如何[测试SQL注入](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html)漏洞的文章
