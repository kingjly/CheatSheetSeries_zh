# 查询参数化备忘录

## 介绍

[SQL 注入](https://owasp.org/www-community/attacks/SQL_Injection)是最危险的 Web 漏洞之一。它在 OWASP Top 10 的 [2013 版本](https://wiki.owasp.org/index.php/Top_10_2013-A1-Injection)和 [2017 版本](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html)中都位居第一。截至 2021 年，它在 [OWASP Top 10](https://owasp.org/Top10/A03_2021-Injection/) 中排名第 3。

它代表了一个严重的威胁，因为 SQL 注入允许恶意攻击者代码以可以窃取数据、修改数据，甚至可能便于对底层操作系统进行命令注入的方式更改 Web 应用程序的 SQL 语句结构。

本备忘录是 [SQL 注入预防备忘录](SQL_Injection_Prevention_Cheat_Sheet.md) 的衍生作品。

## 参数化查询示例

通过使用[*参数化查询*](SQL_Injection_Prevention_Cheat_Sheet.md)可以最好地防止 SQL 注入。下面的图表通过大多数常见 Web 语言的实际代码示例，展示了如何构建参数化查询。这些代码示例的目的是向 Web 开发者展示在 Web 应用程序中构建数据库查询时如何避免 SQL 注入。

请注意，许多客户端框架和库提供客户端查询参数化。这些库通常在发送原始查询到服务器之前只是使用字符串拼接构建查询。请确保查询参数化在服务器端完成！

### 预处理语句示例

#### 使用 Java 内置特性

```java
String custname = request.getParameter("customerName");
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";  
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname);
ResultSet results = pstmt.executeQuery( );
```

#### 使用 Java 与 Hibernate

```java
// HQL
@Entity // 声明为实体
@NamedQuery(
 name="findByDescription",
 query="FROM Inventory i WHERE i.productDescription = :productDescription"
)
public class Inventory implements Serializable {
 @Id
 private long id;
 private String productDescription;
}

// 使用场景
// 这里确实应该进行验证
String userSuppliedParameter = request.getParameter("Product-Description");
// 执行输入验证以检测攻击
List<Inventory> list =
 session.getNamedQuery("findByDescription")
 .setParameter("productDescription", userSuppliedParameter).list();

// 条件 API
// 这里确实应该进行验证
String userSuppliedParameter = request.getParameter("Product-Description");
// 执行输入验证以检测攻击
Inventory inv = (Inventory) session.createCriteria(Inventory.class).add
(Restrictions.eq("productDescription", userSuppliedParameter)).uniqueResult();
```

#### 使用 .NET 内置特性

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

#### 使用 ASP .NET 内置特性

```csharp
string sql = "SELECT * FROM Customers WHERE CustomerId = @CustomerId";
SqlCommand command = new SqlCommand(sql);
command.Parameters.Add(new SqlParameter("@CustomerId", System.Data.SqlDbType.Int));
command.Parameters["@CustomerId"].Value = 1;
```

#### 使用 Ruby 与 ActiveRecord

```ruby
## 创建
Project.create!(:name => 'owasp')
## 读取
Project.all(:conditions => "name = ?", name)
Project.all(:conditions => { :name => name })
Project.where("name = :name", :name => name)
## 更新
project.update_attributes(:name => 'owasp')
## 删除
Project.delete(:name => 'name')
```

#### 使用 Ruby 内置特性

```ruby
insert_new_user = db.prepare "INSERT INTO users (name, age, gender) VALUES (?, ? ,?)"
insert_new_user.execute 'aizatto', '20', 'male'
```

#### 使用 PHP 与 PHP 数据对象

```php
$stmt = $dbh->prepare("INSERT INTO REGISTRY (name, value) VALUES (:name, :value)");
$stmt->bindParam(':name', $name);
$stmt->bindParam(':value', $value);
```

#### 使用 Cold Fusion 内置特性

```coldfusion
<cfquery name = "getFirst" dataSource = "cfsnippets">
    SELECT * FROM #strDatabasePrefix#_courses WHERE intCourseID =
    <cfqueryparam value = #intCourseID# CFSQLType = "CF_SQL_INTEGER">
</cfquery>
```

#### 使用 PERL 与数据库独立接口

```perl
my $sql = "INSERT INTO foo (bar, baz) VALUES ( ?, ? )";
my $sth = $dbh->prepare( $sql );
$sth->execute( $bar, $baz );
```

#### 使用 Rust 与 SQLx
<!-- 由 GeekMasher 贡献 -->

```rust
// 从 CLI 参数输入，但可以是任何内容
let username = std::env::args().last().unwrap();

// 使用内置宏（编译时检查）
let users = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE name = ?",
        username
    )
    .fetch_all(&pool)
    .await 
    .unwrap();

// 使用内置函数
let users: Vec<User> = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE name = ?"
    )
    .bind(&username)
    .fetch_all(&pool)
    .await
    .unwrap();
```

### 存储过程示例

在 Web 应用程序中编写的 SQL 并不是引入 SQL 注入漏洞的唯一位置。如果您使用存储过程，并且在其中动态构造 SQL，也可能引入 SQL 注入漏洞。

可以使用绑定变量对动态 SQL 进行参数化，以确保动态构造的 SQL 是安全的。

以下是不同数据库中使用绑定变量的存储过程示例。

#### Oracle 使用 PL/SQL

##### 普通存储过程

没有创建动态 SQL。传递给存储过程的参数自然绑定到查询中的位置，无需特别处理：

```sql
PROCEDURE SafeGetBalanceQuery(UserID varchar, Dept varchar) AS BEGIN
   SELECT balance FROM accounts_table WHERE user_ID = UserID AND department = Dept;
END;
```

##### 使用 EXECUTE 运行的存储过程中使用绑定变量

使用绑定变量告诉数据库，这个动态 SQL 的输入是"数据"而不是可能的代码：

```sql
PROCEDURE AnotherSafeGetBalanceQuery(UserID varchar, Dept varchar)
          AS stmt VARCHAR(400); result NUMBER;
BEGIN
   stmt := 'SELECT balance FROM accounts_table WHERE user_ID = :1
            AND department = :2';
   EXECUTE IMMEDIATE stmt INTO result USING UserID, Dept;
   RETURN result;
END;
```

#### SQL Server 使用 Transact-SQL

##### 普通存储过程

没有创建动态 SQL。传递给存储过程的参数自然绑定到查询中的位置，无需特别处理：

```sql
PROCEDURE SafeGetBalanceQuery(@UserID varchar(20), @Dept varchar(10)) AS BEGIN
   SELECT balance FROM accounts_table WHERE user_ID = @UserID AND department = @Dept
END
```

##### 使用 EXEC 运行的存储过程中使用绑定变量

使用绑定变量告诉数据库，这个动态 SQL 的输入是"数据"而不是可能的代码：

```sql
PROCEDURE SafeGetBalanceQuery(@UserID varchar(20), @Dept varchar(10)) AS BEGIN
   DECLARE @sql VARCHAR(200)
   SELECT @sql = 'SELECT balance FROM accounts_table WHERE '
                 + 'user_ID = @UID AND department = @DPT'
   EXEC sp_executesql @sql,
                      '@UID VARCHAR(20), @DPT VARCHAR(10)',
                      @UID=@UserID, @DPT=@Dept
END
```

## 参考文献

- [Bobby Tables 网站（受 XKCD 网络漫画启发）提供了不同语言中参数化预处理语句和存储过程的众多示例](http://bobby-tables.com/)
- OWASP [SQL 注入预防备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)
