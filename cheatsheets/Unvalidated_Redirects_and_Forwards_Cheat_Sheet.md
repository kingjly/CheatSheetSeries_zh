# 未验证重定向和转发备忘录

## 简介

当 Web 应用程序接受不可信的输入，可能导致应用程序将请求重定向到包含在不可信输入中的 URL 时，就会出现未验证的重定向和转发。通过修改不可信的 URL 输入到恶意站点，攻击者可能成功发起钓鱼骗局并窃取用户凭据。

由于修改后的链接中的服务器名称与原始站点相同，钓鱼尝试可能看起来更加可信。未验证的重定向和转发攻击还可用于恶意制作 URL，使其通过应用程序的访问控制检查，然后将攻击者转发到他们通常无法访问的特权功能。

## 安全的 URL 重定向

当我们希望自动将用户重定向到另一个页面（无需访问者的操作，如点击超链接）时，可以实现以下代码：

Java

```java
response.sendRedirect("http://www.mysite.com");
```

PHP

```php
<?php
/* 重定向浏览器 */
header("Location: http://www.mysite.com");
/* 退出以防止其余代码执行 */
exit;
?>
```

ASP .NET

```csharp
Response.Redirect("~/folder/Login.aspx")
```

Rails

```ruby
redirect_to login_path
```

Rust actix web

```rust
  Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, "https://mysite.com/"))
        .finish())
```

在上述示例中，URL 在代码中明确声明，攻击者无法操纵。

## 危险的 URL 重定向

以下示例演示了不安全的重定向和转发代码。

### 危险的 URL 重定向示例 1

以下 Java 代码从名为 `url` 的参数接收 URL（[GET 或 POST](https://docs.oracle.com/javaee/7/api/javax/servlet/ServletRequest.html#getParameter-java.lang.String-)）并重定向到该 URL：

```java
response.sendRedirect(request.getParameter("url"));
```

以下 PHP 代码从查询字符串（通过名为 `url` 的参数）获取 URL，然后将用户重定向到该 URL。此外，此 `header()` 函数之后的 PHP 代码将继续执行，因此如果用户配置其浏览器忽略重定向，他们可能能够访问页面的其余部分。

```php
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);
```

类似的 C\# .NET 易受攻击代码：

```csharp
string url = request.QueryString["url"];
Response.Redirect(url);
```

在 Rails 中：

```ruby
redirect_to params[:url]
```

Rust actix web

```rust
  Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, query_string.path.as_str()))
        .finish())
```

如果没有应用验证或额外的方法控制来验证 URL 的确定性，上述代码容易受到攻击。这种漏洞可以作为钓鱼骗局的一部分，通过将用户重定向到恶意站点。

如果不应用验证，恶意用户可以创建超链接以将您的用户重定向到未验证的恶意网站，例如：

```text
 http://example.com/example.php?url=http://malicious.example.com
```

用户看到链接指向原始可信站点（`example.com`），并没有意识到可能发生的重定向

### 危险的 URL 重定向示例 2

[ASP .NET MVC 1 和 2 网站](https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/preventing-open-redirection-attacks)特别容易受到开放重定向攻击。为了避免这种漏洞，您需要使用 MVC 3。

下面是 ASP.NET MVC 2 应用程序中 LogOn 操作的代码。成功登录后，控制器返回到 returnUrl 的重定向。可以看到，对 returnUrl 参数没有进行任何验证。

ASP.NET MVC 2 `AccountController.cs` 中的 LogOn 操作（请参阅上面提供的 Microsoft 文档链接）：

```csharp
[HttpPost]
 public ActionResult LogOn(LogOnModel model, string returnUrl)
 {
   if (ModelState.IsValid)
   {
     if (MembershipService.ValidateUser(model.UserName, model.Password))
     {
       FormsService.SignIn(model.UserName, model.RememberMe);
       if (!String.IsNullOrEmpty(returnUrl))
       {
         return Redirect(returnUrl);
       }
       else
       {
         return RedirectToAction("Index", "Home");
       }
     }
     else
     {
       ModelState.AddModelError("", "The user name or password provided is incorrect.");
     }
   }

   // 如果执行到这里，说明某些操作失败，重新显示表单
   return View(model);
 }
```

### 危险的转发示例

当应用程序允许用户输入在站点的不同部分之间转发请求时，应用程序必须检查：
- 用户是否有权访问该 URL
- 是否有权执行该 URL 提供的功能
- 是否是适当的 URL 请求

如果应用程序未执行这些检查，攻击者精心制作的 URL 可能会通过应用程序的访问控制检查，然后将攻击者转发到通常不允许的管理功能。

示例：

```text
http://www.example.com/function.jsp?fwd=admin.jsp
```

以下是一个 Java servlet，它将接收一个 `GET` 请求，其中包含名为 `fwd` 的 URL 参数，用于转发到 URL 参数中指定的地址。servlet 将从[请求](https://docs.oracle.com/javaee/7/api/javax/servlet/ServletRequest.html#getParameter-java.lang.String-)中检索 URL 参数值，并在响应浏览器之前完成服务器端转发处理。

```java
public class ForwardServlet extends HttpServlet
{
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
    String query = request.getQueryString();
    if (query.contains("fwd"))
    {
      String fwd = request.getParameter("fwd");
      try
      {
        request.getRequestDispatcher(fwd).forward(request, response);
      }
      catch (ServletException e)
      {
        e.printStackTrace();
      }
    }
  }
}
```

## 防止未验证的重定向和转发

安全使用重定向和转发可以通过以下方式实现：

- 简单地避免使用重定向和转发。
- 如果使用，不要允许 URL 作为目标的用户输入。
- 在可能的情况下，让用户提供短名称、ID 或令牌，这些在服务器端映射到完整的目标 URL。
    - 这提供了针对 URL 篡改攻击的最高程度保护。
    - 要小心不要引入枚举漏洞，即用户可以通过循环 ID 找到所有可能的重定向目标。
- 如果无法避免用户输入，请确保所提供的**值**是有效的、适合应用程序的，并且对用户是**授权**的。
- 通过创建可信 URL 列表（主机列表或正则表达式）来净化输入。
    - 这应该基于允许列表方法，而不是拒绝列表。
- 强制所有重定向首先通过一个页面，通知用户他们正要离开您的站点，并清楚地显示目标，然后让他们点击链接确认。

### 验证 URL

验证和净化用户输入以确定 URL 是否安全并非易事。如何实现 URL 验证的详细说明请参见[服务器端请求伪造防御备忘录](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#应用层)

## 参考资料

- [CWE 条目 601：开放重定向](http://cwe.mitre.org/data/definitions/601.html)
- [WASC 文章：URL 重定向器滥用](http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse)
- [Google 博客文章：开放重定向的危险](http://googlewebmastercentral.blogspot.com/2009/01/open-redirect-urls-is-your-site-being.html)
- [防止开放重定向攻击（C\#）](http://www.asp.net/mvc/tutorials/security/preventing-open-redirection-attacks)
