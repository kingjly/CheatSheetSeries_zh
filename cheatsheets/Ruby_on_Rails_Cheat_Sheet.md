# Ruby on Rails 安全备忘录

## 介绍

这份*备忘录*旨在为开发者提供快速、基本的 Ruby on Rails 安全提示。它补充、扩展或强调了 Rails 核心[安全指南](https://guides.rubyonrails.org/security.html)中提出的要点。

Rails 框架为开发者抽象了许多繁琐的工作，并提供了快速、轻松完成复杂任务的方法。对于不熟悉 Rails 内部工作原理的新开发者来说，可能需要一套基本的指南来保护应用程序的基本方面。本文档的目的就是成为这样的指南。

## 安全项目

### 命令注入

Ruby 提供了一个名为 "eval" 的函数，可以基于字符串动态构建新的 Ruby 代码。它还有多种调用系统命令的方法。

``` ruby
eval("ruby code here")
system("os command here")
`ls -al /` # (反引号包含操作系统命令)
exec("os command here")
spawn("os command here")
open("| os command here")
Process.exec("os command here")
Process.spawn("os command here")
IO.binread("| os command here")
IO.binwrite("| os command here", "foo")
IO.foreach("| os command here") {}
IO.popen("os command here")
IO.read("| os command here")
IO.readlines("| os command here")
IO.write("| os command here", "foo")
```

虽然这些命令的功能非常有用，但在基于 Rails 的应用程序中使用时应该极其谨慎。通常，这是一个坏主意。如果必须使用，应使用可能值的白名单，并尽可能彻底地验证任何输入。

[Rails](https://guides.rubyonrails.org/security.html#command-line-injection) 和 [OWASP](https://owasp.org/www-community/attacks/Command_Injection) 的指南包含有关命令注入的更多信息。

### SQL 注入

Ruby on Rails 通常与称为 ActiveRecord 的 ORM 一起使用，尽管它灵活且可以与其他数据源一起使用。典型的简单 Rails 应用程序使用 Rails 模型上的方法查询数据。许多用例默认防止 SQL 注入。但是，仍然可以编写允许 SQL 注入的代码。

``` ruby
name = params[:name]
@projects = Project.where("name like '" + name + "'");
```

这个语句是可注入的，因为 name 参数没有被转义。

以下是构建此类语句的惯用方法：

``` ruby
@projects = Project.where("name like ?", "%#{ActiveRecord::Base.sanitize_sql_like(params[:name])}%")
```

注意不要基于用户控制的输入构建 SQL 语句。更多逼真和详细的示例可以在 [rails-sqli.org](https://rails-sqli.org) 找到。OWASP 对 [SQL 注入](https://owasp.org/www-community/attacks/SQL_Injection) 有大量信息。

### 跨站脚本（XSS）

默认情况下，XSS 防护是默认行为。当字符串数据显示在视图中时，在发送回浏览器之前会被转义。这已经很有帮助，但开发者有时会绕过这种保护 - 例如为了启用富文本编辑。如果要将带有标签的变量传递到前端，可能会诱惑开发者在 .erb 文件（Ruby 标记）中这样做：

``` ruby
# 错误！不要这样做！
<%= raw @product.name %>

# 错误！不要这样做！
<%== @product.name %>

# 错误！不要这样做！
<%= @product.name.html_safe %>
```

不幸的是，任何使用 `raw`、`html_safe` 或类似方法的字段都将成为潜在的 XSS 目标。请注意，关于 `html_safe()` 还存在广泛的误解。

[这篇文章](https://stackoverflow.com/questions/4251284/raw-vs-html-safe-vs-h-to-unescape-html)详细描述了底层的 SafeBuffer 机制。其他改变字符串输出准备方式的标签也可能引入类似问题。

String 的 `html_safe` 方法名称有些令人困惑。它意味着我们确定字符串的内容可以安全地包含在 HTML 中而无需转义。**这个方法本身是不安全的！**

如果必须接受用户的 HTML 内容，请考虑在应用程序中使用富文本的标记语言（例如：Markdown 和 textile）并禁止 HTML 标签。这有助于确保接受的输入不包含可能恶意的 HTML 内容。

如果无法限制用户输入 HTML，请考虑实施内容安全策略以禁止执行任何 JavaScript。最后，考虑使用允许列出允许标签的 `#sanitize` 方法。请小心，这个方法已多次被证明存在缺陷，永远不会是完整的解决方案。

对于旧版本的 Rails，一个经常被忽视的 XSS 攻击向量是链接的 `href` 值：

``` ruby
<%= link_to "个人网站", @user.website %>
```

如果 `@user.website` 包含以 `javascript:` 开头的链接，当用户点击生成的链接时将执行内容：

``` html
<a href="javascript:alert('Haxored')">个人网站</a>
```

较新的 Rails 版本以更好的方式转义此类链接。

``` ruby
link_to "个人网站", 'javascript:alert(1);'.html_safe()
# 将生成：
# "<a href="javascript:alert(1);">个人网站</a>"
```

使用[内容安全策略](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)是禁止执行以 `javascript:` 开头的链接的另一种安全措施。

[Brakeman 扫描器](https://github.com/presidentbeef/brakeman)有助于在 Rails 应用程序中发现 XSS 问题。

OWASP 在顶级页面上提供了关于 XSS 的更多一般信息：[跨站脚本（XSS）](https://owasp.org/www-community/attacks/xss/)。

### 会话

默认情况下，Ruby on Rails 使用基于 Cookie 的会话存储。这意味着除非更改某些内容，否则会话不会在服务器上过期。这意味着某些默认应用程序可能容易受到重放攻击。这也意味着敏感信息永远不应放入会话中。

最佳实践是使用基于数据库的会话，在 Rails 中这非常容易：

``` ruby
Project::Application.config.session_store :active_record_store
```

有一个[会话管理备忘录](Session_Management_Cheat_Sheet.md)。

### 认证

与所有敏感数据一样，首先在配置中启用 TLS 来保护您的认证：

``` ruby
# config/environments/production.rb
# 强制所有访问应用程序通过 SSL，使用严格传输安全，
# 并使用安全 Cookies
config.force_ssl = true
```

在您的配置中取消注释上面的第 3 行。

一般来说，Rails 本身不提供认证。然而，大多数使用 Rails 的开发者会利用 Devise 或 AuthLogic 等库来提供认证。

要启用认证，可以使用 Devise gem。

使用以下命令安装：

```bash
gem 'devise'
```

然后将其安装到用户模型：

```bash
rails generate devise:install
```

接下来，在路由中指定需要认证访问的资源：

``` ruby
Rails.application.routes.draw do
  authenticate :user do
    resources :something do  # 这些资源需要认证
      ...
    end
  end

  devise_for :users # 注册/登录/登出路由

  root to: 'static#home' # 无需认证
end
```

要强制密码复杂性，可以使用 [zxcvbn gem](https://github.com/bitzesty/devise_zxcvbn)。在用户模型中配置：

``` ruby
class User < ApplicationRecord
  devise :database_authenticatable,
    # 其他 devise 功能，然后
    :zxcvbnable
end
```

并配置所需的密码复杂性：

``` ruby
# 在 config/initializers/devise.rb 中
Devise.setup do |config|
  # devise 的 zxcvbn 分数
  config.min_password_score = 4 # 复杂性分数在这里
  ...
```

您可以尝试[这个概念验证](https://github.com/qutorial/revise)以了解更多。

接下来，[omniauth gem](https://github.com/omniauth/omniauth) 允许多种认证策略。使用它可以配置与 Facebook、LDAP 和许多其他提供者的安全认证。在[此处](https://github.com/omniauth/omniauth#integrating-omniauth-into-your-application)阅读更多。

#### 令牌认证

Devise 通常使用 Cookies 进行认证。

如果希望使用令牌认证，可以使用 [devise_token_auth](https://github.com/lynndylanhurley/devise_token_auth) gem。

它支持多种前端技术，例如 angular2-token。

此 gem 的配置类似于 devise gem 本身。它还需要 omniauth 作为依赖。

```bash
# 基于令牌的认证
gem 'devise_token_auth'
gem 'omniauth'
```

然后定义一个路由：

```ruby
mount_devise_token_auth_for 'User', at: 'auth'
```

并相应地修改用户模型。

这些操作可以通过一个命令完成：

```bash
rails g devise_token_auth:install [USER_CLASS] [MOUNT_PATH]
```

根据您的使用情况，您可能需要编辑生成的迁移以避免不必要的字段和/或字段重复。

注意：当您仅使用令牌认证时，控制器中不再需要 [CSRF](https://owasp.org/www-community/attacks/csrf) 保护。如果同时使用 Cookies 和令牌，使用 Cookies 进行认证的路径仍然必须防止伪造！

有一个[认证备忘录](Authentication_Cheat_Sheet.md)。

### 不安全的直接对象引用或强制浏览

默认情况下，Ruby on Rails 应用程序使用 RESTful URI 结构。这意味着路径通常是直观且可猜测的。为了防止用户尝试访问或修改属于另一个用户的数据，特别控制操作很重要。在原始的 Rails 应用程序中，没有这种内置保护。可以在控制器级别手动完成此操作。

还可以，并且可能推荐，考虑基于资源的访问控制库，如 [cancancan](https://github.com/CanCanCommunity/cancancan)（cancan 的替代品）或 [pundit](https://github.com/elabs/pundit)。这确保数据库对象的所有操作都经过应用程序的业务逻辑授权。

关于这类漏洞的更多一般信息，请参见 [OWASP Top 10 页面](https://wiki.owasp.org/index.php/Top_10_2010-A4-Insecure_Direct_Object_References)。

### CSRF（跨站请求伪造）

Ruby on Rails 对 CSRF 令牌有特定的内置支持。要启用它或确保已启用，请在基础 `ApplicationController` 中查找如下指令：

``` ruby
class ApplicationController < ActionController::Base
  protect_from_forgery
```

请注意，这种控制的语法包括添加例外的方法。例外可能对 API 或其他原因有用 - 但应经过审查并有意识地包含。在下面的示例中，Rails 的 ProjectController 不会为 show 方法提供 [CSRF](https://owasp.org/www-community/attacks/csrf) 保护。

``` ruby
class ProjectController < ApplicationController
  protect_from_forgery except: :show
```

另请注意，默认情况下，Rails 不会为任何 HTTP `GET` 请求提供 CSRF 保护。

**注意：** 如果仅使用令牌认证，则无需像这样在控制器中防止 CSRF。如果在某些路径上使用基于 Cookie 的认证，则仍然需要保护。

OWASP 有一个关于[跨站请求伪造（CSRF）](https://owasp.org/www-community/attacks/csrf)的顶级页面。

### 重定向和转发

Web 应用程序经常需要根据客户端提供的数据动态重定向用户。为了澄清，动态重定向通常需要客户端在请求中包含一个 URL 参数。一旦应用程序接收到请求，用户就会被重定向到请求中指定的 URL。

例如：

`http://www.example.com/redirect?url=http://www.example_commerce_site.com/checkout`

上述请求会将用户重定向到 `http://www.example.com/checkout`。与此功能相关的安全问题是利用组织的可信品牌来钓鱼用户，并诱骗他们访问恶意站点，在我们的示例中是 `badhacker.com`。

示例：

`http://www.example.com/redirect?url=http://badhacker.com`

最基本但限制性最强的保护是使用 `:only_path` 选项。将其设置为 true 将基本上去除任何主机信息。但是，`:only_path` 选项必须是第一个参数的一部分。如果第一个参数不是哈希表，则无法传入此选项。在没有自定义帮助程序或允许列表的情况下，这是一种可行的方法：

``` ruby
begin
  if path = URI.parse(params[:url]).path
    redirect_to path
  end
rescue URI::InvalidURIError
  redirect_to '/'
end
```

如果必须将用户输入与已批准站点列表或 TLD 的正则表达式匹配，那么利用 `URI.parse()` 获取主机，然后获取主机值并将其与正则表达式模式匹配是有意义的。这些正则表达式必须至少有锚点，否则攻击者更有可能绕过验证程序。

示例：

``` ruby
require 'uri'
host = URI.parse("#{params[:url]}").host
# 这可能容易受到 javascript://trusted.com/%0Aalert(0) 的攻击
# 所以也要检查 .scheme 和 .port
validation_routine(host) if host
def validation_routine(host)
  # 验证程序，我们使用 \A 和 \z 作为锚点，而不是 ^ 和 $
  # 你也可以根据允许列表检查主机值
end
```

盲目重定向到用户输入参数还可能导致 XSS。

示例代码：

``` ruby
redirect_to params[:to]
```

将生成此 URL：

`http://example.com/redirect?to[status]=200&to[protocol]=javascript:alert(0)//`

解决此类漏洞的明显方法是限制特定顶级域名（TLD）、静态定义特定站点或将键映射到其值。

示例代码：

``` ruby
ACCEPTABLE_URLS = {
  'our_app_1' => "https://www.example_commerce_site.com/checkout",
  'our_app_2' => "https://www.example_user_site.com/change_settings"
}
```

将生成此 URL：

`http://www.example.com/redirect?url=our_app_1`

重定向处理代码：

``` ruby
def redirect
  url = ACCEPTABLE_URLS["#{params[:url]}"]
  redirect_to url if url
end
```

OWASP 有一个关于[未验证的重定向和转发](Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)的更通用资源。

### 动态渲染路径

在 Rails 中，控制器操作和视图可以通过调用 `render` 方法动态确定要渲染的视图或局部视图。如果使用用户输入来确定模板名称，攻击者可能导致应用程序渲染任意视图，如管理页面。

在使用用户输入确定要渲染的视图时要小心。如果可能，请避免在视图名称或路径中使用任何用户输入。

### 跨域资源共享

有时需要与另一个域共享资源。例如，通过 AJAX 请求向另一个域发送数据的文件上传功能。在这些情况下，必须遵守 Web 浏览器的同源规则。符合 HTML5 标准的现代浏览器将允许这种情况发生，但为此必须采取一些预防措施。

使用非标准 HTTP 构造（例如非典型的 Content-Type 请求头）时，适用以下情况：

接收站点应仅列出允许发出此类请求的域，并在对 `OPTIONS` 请求和 `POST` 请求的响应中设置 `Access-Control-Allow-Origin` 请求头。这是因为首先发送 OPTIONS 请求，以确定远程或接收站点是否允许请求域。接下来，发送第二个请求，即 `POST` 请求。再次，必须设置请求头，以使事务显示为成功。

### 标准 HTTP 构造

*请求被发送，浏览器在接收响应后检查响应头，以确定是否可以和应该处理响应。*

Rails 中的允许列表：

**Gemfile:**

```bash
gem 'rack-cors', :require => 'rack/cors'
```

**config/application.rb:**

```ruby
module Sample
  class Application < Rails::Application
    config.middleware.use Rack::Cors do
      allow do
        origins 'someserver.example.com'
        resource %r{/users/\d+.json},
        :headers => ['Origin', 'Accept', 'Content-Type'],
        :methods => [:post, :get]
      end
    end
  end
end
```

### 安全相关的头

要设置头值，只需在控制器中将 response.headers 对象作为哈希访问（通常在 before/after_filter 中）。

```ruby
response.headers['X-header-name'] = 'value'
```

Rails 提供 `default_headers` 功能，将自动应用提供的值。这适用于几乎所有情况下的大多数头。

```ruby
ActionDispatch::Response.default_headers = {
  'X-Frame-Options' => 'SAMEORIGIN',
  'X-Content-Type-Options' => 'nosniff',
  'X-XSS-Protection' => '0'
}
```

[严格传输安全](https://owasp.org/www-project-secure-headers/#headers-link)是一个特殊情况，在环境文件中设置（例如 `production.rb`）

```ruby
config.force_ssl = true
```

对于非前沿版本，有一个库（[secure_headers](https://github.com/twitter/secureheaders)）提供相同的行为和内容安全策略抽象。它将根据用户代理自动应用逻辑以生成简洁的头集。

### 业务逻辑漏洞

任何技术的任何应用程序都可能包含导致安全漏洞的业务逻辑错误。业务逻辑漏洞很难甚至不可能使用自动化工具检测。防止业务逻辑安全漏洞的最佳方法是进行代码审查、结对编程和编写单元测试。

### 攻击面

一般来说，Rails 避免开放重定向和路径遍历类型的漏洞，因为其 `/config/routes.rb` 文件规定了哪些 URL 应该可访问以及由哪些控制器处理。在考虑攻击面范围时，路由文件是一个很好的查看位置。

一个示例如下：

```ruby
# 这是一个不应该做的示例
match ':controller(/:action(/:id(.:format)))'
```

在这种情况下，此路由允许调用任何控制器上的任何公共方法作为操作。作为开发者，你希望确保用户只能以预期的方式访问预期的控制器方法。

### 敏感文件

许多 Ruby on Rails 应用程序是开源的，托管在公开可用的源代码仓库上。无论是这种情况还是代码提交到公司源代码控制系统，都有一些应该被排除或仔细管理的文件。

```text
/config/database.yml                 -  可能包含生产凭据。
/config/initializers/secret_token.rb -  包含用于哈希会话 Cookie 的密钥。
/db/seeds.rb                         -  可能包含种子数据，包括引导管理员用户。
/db/development.sqlite3              -  可能包含真实数据。
```

### 加密

Rails 使用操作系统加密。一般来说，自己编写加密总是一个坏主意。

Devise 默认使用 bcrypt 进行密码哈希，这是一个适当的解决方案。

通常，以下配置会导致生产环境使用 10 次迭代：`/config/initializers/devise.rb`

```ruby
config.stretches = Rails.env.test? ? 1 : 10
```

## 更新 Rails 并制定更新依赖的流程

在 2013 年初，Rails 框架中发现了许多关键漏洞。落后于当前版本的组织在更新时遇到更多麻烦，并面临更艰难的决策，包括修补框架本身的源代码。

Ruby 应用程序的一个额外问题是，大多数库（gems）不是由其作者签名的。实际上不可能使用来自可信来源的库构建基于 Rails 的项目。一个好的做法可能是审核你正在使用的 gems。

一般来说，制定更新依赖的流程很重要。一个示例流程可能定义三种触发响应更新的机制：

- 每月/季度更新依赖项。
- 每周考虑重要的安全漏洞，并可能触发更新。
- 在特殊情况下，可能需要应用紧急更新。

## 工具

使用 [brakeman](https://brakemanscanner.org/)，这是一个用于 Rails 应用程序的开源代码分析工具，以识别许多潜在问题。它不一定会产生全面的安全发现，但可以找到容易暴露的问题。查看 brakeman 警告类型文档是了解 Rails 潜在问题的好方法。

一个较新的替代方案是 [bearer](https://github.com/Bearer/bearer)，这是一个用于 Ruby 和 JavaScript/TypeScript 代码的开源代码安全和隐私分析工具，用于识别广泛的 OWASP Top 10 潜在问题。它提供了许多配置选项，并可以轻松集成到 CI/CD 管道中。

有一些新兴工具可用于跟踪依赖集中的安全问题，如来自 [GitHub](https://github.blog/2017-11-16-introducing-security-alerts-on-github/) 和 [GitLab](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/) 的自动扫描。

另一个工具领域是安全测试工具 [Gauntlt](http://gauntlt.org)，它基于 cucumber 并使用 gherkin 语法定义攻击文件。

2013 年 5 月推出、与 brakeman 扫描器非常相似的 [dawnscanner](https://github.com/thesp0nge/dawnscanner) rubygem 是一个用于 Rails、Sinatra 和 Padrino Web 应用程序的静态安全问题分析器。1.6.6 版本有超过 235 个 Ruby 特定的 CVE 安全检查。

## 相关文章和参考资料

- [官方 Rails 安全指南](https://guides.rubyonrails.org/security.html)
- [OWASP Ruby on Rails 安全指南](https://owasp.org/www-pdf-archive/Rails_Security_2.pdf)
- [Ruby 安全审查指南](http://code.google.com/p/ruby-security/wiki/Guide)
- [Ruby on Rails 安全邮件列表](https://groups.google.com/forum/?fromgroups#!forum/rubyonrails-security)
- [Rails 不安全的默认设置](https://codeclimate.com/blog/rails-insecure-defaults/)
