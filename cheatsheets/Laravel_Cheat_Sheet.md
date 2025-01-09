# Laravel 安全备忘录

## 引言

本 *备忘录* 旨在为构建 Laravel 应用程序的开发者提供安全建议。它旨在涵盖所有常见的安全漏洞以及如何确保 Laravel 应用程序的安全性。

Laravel 框架提供了内置的安全特性，并且默认情况下是安全的。然而，它还为复杂的用例提供了额外的灵活性。这意味着对 Laravel 内部工作原理不熟悉的开发者可能会陷入以不安全的方式使用复杂特性的陷阱。本指南旨在教育开发者避免常见的陷阱，并以安全的方式开发 Laravel 应用程序。

您还可以参考 [Enlightn 安全文档](https://www.laravel-enlightn.com/docs/security/)，其中突出了常见的安全漏洞和保护 Laravel 应用程序的最佳实践。

## 基础知识

- 确保在生产环境中关闭调试模式。要关闭调试模式，请将 `APP_DEBUG` 环境变量设置为 `false`：

```ini
APP_DEBUG=false
```

- 确保已生成应用程序密钥。Laravel 应用程序使用应用程序密钥进行对称加密和 SHA256 哈希，如 cookie 加密、签名 URL、密码重置令牌和会话数据加密。要生成应用程序密钥，您可以运行 `key:generate` Artisan 命令：

```bash
php artisan key:generate
```

- 确保 PHP 配置安全。您可以参考 [PHP 配置备忘录](PHP_Configuration_Cheat_Sheet.md)，了解更多关于安全的 PHP 配置设置。

- 为 Laravel 应用程序设置安全的文件和目录权限。通常，所有 Laravel 目录应设置最大权限级别为 `775`，非可执行文件的最大权限级别为 `664`。可执行文件（如 Artisan 或部署脚本）应提供最大权限级别 `775`。

- 确保应用程序没有易受攻击的依赖项。您可以使用 [Enlightn 安全检查器](https://github.com/enlightn/security-checker) 检查这一点。

## Cookie 安全和会话管理

默认情况下，Laravel 配置是安全的。但是，如果您更改 cookie 或会话配置，请确保以下几点：

- 如果使用 `cookie` 会话存储或存储任何不应被客户端读取或篡改的数据，请启用 cookie 加密中间件。通常，除非应用程序有非常特定的需要禁用此功能的用例，否则应启用此功能。要启用此中间件，只需在 `App\Http\Kernel` 类的 `web` 中间件组中添加 `EncryptCookies` 中间件：

```php
/**
 * 应用程序的路由中间件组。
 *
 * @var array
 */
protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\EncryptCookies::class,
        ...
    ],
    ...
];
```

- 通过 `config/session.php` 文件启用会话 cookie 的 `HttpOnly` 属性，使会话 cookie 对 Javascript 不可访问：

```php
'http_only' => true,
```

- 除非在 Laravel 应用程序中使用子域名路由注册，否则建议将 cookie 的 `domain` 属性设置为 null，以便只有同一来源（不包括子域名）可以设置 cookie。这可以在 `config/session.php` 文件中配置：

```php
'domain' => null,
```

- 在 `config/session.php` 文件中将 `SameSite` cookie 属性设置为 `lax` 或 `strict`，以将 cookie 限制在第一方或同站点上下文：

```php
'same_site' => 'lax',
```

- 如果您的应用程序仅使用 HTTPS，建议在 `config/session.php` 文件中将 `secure` 配置选项设置为 `true`，以防止中间人攻击。如果您的应用程序同时使用 HTTP 和 HTTPS，建议将此值设置为 `null`，以便在提供 HTTPS 请求时自动设置安全属性：

```php
'secure' => null,
```

- 确保会话空闲超时值较低。[OWASP 建议](Session_Management_Cheat_Sheet.md)对于高价值应用程序为 2-5 分钟的空闲超时，对于低风险应用程序为 15-30 分钟。这可以在 `config/session.php` 文件中配置：

```php
'lifetime' => 15,
```

您还可以参考 [Cookie 安全指南](https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20171130_Cookie_Security_Myths_Misconceptions_David_Johansson.pdf)，了解更多关于 cookie 安全性和上述 cookie 属性的信息。

## 身份验证

### 守卫和提供者

在其核心，Laravel 的身份验证设施由"守卫"和"提供者"组成。守卫定义了如何对每个请求进行身份验证。提供者定义了如何从持久存储中检索用户。

Laravel 自带一个使用会话存储和 cookie 维护状态的 `session` 守卫，以及用于 API 令牌的 `token` 守卫。

对于提供者，Laravel 自带使用 Eloquent ORM 检索用户的 `eloquent` 提供者和使用数据库查询构建器检索用户的 `database` 提供者。

守卫和提供者可以在 `config/auth.php` 文件中配置。Laravel 还提供构建自定义守卫和提供者的能力。

### 入门套件

Laravel 提供了多种包含内置身份验证功能的官方应用程序入门套件：

1. [Laravel Breeze](https://laravel.com/docs/8.x/starter-kits#laravel-breeze)：Laravel 所有身份验证功能的简单、最小实现，包括登录、注册、密码重置、电子邮件验证和密码确认。
2. [Laravel Fortify](https://laravel.com/docs/fortify)：一个无头身份验证后端，包括上述身份验证功能以及双因素身份验证。
3. [Laravel Jetstream](https://jetstream.laravel.com/)：在 Laravel Fortify 身份验证功能之上提供 UI 的应用程序入门套件。

建议使用这些入门套件之一，以确保 Laravel 应用程序的强大和安全的身份验证。

### API 身份验证包

Laravel 还提供以下 API 身份验证包：

1. [Passport](https://laravel.com/docs/passport)：OAuth2 身份验证提供者。
2. [Sanctum](https://laravel.com/docs/sanctum)：API 令牌身份验证提供者。

Fortify 和 Jetstream 等入门套件内置支持 Sanctum。

## 批量赋值

[批量赋值](Mass_Assignment_Cheat_Sheet.md)是使用像 Laravel 的 Eloquent ORM 这样的 ORM 的现代 Web 应用程序中的常见漏洞。

批量赋值是一种漏洞，攻击者滥用 ORM 模式来修改用户通常不应被允许修改的数据项。

考虑以下代码：

```php
Route::any('/profile', function (Request $request) {
    $request->user()->forceFill($request->all())->save();

    $user = $request->user()->fresh();

    return response()->json(compact('user'));
})->middleware('auth');
```

上述配置文件路由允许登录用户更改其个人资料信息。

然而，假设用户表中有一个 `is_admin` 列。您可能不希望用户更改此列的值。但是，上述代码允许用户更改用户表中其行的任何列值。这是一个批量赋值漏洞。

Laravel 默认提供了内置功能来防止此漏洞。请确保以下几点以保持安全：

- 使用 `$request->only` 或 `$request->validated` 限定要更新的允许参数，而不是使用 `$request->all`。
- 不要取消模型保护或将 `$guarded` 变量设置为空数组。这样做实际上会禁用 Laravel 的内置批量赋值保护。
- 避免使用绕过保护机制的方法，如 `forceFill` 或 `forceCreate`。但是，如果传入经过验证的值数组，您可以使用这些方法。

## SQL 注入

SQL 注入攻击在现代 Web 应用程序中非常常见，攻击者通过提供恶意请求输入数据来干扰 SQL 查询。本指南介绍 SQL 注入及如何在 Laravel 应用程序中防范。您还可以参考 [SQL 注入预防备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)，了解更多不特定于 Laravel 的信息。

### Eloquent ORM SQL 注入保护

默认情况下，Laravel 的 Eloquent ORM 通过参数化查询和使用 SQL 绑定来防止 SQL 注入。例如，考虑以下查询：

```php
use App\Models\User;

User::where('email', $email)->get();
```

上述代码执行以下查询：

```sql
select * from `users` where `email` = ?
```

因此，即使 `$email` 是不可信的用户输入数据，您也受到 SQL 注入攻击的保护。

### 原始查询 SQL 注入

Laravel 还提供原始查询表达式和原始查询，以构建复杂查询或数据库特定查询。

虽然这为灵活性提供了便利，但您必须始终小心使用 SQL 数据绑定。考虑以下查询：

```php
use Illuminate\Support\Facades\DB;
use App\Models\User;

User::whereRaw('email = "'.$request->input('email').'"')->get();
DB::table('users')->whereRaw('email = "'.$request->input('email').'"')->get();
```

这两行代码实际上执行相同的查询，由于未对不可信的用户输入数据使用 SQL 绑定，因此容易受到 SQL 注入攻击。

上述代码执行以下查询：

```sql
select * from `users` where `email` = "email 查询参数的值"
```

始终记得对请求数据使用 SQL 绑定。我们可以通过以下修改来修复上述代码：

```php
use App\Models\User;

User::whereRaw('email = ?', [$request->input('email')])->get();
```

我们甚至可以使用命名 SQL 绑定：

```php
use App\Models\User;

User::whereRaw('email = :email', ['email' => $request->input('email')])->get();
```

### 列名 SQL 注入

您绝不能允许用户输入数据决定查询引用的列名。

以下查询可能容易受到 SQL 注入：

```php
use App\Models\User;

User::where($request->input('colname'), 'somedata')->get();
User::query()->orderBy($request->input('sortBy'))->get();
```

需要注意的是，尽管 Laravel 有一些内置功能（如包装列名）来防止上述 SQL 注入漏洞，但某些数据库引擎（取决于版本和配置）可能仍然容易受到攻击，因为数据库不支持绑定列名。

至少，这可能导致批量赋值漏洞，而不是 SQL 注入，因为您可能期望某组列值，但由于这里没有验证，用户可以自由使用其他列。

始终验证此类情况下的用户输入：

```php
use App\Models\User;

$request->validate(['sortBy' => 'in:price,updated_at']);
User::query()->orderBy($request->validated()['sortBy'])->get();
```

### 验证规则 SQL 注入

某些验证规则可以提供数据库列名。这些规则以与列名 SQL 注入相同的方式容易受到 SQL 注入攻击，因为它们以类似的方式构造查询。

例如，以下代码可能容易受到攻击：

```php
use Illuminate\Validation\Rule;

$request->validate([
    'id' => Rule::unique('users')->ignore($id, $request->input('colname'))
]);
```

在幕后，上述代码触发以下查询：

```php
use App\Models\User;

$colname = $request->input('colname');
User::where($colname, $request->input('id'))->where($colname, '<>', $id)->count();
```

由于列名由用户输入决定，这类似于列名 SQL 注入。

## 跨站脚本（XSS）

[XSS 攻击](https://owasp.org/www-community/attacks/xss/)是指将恶意脚本（如 JavaScript 代码片段）注入可信网站的注入攻击。

Laravel 的 [Blade 模板引擎](https://laravel.com/docs/blade)具有 echo 语句 `{{ }}`，它使用 PHP 的 `htmlspecialchars` 函数自动转义变量，以防止 XSS 攻击。

Laravel 还提供使用非转义语法 `{!! !!}` 显示未转义数据的功能。对于任何不可信的数据，都不得使用此语法，否则您的应用程序将受到 XSS 攻击。

例如，如果在任何 Blade 模板中有如下内容，将导致漏洞：

```blade
{!! request()->input('somedata') !!}
```

而这是安全的：

```blade
{{ request()->input('somedata') }}
```

关于不特定于 Laravel 的 XSS 预防的其他信息，您可以参考 [跨站脚本预防备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)。

## 不受限制的文件上传

不受限制的文件上传攻击是指攻击者上传恶意文件以破坏 Web 应用程序。本节描述在构建 Laravel 应用程序时如何防范此类攻击。您还可以参考 [文件上传备忘录](File_Upload_Cheat_Sheet.md)以了解更多。

### 始终验证文件类型和大小

始终验证文件类型（扩展名或 MIME 类型）和文件大小，以避免存储 DOS 攻击和远程代码执行：

```php
$request->validate([
    'photo' => 'file|size:100|mimes:jpg,bmp,png'
]);
```

存储 DOS 攻击利用缺失的文件大小验证，上传大量文件以通过耗尽磁盘空间造成拒绝服务（DOS）。

远程代码执行攻击首先上传恶意可执行文件（如 PHP 文件），然后通过访问文件 URL（如果是公开的）触发其恶意代码。

如上所述，这两种攻击都可以通过简单的文件验证来避免。

### 不要依赖用户输入来决定文件名或路径

如果您的应用程序允许用户控制的数据构造文件上传路径，可能会导致覆盖关键文件或将文件存储在不恰当的位置。

考虑以下代码：

```php
Route::post('/upload', function (Request $request) {
    $request->file('file')->storeAs(auth()->id(), $request->input('filename'));

    return back();
});
```

此路由将文件保存到特定用户 ID 的目录。这里我们依赖 `filename` 用户输入数据，这可能导致漏洞，因为文件名可能是 `../2/filename.pdf` 之类的内容。这将在用户 ID 2 的目录中上传文件，而不是当前登录用户的目录。

要修复此问题，我们应使用 PHP 的 `basename` 函数从 `filename` 输入数据中剥离任何目录信息：

```php
Route::post('/upload', function (Request $request) {
    $request->file('file')->storeAs(auth()->id(), basename($request->input('filename')));

    return back();
});
```

### 尽可能避免处理 ZIP 或 XML 文件

XML 文件可能使您的应用程序暴露于各种攻击，如 XXE 攻击、十亿笑攻击等。如果处理 ZIP 文件，可能会遭受 ZIP 炸弹 DOS 攻击。

请参考 [XML 安全备忘录](XML_Security_Cheat_Sheet.md)和 [文件上传备忘录](File_Upload_Cheat_Sheet.md)以了解更多。

## 路径遍历

路径遍历攻击旨在通过使用 `../` 序列及其变体或使用绝对文件路径来操纵请求输入数据，从而访问文件。

如果允许用户通过文件名下载文件，且未从输入数据中剥离目录信息，则可能会遭受此漏洞。

考虑以下代码：

```php
Route::get('/download', function(Request $request) {
    return response()->download(storage_path('content/').$request->input('filename'));
});
```

在这里，文件名未剥离目录信息，因此像 `../../.env` 这样的格式错误的文件名可能会将您的应用程序凭据暴露给潜在攻击者。

与不受限制的文件上传类似，您应使用 PHP 的 `basename` 函数来剥离目录信息：

```php
Route::get('/download', function(Request $request) {
    return response()->download(storage_path('content/').basename($request->input('filename')));
});
```

## 开放重定向

开放重定向攻击本身并不太危险，但它们能够启用钓鱼攻击。

考虑以下代码：

```php
Route::get('/redirect', function (Request $request) {
   return redirect($request->input('url'));
});
```

此代码将用户重定向到用户输入提供的任何外部 URL。这可能使攻击者创建看似安全的 URL，如 `https://example.com/redirect?url=http://evil.com`。例如，攻击者可能使用此类 URL 来伪造密码重置电子邮件，并诱导受害者在攻击者的网站上泄露其凭据。

## 跨站请求伪造（CSRF）

[跨站请求伪造（CSRF）](https://owasp.org/www-community/attacks/csrf)是一种攻击，当恶意网站、电子邮件、博客、即时消息或程序在用户已通过身份验证时，导致用户的 Web 浏览器在可信站点上执行非预期操作。

Laravel 通过 `VerifyCSRFToken` 中间件提供开箱即用的 CSRF 保护。通常，如果在 `App\Http\Kernel` 类的 `web` 中间件组中有此中间件，您应该已经得到很好的保护：

```php
/**
 * 应用程序的路由中间件组。
 *
 * @var array
 */
protected $middlewareGroups = [
    'web' => [
        ...
         \App\Http\Middleware\VerifyCsrfToken::class,
         ...
    ],
];
```

接下来，对于所有 `POST` 请求表单，您可以使用 `@csrf` Blade 指令生成隐藏的 CSRF 输入令牌字段：

```html
<form method="POST" action="/profile">
    @csrf

    <!-- 等同于... -->
    <input type="hidden" name="_token" value="{{ csrf_token() }}" />
</form>
```

对于 AJAX 请求，您可以设置 [X-CSRF-Token 标头](https://laravel.com/docs/csrf#csrf-x-csrf-token)。

Laravel 还提供了使用 CSRF 中间件类中的 `$except` 变量从 CSRF 保护中排除某些路由的能力。通常，您只想从 CSRF 保护中排除无状态路由（如 API 或 Webhook）。如果排除任何其他路由，可能会导致 CSRF 漏洞。

## 命令注入

命令注入漏洞涉及执行使用未转义用户输入数据构造的 shell 命令。

例如，以下代码对用户提供的域名执行 `whois`：

```php
public function verifyDomain(Request $request)
{
    exec('whois '.$request->input('domain'));
}
```

上述代码容易受到攻击，因为用户数据未正确转义。为此，您可以使用 PHP 的 `escapeshellcmd` 和/或 `escapeshellarg` 函数。

## 其他注入

对象注入、eval 代码注入和 extract 变量劫持攻击涉及对不可信的用户输入数据进行反序列化、求值或使用 `extract` 函数。

一些示例：

```php
unserialize($request->input('data'));
eval($request->input('data'));
extract($request->all());
```

通常，避免将任何不可信的输入数据传递给这些危险函数。

## 安全标头

您应考虑在 Web 服务器或 Laravel 应用程序中间件中添加以下安全标头：

- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security（仅适用于 HTTPS 应用程序）
- Content-Security-Policy

更多信息，请参考 [OWASP 安全标头项目](https://owasp.org/www-project-secure-headers/)。

## 工具

您应考虑使用 [Enlightn](https://www.laravel-enlightn.com/)，这是一个用于 Laravel 应用程序的静态和动态分析工具，具有超过 45 个自动化安全检查，可识别潜在的安全问题。Enlightn 有开源版本和商业版本。Enlightn 包含一份详细的 45 页安全漏洞文档，了解 Laravel 安全性的好方法是查看其[文档](https://www.laravel-enlightn.com/docs/security/)。

您还应使用 [Enlightn 安全检查器](https://github.com/enlightn/security-checker)或 [本地 PHP 安全检查器](https://github.com/fabpot/local-php-security-checker)。这两个都是开源包，分别在 MIT 和 AGPL 许可下授权，它们使用[安全咨询数据库](https://github.com/FriendsOfPHP/security-advisories)扫描 PHP 依赖项中的已知漏洞。

## 参考资料

- [Laravel 身份验证文档](https://laravel.com/docs/authentication)
- [Laravel 授权文档](https://laravel.com/docs/authorization)
- [Laravel CSRF 文档](https://laravel.com/docs/csrf)
- [Laravel 验证文档](https://laravel.com/docs/validation)
- [Enlightn SAST 和 DAST 工具](https://www.laravel-enlightn.com/)
- [Laravel Enlightn 安全文档](https://www.laravel-enlightn.com/docs/security/)
