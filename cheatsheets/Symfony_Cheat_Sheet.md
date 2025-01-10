# Symfony 安全备忘录

## 引言

本备忘录旨在为使用 Symfony 框架构建应用程序的开发者提供安全建议。
它涵盖了常见的漏洞和最佳实践，以确保您的 Symfony 应用程序安全。

尽管 Symfony 自带内置的安全机制，但开发者必须了解潜在的漏洞和最佳实践，以确保他们构建的应用程序是安全的。
本指南旨在涵盖常见的安全问题，强调理解 Symfony 安全特性及其有效利用的重要性。
无论您是 Symfony 新手还是希望加强安全实践的经验丰富的开发者，本文档都是一个宝贵的资源。
通过遵循此处概述的指南，您可以增强 Symfony 应用程序的安全性，为用户和数据创建一个更安全的数字环境。

## 主要章节

### 跨站脚本攻击（XSS）

跨站脚本攻击（Cross-Site Scripting，XSS）是一种将恶意 JavaScript 代码注入显示变量的攻击类型。
例如，如果变量 name 的值是 `<script>alert('hello')</script>`，并且我们在 HTML 中这样显示：`Hello {{name}}`，那么在 HTML 渲染时，注入的脚本将被执行。

Symfony 默认使用 Twig 模板，通过**输出转义**自动保护应用程序免受 XSS 攻击，方法是使用 `{{ }}` 语句包装包含特殊字符的变量。

```twig
<p>Hello {{name}}</p>
{# 如果 'name' 是 '<script>alert('hello!')</script>'，Twig 将输出：
'<p>Hello &lt;script&gt;alert(&#39;hello!&#39;)&lt;/script&gt;</p>' #}
```

如果您要渲染一个受信任且包含 HTML 内容的变量，可以使用 *Twig 原始过滤器* 来禁用输出转义。

```twig
<p>{{ product.title|raw }}</p>
{# 如果 'product.title' 是 'Lorem <strong>Ipsum</strong>'，Twig 将原样输出
而不是 'Lorem &lt;strong&gt;Ipsum&lt;/strong&gt;' #}
```

查看 [Twig 输出转义文档](https://twig.symfony.com/doc/3.x/api.html#escaper-extension)，了解如何为特定块或整个模板禁用输出转义。

关于不特定于 Symfony 的 XSS 防护的更多信息，您可以参考 [跨站脚本防护备忘录](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)。

### 跨站请求伪造（CSRF）

Symfony 表单组件自动在表单中包含 CSRF 令牌，提供针对 CSRF 攻击的内置保护。
Symfony 自动验证这些令牌，无需手动干预即可保护您的应用程序。

默认情况下，CSRF 令牌作为名为 `_token` 的隐藏字段添加，但可以在每个表单的基础上使用其他设置进行自定义：

```php
use Symfony\Component\Form\AbstractType;
use Symfony\Component\OptionsResolver\OptionsResolver;

class PostForm extends AbstractType
{
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            // ... 
            'csrf_protection' => true,  // 为此表单启用/禁用 csrf 保护
            'csrf_field_name' => '_csrf_token',
            'csrf_token_id'   => 'post_item', // 更改用于生成的任意字符串
        ]);
    }
}
```

如果您不使用 Symfony 表单，可以自行生成和验证 CSRF 令牌。为此，您需要安装 `symfony/security-csrf` 组件。

```bash
composer install symfony/security-csrf
```

在 `config/packages/framework.yaml` 文件中启用/禁用 CSRF 保护：

```yaml
framework:
    csrf_protection: ~
```

接下来，考虑这个 HTML Twig 模板，其中 CSRF 令牌由 `csrf_token()` Twig 函数生成：

```twig
<form action="{{ url('delete_post', { id: post.id }) }}" method="post">
    <input type="hidden" name="token" value="{{ csrf_token('delete-post') }}">
    <button type="submit">删除帖子</button>
</form>
```

然后，您可以在控制器中使用 `isCsrfTokenValid()` 函数获取 CSRF 令牌的值：

```php
use App\Entity\Post;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ExampleController extends AbstractController
{
    #[Route('/posts/{id}', methods: ['DELETE'], name: 'delete_post')]
    public function delete(Post $post, Request $request): Response 
    { 
        $token = $request->request->get('token');
        if($this->isCsrfTokenValid($token)) {
            // ...
        }
        
        // ...
    }
}
```

您可以在 [跨站请求伪造（CSRF）备忘录](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) 中找到更多与 Symfony 无关的 CSRF 信息。

### SQL 注入

SQL 注入是一种安全漏洞，当攻击者能够以执行任意 SQL 代码的方式操纵 SQL 查询时发生。
这可能允许攻击者查看、修改或删除数据库中的数据，从而可能导致未经授权的访问或数据丢失。

特别是在与 Doctrine ORM（对象关系映射）一起使用时，Symfony 通过预处理语句参数提供了防止 SQL 注入的保护。
由于这一点，更难以无意中编写未受保护的查询，但仍然是可能的。
以下示例展示了**不安全的 DQL 使用**：

```php
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ExampleController extends AbstractController {
    
    public function getPost(Request $request, EntityManagerInterface $em): Response
    {
        $id = $request->query->get('id');

        $dql = "SELECT p FROM App\Entity\Post p WHERE p.id = " . $id . ";";
        $query = $em->createQuery($dql);
        $post = $query->getSingleResult();

        // ...
    }
}

```

下面的示例展示了防止 SQL 注入的**正确方法**：

- 使用实体仓库内置方法

```php
$id = $request->query->get('id');
$post = $em->getRepository(Post::class)->findOneBy(['id' => $id]);
```

- 使用 Doctrine DQL 语言

```php
$query = $em->createQuery("SELECT p FROM App\Entity\Post p WHERE p.id = :id");
$query->setParameter('id', $id);
$post = $query->getSingleResult();
```

- 使用 DBAL 查询构建器

```php
$qb = $em->createQueryBuilder();
$post = $qb->select('p')
            ->from('posts','p')
            ->where('id = :id')
            ->setParameter('id', $id)
            ->getQuery()
            ->getSingleResult();
```

关于 Doctrine 的更多信息，您可以参考[他们的文档](https://www.doctrine-project.org/index.html)。
您还可以参考 [SQL 注入预防备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)以获取不特定于 Symfony 或 Doctrine 的更多信息。

### 命令注入

命令注入发生在恶意代码被注入并在应用系统中执行的情况。
更多信息请参考[命令注入防御备忘录](OS_Command_Injection_Defense_Cheat_Sheet.md)。

考虑以下示例，其中使用 exec() 函数删除文件且没有对输入进行转义：

```php
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Annotation\Route;

#[AsController]
class ExampleController 
{

    #[Route('/remove_file', methods: ['POST'])]
    public function removeFile(Request $request): Response
    {
        $filename =  $request->request->get('filename');
        exec(sprintf('rm %s', $filename));

        // ...
    }
}
```

在上面的代码中，没有对用户输入进行验证。想象一下，如果用户提供了像 `test.txt && rm -rf .` 这样的恶意值会发生什么。为了降低这种风险，建议使用原生 PHP 函数，如此处的 `unlink()` 或 Symfony 文件系统组件的 `remove()` 方法，而不是 `exec()`。

对于与您的情况相关的特定 PHP 文件系统函数，您可以参考 [PHP 文档](https://www.php.net/manual/en/refs.fileprocess.file.php) 或 [Symfony 文件系统组件文档](https://symfony.com/doc/current/components/filesystem.html)。

### 开放重定向

开放重定向是一种安全缺陷，当 Web 应用程序将用户重定向到未经验证的参数指定的 URL 时发生。攻击者利用这一漏洞将用户重定向到恶意站点。

在提供的 PHP 代码片段中：

```php
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapQueryParameter;
use Symfony\Component\Routing\Annotation\Route;

class ExampleController extends AbstractController 
{

    #[Route('/dynamic_redirect', methods: ['GET'])]
    public function dynamicRedirect(#[MapQueryParameter] string $url): Response 
    {
        return $this->redirect($url);
    }
}
```

控制器函数基于 `url` 查询参数重定向用户，且没有适当的验证。攻击者可以制作恶意 URL，导致毫无戒心的用户访问恶意站点。为防止开放重定向，始终在重定向之前验证和清理用户输入，并避免在重定向函数中直接使用不可信的输入。

### 文件上传漏洞

文件上传漏洞是指应用程序未能正确验证和处理文件上传时出现的安全问题。确保安全处理文件上传以防止各种类型的攻击非常重要。以下是在 Symfony 中缓解此问题的一些通用准则：

#### 验证文件类型和大小

始终在服务器端验证文件类型，确保只接受允许的文件类型。
同时，考虑限制上传文件的大小，以防止拒绝服务攻击并确保服务器有足够的资源处理上传。

使用 PHP 属性的示例：

```php
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\Validator\Constraints\File;

class UploadDto
{
    public function __construct(
        #[File(
            maxSize: '1024k',
            mimeTypes: [
                'application/pdf',
                'application/x-pdf',
            ],
        )]
        public readonly UploadedFile $file,
    ){}
}
```

使用 Symfony 表单的示例：

```php
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\File;

class FileForm extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('file', FileType::class, [
                'constraints' => [
                    new File([
                        'maxSize' => '1024k', 
                        'mimeTypes' => [
                            'application/pdf',
                            'application/x-pdf',
                        ],
                    ]),
                ],
            ]);
    }
}
```

#### 使用唯一文件名

确保每个上传的文件都有唯一的名称，以防止覆盖现有文件。您可以使用唯一标识符和原始文件名的组合来生成唯一的名称。

#### 安全存储上传文件

将上传的文件存储在公共目录之外，以防止直接访问。如果您使用公共目录存储文件，请配置您的 Web 服务器以拒绝访问上传目录。

请参考 [文件上传备忘录](File_Upload_Cheat_Sheet.md) 以了解更多。

### 目录遍历

目录或路径遍历攻击旨在通过操纵引用文件的输入数据，使用 "../"（点-点-斜杠）序列及其变体或使用绝对文件路径来访问存储在服务器上的文件和目录。
更多详细信息请参考 [OWASP 路径遍历](https://owasp.org/www-community/attacks/Path_Traversal)。

您可以通过验证请求文件位置的绝对路径是否正确，或从文件名输入中剥离目录信息来保护应用程序免受目录遍历攻击。

- 使用 PHP 的 *realpath* 函数检查路径是否存在，并检查它是否指向存储目录

```php
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapQueryParameter;
use Symfony\Component\Routing\Annotation\Route;

class ExampleController extends AbstractController 
{

    #[Route('/download', methods: ['GET'])]
    public function download(#[MapQueryParameter] string $filename): Response 
    {
        $storagePath = $this->getParameter('kernel.project_dir') . '/storage';
        $filePath = $storagePath . '/' . $filename;

        $realBase = realpath($storagePath);
        $realPath = realpath($filePath);

        if ($realPath === false || !str_starts_with($realPath, $realBase))
        {
            //目录遍历！
        }

        // ...

    }
}
```

- 使用 PHP 的 *basename* 函数剥离目录信息

```php
// ...

$storagePath = $this->getParameter('kernel.project_dir') . '/storage';
$filePath = $storagePath . '/' . basename($filename);

// ...
```

### 依赖漏洞

依赖漏洞可能使您的应用程序面临各种风险，因此采用最佳实践至关重要。
保持所有 Symfony 组件和第三方库是最新的。

Composer（PHP 的依赖管理器）使更新 PHP 包变得很容易：

```bash
composer update
```

使用多个依赖项时，其中一些可能包含安全漏洞。
为了解决这一问题，Symfony 提供了 [Symfony 安全检查器](https://symfony.com/doc/current/setup.html#checking-security-vulnerabilities)。该工具专门检查项目中的 *composer.lock* 文件，以识别已安装依赖项中的已知安全漏洞，并解决 Symfony 项目中的潜在安全问题。

使用 [Symfony CLI](https://github.com/symfony-cli/symfony-cli) 运行安全检查器：

```bash
symfony check:security
```

您还应考虑使用类似的工具：

- [本地 PHP 安全检查器](https://github.com/fabpot/local-php-security-checker)

- [Enlightn 安全检查器](https://github.com/enlightn/security-checker)

### 跨域资源共享（CORS）

CORS 是在 Web 浏览器中实现的一项安全功能，用于控制一个域中的 Web 应用程序如何请求和与托管在其他域上的资源交互。

在 Symfony 中，您可以使用 `nelmio/cors-bundle` 管理 CORS 策略。该包允许您精确控制 CORS 规则，而无需更改服务器设置。

使用 Composer 安装：

```bash
composer require nelmio/cors-bundle
```

对于 Symfony Flex 用户，安装会自动在 `config/packages` 目录中生成基本配置文件。查看以 */API* 前缀开头的路由的示例配置。


# config/packages/nelmio_cors.yaml
nelmio_cors:
    defaults:
        origin_regex: true
        allow_origin: ['*']
        allow_methods: ['GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']
        allow_headers: ['*']
        expose_headers: ['Link']
        max_age: 3600
    paths:
        '^/api': ~  # ~ 表示此路径的配置继承自默认值
```

### 安全相关的响应头

建议通过添加以下基本安全响应头来增强 Symfony 应用程序的安全性：

- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Content-Security-Policy
- X-Permitted-Cross-Domain-Policies
- Referrer-Policy
- Clear-Site-Data
- Cross-Origin-Embedder-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- Cache-Control

要了解各个响应头的更多详细信息，请参考 [OWASP 安全响应头项目](https://owasp.org/www-project-secure-headers/)。

在 Symfony 中，您可以通过以下方式手动或自动添加这些响应头：
- 监听 [ResponseEvent](https://symfony.com/doc/current/reference/events.html#kernel-response) 以添加到每个响应
- 配置 Nginx 或 Apache 等 Web 服务器

```php
use Symfony\Component\HttpFoundation\Request;

$response = new Response();
$response->headers->set('X-Frame-Options', 'SAMEORIGIN');
```

### 会话和 Cookies 管理

默认情况下，会话是安全配置且已启用的。但是，可以在 `config/packages/framework.yaml` 的 `framework.session` 键下手动控制。确保在会话配置中设置以下内容，使您的应用程序更加安全。

确保 `cookie_secure` 未明确设置为 `false`（默认为 `true`）。将 `httponly` 设置为 `true` 意味着 Cookie 将不可被 JavaScript 访问。

```yaml
cookie_httponly: true
```

确保设置较短的会话 TTL（生存时间）持续时间。根据 [OWASP 的建议](Session_Management_Cheat_Sheet.md)，对于高价值应用程序，会话 TTL 应为 2-5 分钟；对于低风险应用程序，应为 15-30 分钟。

```yaml
cookie_lifetime: 5
```

建议将 `cookie_samesite` 设置为 `lax` 或 `strict`，以防止 Cookie 从跨域请求发送。`lax` 允许 Cookie 随"安全"的顶级导航和同站点请求一起发送。使用 `strict` 时，如果 HTTP 请求不是来自同一域，则无法发送任何 Cookie。

```yaml
cookie_samesite: lax|strict
```

将 `cookie_secure` 设置为 `auto` 可确保 Cookie 仅通过安全连接发送，即 HTTPS 为 `true`，HTTP 协议为 `false`。

```yaml
cookie_secure: auto
```

OWASP 在 [会话管理备忘录](Session_Management_Cheat_Sheet.md) 中提供了有关会话的更多一般信息。
您还可以参考 [Cookie 安全指南](https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20171130_Cookie_Security_Myths_Misconceptions_David_Johansson.pdf)。

---
在 Symfony 中，会话由框架本身管理，依赖于 Symfony 的会话处理机制，而不是 PHP 的默认会话处理（通过 php.ini 中的 `session.auto_start = 1` 指令）。
PHP 中的 `session.auto_start = 1` 指令用于在每个请求上自动启动会话，绕过对 `session_start()` 的显式调用。但是，在使用 Symfony 进行会话管理时，建议禁用 `session.auto_start` 以防止冲突和意外行为。

### 认证

[Symfony 安全](https://symfony.com/doc/current/security.html)提供了一个强大的认证系统，包括提供者、防火墙和访问控制，以确保安全和受控的访问环境。可以在 `config/packages/security.yaml` 中配置认证设置。

- **提供者**

    Symfony 认证依赖于提供者从各种存储类型（如数据库、LDAP 或自定义源）获取用户信息。提供者根据定义的属性获取用户并加载相应的用户对象。

    在下面的示例中，展示了[实体用户提供者](https://symfony.com/doc/current/security/user_providers.html#security-entity-user-provider)，它使用 Doctrine 通过唯一标识符获取用户。

    ```yaml
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email
    ```

- **防火墙**

    Symfony 使用防火墙为应用程序的不同部分定义安全配置。每个防火墙为传入请求定义一组特定的规则和操作。它们通过指定哪些路由或 URL 是安全的、要使用的认证机制以及如何处理未经授权的访问来保护应用程序的不同部分。防火墙可以与特定模式、请求方法、访问控制和认证提供者相关联。

    ```yaml
    firewalls:
        dev: # 禁用开发环境中使用的路由的安全性
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        admin: # 处理 /admin 模式路由的认证
            lazy: true
            provider: app_user_provider
            pattern: ^/admin
            custom_authenticator: App\Security\AdminAuthenticator
            logout:
                path: app_logout
                target: app_login
        main: # 包含所有剩余路由的主防火墙
            lazy: true
            provider: app_user_provider
    ```

- **访问控制**

    访问控制决定哪些用户可以访问应用程序的特定部分。这些规则由路径模式和所需的角色或权限组成。访问控制规则在 `access_control` 键下配置。

    ```yaml
    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN } # 只有具有 ROLE_ADMIN 角色的用户才被允许
        - { path: ^/login, roles: PUBLIC_ACCESS } # 每个人都可以访问此路由
    ```

### 错误处理披露

Symfony 有一个强大的错误处理系统。默认情况下，出于安全原因，Symfony 应用程序配置为仅在开发环境中显示详细的错误消息。在生产环境中，显示通用错误页面。Symfony 的错误处理系统还允许基于不同 HTTP 状态码的自定义错误页面，提供无缝和品牌化的用户体验。此外，Symfony 还会记录详细的错误信息，帮助开发者高效地识别和解决问题。

有关与 Symfony 无关的错误处理的更多信息，请参考 [错误处理备忘录](Error_Handling_Cheat_Sheet.md)。

### 敏感数据

在 Symfony 中，存储 API 密钥等配置的最佳方式是使用依赖于应用程序位置的环境变量。
为了确保敏感值的安全，Symfony 提供了一个*秘密管理系统*，其中值使用加密密钥额外编码并存储为**秘密**。

考虑一个将 API_KEY 存储为秘密的示例：

要生成一对加密密钥，可以运行以下命令。私钥文件非常敏感，不应提交到仓库。

```bash
bin/console secrets:generate-keys
```

此命令将在 `config/secrets/env(dev|prod|etc.)` 中为 API_KEY 秘密生成一个文件

```bash
bin/console secret:set API_KEY
```

您可以像访问环境变量一样在代码中访问秘密值。
需要非常重要的是，如果存在名称相同的环境变量和秘密，**环境变量的值将始终覆盖秘密**。

更多详细信息请参考 [Symfony 秘密文档](https://symfony.com/doc/current/configuration/secrets.html)。

### 总结

- 确保在生产环境中关闭调试模式。要关闭调试模式，请将 `APP_ENV` 环境变量设置为 `prod`：

    ```ini
    APP_ENV=prod
    ```

- 确保您的 PHP 配置是安全的。您可以参考 [PHP 配置备忘录](PHP_Configuration_Cheat_Sheet.md)，了解更多关于安全的 PHP 配置设置。

- 确保在 Web 服务器中正确配置 SSL 证书，并配置强制 HTTPS，将 HTTP 流量重定向到 HTTPS。

- 实施安全响应头以增强应用程序的安全性。

- 确保正确设置文件和目录权限，以最大程度地降低安全风险。

- 对生产数据库和关键文件实施定期备份。制定恢复计划，以便在出现任何问题时快速恢复应用程序。

- 使用安全检查器扫描依赖项，识别已知的漏洞。

- 考虑设置监控工具和错误报告机制，以快速识别和解决生产环境中的问题。探索诸如 [Blackfire.io](https://www.blackfire.io) 之类的工具。

## 参考资料

- [Symfony CSRF 文档](https://symfony.com/doc/current/security/csrf.html)
- [Symfony Twig 文档](https://symfony.com/doc/current/templates.html)
- [Symfony 验证文档](https://symfony.com/doc/current/validation.html)
- [Symfony Blackfire 文档](https://symfony.com/doc/current/the-fast-track/en/29-performance.html)
- [Doctrine 安全文档](https://www.doctrine-project.org/projects/doctrine-dbal/en/3.7/reference/security.html)
