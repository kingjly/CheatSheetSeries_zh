# Django 安全备忘录

## 简介

Django 框架是一个强大的 Python Web 框架，它内置了可以直接使用的安全功能，以防止常见的 Web 漏洞。本备忘录列出了开发者可以采取的操作和安全提示，以开发安全的 Django 应用程序。它旨在涵盖常见漏洞，以提高 Django 应用程序的安全性。每个条目都有简要说明和特定于 Django 环境的相关代码示例。

Django 框架提供了一些旨在默认安全的内置安全功能。这些功能也很灵活，使开发者能够为复杂用例重用组件。这为不熟悉组件内部工作原理的开发者以不安全的方式配置它们打开了可能性。本备忘录旨在列举此类使用场景。

## 常规建议

- 始终保持 Django 和应用程序的依赖项为最新，以跟上安全漏洞。
- 确保应用程序在生产环境中永远不处于 `DEBUG` 模式。切勿在生产环境中运行 `DEBUG = True`。
- 使用 [`django_ratelimit`](https://django-ratelimit.readthedocs.io/en/stable/) 或 [`django-axes`](https://django-axes.readthedocs.io/en/latest/index.html) 等软件包来防止暴力攻击。

## 认证

- 使用 `django.contrib.auth` 应用程序进行用户认证操作的视图和表单，如登录、注销、密码更改等。在 `settings.py` 文件的 `INSTALLED_APPS` 设置中包含该模块及其依赖项 `django.contrib.contenttypes` 和 `django.contrib.sessions`。

  ```python
  INSTALLED_APPS = [
      # ...
      'django.contrib.auth',
      'django.contrib.contenttypes',
      'django.contrib.sessions',
      # ...
  ]
  ```

- 使用 `@login_required` 装饰器确保只有经过认证的用户可以访问视图。下面的示例代码说明了 `@login_required` 的使用。

  ```python
  from django.contrib.auth.decorators import login_required

  # 如果未认证，用户将被重定向到默认登录页面
  @login_required
  def my_view(request):
    # 您的视图逻辑

  # 如果未认证，用户将被重定向到自定义的 '/login-page/'
  @login_required(login_url='/login-page/')
  def my_view(request):
    # 您的视图逻辑
  ```

- 使用密码验证器来强制执行密码策略。在 `settings.py` 文件中添加或更新 `AUTH_PASSWORD_VALIDATORS` 设置，以包含应用程序所需的特定验证器。

  ```python
  AUTH_PASSWORD_VALIDATORS = [
    {
      # 检查密码与用户属性集的相似性
      'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
      'OPTIONS': {
        'user_attributes': ('username', 'email', 'first_name', 'last_name'),
        'max_similarity': 0.7,
      }
    },
    {
      # 检查密码是否满足最小长度
      'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
      'OPTIONS': {
        'min_length': 8,
      }
    },
    {
      # 检查密码是否出现在常用密码列表中
      'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
      # 检查密码是否不完全是数字
      'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    }
  ]
  ```

- 使用 `make-password` 实用函数对明文密码进行哈希处理。

  ```python
  from django.contrib.auth.hashers import make_password
  #...
  hashed_pwd = make_password('plaintext_password')
  ```

- 使用 `check-password` 实用函数检查明文密码是否与哈希密码匹配。

  ```python
  from django.contrib.auth.hashers import check_password
  #...
  plain_pwd = 'plaintext_password'
  hashed_pwd = 'hashed_password_from_database'

  if check_password(plain_pwd, hashed_pwd):
    print("密码正确。")
  else:
    print("密码不正确。")
  ```

## 密钥管理

`settings.py` 中的 `SECRET_KEY` 参数用于加密签名，应保密。考虑以下建议：

- 生成至少 50 个字符的密钥，包含字母、数字和符号的混合。
- 确保使用强随机生成器（如 Django 中的 `get_random_secret_key()` 函数）生成 `SECRET_KEY`。
- 避免在 `settings.py` 或任何其他位置硬编码 `SECRET_KEY` 值。考虑将密钥值存储在环境变量或秘密管理器中。

  ```python
  import os
  SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
  ```

- 定期轮换密钥，请记住此操作可能会使会话、密码重置令牌等失效。如果密钥被泄露，立即轮换密钥。

## 标头

在项目的 `settings.py` 的 `MIDDLEWARE` 设置中包含 `django.middleware.security.SecurityMiddleware` 模块，以向响应添加安全相关的标头。此模块用于设置以下参数：

- `SECURE_CONTENT_TYPE_NOSNIFF`：将此键设置为 `True`。通过启用标头 `X-Content-Type-Options: nosniff` 来防止 MIME 类型嗅探攻击。
- `SECURE_BROWSER_XSS_FILTER`：将此键设置为 `True`。通过设置标头 `X-XSS-Protection: 1; mode=block` 来启用浏览器的 XSS 过滤器。
- `SECURE_HSTS_SECONDS`：确保站点仅通过 HTTPS 访问。

在项目的 `settings.py` 的 `MIDDLEWARE` 设置中包含 `django.middleware.clickjacking.XFrameOptionsMiddleware` 模块（此模块应在 `django.middleware.security.SecurityMiddleware` 模块之后列出，因为顺序很重要）。此模块用于设置以下参数：

- `X_FRAME_OPTIONS`：将此键设置为 'DENY' 或 'SAMEORIGIN'。此设置将 `X-Frame-Options` 标头添加到所有 HTTP 响应中。这可以防止点击劫持攻击。

## Cookies

- `SESSION_COOKIE_SECURE`：在 `settings.py` 文件中将此键设置为 `True`。这将仅通过安全（HTTPS）连接发送会话 cookie。
- `CSRF_COOKIE_SECURE`：在 `settings.py` 文件中将此键设置为 `True`。这将确保 CSRF cookie 仅通过安全连接发送。
- 在使用 `HttpResponse.set_cookie()` 方法在视图中设置自定义 cookie 时，请确保将其安全参数设置为 `True`。

  ```python
  response = HttpResponse("某些响应")
  response.set_cookie('my_cookie', 'cookie_value', secure=True)
  ```

## 跨站请求伪造（CSRF）

- 在项目的 `settings.py` 的 `MIDDLEWARE` 设置中包含 `django.middleware.csrf.CsrfViewMiddleware` 模块，以向响应添加 CSRF 相关标头。
- 在表单中使用 `{% csrf_token %}` 模板标签来包含 CSRF 令牌。下面显示了一个示例。

  ```html
  <form method="post">
      {% csrf_token %}
      <!-- 您的表单字段在这里 -->
  </form>
  ```

- 对于 AJAX 调用，必须在使用 AJAX 调用之前提取 CSRF 令牌。
- 可以在 Django 的 [跨站请求伪造保护](https://docs.djangoproject.com/en/3.2/ref/csrf/)文档中找到其他建议和控制。

## 跨站脚本（XSS）

本节中的建议是对前面已提到的 XSS 建议的补充。

- 使用内置模板系统在 Django 中渲染模板。请参阅 Django 的[自动 HTML 转义](https://docs.djangoproject.com/en/3.2/ref/templates/language/#automatic-html-escaping)文档以了解更多。
- 避免使用 `safe`、`mark_safe` 或 `json_script` 过滤器来禁用 Django 的自动模板转义。Python 中的等效函数是 `make_safe()` 函数。请参阅 [json_script](https://docs.djangoproject.com/en/3.2/ref/templates/builtins/#json-script0) 模板过滤器文档以了解更多。
- 请参阅 Django 的[跨站脚本（XSS）保护](https://docs.djangoproject.com/en/3.2/topics/security/#cross-site-scripting-xss-protection)文档以了解更多。

## HTTPS

- 如果尚未添加，请在项目的 `settings.py` 的 `MIDDLEWARE` 设置中包含 `django.middleware.security.SecurityMiddleware` 模块。
- 在 `settings.py` 文件中设置 `SECURE_SSL_REDIRECT = True`，以确保所有通信都通过 HTTPS 进行。这将自动将任何 HTTP 请求重定向到 HTTPS。这也是 301（永久）重定向，因此浏览器将记住后续请求的重定向。
- 如果 Django 应用程序位于代理或负载均衡器后面，请将 `SECURE_PROXY_SSL_HEADER` 设置设置为 `TRUE`，以便 Django 可以检测原始请求的协议。有关更多详细信息，请参阅 [SECURE_PROXY_SSL_HEADER 文档](https://docs.djangoproject.com/en/3.2/ref/settings/#secure-proxy-ssl-header)。

## 管理面板 URL

建议修改指向管理面板的默认 URL（example.com/admin/），以稍微增加自动攻击的难度。操作方法如下：

在项目中的默认应用文件夹中，找到管理顶级 URL 的 `urls.py` 文件。在文件中，修改 `urlpatterns` 列表，使指向 `admin.site.urls` 的 URL 与 "admin/" 不同。这种方法通过模糊用于管理访问的常见端点，增加了一层额外的安全性。

## 参考资料

其他文档 -

- [点击劫持保护](https://docs.djangoproject.com/en/3.2/topics/security/#clickjacking-protection)
- [安全中间件](https://docs.djangoproject.com/en/3.2/topics/security/#module-django.middleware.security)
