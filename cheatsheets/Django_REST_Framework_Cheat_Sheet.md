# Django REST Framework (DRF) 安全备忘录

## 简介

本备忘录为 Django REST Framework 开发者提供安全建议。这是一套针对需要保护应用程序基本安全方面的 Django REST 开发者的基本指南。

## Django 中的视图是什么？

Django 中的视图是一个 Python 类或函数，在接收 Web 请求后返回 Web 响应。该响应可以是简单的 HTTP、HTML 模板，或将用户重定向到另一个页面的 HTTP 重定向请求。

## 设置

要配置 Django REST Framework (DRF)，您需要访问 REST_FRAMEWORK 命名空间。通常，您可以在 settings.py 文件中找到此命名空间。从安全角度来看，最相关的项目是：

### DEFAULT_AUTHENTICATION_CLASSES

默认用于通过访问 `request.user` 或 `request.auth` 属性识别已认证用户的认证类列表。这些类包括 'rest_framework.authentication.SessionAuthentication'（会话认证）和 'rest_framework.authentication.BasicAuthentication'（基本认证）。

### DEFAULT_PERMISSION_CLASSES

定义 Django 在可以访问视图之前检查的默认权限集的权限类列表。由于默认值是 'rest_framework.permissions.AllowAny'，这意味着**除非更改默认权限类，否则默认情况下每个人都可以访问每个视图。**

### DEFAULT_THROTTLE_CLASSES

确定在视图开始时检查的默认限流类列表。**由于默认类为空，因此默认情况下没有限流。**

### DEFAULT_PAGINATION_CLASS

用于查询集分页的默认类。**在 Django 中，分页默认是禁用的。**如果数据量很大，没有适当的分页可能会导致拒绝服务（DoS）问题或攻击。

## OWASP API 安全 Top 10（2019）

[OWASP API 安全 Top 10](https://owasp.org/www-project-api-security/) 是由[开放 Web 应用程序安全项目（OWASP）](https://owasp.org/)开发的 API 最关键安全风险列表。它旨在帮助组织识别和优先处理其 API 的最重大风险，以便实施适当的控制措施来缓解这些风险。

本节使用 2019 年版本的 API 安全 Top 10。保护 Web API 的最佳方法是从顶部威胁（下面的 A1）开始，逐步向下。这将确保在安全方面花费的任何时间都是最有效的，因为您将首先涵盖最重要的威胁。查看 Top 10 后，通常建议评估其他威胁或进行专业渗透测试。

### API1:2019 对象级授权被破坏

使用对象级权限时，应确保使用 `.check_object_permissions(request, obj)` 方法检查用户是否可以访问对象。

示例：

```python
def get_object(self):
    obj = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
    self.check_object_permissions(self.request, obj)
    return obj
```

不要在不检查请求是否应该访问该对象的情况下重写 `get_object()` 方法。

### API2:2019 用户认证被破坏

为防止用户认证被破坏，请使用具有项目正确类的 DEFAULT_AUTHENTICATION_CLASSES 设置，并在每个非公共 API 端点上进行认证。除非您对更改有信心并了解其影响，否则不要在基于类（变量 `authentication_classes`）或基于函数（装饰器 `authentication_classes`）的视图上重写认证类。

### API3:2019 过度数据暴露

为防止此问题，仅显示所需的最少信息。确保检查序列化程序和要显示的信息。如果序列化程序继承自 ModelSerializer，请不要使用 exclude Meta 属性。

### API4:2019 缺乏资源和速率限制

为防止此问题，配置 DEFAULT_THROTTLE_CLASSES 设置，并且除非您对更改有信心并了解其影响，否则不要在基于类（变量 `throttle_classes`）或基于函数（装饰器 `throttle_classes`）的视图上重写限流类。

额外提示：如果可能，使用 WAF 或类似工具进行速率限制。DRF 应该是最后一层速率限制。

### API5:2019 功能级授权被破坏

要解决此问题，请更改 DEFAULT_PERMISSION_CLASSES 的默认值（`'rest_framework.permissions.AllowAny'`）。使用具有项目正确类的 DEFAULT_PERMISSION_CLASSES 设置。

除公共 API 端点外，不要使用 `rest_framework.permissions.AllowAny`，并且除非您对更改有信心并了解其影响，否则不要在基于类（变量 `permission_classes`）或基于函数（装饰器 `permission_classes`）的视图上重写授权类。

### API6:2019 大规模赋值

为防止此问题，使用 ModelForms 时使用 Meta.fields（允许列表方法）。不要使用 Meta.exclude（拒绝列表方法）或 `ModelForms.Meta.fields = "__all__"`

### API7:2019 安全配置错误

要解决此问题，您必须有一个可重复的强化过程，以快速轻松地部署正确锁定的环境。拥有一个持续评估所有环境中配置和设置有效性的自动化流程。

**不要使用默认密码。将 Django 设置 `DEBUG` 和 `DEBUG_PROPAGATE_EXCEPTIONS` 设置为 False。确保 API 只能通过指定的 HTTP 动词访问。所有其他 HTTP 动词都应禁用。将 `SECRET_KEY` 设置为随机值，并且永远不要对密钥进行硬编码。**

**确实要验证、过滤和清理所有客户端提供的数据或来自集成系统的其他数据。**

### API8:2019 注入

#### SQL 注入

**要防止此问题，请使用参数化查询。**使用 `raw()`、`extra()` 和自定义 SQL（通过 `cursor.execute()`）等危险方法时要小心。不要将用户输入添加到危险方法（`raw()`、`extra()`、`cursor.execute()`）中。

#### 远程代码执行（RCE）

要解决此问题，对 YAML 文件使用 `Loader=yaml.SafeLoader`。不要使用 `load()` 方法加载用户控制的 YAML 文件。

另外，不要将用户输入添加到危险方法（`eval()`、`exec()` 和 `execfile()`）中，并且不要加载用户控制的 pickle 文件，包括 pandas 方法 `pandas.read_pickle()`。

### API9:2019 不当资产管理

为防止此问题，创建所有 API 主机的清单。在此清单中，记录每个主机的重要方面。重点关注 API 版本和 API 环境（例如，生产、暂存、测试、开发），并确定谁应该有权访问主机（例如，公共、内部、合作伙伴）。确保记录 API 的所有方面，如认证、错误、重定向、速率限制、跨域资源共享（CORS）策略和端点，包括其参数、请求和响应。

### API10:2019 日志和监控不足

为了具备适当的日志和监控功能，请执行以下操作：

--记录所有失败的认证尝试、拒绝访问和输入验证错误，并提供足够的用户上下文以识别可疑或恶意账户。

--以适合日志管理解决方案使用的格式创建日志，并包含足够的详细信息以识别恶意行为者。

--将日志视为敏感数据，并保证其在静态和传输过程中的完整性。

--配置监控系统以持续监控基础设施、网络和 API 功能。

--使用安全信息和事件管理（SIEM）系统聚合和管理 API 堆栈和主机的所有组件的日志。

--配置自定义仪表板和警报，使可疑活动能够更早地被检测和响应。

--建立有效的监控和警报机制，以便及时检测和响应可疑活动。

不要：

--记录通用错误消息，如：Log.Error("发生了错误")；而是记录堆栈跟踪、错误消息和导致错误的用户 ID。

--记录敏感数据，如用户密码、API 令牌或个人身份信息（PII）。

## 其他安全风险

以下是 OWASP API 安全 Top 10 中未讨论的 API 安全风险列表。

### 业务逻辑漏洞

注意可能导致安全漏洞的业务逻辑错误。由于业务逻辑漏洞难以或不可能使用自动化工具检测，防止业务逻辑安全漏洞的最佳方法是使用威胁模型、进行安全设计审查、代码审查、结对编程和编写单元测试。

### 秘密管理

**秘密不应硬编码。最佳实践是使用秘密管理器。**有关更多信息，请查看 OWASP [秘密管理备忘录](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

## 更新 Django 和 DRF 并制定更新依赖项的流程

所有应用程序都有依赖项，这些依赖项可能存在漏洞。一个好的做法是审核项目正在使用的依赖项。通常，制定更新依赖项的流程很重要。示例流程可能定义三种触发更新响应的机制：

--每月/季度更新依赖项。
--每周考虑重要的安全漏洞并可能触发更新。
--在特殊情况下，可能需要应用紧急更新。

Django 安全团队提供了有关 [Django 如何披露安全问题](https://docs.djangoproject.com/en/4.1/internals/security/#how-django-discloses-security-issues)的信息。

在考虑库时，考虑库的"安全健康"。更新频率如何？是否有已知漏洞？是否有活跃的社区？等等。一些工具可以帮助完成此任务（例如 [Snyk Advisor](https://snyk.io/advisor/python)）。

## SAST 工具

对于 Python，有几个出色的开源静态分析安全工具值得考虑，包括：

Bandit – [Bandit](https://bandit.readthedocs.io/en/latest/) 是一个旨在发现 Python 常见安全问题的工具。Bandit 处理每个文件，从中构建抽象语法树（AST），并针对 AST 节点运行适当的插件。Bandit 扫描完所有文件后生成报告。Bandit 最初是在 OpenStack 安全项目中开发的，后来转移到 PyCQA。

Semgrep – [Semgrep](https://semgrep.dev/) 是一个快速、开源的静态分析引擎，用于查找错误、检测第三方依赖项中的漏洞并执行代码标准。由"Return To Corporation"（通常称为 r2c）和开源贡献者开发。它基于规则工作，可以关注安全、语言最佳实践或其他内容。创建规则很容易，semgrep 非常强大。对于 Django，有 29 个规则。

PyCharm 安全 – [Pycharm-security](https://pycharm-security.readthedocs.io/en/latest/index.html) 是 PyCharm 或带有 Python 插件的 JetBrains IDE 的插件。该插件查看 Python 代码中的常见安全漏洞并建议修复。它还可以从 Docker 容器中执行。它有大约 40 个检查，其中一些是 Django 特定的。

## 相关文章和参考资料

- [Django REST Framework (DRF) 安全代码指南](https://openaccess.uoc.edu/handle/10609/147246)
- [Django 的安全策略](https://docs.djangoproject.com/en/4.1/internals/security/)
- [Django 中的安全性](https://docs.djangoproject.com/en/4.1/topics/security/)
