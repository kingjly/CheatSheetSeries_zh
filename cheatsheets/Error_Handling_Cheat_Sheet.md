# 错误处理备忘录

## 引言

错误处理是应用程序整体安全性的一部分。不同于电影中的情节，攻击总是从**侦察**阶段开始，攻击者会尽可能多地收集关于目标的技术信息（通常是*名称*和*版本*属性），例如应用服务器、框架、库等。

未经处理的错误可能会帮助攻击者完成这个初始阶段，这对于后续攻击非常重要。

以下[链接](https://web.archive.org/web/20230929111320/https://cipher.com/blog/a-complete-guide-to-the-phases-of-penetration-testing/)提供了攻击不同阶段的描述。

## 背景

错误处理层面的问题可能会泄露目标的大量信息，并且可以用于识别目标功能中的注入点。

下面是通过向用户呈现异常来披露技术栈（这里是 Struts2 和 Tomcat 版本）的示例：

```text
HTTP Status 500 - For input string: "null"

type Exception report

message For input string: "null"

description The server encountered an internal error that prevented it from fulfilling this request.

exception

java.lang.NumberFormatException: For input string: "null"
    java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
    java.lang.Integer.parseInt(Integer.java:492)
    java.lang.Integer.parseInt(Integer.java:527)
    sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
    sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:57)
    sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
    java.lang.reflect.Method.invoke(Method.java:606)
    com.opensymphony.xwork2.DefaultActionInvocation.invokeAction(DefaultActionInvocation.java:450)
    com.opensymphony.xwork2.DefaultActionInvocation.invokeActionOnly(DefaultActionInvocation.java:289)
    com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:252)
    org.apache.struts2.interceptor.debugging.DebuggingInterceptor.intercept(DebuggingInterceptor.java:256)
    com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:246)
    ...

note: The full stack trace of the root cause is available in the Apache Tomcat/7.0.56 logs.
```

下面是披露 SQL 查询错误以及站点安装路径的示例，可用于识别注入点：

```text
Warning: odbc_fetch_array() expects parameter /1 to be resource, boolean given
in D:\app\index_new.php on line 188
```

[OWASP 测试指南](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/)提供了从应用程序获取技术信息的不同技术。

## 目标

本文展示了如何配置全局错误处理程序，作为应用程序运行时配置的一部分。在某些情况下，在代码中定义此错误处理程序可能更有效。其结果是，当发生意外错误时，应用程序返回一个通用响应，但错误详细信息会被记录在服务器端以供调查，而不是返回给用户。

下面的架构图展示了目标方法：

![概览](../assets/Error_Handling_Cheat_Sheet_Overview.png)

由于大多数最新的应用程序拓扑是*基于 API* 的，本文假设后端仅公开 REST API 且不包含任何用户界面内容。应用程序应尽可能详尽地覆盖所有可能的故障模式，并仅使用 5xx 错误来指示无法完成的请求的响应，但不提供可能泄露实现细节的任何响应内容。为此，[RFC 7807 - HTTP API 的问题详情](https://www.rfc-editor.org/rfc/rfc7807)定义了一种文档格式。
对于错误日志记录操作本身，应使用[日志记录速查表](Logging_Cheat_Sheet.md)。本文重点关注错误处理部分。

## 建议

对于每种技术栈，提出以下配置选项：

### 标准 Java Web 应用程序

对于这类应用程序，可以在 **web.xml** 部署描述符级别配置全局错误处理程序。

这里提出一个可从 Servlet 规范 *2.5 版本* 及以上使用的配置。

使用此配置，任何意外错误都将重定向到 **error.jsp** 页面，在该页面中将跟踪错误并返回一个通用响应。

在 **web.xml** 文件中配置重定向：

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ns="http://java.sun.com/xml/ns/javaee"
xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
version="3.0">
...
    <error-page>
        <exception-type>java.lang.Exception</exception-type>
        <location>/error.jsp</location>
    </error-page>
...
</web-app>
```

**error.jsp** 文件的内容：

``` java
<%@ page language="java" isErrorPage="true" contentType="application/json; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%
String errorMessage = exception.getMessage();
//通过名为"exception"的隐式变量记录异常
//...
//我们构建一个 JSON 格式的通用响应，因为我们处于 REST API 应用上下文
//我们还添加了一个 HTTP 响应头，向客户端应用程序指示这是一个错误响应
response.setHeader("X-ERROR", "true");
//请注意，我们使用的是内部服务器错误响应
//在某些情况下，当客户端行为异常时，返回 4xx 错误代码可能更谨慎
response.setStatus(500);
%>
{"message":"发生错误，请重试"}
```

### Java SpringMVC/SpringBoot Web 应用程序

使用 [SpringMVC](https://docs.spring.io/spring/docs/current/spring-framework-reference/web.html) 或 [SpringBoot](https://spring.io/projects/spring-boot)，您可以通过在项目中实现以下类来定义全局错误处理程序。Spring Framework 6 引入了[基于 RFC 7807 的问题详情](https://github.com/spring-projects/spring-framework/issues/27052)。

我们通过 [@ExceptionHandler](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/bind/annotation/ExceptionHandler.html) 注解指示处理程序在应用程序抛出任何扩展 *java.lang.Exception* 类的异常时执行操作。我们还使用 [ProblemDetail 类](https://docs.spring.io/spring-framework/docs/6.0.0/javadoc-api/org/springframework/http/ProblemDetail.html)来创建响应对象。

``` java
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * 全局错误处理程序，负责在意外错误情况下返回通用响应。
 */
@RestControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = {Exception.class})
    public ProblemDetail handleGlobalError(RuntimeException exception, WebRequest request) {
        //通过"exception"参数的内容记录异常
        //...
        //请注意，我们使用的是内部服务器错误响应
        //在某些情况下，如果客户端行为异常，返回 4xx 错误代码可能更谨慎
        //根据规范，内容类型可以是 "application/problem+json" 或 "application/problem+xml"
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "发生错误，请重试");
    }
}
```

参考资料：
- [使用 Spring 处理异常](https://www.baeldung.com/exception-handling-for-rest-with-spring)
- [使用 SpringBoot 处理异常](https://www.toptal.com/java/spring-boot-rest-api-error-handling)

### ASP.NET Core Web 应用程序

使用 [ASP.NET Core](https://docs.microsoft.com/en-us/aspnet/core/?view=aspnetcore-2.2)，您可以通过指定异常处理程序为专用的 API 控制器来定义全局错误处理程序。

专门用于错误处理的 API 控制器的内容：

``` csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Net;

namespace MyProject.Controllers
{
    /// <summary>
    /// API 控制器，用于拦截和处理所有意外异常
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class ErrorController : ControllerBase
    {
        /// <summary>
        /// 对此控制器的任何调用都将调用此操作以处理当前错误
        /// </summary>
        /// <returns>因为我们处于 REST API 应用上下文，所以返回 JSON 格式的通用错误</returns>
        [HttpGet]
        [HttpPost]
        [HttpHead]
        [HttpDelete]
        [HttpPut]
        [HttpOptions]
        [HttpPatch]
        public JsonResult Handle()
        {
            //获取导致调用此控制器的异常
            Exception exception = HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error;
            //如果异常不为 NULL，则通过名为"exception"的变量记录异常
            //...
            //我们构建一个 JSON 格式的通用响应，因为我们处于 REST API 应用上下文
            //我们还添加了一个 HTTP 响应头，向客户端应用程序指示这是一个错误响应
            var responseBody = new Dictionary<String, String>{ {
                "message", "发生错误，请重试"
            } };
            JsonResult response = new JsonResult(responseBody);
            //请注意，我们使用的是内部服务器错误响应
            //在某些情况下，如果客户端行为异常，返回 4xx 错误代码可能更谨慎
            response.StatusCode = (int)HttpStatusCode.InternalServerError;
            Request.HttpContext.Response.Headers.Remove("X-ERROR");
            Request.HttpContext.Response.Headers.Add("X-ERROR", "true");
            return response;
        }
    }
}
```

在应用程序 **Startup.cs** 文件中定义异常处理程序到专用错误处理 API 控制器的映射：

``` csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyProject
{
    public class Startup
    {
...
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            //首先配置错误处理中间件！
            //在非开发环境中启用全局错误处理程序
            //因为调试页面在实现期间很有用
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                //我们的全局处理程序定义在 "/api/error" URL 上，因此我们指示
                //异常处理程序在应用程序引发任何意外异常时调用此 API 控制器
                app.UseExceptionHandler("/api/error");

                //要自定义响应内容类型和文本，请使用带有内容类型和格式字符串的 UseStatusCodePages 重载。
                app.UseStatusCodePages("text/plain", "状态码页面，状态码：{0}");
            }

            //我们配置其他中间件，请记住声明顺序很重要...
            app.UseMvc();
            //...
        }
    }
}
```

参考资料：
- [ASP.Net Core 异常处理](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/error-handling?view=aspnetcore-2.1)

### ASP.NET Web API Web 应用程序

使用 [ASP.NET Web API](https://www.asp.net/web-api)（来自标准 .NET 框架，而非 .NET Core 框架），您可以定义和注册处理程序以跟踪和处理应用程序中发生的任何错误。

用于跟踪错误详细信息的处理程序定义：

``` csharp
using System;
using System.Web.Http.ExceptionHandling;

namespace MyProject.Security
{
    /// <summary>
    /// 全局记录器，用于跟踪应用程序级别发生的任何错误
    /// </summary>
    public class GlobalErrorLogger : ExceptionLogger
    {
        /// <summary>
        /// 负责从跟踪角度管理错误的方法
        /// </summary>
        /// <param name="context">包含错误详细信息的上下文</param>
        public override void Log(ExceptionLoggerContext context)
        {
            //获取异常
            Exception exception = context.Exception;
            //如果异常不为 NULL，则通过名为"exception"的变量记录异常
            //...
        }
    }
}
```

用于管理错误以返回通用响应的处理程序定义：

``` csharp
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;

namespace MyProject.Security
{
    /// <summary>
    /// 全局处理程序，用于处理应用程序级别发生的任何错误
    /// </summary>
    public class GlobalErrorHandler : ExceptionHandler
    {
        /// <summary>
        /// 负责处理错误时发送通用响应的方法
        /// </summary>
        /// <param name="context">错误上下文</param>
        public override void Handle(ExceptionHandlerContext context)
        {
            context.Result = new GenericResult();
        }

        /// <summary>
        /// 用于表示发送的通用响应的类
        /// </summary>
        private class GenericResult : IHttpActionResult
        {
            /// <summary>
            /// 负责创建通用响应的方法
            /// </summary>
            /// <param name="cancellationToken">用于取消任务的对象</param>
            /// <returns>负责发送通用响应的任务</returns>
            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                //我们构建一个 JSON 格式的通用响应，因为我们处于 REST API 应用上下文
                //我们还添加了一个 HTTP 响应头，向客户端应用程序指示这是一个错误响应
                var responseBody = new Dictionary<String, String>{ {
                    "message", "发生错误，请重试"
                } };
                // 请注意，我们使用的是内部服务器错误响应
                // 在某些情况下，如果客户端行为异常，返回 4xx 错误代码可能更谨慎 
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
                response.Headers.Add("X-ERROR", "true");
                response.Content = new StringContent(JsonConvert.SerializeObject(responseBody),
                                                     Encoding.UTF8, "application/json");
                return Task.FromResult(response);
            }
        }
    }
}
```

在应用程序 **WebApiConfig.cs** 文件中注册这两个处理程序：

``` csharp
using MyProject.Security;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;

namespace MyProject
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            //首先注册全局错误日志记录和处理程序
            config.Services.Replace(typeof(IExceptionLogger), new GlobalErrorLogger());
            config.Services.Replace(typeof(IExceptionHandler), new GlobalErrorHandler());
            //其余配置
            //...
        }
    }
}
```

在 **Web.config** 文件的 ```csharp <system.web>``` 节点中设置 customErrors 节：

```csharp
<configuration>
    ...
    <system.web>
        <customErrors mode="RemoteOnly"
                      defaultRedirect="~/ErrorPages/Oops.aspx" />
        ...
    </system.web>
</configuration>
```

参考资料：
- [ASP.Net Web API 异常处理](https://exceptionnotfound.net/the-asp-net-web-api-exception-handling-pipeline-a-guided-tour/)
- [ASP.NET 错误处理](https://docs.microsoft.com/en-us/aspnet/web-forms/overview/getting-started/getting-started-with-aspnet-45-web-forms/aspnet-error-handling)

## 原型源代码

为找到正确的设置而创建的所有沙盒项目的源代码存储在此 [GitHub 仓库](https://github.com/righettod/poc-error-handling)。

## 附录 HTTP 错误

可以在 [RFC 2616](https://www.ietf.org/rfc/rfc2616.txt) 中找到 HTTP 错误的参考。使用不提供实现细节的错误消息对于避免信息泄露很重要。通常，考虑对由 HTTP 客户端错误引起的请求（例如未经授权的访问、请求正文过大）使用 4xx 错误代码，并使用 5xx 来指示由服务器端触发的错误，这些错误是由于不可预见的错误。确保监控应用程序的 5xx 错误，这是应用程序对某些输入集合失败的良好指示。
