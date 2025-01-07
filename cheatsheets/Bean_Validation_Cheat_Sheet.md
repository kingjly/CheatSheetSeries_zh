# Bean 验证备忘录

## 引言

本文旨在为在应用程序中提供 Java Bean 验证安全功能提供清晰、简单且可操作的指导。

Bean 验证（JSR303，即 [Bean 验证 1.0](https://beanvalidation.org/1.0/spec/) / JSR349，即 [Bean 验证 1.1](https://beanvalidation.org/1.1/spec/)）是 Java 中执行[输入验证](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)最常见的方法之一。这是一个与应用层无关的验证规范，它为开发者提供了在领域模型上定义一组验证约束，并在各个应用层中执行这些约束验证的手段。

这种方法的一个优势是验证约束和相应的验证器只需编写一次，从而减少重复工作并确保统一性：

### 典型验证

![典型验证](../assets/Bean_Validation_Cheat_Sheet_Typical.png)

### Bean 验证

![JSR](../assets/Bean_Validation_Cheat_Sheet_JSR.png)

## 设置

本指南中的示例使用 Hibernate Validator（Bean 验证 1.1 的参考实现）。

在 **pom.xml** 中添加 Hibernate Validator：

```xml
<dependency>
   <groupId>org.hibernate</groupId>
   <artifactId>hibernate-validator</artifactId>
   <version>5.2.4.Final</version>
</dependency>
```

在 Spring 的 **context.xml** 中启用 bean 验证支持：

```xml
<beans:beans ...
   ...
   <mvc:annotation-driven />
   ...
</beans:beans>
```

更多信息，请参见[设置指南](https://hibernate.org/validator/documentation/getting-started/)

## 基础知识

要开始使用 Bean 验证，您必须在模型中添加验证约束（`@Pattern`、`@Digits`、`@Min`、`@Max`、`@Size`、`@Past`、`@Future`、`@CreditCardNumber`、`@Email`、`@URL` 等），并在各个应用层传递模型时使用 `@Valid` 注解。

约束可以应用于以下几个位置：

- 字段
- 属性
- 类

对于 Bean 验证 1.1，还可以应用于：

- 参数
- 返回值
- 构造函数

为简单起见，下面的所有示例都使用字段约束，并且所有验证都由控制器触发。请参考 Bean 验证文档以获取完整的示例列表。

在错误处理方面，Hibernate Validator 返回一个包含 `List<ObjectError>` 的 `BindingResult` 对象。下面的示例采用简单的错误处理，而生产就绪的应用程序将具有更精细的设计，负责日志记录和错误页面重定向。

## 预定义约束

[后续内容保持不变，包括 @Pattern、@Digits、@Size、@Past/@Future 等部分]

## 自定义约束

Bean 验证最强大的功能之一是能够定义超出内置约束提供的简单验证的自定义约束。

创建自定义约束超出了本指南的范围。请参见此[文档](https://docs.jboss.org/hibernate/validator/5.2/reference/en-US/html/ch06.html)。

## 错误消息

可以在验证注解中指定消息 ID，以自定义错误消息：

```java
@Pattern(regexp = "[a-zA-Z0-9 ]", message="article.title.error")
private String articleTitle;
```

Spring MVC 将在已定义的 MessageSource 中查找 ID 为 *article.title.error* 的消息。更多信息请参见此[文档](https://www.silverbaytech.com/2013/04/16/custom-messages-in-spring-validation/)。
