# 授权测试自动化备忘录

## 介绍

**在实现应用程序的安全保护措施时，定义和实施授权是最重要的部分之一。尽管在创建阶段进行了各种检查和安全审计，大多数授权问题通常发生在功能在更新版本中被添加或修改而未确定其对应用授权的影响（通常是由于成本或时间的原因）。**

为了解决这个问题，我们建议开发人员自动化授权矩阵的评估，并在每次新发布时进行测试。这可以确保团队知道应用程序中的更改是否与授权定义和/或实现冲突。

## 上下文

授权通常包含两个元素（也称为维度）：**功能** 和 **逻辑角色**。有时还会添加第三个维度“数据”，以定义基于业务数据级别的访问权限。

一般而言，每个授权的这两个维度应该在电子表格中列出，该电子表格被称为**授权矩阵**。当进行授权测试时，逻辑角色有时会被称作**视角**。

## 目标

此速查表旨在帮助您生成自动化授权测试的方法，在授权矩阵上进行操作。由于开发人员需要设计自己的授权测试自动化方法，因此此速查表将展示一种可能的实现方式，即为暴露REST服务的应用程序提供授权测试自动化的方法。

## 提议

### 准备自动化的授权矩阵

在开始自动化授权矩阵测试之前，我们需要完成以下步骤：

1. **以透视格式文件的形式正式化授权矩阵，这将允许您：**
    1. 轻松通过程序处理矩阵。
    2. 当需要跟进授权组合时，让人类能够阅读和更新。
    3. 设置授权的层次结构，从而可以轻松创建不同的组合。
    4. 尽可能减少对实现应用所使用的技术和设计的依赖。

2. **创建一套集成测试，这些测试完全使用授权矩阵透视文件作为输入源，这将允许您评估不同组合，并具有以下优点：**
    1. 当授权矩阵透视文件更新时，维护量降至最低。
    2. 在测试失败的情况下，可以清楚地指出不符合授权矩阵的授权组合。

### 创建授权矩阵透视文件

**在本示例中，我们使用XML格式来正式化授权矩阵。**

此XML结构有三个主要部分（或节点）：

- 节点 **roles**：描述系统中可能使用的逻辑角色，提供角色列表，并解释不同角色（权限级别）。
- 节点 **services**：提供由系统暴露的服务的列表，以及这些服务的描述及其关联的可以调用它们的逻辑角色。
- 节点 **services-testing**：如果服务使用除URL或路径之外的数据作为输入，则为每个服务提供测试负载。

**以下示例展示了如何使用XML定义一个授权：**

> 占位符（值在{}之间）用于标记需要通过集成测试放置测试值的位置

```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!--
      此文件表示系统暴露的不同服务的授权矩阵：

      测试将使用此文件作为不同测试用例的输入源，以便：
      1) 定义合法访问和正确的实现
      2) 确定非法访问（服务实现中的授权定义问题）

      "name" 属性用于唯一标识一个SERVICE或一个ROLE。
  -->
  <authorization-matrix>

      <!-- 描述系统中可能使用的逻辑角色，这里用来提供不同角色的列表+解释
      （权限级别） -->
      <roles>
          <role name="ANONYMOUS"
          description="表示无需授权"/>
          <role name="BASIC"
          description="影响普通用户的角色（最低访问权限，仅高于匿名用户）"/>
          <role name="ADMIN"
          description="影响管理员的角色（最高访问权限）"/>
      </roles>

      <!-- 列出并描述系统暴露的服务及其关联的可以调用它们的逻辑角色 -->
      <services>
          <service name="ReadSingleMessage" uri="/{messageId}" http-method="GET"
          http-response-code-for-access-allowed="200" http-response-code-for-access-denied="403">
              <role name="ANONYMOUS"/>
              <role name="BASIC"/>
              <role name="ADMIN"/>
          </service>
          <service name="ReadAllMessages" uri="/" http-method="GET"
          http-response-code-for-access-allowed="200" http-response-code-for-access-denied="403">
              <role name="ANONYMOUS"/>
              <role name="BASIC"/>
              <role name="ADMIN"/>
          </service>
          <service name="CreateMessage" uri="/" http-method="PUT"
          http-response-code-for-access-allowed="200" http-response-code-for-access-denied="403">
              <role name="BASIC"/>
              <role name="ADMIN"/>
          </service>
          <service name="DeleteMessage" uri="/{messageId}" http-method="DELETE"
          http-response-code-for-access-allowed="200" http-response-code-for-access-denied="403">
              <role name="ADMIN"/>
          </service>
      </services>

      <!-- 如果需要，为每个服务提供测试负载 -->
      <services-testing>
          <service name="ReadSingleMessage">
              <payload/>
          </service>
          <service name="ReadAllMessages">
              <payload/>
          </service>
          <service name="CreateMessage">
              <payload content-type="application/json">
                  {"content":"test"}
              </payload>
          </service>
          <service name="DeleteMessage">
              <payload/>
          </service>
      </services-testing>

  </authorization-matrix>
```

### 实现集成测试

**要创建一个集成测试，应尽量使用最少的代码并为每个视角（POV）实现一个测试用例，以便按访问级别（逻辑角色）对验证进行分类。这将有助于错误的呈现/识别。**

在该集成测试中，我们实现了解析、对象映射和访问授权矩阵的功能，通过将XML转换为Java对象再反向转换回XML这些功能来实施测试（这里使用了JAXB）。这些特性用于实现测试并限制代码量仅限于负责执行测试的开发人员。

**以下是一个集成测试用例类的示例实现：**







``` java
  import org.owasp.pocauthztesting.enumeration.SecurityRole;
  import org.owasp.pocauthztesting.service.AuthService;
  import org.owasp.pocauthztesting.vo.AuthorizationMatrix;
  import org.apache.http.client.methods.CloseableHttpResponse;
  import org.apache.http.client.methods.HttpDelete;
  import org.apache.http.client.methods.HttpGet;
  import org.apache.http.client.methods.HttpPut;
  import org.apache.http.client.methods.HttpRequestBase;
  import org.apache.http.entity.StringEntity;
  import org.apache.http.impl.client.CloseableHttpClient;
  import org.apache.http.impl.client.HttpClients;
  import org.junit.Assert;
  import org.junit.BeforeClass;
  import org.junit.Test;
  import org.xml.sax.InputSource;
  import javax.xml.bind.JAXBContext;
  import javax.xml.parsers.SAXParserFactory;
  import javax.xml.transform.Source;
  import javax.xml.transform.sax.SAXSource;
  import java.io.File;
  import java.io.FileInputStream;
  import java.util.ArrayList;
  import java.util.List;
  import java.util.Optional;

  /**
   * 集成测试用例验证授权矩阵的正确实现。它们通过逻辑角色创建一个测试案例，该测试案例将测试系统暴露的所有服务的访问权限。此实现侧重于可读性。
   */
  public class AuthorizationMatrixIT {

      /**
       * 授权矩阵的对象表示
       */
      private static AuthorizationMatrix AUTHZ_MATRIX;

      private static final String BASE_URL = "http://localhost:8080";

      /**
       * 加载授权矩阵到对象树中
       *
       * @throws Exception 如果发生任何错误
       */
      @BeforeClass
      public static void globalInit() throws Exception {
          try (FileInputStream fis = new FileInputStream(new File("authorization-matrix.xml"))) {
              SAXParserFactory spf = SAXParserFactory.newInstance();
              spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
              spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
              spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
              Source xmlSource = new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(fis));
              JAXBContext jc = JAXBContext.newInstance(AuthorizationMatrix.class);
              AUTHZ_MATRIX = (AuthorizationMatrix) jc.createUnmarshaller().unmarshal(xmlSource);
          }
      }

      /**
       * 通过匿名用户测试服务的访问权限。
       *
       * @throws Exception
       */
      @Test
      public void testAccessUsingAnonymousUserPointOfView() throws Exception {
          // 运行测试 - 没有访问令牌
          List<String> errors = executeTestWithPointOfView(SecurityRole.ANONYMOUS, null);
          // 验证测试结果
          Assert.assertEquals("使用匿名用户视角检测到的访问问题：\n" + formatErrorsList(errors), 0, errors.size());
      }

      /**
       * 通过基本用户测试服务的访问权限。
       *
       * @throws Exception
       */
      @Test
      public void testAccessUsingBasicUserPointOfView() throws Exception {
          // 获取表示关联视角授权的访问令牌
          String accessToken = generateTestCaseAccessToken("basic", SecurityRole.BASIC);
          // 运行测试
          List<String> errors = executeTestWithPointOfView(SecurityRole.BASIC, accessToken);
          // 验证测试结果
          Assert.assertEquals("使用基本用户视角检测到的访问问题：\n " + formatErrorsList(errors), 0, errors.size());
      }

      /**
       * 通过管理员用户测试服务的访问权限。
       *
       * @throws Exception
       */
      @Test
      public void testAccessUsingAdministratorUserPointOfView() throws Exception {
          // 获取表示关联视角授权的访问令牌
          String accessToken = generateTestCaseAccessToken("admin", SecurityRole.ADMIN);
          // 运行测试
          List<String> errors = executeTestWithPointOfView(SecurityRole.ADMIN, accessToken);
          // 验证测试结果
          Assert.assertEquals("使用管理员用户视角检测到的访问问题：\n" + formatErrorsList(errors), 0, errors.size());
      }

      /**
       * 使用指定的视角（POV）评估所有服务的访问权限。
       *
       * @param pointOfView 要使用的视角
       * @param accessToken 与视角相关的授权访问令牌。
       * @return 检测到的错误列表
       * @throws Exception 如果发生任何错误
       */
      private List<String> executeTestWithPointOfView(SecurityRole pointOfView, String accessToken) throws Exception {
          List<String> errors = new ArrayList<>();
          String errorMessageTplForUnexpectedReturnCode = "调用视角 '%s' 时，服务 '%s' 返回响应码 %s，这与允许或拒绝情况下预期的响应码不符。";
          String errorMessageTplForIncorrectReturnCode = "调用视角 '%s' 时，服务 '%s' 返回响应码 %s，这与预期的响应码不符（%s 预期）。";
          String fatalErrorMessageTpl = "调用视角 '%s' 时，服务 '%s' 出现错误：%s";

          // 获取要调用的服务列表
          List<AuthorizationMatrix.Services.Service> services = AUTHZ_MATRIX.getServices().getService();

          // 获取用于测试的服务负载列表
          List<AuthorizationMatrix.ServicesTesting.Service> servicesTestPayload = AUTHZ_MATRIX.getServicesTesting().getService();

          // 顺序调用所有服务（此处不特别关注性能）
          services.forEach(service -> {
              // 获取当前服务的测试负载
              String payload = null;
              String payloadContentType = null;
              Optional<AuthorizationMatrix.ServicesTesting.Service> serviceTesting = servicesTestPayload.stream().filter(srvPld -> srvPld.getName().equals(service.getName())).findFirst();
              if (serviceTesting.isPresent()) {
                  payload = serviceTesting.get().getPayload().getValue();
                  payloadContentType = serviceTesting.get().getPayload().getContentType();
              }
              // 调用服务并验证响应是否一致
              try {
                  // 调用服务
                  int serviceResponseCode = callService(service.getUri(), payload, payloadContentType, service.getHttpMethod(), accessToken);
                  // 检查表示指定视角的角色是否定义在当前服务中
                  Optional<AuthorizationMatrix.Services.Service.Role> role = service.getRole().stream().filter(r -> r.getName().equals(pointOfView.name())).findFirst();
                  boolean accessIsGrantedInAuthorizationMatrix = role.isPresent();
                  // 根据返回的响应码和矩阵中配置的授权验证行为是否一致
                  if (serviceResponseCode == service.getHttpResponseCodeForAccessAllowed()) {
                      // 角色不在允许访问服务的角色列表中，因此这是一个错误
                      if (!accessIsGrantedInAuthorizationMatrix) {
                          errors.add(String.format(errorMessageTplForIncorrectReturnCode, service.getName(), pointOfView.name(), serviceResponseCode,
                           service.getHttpResponseCodeForAccessDenied()));
                      }
                  } else if (serviceResponseCode == service.getHttpResponseCodeForAccessDenied()) {
                      // 角色在允许访问服务的角色列表中，因此这是一个错误
                      if (accessIsGrantedInAuthorizationMatrix) {
                          errors.add(String.format(errorMessageTplForIncorrectReturnCode, service.getName(), pointOfView.name(), serviceResponseCode,
                           service.getHttpResponseCodeForAccessAllowed()));
                      }
                  } else {
                      errors.add(String.format(errorMessageTplForUnexpectedReturnCode, service.getName(), pointOfView.name(), serviceResponseCode));
                  }
              } catch (Exception e) {
                  errors.add(String.format(fatalErrorMessageTpl, service.getName(), pointOfView.name(), e.getMessage()));
              }

          });

          return errors;
      }

      /**
       * 以特定负载调用服务并返回接收到的HTTP响应码。
       * 此步骤被委托，以便使测试案例更容易维护。
       *
       * @param uri                要调用的服务URI
       * @param payloadContentType 要发送的负载内容类型
       * @param payload            要发送的负载
       * @param httpMethod         使用的HTTP方法
       * @param accessToken        用于表示调用者身份的访问令牌
       * @return 接收到的HTTP响应码
       * @throws Exception 如果发生任何错误
       */
      private int callService(String uri, String payload, String payloadContentType, String httpMethod, String accessToken) throws Exception {
          int rc;

          // 构建请求 - 为了组合更灵活，使用Apache HTTP Client。
          HttpRequestBase request;
          String url = (BASE_URL + uri).replaceAll("\\{messageId\\}", "1");
          switch (httpMethod) {
              case "GET":
                  request = new HttpGet(url);
                  break;
              case "DELETE":
                  request = new HttpDelete(url);
                  break;
              case "PUT":
                  request = new HttpPut(url);
                  if (payload != null) {
                      request.setHeader("Content-Type", payloadContentType);
                      ((HttpPut) request).setEntity(new StringEntity(payload.trim()));
                  }
                  break;
              default:
                  throw new UnsupportedOperationException(httpMethod + " 不支持！");
          }
          request.setHeader("Authorization", (accessToken != null) ? accessToken : "");

          // 发送请求并获取HTTP响应码。
          try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
              try (CloseableHttpResponse httpResponse = httpClient.execute(request)) {
                  // 不关心响应内容...
                  rc = httpResponse.getStatusLine().getStatusCode();
              }
          }

          return rc;
      }

      /**
       * 为指定的用户和角色生成JWT访问令牌。
       *
       * @param login 用户登录名
       * @param role   授权逻辑角色
       * @return JWT访问令牌
       * @throws Exception 如果在创建过程中发生任何错误
       */
      private String generateTestCaseAccessToken(String login, SecurityRole role) throws Exception {
          return new AuthService().issueAccessToken(login, role);
      }

      /**
       * 将错误列表格式化为可打印的字符串。
       *
       * @param errors 错误列表
       * @return 可打印的字符串
       */
      private String formatErrorsList(List<String> errors) {
          StringBuilder buffer = new StringBuilder();
          errors.forEach(e -> buffer.append(e).append("\n"));
          return buffer.toString();
      }
  }
```

如果检测到授权问题（或多个问题），输出如下：

```java
testAccessUsingAnonymousUserPointOfView(org.owasp.pocauthztesting.AuthorizationMatrixIT)
Time elapsed: 1.009 s  ### 失败
java.lang.AssertionError:
使用匿名用户视角检测到的访问问题：
    调用视角 'ANONYMOUS' 时，服务 'DeleteMessage' 返回响应码 200，这与预期的响应码（403）不符。
    
    调用视角 'ANONYMOUS' 时，服务 'CreateMessage' 返回响应码 200，这与预期的响应码（403）不符。

testAccessUsingBasicUserPointOfView(org.owasp.pocauthztesting.AuthorizationMatrixIT)
Time elapsed: 0.05 s  ### 失败
java.lang.AssertionError:
使用基本用户视角检测到的访问问题：
    调用视角 'BASIC' 时，服务 'DeleteMessage' 返回响应码 200，这与预期的响应码（403）不符。
```

## 授权矩阵用于审计/审查的呈现

即使授权矩阵以人类可读格式存储（XML），您可能仍然希望展示一个实时渲染的XML文件表示形式，以便发现潜在不一致并简化审查、审计和讨论。

要实现此任务，您可以使用以下XSL样式表：

``` xslt
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/">
    <html>
      <head>
        <title>授权矩阵</title>
        <link rel="stylesheet"
              href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css"
              integrity="sha384-rwoIResjU2yc3z8GV/NPeZWAv56rSmLldC3R/AZzGRnGxQQKnKkoFVhFQhNUwEyJ"
              crossorigin="anonymous" />
      </head>
      <body>
        <h3>角色</h3>
        <ul>
          <xsl:for-each select="authorization-matrix/roles/role">
            <xsl:choose>
              <xsl:when test="@name = 'ADMIN'">
                <div class="alert alert-warning" role="alert">
                  <strong><xsl:value-of select="@name" /></strong> :
                  <xsl:value-of select="@description" />
                </div>
              </xsl:when>
              <xsl:when test="@name = 'BASIC'">
                <div class="alert alert-info" role="alert">
                  <strong><xsl:value-of select="@name" /></strong> :
                  <xsl:value-of select="@description" />
                </div>
              </xsl:when>
              <xsl:otherwise>
                <div class="alert alert-danger" role="alert">
                  <strong><xsl:value-of select="@name" /></strong> :
                  <xsl:value-of select="@description" />
                </div>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:for-each>
        </ul>
        <h3>授权</h3>
        <table class="table table-hover table-sm">
          <thead class="thead-inverse">
            <tr>
              <th>服务</th>
              <th>URI</th>
              <th>方法</th>
              <th>角色</th>
            </tr>
          </thead>
          <tbody>
            <xsl:for-each select="authorization-matrix/services/service">
              <xsl:variable name="service-name" select="@name" />
              <xsl:variable name="service-uri" select="@uri" />
              <xsl:variable name="service-method" select="@http-method" />
              <xsl:for-each select="role">
                <tr>
                  <td scope="row"><xsl:value-of select="$service-name" /></td>
                  <td><xsl:value-of select="$service-uri" /></td>
                  <td><xsl:value-of select="$service-method" /></td>
                  <td>
                    <xsl:variable name="service-role-name" select="@name" />
                    <xsl:choose>
                      <xsl:when test="@name = 'ADMIN'">
                        <div class="alert alert-warning" role="alert"><xsl:value-of select="@name" /></div>
                      </xsl:when>
                      <xsl:when test="@name = 'BASIC'">
                        <div class="alert alert-info" role="alert"><xsl:value-of select="@name" /></div>
                      </xsl:when>
                      <xsl:otherwise>
                        <div class="alert alert-danger" role="alert"><xsl:value-of select="@name" /></div>
                      </xsl:otherwise>
                    </xsl:choose>
                  </td>
                </tr>
              </xsl:for-each>
            </xsl:for-each>
          </tbody>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

示例的渲染结果：

![RenderingExample](../assets/Authorization_Testing_Automation_AutomationRendering.png)

## 源代码

[GitHub 仓库](https://github.com/righettod/poc-authz-testing)
