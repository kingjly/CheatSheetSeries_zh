# JAAS 备忘录

## 引言 - 什么是 JAAS 认证

验证用户或其他系统身份的过程称为认证。

[JAAS](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html)作为一个认证框架，管理从登录到注销的已认证用户的身份和凭据。

JAAS 认证生命周期：

1. 创建 `LoginContext`。
2. 读取配置文件以初始化一个或多个 `LoginModules`。
3. 为每个 LoginModule 调用 `LoginContext.initialize()`。
4. 为每个 LoginModule 调用 `LoginContext.login()`。
5. 如果登录成功，则调用 `LoginContext.commit()`，否则调用 `LoginContext.abort()`

## 配置文件

JAAS 配置文件包含每个可用于应用程序登录的 `LoginModule` 的配置节。

JAAS 配置文件中的一个配置节示例：

```text
Branches
{
    USNavy.AppLoginModule required
    debug=true
    succeeded=true;
}
```

注意分号的位置，用于终止 `LoginModule` 条目和配置节。

"required"一词表示 `LoginContext` 的 `login()` 方法在用户登录时必须成功。`LoginModule` 特定的值 `debug` 和 `succeeded` 会传递给 `LoginModule`。

这些值由 `LoginModule` 定义，其使用在 `LoginModule` 内部管理。请注意，选项使用键值对配置，如 `debug="true"`，键和值应由 `=` 号分隔。

## Main.java（客户端）

- 执行语法：

```text
Java –Djava.security.auth.login.config==packageName/packageName.config
        packageName.Main 配置节1

其中：
    packageName 是包含配置文件的目录。
    packageName.config 指定 Java 包 packageName 中的配置文件。
    packageName.Main 指定 Java 包 packageName 中的 Main.java。
    配置节1 是 Main() 应从配置文件读取的配置节名称。
```

- 执行时，第一个命令行参数是配置文件中的配置节。配置节命名要使用的 `LoginModule`。第二个参数是 `CallbackHandler`。
- 使用传递给 `Main.java` 的参数创建新的 `LoginContext`。
    - `loginContext = new LoginContext (args[0], new AppCallbackHandler());`
- 调用 LoginContext 登录模块：
    - `loginContext.login();`
- 从 `loginContext.login()` 返回 succeeded 选项的值。
- 如果登录成功，则创建一个主体（Subject）。

## LoginModule.java

`LoginModule` 必须具有以下认证方法：

- `initialize()`
- `login()`
- `commit()`
- `abort()`
- `logout()`

### initialize()

在 `Main()` 中，`LoginContext` 从配置文件读取正确的配置节后，实例化配置节中指定的 `LoginModule`。

- `initialize()` 方法签名：
    - `Public void initialize (Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)`
- 应按以下方式保存上述参数：
    - `this.subject = subject;`
    - `this.callbackHandler = callbackHandler;`
    - `this.sharedState = sharedState;`
    - `this.options = options;`
- `initialize()` 方法的作用：
    - 在成功 `login()` 后构建 `Subject` 类的主体对象。
    - 设置与用户交互以收集登录信息的 `CallbackHandler`。
    - 如果 `LoginContext` 指定 2 个或更多 LoginModules（这是合法的），它们可以通过 `sharedState` 映射共享信息。
    - 在选项映射中保存调试和成功等状态信息。

### login()

捕获用户提供的登录信息。下面的代码片段声明了两个回调对象数组，当传递给 `callbackHandler.java` 程序中的 `callbackHandler.handle` 方法时，将加载用户交互提供的用户名和密码：

```java
NameCallback nameCB = new NameCallback("Username");
PasswordCallback passwordCB = new PasswordCallback ("Password", false);
Callback[] callbacks = new Callback[] { nameCB, passwordCB };
callbackHandler.handle (callbacks);
```

- 认证用户
- 从回调对象中检索用户提供的信息：
    - `String ID = nameCallback.getName ();`
    - `char[] tempPW = passwordCallback.getPassword ();`
- 将 `name` 和 `tempPW` 与存储在 LDAP 等存储库中的值进行比较。
- 设置 succeeded 变量的值并返回到 `Main()`。

### commit()

一旦在 `login()` 期间成功验证用户凭据，JAAS 认证框架会根据需要将凭据与主体（Subject）关联。

有两种类型的凭据，**公共**和**私有**：

- 公共凭据包括公钥。
- 私有凭据包括密码和公钥。

将主体（即用户登录名以外的身份）（如员工编号或用户组成员资格）添加到主体。

下面是一个 `commit()` 方法示例，首先为经过认证的用户所属的每个组，将组名作为主体添加到主体。然后将主体的用户名添加到其公共凭据中。

设置并将任何主体和公共凭据添加到主体的代码片段：

```java
public boolean commit() {
    If (userAuthenticated) {
        Set groups = UserService.findGroups (username);
        for (Iterator itr = groups.iterator (); itr.hasNext (); {
            String groupName = (String) itr.next ();
            UserGroupPrincipal group = new UserGroupPrincipal (GroupName);
            subject.getPrincipals ().add (group);
        }
        UsernameCredential cred = new UsernameCredential (username);
        subject.getPublicCredentials().add (cred);
    }
}
```

### abort()

当认证不成功时，调用 `abort()` 方法。在 `abort()` 方法退出 `LoginModule` 之前，应注意重置状态，包括用户名和密码输入字段。

### logout()

当调用 `LoginContext.logout` 时释放用户的主体和凭据：

```java
public boolean logout() {
    if (!subject.isReadOnly()) {
        Set principals = subject.getPrincipals(UserGroupPrincipal.class);
        subject.getPrincipals().removeAll(principals);
        Set creds = subject.getPublicCredentials(UsernameCredential.class);
        subject.getPublicCredentials().removeAll(creds);
        return true;
    } else {
        return false;
    }
}
```

## CallbackHandler.java

`callbackHandler` 位于与任何单个 `LoginModule` 分开的源（`.java`）文件中，以便为具有不同回调对象的多个 LoginModules 提供服务：

- 创建 `CallbackHandler` 类的实例，并且只有一个 `handle()` 方法。
- 为需要用户名和密码登录的 LoginModule 提供服务的 `CallbackHandler`：

```java
public void handle(Callback[] callbacks) {
    for (int i = 0; i < callbacks.length; i++) {
        Callback callback = callbacks[i];
        if (callback instanceof NameCallback) {
            NameCallback nameCallBack = (NameCallback) callback;
            nameCallBack.setName(username);
    }  else if (callback instanceof PasswordCallback) {
            PasswordCallback passwordCallBack = (PasswordCallback) callback;
            passwordCallBack.setPassword(password.toCharArray());
        }
    }
}
```

## 相关文章

- [JAAS 实战](https://jaasbook.wordpress.com/2009/09/27/intro/)，Michael Coté，2009年9月27日发布，URL为 5/14/2012。
- Pistoia Marco, Nagaratnam Nataraj, Koved Larry, Nadalin Anthony 的书籍 ["企业 Java 安全" - Addison-Wesley, 2004](https://www.oreilly.com/library/view/enterprise-javatm-security/0321118898/)。

## 声明

本 JAAS 备忘录中的所有代码都逐字复制自[这个免费源](https://jaasbook.wordpress.com/2009/09/27/intro/)。
