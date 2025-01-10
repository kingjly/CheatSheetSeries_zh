# 操作系统命令注入防御备忘录

## 简介

命令注入（或操作系统命令注入）是一种注入类型，当软件使用外部影响的输入构造系统命令时，未正确中和可能修改最初预期命令的特殊元素。

### 示例

原始输入：
```shell
calc
```
执行结果：打开 Windows 计算器

被篡改的输入：
```shell
calc & echo "test"
```
执行结果：同时显示计算器和 "test"

## 主要防御策略

### 防御选项 1：避免直接调用操作系统命令

首选方案是避免直接调用操作系统命令。使用内置库函数是最佳替代方案，因为它们不能被操纵执行非预期任务。

示例：
- 使用 `mkdir()` 替代 `system("mkdir /dir_name")`
- 优先使用特定语言的可用库或 API

### 防御选项 2：针对特定操作系统转义添加到命令中的值

使用专门的转义函数，如 PHP 的 `escapeshellarg()`。

### 防御选项 3：参数化与输入验证结合

如果无法避免调用系统命令，应采用两层防御：

#### 第一层：参数化

使用结构化机制自动强制数据和命令分离，提供相关的引用和编码。

#### 第二层：输入验证

- **命令验证**：仅允许预定义的命令列表
- **参数验证**：
  - 正面（白名单）输入验证
  - 白名单正则表达式
  - 使用 `--` 分隔参数，防止参数注入

### 需要转义的特殊字符

```text
& | ; $ > < ` \ ! ' " ( )
```

## 额外防御措施

- 应用程序应使用完成任务所需的最低权限运行
- 尽可能创建具有有限权限的隔离账户

## 代码示例

### Java

使用 `ProcessBuilder`，命令必须与参数分开：

```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");
Map<String, String> env = pb.environment();
pb.directory(new File("TrustedDir"));
Process p = pb.start();
```

### PHP

使用 `escapeshellarg()` 或 `escapeshellcmd()`：

```php
$safePath = escapeshellarg($userProvidedPath);
system("ls " . $safePath);
```

### .NET

参考 [DotNet 安全备忘录](DotNet_Security_Cheat_Sheet.md#os-injection)

## 相关资源

### 漏洞描述
- OWASP [命令注入](https://owasp.org/www-community/attacks/Command_Injection)

### 漏洞避免
- [不要调用 system()](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87152177)

### 代码审查
- OWASP [审查操作系统注入代码](https://wiki.owasp.org/index.php/Reviewing_Code_for_OS_Injection)

### 测试
- OWASP [Web 安全测试指南 - 命令注入测试](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection.html)

### 外部参考
- [CWE 条目 77：命令注入](https://cwe.mitre.org/data/definitions/77.html)
