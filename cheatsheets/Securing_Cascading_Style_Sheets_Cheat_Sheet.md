# CSS 安全备忘录

## 引言

本 `CSS`（不是 [XSS](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)，而是[层叠样式表](https://www.w3schools.com/css/css_intro.asp)）备忘录旨在为程序员、测试人员、安全分析师、前端开发人员以及对 Web 应用程序安全感兴趣的人提供建议和要求，以在编写 `层叠样式表` 时实现更好的安全性。

让我们通过一个示例来说明这种风险：

桑索斯是一家名为 **X** 的公司的程序员，他正在编写层叠样式表来实现 Web 应用程序的样式。该应用程序有不同的角色，如 **学生**、**教师**、**超级用户** 和 **管理员**，这些角色具有不同的权限（基于权限的访问控制 - PBAC）和角色（基于角色的访问控制 - RBAC）。这些角色不仅具有不同的访问控制，还可能针对个人或特定角色组有不同的网页样式。

桑索斯认为创建一个包含所有角色的 CSS 样式/选择器的"全局样式"CSS 文件是一个很好的优化方案。根据他们的角色，特定的功能或用户界面元素将被渲染。例如，管理员的功能将与 **学生**、**教师** 或 **超级用户** 不同。然而，某些权限或功能可能对某些角色是通用的。

示例：个人资料设置适用于所有用户，而 *添加用户* 或 *删除用户* 仅适用于 **管理员**。

示例：

- `.login`
- `.profileStudent`
- `.changePassword`
- `.addUsers`
- `.deleteUsers`
- `.addNewAdmin`
- `.deleteAdmin`
- `.exportUserData`
- `.exportProfileData`
- ...

现在，让我们来研究这种编码方式的风险。

### 风险 \#1

有动机的攻击者总是查看 `*.CSS` 文件，即使在未登录的情况下也能了解应用程序的功能。

例如：吉姆是一个有动机的攻击者，总是尝试在其他攻击之前通过查看源代码查看 CSS 文件。当吉姆查看 CSS 文件时，他们会看到不同的功能和基于 CSS 选择器的不同角色，如 `.profileSettings`、`.editUser`、`.addUser`、`.deleteUser` 等。吉姆可以使用 CSS 进行情报收集，以帮助获取敏感角色的访问权限。这是攻击者在尝试执行危险攻击以获取 Web 应用程序访问权限之前进行的侦察。

简而言之，使用全局样式可能会泄露对攻击者有利的敏感信息。

### 风险 \#2

假设桑索斯习惯于编写描述性的选择器名称，如 `.profileSettings`、`exportUserData`、`.changePassword`、`.oldPassword`、`.newPassword`、`.confirmNewPassword` 等。优秀的程序员喜欢保持代码的可读性和可用性，以便团队的代码审查员使用。风险在于攻击者可以将这些选择器映射到 Web 应用程序的实际功能。

## 减轻攻击者动机的防御机制

### 防御机制 \#1

作为 CSS 编码员/程序员，始终按访问控制级别隔离 CSS。这意味着 **学生** 将有一个名为 `StudentStyling.CSS` 的 CSS 文件，而 **管理员** 有 `AdministratorStyling.CSS`，依此类推。确保这些 `*.CSS` 文件只能被具有适当访问控制级别的用户访问。只有具有适当访问控制级别的用户才能访问其 `*.CSS` 文件。

如果具有 **学生** 角色的经过身份验证的用户尝试通过强制浏览访问 `AdministratorStyling.CSS`，则应记录正在发生入侵的警报。

### 防御机制 \#2

另一个选择是修改 CSS 文件以删除任何标识信息。作为一般规则，建议您的网站在页面之间保持一致的样式，最好以这样的方式编写常规 CSS 规则，使其适用于多个页面。这减少了首先需要特定选择器的需求。此外，通常可以创建 CSS 选择器来定位特定的 HTML 元素，而无需使用 ID 或类名。例如，`#UserPage .Toolbar .addUserButton` 可以重写为更模糊的内容，如 `#page_u header button:first-of-type`。

构建时和运行时工具也存在，可以集成以混淆您的类名。这可以降低攻击者猜测应用程序功能的机会。一些示例：

- [JSS](https://cssinjs.org)（CSS in JS）有一个 `minify` 选项，可以生成如 `.c001`、`.c002` 这样的类名。
- [CSS Modules](https://github.com/css-modules/css-modules) 有 `modules` 和 `localIdentName` 选项，其功能类似于 JSS，但允许导入任何 CSS 文件而无需对应用程序进行重大结构更改。
- [.Net Blazor CSS 隔离](https://learn.microsoft.com/en-us/aspnet/core/blazor/components/css-isolation) 可用于将 CSS 范围限定为使用它的组件，并生成类似 `button.add[b-3xxtam6d07]` 的选择器。
- CSS 库，如 [Bootstrap](https://getbootstrap.com) 和 [Tailwind](https://tailwindcss.com)，可以减少对特定 CSS 选择器的需求，因为它们提供了强大的基础主题。

### 防御机制 \#3

允许用户通过 HTML 输入创作内容的 Web 应用程序可能容易受到 CSS 的恶意使用。上传的 HTML 可能使用 Web 应用程序允许的样式，但可能用于非预期目的，从而导致安全风险。

示例：您可以阅读 [LinkedIn](https://www.scmagazine.com/news/vulnerability-management/style-sheet-vulnerability-allowed-attacker-to-hijack-linkedin-pages) 如何存在一个允许恶意使用 CSS 执行[点击劫持](https://owasp.org/www-community/attacks/Clickjacking)攻击的漏洞。这导致文档进入一种状态，在页面上任何位置点击都会导致加载潜在的恶意网站。您可以在[此处](Clickjacking_Defense_Cheat_Sheet.md)阅读有关缓解点击劫持攻击的更多信息。
