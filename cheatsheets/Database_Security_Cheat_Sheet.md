# 数据库安全备忘录

## 引言

本备忘录为安全配置 SQL 和 NoSQL 数据库提供建议。它旨在供负责管理数据库的应用程序开发人员使用。有关防止 SQL 注入攻击的详细信息，请参阅 [SQL 注入防御备忘录](SQL_Injection_Prevention_Cheat_Sheet.md)。

## 保护后端数据库

应用程序的后端数据库应与其他服务器隔离，并仅与尽可能少的主机连接。这项任务将取决于系统和网络架构。考虑以下建议：

- 禁用网络（TCP）访问，要求所有访问通过本地套接字文件或命名管道。
- 将数据库配置为仅绑定到本地主机。
- 使用防火墙规则将网络端口访问限制到特定主机。
- 将数据库服务器放置在与应用程序服务器隔离的单独 DMZ 中。

任何与数据库一起使用的基于 Web 的管理工具（如 phpMyAdmin）也应受到类似的保护。

当应用程序在不受信任的系统（如胖客户端）上运行时，它应始终通过可以强制执行适当访问控制和限制的 API 连接到后端。**绝对不能**从胖客户端直接连接到后端数据库。

### 实施传输层保护

大多数数据库默认配置从未加密的网络连接开始，尽管有些会加密初始身份验证（如 Microsoft SQL Server）。即使初始身份验证已加密，其余流量也将未加密，所有类型的敏感信息都将以明文形式通过网络发送。应采取以下步骤防止未加密流量：

- 配置数据库仅允许加密连接。
- 在服务器上安装受信任的数字证书。
- 客户端应用程序使用 TLSv1.2+ 和现代密码（如 AES-GCM 或 ChaCha20）连接。
- 客户端应用程序验证数字证书的正确性。

[传输层安全备忘录](Transport_Layer_Security_Cheat_Sheet.md)包含有关安全配置 TLS 的进一步指导。

## 配置安全身份验证

数据库应始终需要身份验证，包括来自本地服务器的连接。数据库账户应：

- 使用强且唯一的密码保护。
- 由单个应用程序或服务使用。
- 按照下面[权限部分](#创建安全权限)讨论的最小权限进行配置。

与任何具有自己用户账户的系统一样，应遵循常规账户管理流程，包括：

- 定期审查账户，确保仍然需要。
- 定期审查权限。
- 在应用程序退役时删除用户账户。
- 在员工离职或有理由相信账户可能已泄露时更改密码。

对于 Microsoft SQL Server，考虑使用 [Windows 或集成身份验证](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/authentication-in-sql-server)，它使用现有的 Windows 账户而不是 SQL Server 账户。这还消除了在应用程序中存储凭据的需求，因为它将使用其运行时的 Windows 用户凭据连接。[MySQL 的 Windows 本机身份验证插件](https://dev.mysql.com/doc/connector-net/en/connector-net-programming-authentication-windows-native.html)提供类似功能。

### 安全存储数据库凭据

数据库凭据绝不应存储在应用程序源代码中，尤其是未加密的凭据。相反，它们应存储在满足以下条件的配置文件中：

- 位于 Web 根目录之外。
- 具有适当的权限，只能由所需用户读取。
- 未签入源代码仓库。

在可能的情况下，这些凭据还应使用内置功能加密或以其他方式保护，如 [ASP.NET](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/connection-strings-and-configuration-files#encrypting-configuration-file-sections-using-protected-configuration) 中可用的 `web.config` 加密。

## 创建安全权限

当开发人员为数据库用户账户分配权限时，应遵循最小权限原则（即账户只应具有应用程序正常运行所需的最小权限）。根据数据库中可用的功能，可以在多个越来越精细的级别应用此原则。在所有环境中，您可以执行以下操作：

- 不使用内置的 `root`、`sa` 或 `SYS` 账户。
- 不授予账户对数据库实例的管理权限。
- 确保账户只能从允许的主机连接。通常是 `localhost` 或应用程序服务器的地址。
- 账户只能访问所需的特定数据库。开发、UAT 和生产环境应使用单独的数据库和账户。
- 仅授予数据库所需的权限。大多数应用程序只需要 `SELECT`、`UPDATE` 和 `DELETE` 权限。账户不应是数据库的所有者，因为这可能导致权限提升漏洞。
- 避免使用数据库链接或链接服务器。如果需要，请使用仅被授予访问所需最小数据库、表和系统权限的账户。

大多数安全关键应用程序在更精细的级别应用权限，包括：

- 表级权限。
- 列级权限。
- 行级权限。
- 阻止对底层表的直接访问，并要求通过受限[视图](https://en.wikipedia.org/wiki/View_(SQL))进行所有访问。

## 数据库配置和强化

数据库服务器的底层操作系统应基于安全基线进行强化，如 [CIS 基准](https://www.cisecurity.org/cis-benchmarks/)或 [Microsoft 安全基线](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)。

数据库应用程序也应正确配置和强化。以下原则应适用于任何数据库应用程序和平台：

- 安装所有必需的安全更新和补丁。
- 配置数据库服务在低权限用户账户下运行。
- 删除任何默认账户和数据库。
- 将[事务日志](https://en.wikipedia.org/wiki/Transaction_log)存储在与主数据库文件不同的磁盘上。
- 配置数据库定期备份。确保备份受适当权限保护，并最好加密。

以下部分为特定数据库软件提供了一些额外建议，补充了上面给出的更一般性建议。

### 强化 Microsoft SQL Server

- 禁用 `xp_cmdshell`、`xp_dirtree` 和其他不需要的存储过程。
- 禁用公共语言运行时（CLR）执行。
- 禁用 SQL 浏览器服务。
- 除非必需，否则禁用[混合模式身份验证](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver15)。
- 确保已删除示例 [Northwind 和 AdventureWorks 数据库](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/linq/downloading-sample-databases)。
- 参见 Microsoft 关于[保护 SQL Server](https://docs.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server) 的文章。

### 强化 MySQL 或 MariaDB 服务器

- 运行 `mysql_secure_installation` 脚本以删除默认数据库和账户。
- 对所有用户禁用 [FILE](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) 权限，防止他们读取或写入文件。
- 参见 [Oracle MySQL](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html) 和 [MariaDB](https://mariadb.com/kb/en/library/securing-mariadb/) 强化指南。

### 强化 PostgreSQL 服务器

- 参见 [PostgreSQL 服务器设置和操作文档](https://www.postgresql.org/docs/current/runtime.html)和较旧的[安全文档](https://www.postgresql.org/docs/7.0/security.htm)。

### MongoDB

- 参见 [MongoDB 安全检查清单](https://docs.mongodb.com/manual/administration/security-checklist/)。

### Redis

- 参见 [Redis 安全指南](https://redis.io/topics/security)。
