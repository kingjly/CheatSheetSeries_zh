# 网络分段备忘录

## 引言

网络分段是现代服务多层深度防御的核心。分段可以减缓攻击者实施以下攻击的速度：

- SQL 注入，参见 [SQL 注入预防备忘录](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md)；
- 攻陷具有高级权限的员工工作站；
- 攻陷组织外围的另一台服务器；
- 通过攻陷 LDAP 目录、DNS 服务器和其他在互联网上发布的企业服务和站点来攻陷目标服务。

本备忘录的主要目标是展示网络分段的基础知识，通过构建安全且最大程度隔离的服务网络架构，有效地对抗攻击。

分段将避免以下情况：

- 在公共 Web 服务器（NginX、Apache、Internet Information Service）上执行任意命令，防止攻击者直接访问数据库；
- 即使攻击者未经授权访问数据库服务器，也无法访问互联网上的 CnC（命令与控制）。

## 内容

- 示意图符号；
- 三层网络架构；
- 服务间交互；
- 网络安全策略；
- 有用的链接。

## 示意图符号

网络图中使用的元素：

![示意图符号](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_Schematic_symbols.drawio.png)

跨越矩形边界意味着穿过防火墙：
![流量通过两个防火墙](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_firewall_1.drawio.png)

在上图中，流量通过名为 FW1 和 FW2 的两个防火墙

![流量通过一个防火墙](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_firewall_2.drawio.png)

在上图中，流量通过一个防火墙，防火墙后有两个 VLAN

后续图表中不再包含防火墙图标，以避免过度复杂

## 三层网络架构

默认情况下，开发的信息系统应至少由三个组件（**安全区域**）组成：

1. [前端（FRONTEND）](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md#FRONTEND)；
2. [中间层（MIDDLEWARE）](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md#MIDDLEWARE)；
3. [后端（BACKEND）](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Network_Segmentation_Cheat_Sheet.md#BACKEND)。

### 前端（FRONTEND）

前端是包含以下网络元素的一组网段：

- 负载均衡器；
- 应用层防火墙；
- Web 服务器；
- Web 缓存。

![前端](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_FRONTEND.drawio.png)

### 中间层（MIDDLEWARE）

中间层是用于容纳以下网络元素的一组网段：

- 实现信息系统逻辑的 Web 应用程序（处理来自客户端、公司其他服务和外部服务的请求；执行请求）；
- 授权服务；
- 分析服务；
- 消息队列；
- 流处理平台。

![中间层](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_MIDDLEWARE.drawio.png)

### 后端（BACKEND）

后端是用于容纳以下网络元素的一组网段：

- SQL 数据库；
- LDAP 目录（域控制器）；
- 加密密钥存储；
- 文件服务器。

![后端](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_BACKEND.drawio.png)

### 三层网络架构示例

![后端](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_TIER_Example.drawio.png)

下面的示例展示了一个组织的本地网络。该组织名为"Contoso"。

边缘防火墙包含 **前端（FRONTEND）** 安全区域的 2 个 VLAN：

- _DMZ 入站_ - 用于托管可从互联网访问的服务和应用程序，必须受 WAF 保护；
- _DMZ 出站_ - 用于托管无法从互联网访问但可访问外部网络的服务（防火墙不包含允许来自外部网络的流量的任何规则）。

内部防火墙包含 4 个 VLAN：

- **中间层（MIDDLEWARE）** 安全区域仅包含一个名为 _应用程序_ 的 VLAN - 用于托管相互交互（服务间通信）并与其他服务交互的信息系统应用程序的网段；
- **后端（BACKEND）** 安全区域包含：
    - _数据库_ - 用于划分自动化系统各种数据库的网段；
    - _AD 服务_ - 用于托管各种 Active Directory 服务的网段，在示例中仅显示一台域控制器 Contoso.com 服务器；
    - _日志_ - 用于托管日志服务器的网段，服务器集中存储自动化系统的应用程序日志。

## 服务间交互

通常，公司的一些信息系统会相互交互。为此类交互定义防火墙策略非常重要。

基本允许的交互由下图中的绿色箭头指示：
![服务间交互](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_interservice.drawio.png)
上图还显示了从前端（FRONTEND）和中间层（MIDDLEWARE）网段到外部网络（例如互联网）的允许访问。

从此图可以得出：

1. 不同信息系统的前端（FRONTEND）和中间层（MIDDLEWARE）网段之间的访问是被禁止的；
2. 禁止从中间层（MIDDLEWARE）网段访问另一个服务的后端（BACKEND）网段（禁止绕过应用服务器直接访问外部数据库）。

禁止的访问在下图中以红色箭头表示：
![禁止的服务间通信](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_interservice_deny.drawio.png)

### 同一网络上的多个应用

如果您希望在组织中减少网络数量并在每个网络上托管更多应用，可以接受在这些网络上托管负载均衡器。此均衡器将在网络上对流量进行负载均衡。

在这种情况下，需要为此类网络开放一个端口，并且可以基于 HTTP 请求参数等进行负载均衡。

这种分段的示例：
![带负载均衡的服务间通信](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_interservice_balancer.drawio.png)

可以看到，每个网络只有一个入站访问，访问在网络中的负载均衡器上开放。但在这种情况下，分段不再起作用，不同网络段应用程序之间的访问控制是通过负载均衡器在 OSI 模型的第 7 层进行的。

## 网络安全策略

组织必须定义一个描述防火墙规则和基本允许网络访问的"文件"策略。

此策略对以下人员至少是有用的：

- 网络管理员；
- 安全代表；
- IT 审计员；
- 信息系统和软件架构师；
- 开发人员；
- IT 管理员。

当策略通过类似图像描述时，会更加便利。信息应尽可能简洁和直观地呈现。

### 个别策略条款示例

网络策略中的示例将帮助同事快速理解什么访问是潜在允许的，可以被请求。

#### CI/CD 的权限

网络安全策略可以定义软件开发系统允许的基本权限。让我们看一个这种策略可能的样子：
![CI-CD](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_repo.drawio.png)

#### 安全日志记录

在任何信息系统被攻陷的情况下，重要的是其日志不会被攻击者后续修改。为此，可以执行以下操作：将日志复制到单独的服务器，例如使用 syslog 协议，该协议不允许攻击者修改日志，syslog 仅允许向日志中添加新事件。

针对此活动的网络安全策略如下：
![日志记录](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_logs.drawio.png)
在此示例中，我们还讨论了可能包含安全事件的应用程序日志，以及可能表明攻击的潜在重要事件。

#### 监控系统的权限

假设公司使用 Zabbix 作为 IT 监控系统。在这种情况下，策略可能如下所示：
![Zabbix 示例](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/assets/Network_Segmentation_Cheat_Sheet_Monitoring.drawio.png)

## 有用的链接

- [sergiomarotco](https://github.com/sergiomarotco) 的完整网络分段备忘录：[链接](https://github.com/sergiomarotco/Network-segmentation-cheat-sheet)。
