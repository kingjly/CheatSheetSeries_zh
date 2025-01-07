# 基于 C 的工具链加固备忘录

## 引言

基于 C 的工具链加固是一种项目设置处理方法，可帮助您在 C、C++ 和 Objective C 语言的多种开发环境中交付可靠和安全的代码。本文将研究 Microsoft 和 GCC 工具链在 C、C++ 和 Objective C 语言中的应用。它将指导您采取哪些步骤来创建具有更坚固防御姿态和更高平台安全集成的可执行文件。有效配置工具链还意味着您的项目将在开发过程中享受许多好处，包括增强的警告和静态分析，以及自我调试代码。

在加固工具链时，需要检查四个领域：配置、预处理器、编译器和链接器。几乎所有这些领域在设置项目时都被忽视或忽略。这种忽视似乎是普遍存在的，并且适用于几乎所有项目，包括自动配置项目、基于 Makefile 的项目、基于 Eclipse 的项目、基于 Visual Studio 的项目和基于 Xcode 的项目。在配置和构建时解决这些差距很重要，因为在某些平台上，[在分发可执行文件后添加强化是困难甚至不可能的](https://sourceware.org/ml/binutils/2012-03/msg00309.html)。

这是一篇规范性文章，不会争论语义或推测行为。一些信息，如 C/C++ 委员会对 [`程序诊断`、`NDEBUG`、`assert` 和 `abort()`](https://groups.google.com/a/isocpp.org/forum/?fromgroups=#!topic/std-discussion/ak8e1mzBhGs) 的动机和渊源，似乎已经像《指环王》中的故事一样失传了。因此，本文将指定语义（例如，"调试"和"发布"构建配置的哲学），分配行为（例如，在"调试"和"发布"构建配置中 assert 应该做什么），并提出立场。如果您觉得这种姿态过于激进，则应根据需要适当调整。

安全的工具链并非万能药。它是整体工程过程中确保成功的一个组成部分。它将补充现有的流程，如静态分析、动态分析、安全编码、负面测试套件等。诸如 Valgrind 和 Helgrind 之类的工具仍然是必需的，项目仍然需要坚实的设计和架构。

OWASP [ESAPI C++](https://code.google.com/p/owasp-esapi-cplusplus/source) 项目践行了自己的理念。本文中的许多示例直接来自 ESAPI C++ 项目。

最后，对于那些希望获得简明版本的人，可以访问 [基于 C 的工具链加固备忘录](C-Based_Toolchain_Hardening_Cheat_Sheet.md)。

## 智慧

代码**必须**是正确的。它**应该**是安全的。它**可以**是高效的。

[乔恩·本特利博士](https://en.wikipedia.org/wiki/Jon_Bentley)：*"如果它不需要正确，我可以让它达到你想要的速度"*。

[加里·麦克格劳博士](https://en.wikipedia.org/wiki/Gary_McGraw)：*"汝不可仅仅依赖安全特性和功能来构建安全软件，因为安全是整个系统的新兴属性，因此依赖于正确构建和集成所有部分"*。

## 配置

配置是配置项目成功的第一个机会。您不仅要配置项目以满足可靠性和安全性目标，还必须正确配置集成的库。通常有三种选择。首先，如果在 Linux 或 Unix 上，可以使用自动配置实用程序。其次，可以手动编写 Makefile。这在 Linux、macOS 和 Unix 上很普遍，但也适用于 Windows。最后，可以使用集成开发环境（IDE）。

### 构建配置

在此阶段，您应该专注于配置两种构建：调试（Debug）和发布（Release）。调试版本用于开发并包含完整的检测。发布版本配置用于生产。两种设置之间的差异通常是*优化级别*和*调试级别*。第三种构建配置是测试（Test），通常是发布配置的特殊情况。

对于调试和发布构建，设置通常是截然不同的。调试配置没有优化且包含完整的调试信息，而发布构建具有优化和最小到中等的调试信息。此外，调试代码具有完整的断言和额外的库集成，如 mudflaps 和 malloc 守卫，如 `dmalloc`。

测试配置通常是一个发布配置，使所有内容对测试公开并构建测试工具。例如，所有公共成员函数（C++ 类）和所有接口（库或共享对象）都应可用于测试。许多面向对象的纯粹主义者反对测试私有接口，但这不是关于面向对象性。这是关于构建可靠和安全的软件。

[GCC 4.8](https://gcc.gnu.org/gcc-4.8/changes.html) 引入了 `-Og` 优化。请注意，这只是一个优化，仍然需要通过 `-g` 设置调试级别。

#### 调试构建

开发人员在排查问题时大部分时间都在调试构建中，因此这种构建应该集中力量和工具，或成为"力量倍增器"。尽管许多人没有意识到，调试代码比发布代码更有价值，因为它配备了额外的检测。调试检测将使程序几乎"自我调试"，并帮助您捕获诸如错误参数、API 调用失败和内存问题等错误。

自我调试代码可减少故障排除和调试期间的时间。减少调试器下的时间意味着您有更多时间进行开发和功能请求。如果代码在没有调试检测的情况下被检入，则应通过添加检测来修复，或拒绝提交。

对于 GCC，优化和调试符号通过两个开关控制：`-O` 和 `-g`。作为最小调试会话的一部分，您应该使用以下设置：

```text
-O0 -g3 -ggdb
```

`-O0` 关闭优化，`-g3` 确保最大的调试信息可用。您可能需要使用 `-O1`，以便执行一些分析。否则，您的调试构建将缺少在发布构建中不存在的许多警告。`-g3` 确保调试会话可以使用最大的调试信息，包括符号常量和 `#define`。`-ggdb` 包括帮助 GDB 进行调试会话的扩展。为完整起见，Jan Krachtovil 在私人邮件中表示 `-ggdb` 目前没有影响。

发布构建还应考虑 `-mfunction-return=thunk` 和 `-mindirect-branch=thunk` 配对。这些是"Reptoline"修复，是用于阻止 Spectre 和 Meltdown 等推测执行 CPU 漏洞的间接分支。由于是间接（而非直接）分支，CPU 无法判断要`推测性`执行什么代码。这是一个额外的间接层，类似于通过指针调用指针。

调试构建还应定义 `DEBUG`，并确保未定义 `NDEBUG`。`NDEBUG` 会删除"程序诊断"并具有不良行为和副作用，下文将详细讨论。这些定义应对所有代码都存在，而不仅仅是程序本身。您对所有代码（您的程序和包含的库）都这样做，因为您还需要知道它们如何失败（请记住，您会收到错误报告 - 而不是第三方库）。

此外，您还应使用其他相关标志，如 `-fno-omit-frame-pointer`。确保帧指针存在可以更容易地解码堆栈跟踪。由于调试构建不会发布，将符号保留在可执行文件中是可以的。带有调试信息的程序不会遭受性能损失。例如，请参见 [gcc -g 选项如何影响性能？](https://gcc.gnu.org/ml/gcc-help/2005-03/msg00032.html)

最后，您应确保项目包含额外的诊断库，如 `dmalloc` 和 [地址消毒剂](https://github.com/google/sanitizers/tree/master/hwaddress-sanitizer)。一些内存检查工具的比较可在 [内存工具比较](https://github.com/google/sanitizers/wiki/AddressSanitizerComparisonOfMemoryTools) 中找到。如果您不在调试构建中包含额外的诊断，那么您应该开始使用它们，因为发现意料之外的错误是可以的。

#### 发布构建

发布构建是客户收到的版本。它们旨在在生产硬件和服务器上运行，应该是可靠、安全和高效的。稳定的发布构建是开发过程中辛勤工作和努力的成果。

对于发布构建，您应该在发布构建的 `CFLAGS` 和 `CXXFLAGS` 中使用以下设置：

```text
-On -g2
```

`-O`_`n`_ 设置速度或大小的优化（例如，`-Os` 或 `-O2`），`-g2` 确保创建调试信息。

调试信息应该被剥离，并保留以便在现场崩溃报告中进行符号化。虽然不受欢迎，但调试信息可以原位保留而不会造成性能损失。有关详细信息，请参见 _[gcc -g 选项如何影响性能？](https://gcc.gnu.org/ml/gcc-help/2005-03/msg00032.html)_

发布构建还应定义 `NDEBUG`，并确保未定义 `DEBUG`。调试和诊断的时间已经结束，因此用户获得具有完全优化、无"编程诊断"和其他效率的生产代码。如果无法优化或执行过多日志记录，通常意味着程序尚未准备好投入生产。

如果您一直依赖 `assert` 然后随后的 `abort()`，那么您一直在滥用"编程诊断"，因为它在生产代码中毫无用处。如果您想要内存转储，请创建一个，这样用户就不必担心秘密和其他敏感信息以纯文本形式写入文件系统并通过电子邮件发送。

对于 Windows，您将对调试构建使用 `/Od`，对发布构建使用 `/Ox`、`/O2` 或 `/Os`。有关详细信息，请参见微软的 [/O 选项（优化代码）](https://docs.microsoft.com/en-us/cpp/build/reference/o-options-optimize-code)。

#### 测试构建

测试构建用于通过正面和负面测试套件提供启发式验证。在测试配置下，测试所有接口以确保它们按规范和满意度执行。"满意度"是主观的，但应包括不崩溃且即使面对负面测试也不会破坏内存区域。

因为测试所有接口（而不仅仅是公共接口），您的 `CFLAGS` 和 `CXXFLAGS` 应包括：

```text
-Dprotected=public -Dprivate=public
```

您还应将 `__attribute__` `((visibility` `("hidden")))` 更改为 `__attribute__` `((visibility` `("default")))`.

几乎每个人都能正确进行正面测试，所以不需要多说。负面自测更有趣，您应该专注于尝试使程序失败，以验证它是否优雅地失败。请记住，恶意行为者在试图使您的程序失败时不会很有礼貌，而是您的项目会因错误报告或在 [Full Disclosure](https://nmap.org/mailman/listinfo/fulldisclosure) 或 [Bugtraq](https://www.securityfocus.com/archive) 上出现而丢脸 - 而不是您包含的 `<某个库>`。

### 自动工具

自动配置工具在许多 Linux 和 Unix 系统上很受欢迎，这些工具包括 _Autoconf_、_Automake_、_config_ 和 _Configure_。这些工具一起从脚本和模板文件生成项目文件。完成该过程后，您的项目应该已设置并可以使用 `make` 进行构建。

使用自动配置工具时，有几个值得一提的感兴趣文件。这些文件是 Autotools 链的一部分，包括 `m4` 以及各种 `*.in`、`*.ac`（Autoconf）和 `*.am`（Automake）文件。有时，您必须打开它们或生成的 Makefile 以调整"现成"配置。

命令行配置工具链有三个缺点：(1) 它们经常忽略用户请求，(2) 它们无法创建配置，(3) 安全性通常不是目标。

为了证明第一个问题，使用以下命令配置您的项目：`configure` `CFLAGS="-Wall` `-fPIE"` `CXXFLAGS="-Wall` `-fPIE"` `LDFLAGS="-pie"`。您可能会发现 Autotools 忽略了您的请求，这意味着下面的命令可能不会产生预期结果。作为解决方法，您将不得不打开 `m4` 脚本、`makefile.in` 或 `makefile.am`，并修复配置。

```bash
$ configure CFLAGS="-Wall -Wextra -Wconversion -fPIE -Wno-unused-parameter
    -Wformat=2 -Wformat-security -fstack-protector-all -Wstrict-overflow"
    LDFLAGS="-pie -z,noexecstack -z,noexecheap -z,relro -z,now"
```

对于第二点，您可能会失望地发现 [Automake 不支持配置的概念](https://lists.gnu.org/archive/html/automake/2012-12/msg00019.html)。这不完全是 Autoconf 或 Automake 的错 - _Make_ 及其无法检测更改的能力是根本问题。具体来说，_Make_ 只[检查先决条件和目标的修改时间](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/make.html)，不检查诸如 `CFLAGS` 和 `CXXFLAGS` 之类的内容。其净效果是，当您发出 `make` `debug`，然后 `make` `test` 或 `make` `release` 时，您将不会得到预期的结果。

最后，您可能会失望地发现像 Autoconf 和 Automake 这样的工具错过了许多安全相关的机会，并且开箱即不安全。有许多编译器开关和链接器标志可以提高程序的防御姿态，但默认情况下并未启用。像 Autoconf 这样本应处理这种情况的工具，往往提供服务于最低公共分母的设置。

最近在 Automake 邮件列表上的一次讨论阐明了这个问题：_[启用编译器警告标志](https://lists.gnu.org/archive/html/autoconf/2012-12/msg00038.html)_。改进默认配置的尝试遭到了抵制并且未采取任何行动。抵制通常采用"`<某些有用警告>也会产生误报`"或"`<某些晦涩平台>不支持<已建立的安全特性>`"的形式。值得注意的是，_[Linux 和 Unix 安全编程指南](https://dwheeler.com/secure-programs/)_ 的作者 David Wheeler 是试图改进姿态的人之一。

### Makefile

Make 是最早的构建工具之一，可以追溯到 1970 年代。它在 Linux、macOS 和 Unix 上都可用，因此您将经常遇到使用它的项目。不幸的是，Make 有许多缺陷（[递归 Make 被认为是有害的](https://embeddedartistry.com/blog/2017/04/10/recursive-make-considered-harmful/)和 [GNU Make 有什么问题？](https://www.conifersystems.com/whitepapers/gnu-make/)），并可能造成一些不适。尽管存在问题，ESAPI C++ 主要出于三个原因使用 Make：首先，它无处不在；其次，它比 Autotools 系列更容易管理；第三，`libtool` 是不可接受的。

考虑当您：(1) 输入 `make` `debug`，然后输入 `make` `release` 时会发生什么。每个构建由于优化和调试支持级别的不同，都需要不同的 `CFLAGS`。在您的 Makefile 中，您将提取相关目标并设置 `CFLAGS` 和 `CXXFLAGS`，类似于下面（摘自 [ESAPI C++ Makefile](https://code.google.com/archive/p/owasp-esapi-cplusplus/source/default/source)）：

```text
## makefile
DEBUG_GOALS = $(filter $(MAKECMDGOALS), debug)
ifneq ($(DEBUG_GOALS),)
    WANT_DEBUG := 1
    WANT_TEST := 0
    WANT_RELEASE := 0
endif
…

ifeq ($(WANT_DEBUG),1)
    ESAPI_CFLAGS += -DDEBUG=1 -UNDEBUG -g3 -ggdb -O0
    ESAPI_CXXFLAGS += -DDEBUG=1 -UNDEBUG -g3 -ggdb -O0
endif

ifeq ($(WANT_RELEASE),1)
    ESAPI_CFLAGS += -DNDEBUG=1 -UDEBUG -g -O2
    ESAPI_CXXFLAGS += -DNDEBUG=1 -UDEBUG -g -O2
endif

ifeq ($(WANT_TEST),1)
    ESAPI_CFLAGS += -DESAPI_NO_ASSERT=1 -g2 -ggdb -O2 -Dprivate=public
                                                      -Dprotected=public
    ESAPI_CXXFLAGS += -DESAPI_NO_ASSERT=1 -g2 -ggdb -O2 -Dprivate=public
                                                        -Dprotected=public
endif
…

## 将 ESAPI 标志与用户提供的标志合并。我们执行额外的步骤，以确保
## 用户选项跟随我们的选项，这应该给用户选项优先权。
override CFLAGS := $(ESAPI_CFLAGS) $(CFLAGS)
override CXXFLAGS := $(ESAPI_CXXFLAGS) $(CXXFLAGS)
override LDFLAGS := $(ESAPI_LDFLAGS) $(LDFLAGS)
…
```

Make 将首先使用类似于以下规则在调试配置下构建程序，以便进行调试会话：

```text
%.cpp:%.o:
        $(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
```

当您想要发布构建时，Make 将不执行任何操作，因为尽管 `CFLAGS` 和 `CXXFLAGS` 已更改，它仍认为一切都是最新的。因此，您的程序实际上仍处于调试配置，并在运行时有 `SIGABRT` 的风险，因为调试检测存在（回想一下，当未定义 `NDEBUG` 时，`assert` 调用 `abort()`）。本质上，由于 `make`，您已经对自己进行了拒绝服务攻击。

此外，许多项目不尊重用户的命令行。ESAPI C++ 尽最大努力通过 `override` 确保用户的标志被接受，如上所示，但其他项目则不然。例如，考虑一个应该启用位置无关可执行文件（PIE 或 ASLR）和数据执行防护（DEP）的项目。忽略用户设置，加上开箱即不安全的设置（并且在自动设置或自动配置期间不选择它们），意味着使用以下命令构建的程序可能既没有 PIE 也没有 DEP：

```bash
make CFLAGS="-fPIE" CXXFLAGS="-fPIE" LDFLAGS="-pie -z,noexecstack, -z,noexecheap"
```

在 Linux 上，ASLR 和 DEP 等防御措施尤为重要，因为[数据执行 - 而非防护 - 是常态](https://linux.die.net/man/5/elf)。
