# OWASP Cheat Sheet Series 中文版

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/OWASP_Project_Inventory#tab=Flagship_Projects)
[![Creative Commons License](https://img.shields.io/github/license/OWASP/CheatSheetSeries)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")
![Translation Status](https://img.shields.io/badge/翻译进度-进行中-yellow)

## 📢 翻译项目说明

这是 OWASP Cheat Sheet Series 项目的中文翻译版本。我们希望通过翻译来帮助中文开发者更好地了解和实践 Web 应用安全。

- 🔗 [原项目地址](https://github.com/OWASP/CheatSheetSeries)
- 📚 [原项目官网](https://cheatsheetseries.owasp.org)
- 🌐 [OWASP 主页](https://owasp.org/www-project-cheat-sheets/)

### 翻译说明

- 本项目专注于翻译 `cheatsheets` 目录下的核心内容
- 翻译力求准确、通顺，同时保留重要的专业术语
- 欢迎社区贡献者参与翻译和审校工作

### 翻译进度

- 目前翻译工作正在进行中
- 已翻译文件位于 `cheatsheets` 目录

# Welcome to the OWASP Cheat Sheet Series

[原 README 其余内容保持不变...]



# Welcome to the OWASP Cheat Sheet Series

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/OWASP_Project_Inventory#tab=Flagship_Projects)
[![Creative Commons License](https://img.shields.io/github/license/OWASP/CheatSheetSeries)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

Welcome to the official repository for the Open Web Application Security Project® (OWASP) Cheat Sheet Series project. The project focuses on providing good security practices for builders in order to secure their applications.

In order to read the cheat sheets and **reference** them, use the project [official website](https://cheatsheetseries.owasp.org). The project details can be viewed on the [OWASP main website](https://owasp.org/www-project-cheat-sheets/) without the cheat sheets.

:triangular_flag_on_post: Markdown files are the working sources and aren't intended to be referenced in any external documentation, books or websites.

## Cheat Sheet Series Team

### Project Leaders

- [Jim Manico](https://github.com/jmanico)
- [Jakub Maćkowski](https://github.com/mackowski)

### Core Team

- [Kevin W. Wall](https://github.com/kwwall)
- [Shlomo Zalman Heigh](https://github.com/szh)

## Chat With Us

We're easy to find on Slack:

1. Join the OWASP Group Slack with this [invitation link](https://owasp.org/slack/invite).
2. Join the [#cheatsheets channel](https://owasp.slack.com/messages/C073YNUQG).

Feel free to ask questions, suggest ideas, or share your best recipes.

## Contributions, Feature Requests, and Feedback

We are actively inviting new contributors! To start, please read the [contribution guide](CONTRIBUTING.md).

This project is only possible thanks to the work of many dedicated volunteers. Everyone is encouraged to help in ways large and small. Here are a few ways you can help:

- Read the current content and help us fix any spelling mistakes or grammatical errors.
- Choose an existing [issue](https://github.com/OWASP/CheatSheetSeries/issues) on GitHub and submit a pull request to fix it.
- Open a new issue to report an opportunity for improvement.

### Automated Build

This [link](https://cheatsheetseries.owasp.org/bundle.zip) allows you to download a build (ZIP archive) of the offline website.

### Local Build [![pyVersion3x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

The OWASP Cheat Sheet Series website can be built and tested locally by issuing the following commands:

```sh
make install-python-requirements
make generate-site
make serve  # Binds port 8000
```

### Container Build

The OWASP Cheat Sheet Series website can be built and tested locally inside a container by issuing the following commands:

#### Docker

```sh
docker build -t cheatsheetseries .
docker run --name cheatsheetseries -p 8000:8000 cheatsheetseries
```

#### Podman

```sh
podman build -t cheatsheetseries .
podman run --name cheatsheetseries -p 8000:8000 localhost/cheatsheetseries
```

## Contributors

- **From 2014 to 2018:** [V1](CONTRIBUTOR-V1.md) - Initial version of the project hosted on the [OWASP WIKI](https://wiki.owasp.org).
- **From 2019:** [V2](https://github.com/OWASP/CheatSheetSeries/graphs/contributors) - Hosted on [GitHub](https://github.com/OWASP/CheatSheetSeries).

## Special thanks

A special thank you to the following people for their help provided during the migration:

- [Dominique Righetto](https://github.com/righettod): For his special leadership and guidance.
- [Elie Saad](https://github.com/ThunderSon): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets and for years of leadership and other project support.
- [Jakub Maćkowski](https://github.com/mackowski): For valuable help in updating the OWASP Wiki links for all the migrated cheat sheets.

Open Web Application Security Project and OWASP are registered trademarks of the OWASP Foundation, Inc.


## 🤝 参与贡献

我们欢迎任何形式的贡献，特别是：

1. 翻译校对
2. 文档改进
3. 术语表维护
4. 问题反馈

### 如何贡献

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b translate-xxx`)
3. 提交你的改动 (`git commit -m '翻译: xxx'`)
4. 推送到分支 (`git push origin translate-xxx`)
5. 创建一个 Pull Request

### 翻译指南

1. 保持专业术语的准确性
2. 对重要的英文术语保留原文，并在首次出现时附上中文翻译
3. 保持语言通顺，避免直译
4. 遵循原文档的格式规范

## 📝 许可证

本项目采用与原项目相同的许可证 [Creative Commons License](https://creativecommons.org/licenses/by-sa/4.0/)

## 致谢

- 感谢所有参与翻译的贡献者
- 感谢原项目的所有贡献者
- 特别感谢 OWASP 基金会提供这么棒的原创内容

---
Open Web Application Security Project 和 OWASP 是 OWASP 基金会的注册商标。
