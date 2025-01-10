# PHP 配置安全备忘录

## 简介

本指南旨在帮助配置 PHP 及其运行的 Web 服务器，以确保最高安全性。

### 安全参考资源
- [Paragonie 2018 PHP 安全指南](https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software)
- [Awesome PHP 安全](https://github.com/guardrailsio/awesome-php-security)

## PHP 配置与部署

### php.ini 安全配置

#### PHP 错误处理

```ini
expose_php              = Off
error_reporting         = E_ALL
display_errors          = Off
display_startup_errors  = Off
log_errors              = On
error_log               = /valid_path/PHP-logs/php_error.log
ignore_repeated_errors  = Off
```

**注意**：生产环境必须关闭 `display_errors`，并定期检查日志。

#### PHP 常规设置

```ini
doc_root                = /path/DocumentRoot/PHP-scripts/
open_basedir            = /path/DocumentRoot/PHP-scripts/
include_path            = /path/PHP-pear/
extension_dir           = /path/PHP-extensions/
mime_magic.magicfile    = /path/PHP-magic.mime
allow_url_fopen         = Off
allow_url_include       = Off
variables_order         = "GPCS"
allow_webdav_methods    = Off
session.gc_maxlifetime  = 600
```

`allow_url_*` 可防止本地文件包含（LFI）轻易升级为远程文件包含（RFI）。

#### 文件上传处理

```ini
file_uploads            = On
upload_tmp_dir          = /path/PHP-uploads/
upload_max_filesize     = 2M
max_file_uploads        = 2
```

如果应用程序不需要文件上传，应将 `file_uploads` 设置为 `Off`。

#### 可执行文件处理

```ini
enable_dl               = Off
disable_functions       = system, exec, shell_exec, passthru, phpinfo, show_source, highlight_file, popen, proc_open, fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file, chdir, mkdir, rmdir, chmod, rename, filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo
disable_classes         =
```

禁用所有不需要的危险 PHP 函数。

#### 会话处理

```ini
session.save_path                = /path/PHP-session/
session.name                     = myPHPSESSID
session.auto_start               = Off
session.use_trans_sid            = 0
session.cookie_domain            = full.qualified.domain.name
session.use_strict_mode          = 1
session.use_cookies              = 1
session.use_only_cookies         = 1
session.cookie_lifetime          = 14400 # 4小时
session.cookie_secure            = 1
session.cookie_httponly          = 1
session.cookie_samesite          = Strict
session.cache_expire             = 30
session.sid_length               = 256
session.sid_bits_per_character   = 6
```

#### 额外安全检查

```ini
session.referer_check   = /application/path
memory_limit            = 50M
post_max_size           = 20M
max_execution_time      = 60
report_memleaks         = On
html_errors             = Off
zend.exception_ignore_args = On
```

## 安全增强工具

### Snuffleupagus

[Snuffleupagus](https://snuffleupagus.readthedocs.io) 是 Suhosin 的精神继承者，专为 PHP 7 及更高版本设计，具有[现代化特性](https://snuffleupagus.readthedocs.io/features.html)。它被认为是稳定的，可在生产环境中使用。

## 安全建议

1. 始终使用 PHP 官方支持的最新版本
2. 定期审查和更新 `php.ini` 配置
3. 最小权限原则：仅启用必要的功能
4. 使用安全的会话管理设置
5. 禁用不必要的危险函数
6. 配置严格的文件上传限制
7. 使用安全增强工具如 Snuffleupagus

## 版本支持

请查看 [PHP 官方支持版本](https://www.php.net/supported-versions.php)，确保使用受支持的版本。

## 参考资源

- [PHP 核心指令](https://www.php.net/manual/ini.core.php)
- [安全 php.ini 配置示例](https://github.com/danehrlich1/very-secure-php-ini)
