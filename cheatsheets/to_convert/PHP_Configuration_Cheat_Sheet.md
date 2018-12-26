---
title: PHP Configuration Cheat Sheet
permalink: /PHP_Configuration_Cheat_Sheet/
---

Introduction
============

Draft Cheat Sheet

This page is part of the [PHP Security Cheat Sheet](/PHP_Security_Cheat_Sheet "wikilink"), for developers and administrators. It describes secure configuration of PHP and its platform.

------------------------------------------------------------------------

Web Server Configuration
========================

Apache
------

### suPHP

[suPHP](http://suphp.org) makes every php script run as its file owner. This way you are allowed to upload and modify files in your folders without needing to **chmod 777** any folder, which is very bad security practice and will let to your files be compromised easily. Install and configure it on your web server.

PHP Configuration and Deployment
================================

suhosin
-------

Consider using [Suhosin](http://www.hardened-php.net/suhosin/index.html) (Stefan Esser's \[Hardened PHP patch\]) if you want to patch many custom security flaws in various parts of PHP.

php.ini
-------

Note that some of following settings need to be adapted to your system, in particular `/path/` and `/application/`. Also read the [PHP Manual](http://www.php.net/manual/ini.core.php) according dependencies of some settings.

#### PHP error handlling

` expose_php              = Off`
` error_reporting         = E_ALL`
` display_errors          = Off`
` display_startup_errors  = Off`
` log_errors              = On`
` error_log               = /valid_path/PHP-logs/php_error.log`
` ignore_repeated_errors  = Off`

Keep in mind that you need to have display_errors off on a production server and it's a good idea to frequently notice the logs.

#### PHP general settings

` doc_root                = /path/DocumentRoot/PHP-scripts/`
` open_basedir            = /path/DocumentRoot/PHP-scripts/`
` include_path            = /path/PHP-pear/`
` extension_dir           = /path/PHP-extensions/`
` mime_magic.magicfile    = /path/PHP-magic.mime`
` allow_url_fopen         = Off`
` allow_url_include       = Off`
` variables_order         = "GPSE"`
` allow_webdav_methods    = Off`
` register_globals        = Off`
` safe_mode               = Off`
` session.gc_maxlifetime  = 600`

Allow_url_\* prevents LFIs to be easily escalated to RFIs.

#### PHP file upload handling

` file_uploads            = On`
` upload_tmp_dir          = /path/PHP-uploads/`
` upload_max_filesize     = 2M`
` max_file_uploads        = 2`
` `

It's a good idea to turn it off, if your application is not using file uploads.

#### PHP executable handling

` enable_dl               = On`
` disable_functions       = system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open`
` disable_functions       = fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file`
` disable_functions       = chdir, mkdir, rmdir, chmod, rename`
` disable_functions       = filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo`
`   # see also: `[`http://ir.php.net/features.safe-mode`](http://ir.php.net/features.safe-mode)
` disable_classes         = `

These are dangerous PHP functions. You should disable all that you don't use.

#### PHP session handling

` session.auto_start      = Off`
` session.save_path       = /path/PHP-session/`
` session.name            = myPHPSESSID`
` session.hash_function   = 1`
` session.hash_bits_per_character = 6`
` session.use_trans_sid   = 0`
` session.cookie_domain   = full.qualified.domain.name`
` #session.cookie_path     = /application/path/`
` session.cookie_lifetime = 0`
` session.cookie_secure   = On`
` session.cookie_httponly = 1`
` session.use_only_cookies= 1`
` session.cache_expire    = 30`
` default_socket_timeout  = 60`

It is a good practice to change session.name to something new.

#### some more security paranoid checks

` session.referer_check   = /application/path`
` memory_limit            = 8M`
` post_max_size           = 8M`
` max_execution_time       = 60`
` report_memleaks         = On`
` track_errors            = Off`
` html_errors             = Off`

#### PHP Database Settings

#### PHP Database User

#### PHP Windows specific Settings

#### PHP Extension

Related Cheat Sheets
====================

[PHP_Security_Cheat_Sheet](/PHP_Security_Cheat_Sheet "wikilink")

Authors and Primary Editors
===========================

[Achim](/User:Achim\ "wikilink") Hoffmann - [Achim at owasp.org](mailto:achim_at_owasp.org)

--[AbiusX](/User:Abbas_Naderi\ "wikilink") [email](mailto:abbas.naderi@owasp.org)

--[Achim](/User:Achim\ "wikilink"), 30. November 2012

--[User:Tony_Hsu_HsiangChih](/User:Tony_Hsu_HsiangChih "wikilink")

Other Cheatsheets
=================

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")