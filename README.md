# PHPStan Security Extension

An extension for [PHPStan](https://phpstan.org/) that detects common security vulnerabilities in PHP code.
Its main feature is [taint analysis](https://en.wikipedia.org/wiki/Taint_checking): following user input (`$_GET`,
Symfony's `Request` object and route parameters) through variables and function calls, and reporting when it reaches a
dangerous location such as a SQL query, a shell command, or `echo`.

> [!WARNING]
> This extension is experimental and under active development.
> Error identifiers, configuration and behavior may change between releases.
> A clean run does not mean your code is free of vulnerabilities.

## Detected vulnerabilities

| Vulnerability              | Identifier         | Supported sinks                                        |
|----------------------------|--------------------|--------------------------------------------------------|
| SQL injection              | `tainted.sql`      | `PDO`, `mysqli`, `SQLite3`, Doctrine DBAL `Connection` |
| Cross-site scripting (XSS) | `tainted.html`     | `echo`, `print`, `printf()`, `vprintf()`               |
| Command injection          | `tainted.shell`    | `exec()`, `system()`, `shell_exec()`, backticks, ...   |
| Path traversal, SSRF       | `tainted.path`     | `file_get_contents()`, `fopen()`, `unlink()`, ...      |
| File inclusion             | `tainted.include`  | `include`, `include_once`, `require`, `require_once`   |
| Open redirect              | `tainted.redirect` | `header()` with a `Location:` or `Refresh:` header     |

User input is detected from:

- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`
- Symfony's `Request` and its `query`, `request`, `cookies` and `headers` bags
- Controller arguments that match a `{placeholder}` in a `#[Route]` attribute

## Installation

```shell
composer require --dev nth-root/phpstan-security
```

If you use [phpstan/extension-installer](https://github.com/phpstan/extension-installer), that's all. Otherwise,
include the extension in your `phpstan.neon`:

```neon
includes:
    - vendor/nth-root/phpstan-security/extension.neon
```

## Ignoring findings

To ignore a single finding, use a `@phpstan-ignore` PHPDoc tag with the identifier:

```php
/** @phpstan-ignore tainted.sql */
$connection->executeQuery($sql);
```

Or ignore a whole category of findings with `ignoreErrors` in `phpstan.neon`:

```neon
parameters:
    ignoreErrors:
        - identifier: tainted.sql
```

## Known limitations

The analysis only follows tainted data through code it understands.

- `$_SERVER` and `$request->attributes` are not detected as sources yet.
- Built-in functions that aren't configured as a [flow function](config/taint/php.neon) stop taint.
  That currently includes sanitizers like `htmlspecialchars()` and `escapeshellarg()`.
- Return values of user-defined functions and methods aren't followed yet.
- Values assigned to properties (`$this->query = $input`) or array elements (`$arr['q'] = $input`) aren't followed yet.
- The analysis is flow-insensitive: once a variable holds user input, it is considered tainted in that function, even if
  it is overwritten at a later point.
- Symfony route parameters are only treated as user input for routes defined with `#[Route]` attributes.
  Other routing configuration (YAML, XML, PHP) is not read.
- Twig templates aren't analyzed, so XSS through `{{ ... |raw }}` isn't detected.
