# PHPStan Security Extension

An extension for [PHPStan](https://phpstan.org/) that detects common security vulnerabilities in PHP code.
Its main feature is [taint analysis](https://en.wikipedia.org/wiki/Taint_checking): following user input (`$_GET`,
Symfony's and Laravel's `Request` objects, and Symfony route parameters) through variables and function calls, and
reporting when it reaches a dangerous location such as a SQL query, a shell command, or `echo`.
Because it analyzes the whole project at once, it also catches input that a controller passes to a service or repository
in another file.

> [!WARNING]
> This extension is experimental and under active development.
> Error identifiers, configuration and behavior may change between releases.
> A clean run does not mean your code is free of vulnerabilities.

## Detected vulnerabilities

| Vulnerability              | Identifier            | Supported sinks                                                                                                                   |
|----------------------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| SQL injection              | `tainted.sql`         | `PDO`, `mysqli`, `SQLite3`, Doctrine DBAL `Connection`, Laravel connections, the `DB` facade, query builders                      |
| Cross-site scripting (XSS) | `tainted.html`        | `echo`, `print`, `printf()`, `vprintf()`, Symfony and Laravel `new Response()`                                                    |
| Command injection          | `tainted.shell`       | `exec()`, `system()`, `shell_exec()`, backticks, Symfony `Process::fromShellCommandline()`, ...                                   |
| Path traversal, SSRF       | `tainted.path`        | `file_get_contents()`, `fopen()`, `unlink()`, Symfony `Filesystem`, `AbstractController::file()`, `new BinaryFileResponse()`, ... |
| File inclusion             | `tainted.include`     | `include`, `include_once`, `require`, `require_once`                                                                              |
| Open redirect              | `tainted.redirect`    | `header()` with a `Location:` or `Refresh:` header, Symfony `AbstractController::redirect()`, `new RedirectResponse()`            |
| Insecure deserialization   | `tainted.unserialize` | `unserialize()`                                                                                                                   |
| Callable injection         | `tainted.callable`    | `call_user_func()`, `call_user_func_array()`                                                                                      |
| Eval injection             | `tainted.eval`        | `eval`                                                                                                                            |
| XPath injection            | `tainted.xpath`       | `DOMXPath::query()`, `DOMXPath::evaluate()`, `SimpleXMLElement::xpath()`, Symfony `Crawler::filterXPath()`, `Crawler::evaluate()` |
| LDAP injection             | `tainted.ldap`        | `ldap_search()`, `ldap_list()`, `ldap_read()`, Symfony `LdapInterface::query()`                                                   |

User input is detected from:

- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`
- Symfony's `Request` and its `query`, `request`, `cookies` and `headers` bags
- Laravel's `Request` and its facade (`input()`, `query()`, `all()`, `header()`, ...), and `validated()` and `safe()` on
  a `FormRequest`
- Controller arguments that match a `{placeholder}` in a `#[Route]` attribute

A value is no longer considered tainted when it:

- Passes through a sanitizer for that kind of sink: `htmlspecialchars()`, `htmlentities()` and Laravel's `e()` for
  XSS, `escapeshellarg()` for command injection, `ldap_escape()` for LDAP injection, and `basename()` for path traversal
  and file inclusion. The value stays tainted for other sinks, so `exec(htmlspecialchars($input))` is still reported.
  `escapeshellcmd()` isn't a sanitizer, because it allows argument injection.
- Has a native type that can't carry an injection: casts like `(int)`, `int`, `float` and `bool` parameters and return
  types, and values checked with `is_numeric()` or `in_array(..., true)`.

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

## Tested against

| Application                                                         | Result                                                                                                                                                                                                                                                                                                                             |
|---------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [VulnerableSymfony](https://github.com/Secureaks/VulnerableSymfony) | SQL injection in `/search` and `/login`, path traversal in `/legal/content` and the avatar upload                                                                                                                                                                                                                                  |
| [DVWA](https://github.com/digininja/DVWA)                           | SQL injection, command injection, open redirect and path traversal, and XSS through the `security` cookie in `dvwaHtmlEcho()`. Reflected XSS (`xss_r`) and file inclusion (`fi`) are missed, the `impossible` level of `exec` is a false positive, and the JSONP callback in `csp` is reported as XSS although it's served as JSON |
| [vAPI](https://github.com/roottusk/vapi)                            | SQL injection in `API8UsersController`, SSRF in `SurferController`                                                                                                                                                                                                                                                                 |
| [Symfony Demo](https://github.com/symfony/demo)                     | No findings                                                                                                                                                                                                                                                                                                                        |

## Known limitations

### False positives (findings that might be safe)

- Only native types are trusted: a value with a native `int` type or one narrowed by `is_numeric()` isn't tainted,
  but a parameter documented as `@param int` is.
- Parameters and return values are shared by all calls to a function: if any caller passes user input to a function
  that returns its argument, the return value is considered tainted at every call site ([#6]).
- The analysis is flow-insensitive: once a variable holds user input, it is considered tainted in that function, even if
  it is overwritten at a later point ([#5]).
- Responses are checked for XSS even when they aren't HTML ([#7]), such as
  `new Response($csv, 200, ['Content-Type' => 'text/csv'])` or a Laravel `Response` with an array (which becomes JSON).
- Redirects are reported even when the URL starts with a constant path, as in `'/dashboard?tab=' . $tab`, although the
  host can't change ([#8]).

See also the [open issues labelled `false positive`][false positive issues].
To suppress a false positive, see [Ignoring findings](#ignoring-findings).

### False negatives (vulnerabilities that aren't detected)

The analysis only follows tainted data through code it understands.

- `$_SERVER` and `$request->attributes` are not detected as sources yet ([#19], [#20]).
- Built-in functions that aren't configured as a [flow function](config/taint/php.neon) stop taint.
- `htmlspecialchars()` and `htmlentities()` count as HTML sanitizers regardless of their `$flags` and of where the
  output ends up, so XSS through an unquoted attribute or a `javascript:` URL isn't detected.
- `ldap_escape()` counts as an LDAP sanitizer regardless of its `$flags`, so a value escaped for a DN but used in a
  filter (or the other way around) isn't detected.
- `basename()` counts as a sanitizer for file paths, but `basename('..')` is still `..`: `'/uploads/' . basename($name)`
  can name the parent directory, which matters for `unlink()` or `Filesystem::remove()`. Without a directory prefix, a
  `data:` URL also passes through.
- Values assigned to properties (`$this->query = $input`) or array elements (`$arr['q'] = $input`) aren't followed yet
  ([#12], [#11]).
- `foreach` loops aren't followed: in `foreach ($_GET['ids'] as $id)`, `$id` isn't considered tainted ([#10]).
- Symfony route parameters are only treated as user input for routes defined with `#[Route]` attributes.
  Other routing configuration (YAML, XML, PHP) is not read.
- Twig templates aren't analyzed, so XSS through `{{ ... |raw }}` isn't detected.
- Static calls on Eloquent models (`User::whereRaw()`) aren't detected yet ([#53]).
- Laravel's `$request->name`, the `request('name')` helper, and methods called on `$request->string()` aren't followed
  yet ([#25], [#21]).
- Laravel route parameters from `routes/*.php` aren't treated as user input ([#26]).
- Blade templates aren't analyzed, so XSS through `{!! ... !!}` isn't detected.

See also the [open issues labelled `false negative`][false negative issues].

[false positive issues]: https://github.com/nth-root/phpstan-security/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22false%20positive%22
[false negative issues]: https://github.com/nth-root/phpstan-security/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22false%20negative%22
[#5]: https://github.com/nth-root/phpstan-security/issues/5
[#6]: https://github.com/nth-root/phpstan-security/issues/6
[#7]: https://github.com/nth-root/phpstan-security/issues/7
[#8]: https://github.com/nth-root/phpstan-security/issues/8
[#10]: https://github.com/nth-root/phpstan-security/issues/10
[#11]: https://github.com/nth-root/phpstan-security/issues/11
[#12]: https://github.com/nth-root/phpstan-security/issues/12
[#19]: https://github.com/nth-root/phpstan-security/issues/19
[#20]: https://github.com/nth-root/phpstan-security/issues/20
[#21]: https://github.com/nth-root/phpstan-security/issues/21
[#25]: https://github.com/nth-root/phpstan-security/issues/25
[#26]: https://github.com/nth-root/phpstan-security/issues/26
[#53]: https://github.com/nth-root/phpstan-security/issues/53
