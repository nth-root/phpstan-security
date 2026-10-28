# PHPStan Security Extension

An extension for [PHPStan](https://phpstan.org/) which detects common vulnerabilities in PHP code.

## Known limitations

- Symfony route parameters are only treated as user input for routes defined with `#[Route]` attributes.
  Other routing configuration (YAML, XML, PHP) is not read, so their controller arguments are not tracked.
