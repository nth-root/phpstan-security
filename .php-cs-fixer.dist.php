<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

return (new Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@auto' => true,
        '@auto:risky' => true,
        'no_unused_imports' => true,
        'fully_qualified_strict_types' => ['import_symbols' => true],
        'global_namespace_import' => ['import_functions' => true],
        'native_function_invocation' => ['include' => ['@internal'], 'scope' => 'namespaced'],
        'php_unit_test_case_static_method_calls' => ['call_type' => 'this'],
    ])
    // 💡 by default, Fixer looks for `*.php` files excluding `./vendor/` - here, you can groom this config
    ->setFinder(
        (new Finder())
            // 💡 root folder to check
            ->in(__DIR__)
            ->ignoreDotFiles(false)
            ->exclude('tests/Rules/data')
    );
