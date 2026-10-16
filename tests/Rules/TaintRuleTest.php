<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\Rules;

use NthRoot\PhpstanSecurity\Rules\TaintRule;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\SinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

/**
 * @extends RuleTestCase<TaintRule>
 */
class TaintRuleTest extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new TaintRule();
    }

    protected function getCollectors(): array
    {
        return [new SinkCollector(self::getContainer()->getByType(ReflectionProvider::class), new ExpressionFlattener())];
    }

    public function testDetectsDirectUseOfTaintedValue(): void
    {
        $message = static fn(string $source, string $sink): string => sprintf(
            'Tainted value from %s is passed to %s()',
            $source,
            $sink
        );

        $this->analyse([__DIR__ . '/data/taint/direct.php'], [
            [$message('$_GET', 'exec'), 9],
            [$message('$_GET', 'exec'), 13],
        ]);
    }
}
