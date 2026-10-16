<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\Rules;

use NthRoot\PhpstanSecurity\Rules\TaintRule;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\SinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

use function sprintf;

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
        $expressionFlattener = new ExpressionFlattener();

        return [
            new SinkCollector(self::getContainer()->getByType(ReflectionProvider::class), $expressionFlattener),
            new AssignmentCollector($expressionFlattener),
        ];
    }

    public function testDetectsDirectUseOfTaintedValue(): void
    {
        $this->analyse([__DIR__ . '/data/taint/direct.php'], [
            [$this->getMessage('$_GET', 'exec'), 9],
            [$this->getMessage('$_GET', 'exec'), 13],
        ]);
    }

    public function testDetectsThroughLocalVariables(): void
    {
        $this->analyse([__DIR__ . '/data/taint/variables.php'], [
            [$this->getMessage('$_GET', 'exec'), 8],
            [$this->getMessage('$_POST', 'system'), 21],
        ]);
    }

    private function getMessage(string $source, string $sink): string
    {
        return sprintf(
            'Tainted value from %s is passed to %s()',
            $source,
            $sink
        );
    }
}
