<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\Rules;

use NthRoot\PhpstanSecurity\Rules\TaintRule;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\ShellExecSinkCollector;
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
            new ShellExecSinkCollector($expressionFlattener),
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

    public function testDetectsThroughConcatenation(): void
    {
        $this->analyse([__DIR__ . '/data/taint/concatenation.php'], [
            [$this->getMessage('$_GET', 'exec'), 7],
            [$this->getMessage('$_GET', 'exec'), 13],
            [$this->getMessage('$_GET', 'exec'), 19],
            [$this->getMessage('$_POST, $_GET', 'exec'), 29],
            [$this->getMessage('$_GET', 'exec'), 34],
        ]);
    }

    public function testDetectsThroughInterpolation(): void
    {
        $this->analyse([__DIR__ . '/data/taint/interpolation.php'], [
            [$this->getMessage('$_GET', 'exec'), 8],
            [$this->getMessage('$_GET', 'exec'), 9],
            [$this->getMessage('$_GET', 'exec'), 16],
        ]);
    }

    public function testDetectsUseOfBacktickOperator(): void
    {
        $this->analyse([__DIR__ . '/data/taint/shell_exec.php'], [
            ['Tainted value from $_GET is passed to the backtick operator', 7],
            ['Tainted value from $_GET is passed to the backtick operator', 13],
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
