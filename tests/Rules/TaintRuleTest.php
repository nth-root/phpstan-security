<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\Rules;

use NthRoot\PhpstanSecurity\Rules\TaintRule;
use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\CompoundAssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\EchoSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\PrintSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\ShellExecSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\FunctionCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use Override;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

use function sprintf;

/**
 * @extends RuleTestCase<TaintRule>
 */
class TaintRuleTest extends RuleTestCase
{
    private ReflectionProvider $reflectionProvider;

    #[Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->reflectionProvider = self::getContainer()->getByType(ReflectionProvider::class);
    }

    protected function getRule(): Rule
    {
        return new TaintRule();
    }

    protected function getCollectors(): array
    {
        $callArguments = new CallArguments($this->reflectionProvider);
        $expressionFlattener = new ExpressionFlattener($this->reflectionProvider, $callArguments);

        return [
            new FunctionCallSinkCollector($this->reflectionProvider, $expressionFlattener, $callArguments),
            new AssignmentCollector($expressionFlattener),
            new CompoundAssignmentCollector($expressionFlattener),
            new ShellExecSinkCollector($expressionFlattener),
            new EchoSinkCollector($expressionFlattener),
            new PrintSinkCollector($expressionFlattener),
        ];
    }

    public function testDetectsDirectUseOfTaintedValue(): void
    {
        $this->analyse([__DIR__ . '/data/taint/direct.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 16],
        ]);
    }

    public function testDetectsThroughLocalVariables(): void
    {
        $this->analyse([__DIR__ . '/data/taint/variables.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 8],
            [$this->getMessage(SinkType::Shell, '$_POST', 'system()'), 21],
        ]);
    }

    public function testDetectsThroughConcatenation(): void
    {
        $this->analyse([__DIR__ . '/data/taint/concatenation.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 19],
            [$this->getMessage(SinkType::Shell, '$_POST, $_GET', 'exec()'), 29],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 34],
        ]);
    }

    public function testDetectsThroughInterpolation(): void
    {
        $this->analyse([__DIR__ . '/data/taint/interpolation.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 8],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 16],
        ]);
    }

    public function testDetectsThroughTernaryConditions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/conditional.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 8],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 10],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 12],
            [$this->getMessage(SinkType::Shell, '$_POST, $_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 19],
        ]);
    }

    public function testDetectsShellFunctions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/shell_functions.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'shell_exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'passthru()'), 8],
            [$this->getMessage(SinkType::Shell, '$_GET', 'popen()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'proc_open()'), 10],
            [$this->getMessage(SinkType::Shell, '$_GET', 'pcntl_exec()'), 11],
            [$this->getMessage(SinkType::Shell, '$_GET', 'pcntl_exec()'), 12],
        ]);
    }

    public function testDetectsUseOfBacktickOperator(): void
    {
        $this->analyse([__DIR__ . '/data/taint/shell_exec.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'the backtick operator'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'the backtick operator'), 13],
        ]);
    }

    public function testDetectsEchoAndPrint(): void
    {
        $this->analyse([__DIR__ . '/data/taint/html.php'], [
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 7],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 9],
            [$this->getMessage(SinkType::Html, '$_POST', 'echo'), 10],
            [$this->getMessage(SinkType::Html, '$_GET', 'print'), 12],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 16],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 22],
        ]);
    }

    public function testDetectsPrintfFunctions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/printf.php'], [
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 7],
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 8],
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 9],
            [$this->getMessage(SinkType::Html, '$_GET', 'printf()'), 11],
            [$this->getMessage(SinkType::Html, '$_GET', 'vprintf()'), 12],
            [$this->getMessage(SinkType::Html, '$_GET', 'vprintf()'), 13],
        ]);
    }

    public function testDetectsThroughPassThroughFunctions(): void
    {
        $this->analyse([__DIR__ . '/data/taint/passthrough.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 7],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 10],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 12],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 13],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 14],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 18],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 23],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 24],
        ]);
    }

    public function testDetectsThroughCompoundAssignment(): void
    {
        $this->analyse([__DIR__ . '/data/taint/compound_assignment.php'], [
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 9],
            [$this->getMessage(SinkType::Shell, '$_GET', 'exec()'), 16],
            [$this->getMessage(SinkType::Html, '$_GET', 'echo'), 30],
        ]);
    }

    private function getMessage(SinkType $sinkType, string $source, string $sink): string
    {
        return sprintf(
            'Possible %s: tainted value from %s is passed to %s',
            $sinkType->describe(),
            $source,
            $sink
        );
    }
}
