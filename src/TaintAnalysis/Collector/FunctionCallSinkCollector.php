<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;

/**
 * @implements Collector<FuncCall, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class FunctionCallSinkCollector implements Collector
{
    private const UNSAFE_FUNCTIONS = [
        'exec' => ['parameter' => 'command', 'type' => SinkType::Shell],
        'system' => ['parameter' => 'command', 'type' => SinkType::Shell],
        'shell_exec' => ['parameter' => 'command', 'type' => SinkType::Shell],
        'passthru' => ['parameter' => 'command', 'type' => SinkType::Shell],
        'proc_open' => ['parameter' => 'command', 'type' => SinkType::Shell],
        'popen' => ['parameter' => 'command', 'type' => SinkType::Shell],
        'pcntl_exec' => ['parameter' => 'path', 'type' => SinkType::Shell],
    ];

    public function __construct(
        private ReflectionProvider $reflectionProvider,
        private ExpressionFlattener $expressionFlattener
    ) {}

    public function getNodeType(): string
    {
        return FuncCall::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node->name instanceof Name) {
            return null;
        }

        if ($node->isFirstClassCallable()) {
            return null;
        }

        $functionName = $this->reflectionProvider->resolveFunctionName($node->name, $scope);

        if ($functionName === null || !isset(self::UNSAFE_FUNCTIONS[$functionName])) {
            return null;
        }

        $unsafeFunction = self::UNSAFE_FUNCTIONS[$functionName];

        $arg = $node->getArg($unsafeFunction['parameter'], 0);

        if ($arg === null) {
            return null;
        }

        return [
            'sink' => sprintf('%s()', $functionName),
            'type' => $unsafeFunction['type']->value,
            'sources' => $this->expressionFlattener->flatten($arg->value, $scope),
            'line' => $node->getStartLine(),
        ];
    }
}
