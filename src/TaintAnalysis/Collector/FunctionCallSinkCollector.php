<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;

/**
 * @implements Collector<FuncCall, array{sink: string, sources: string[], line: int}>
 */
final readonly class FunctionCallSinkCollector implements Collector
{
    private const UNSAFE_FUNCTIONS = [
        'exec' => 'command',
        'system' => 'command',
        'shell_exec' => 'command',
        'passthru' => 'command',
        'proc_open' => 'command',
        'popen' => 'command',
        'pcntl_exec' => 'path',
    ];

    public function __construct(private ReflectionProvider $reflectionProvider, private ExpressionFlattener $expressionFlattener) {}

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

        if (!isset(self::UNSAFE_FUNCTIONS[$functionName])) {
            return null;
        }

        $arg = $node->getArg(self::UNSAFE_FUNCTIONS[$functionName], 0);

        if ($arg === null) {
            return null;
        }

        return [
            'sink' => sprintf('%s()', $functionName),
            'sources' => $this->expressionFlattener->flatten($arg->value, $scope),
            'line' => $node->getStartLine(),
        ];
    }
}
