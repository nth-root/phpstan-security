<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
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
        'exec' => ['parameters' => ['command'], 'type' => SinkType::Shell],
        'system' => ['parameters' => ['command'], 'type' => SinkType::Shell],
        'shell_exec' => ['parameters' => ['command'], 'type' => SinkType::Shell],
        'passthru' => ['parameters' => ['command'], 'type' => SinkType::Shell],
        'proc_open' => ['parameters' => ['command'], 'type' => SinkType::Shell],
        'popen' => ['parameters' => ['command'], 'type' => SinkType::Shell],
        'pcntl_exec' => ['parameters' => ['path'], 'type' => SinkType::Shell],
        'printf' => ['parameters' => ['format', 'values'], 'type' => SinkType::Html],
        'vprintf' => ['parameters' => ['format', 'values'], 'type' => SinkType::Html],
    ];

    public function __construct(
        private ReflectionProvider $reflectionProvider,
        private ExpressionFlattener $expressionFlattener,
        private CallArguments $callArguments
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

        $sources = [];

        foreach ($this->callArguments->ofFunctionCall($node, $node->name, $scope, $unsafeFunction['parameters']) as $arg) {
            $sources = [...$sources, ...$this->expressionFlattener->flatten($arg, $scope)];
        }

        return [
            'sink' => sprintf('%s()', $functionName),
            'type' => $unsafeFunction['type']->value,
            'sources' => $sources,
            'line' => $node->getStartLine(),
        ];
    }
}
