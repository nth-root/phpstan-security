<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;

/**
 * @implements SinkCollector<FuncCall>
 */
final readonly class FunctionCallSinkCollector implements SinkCollector
{
    public function __construct(
        private ReflectionProvider $reflectionProvider,
        private ExpressionFlattener $expressionFlattener,
        private CallArguments $callArguments,
        private TaintSpec $taintSpec
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
        $sink = $functionName === null ? null : $this->taintSpec->getFunctionSink($functionName);

        if ($sink === null) {
            return null;
        }

        $sources = [];

        foreach ($this->callArguments->ofFunctionCall($node, $node->name, $scope, $sink->parameters) as $arg) {
            $sources = [...$sources, ...$this->expressionFlattener->flattenSinkArgument($arg, $sink->type, $scope)];
        }

        return [
            'sink' => sprintf('%s()', $functionName),
            'type' => $sink->type->value,
            'sources' => $sources,
            'line' => $node->getStartLine(),
        ];
    }
}
