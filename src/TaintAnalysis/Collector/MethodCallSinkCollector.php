<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\TypeCombinator;

use function sprintf;

/**
 * @implements Collector<MethodCall, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class MethodCallSinkCollector implements Collector
{
    public function __construct(
        private ExpressionFlattener $expressionFlattener,
        private CallArguments $callArguments,
        private TaintSpec $taintSpec
    ) {}

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node->name instanceof Identifier || $node->isFirstClassCallable()) {
            return null;
        }

        $methodName = $node->name->toLowerString();
        $receiverType = TypeCombinator::removeNull($scope->getType($node->var));

        foreach ($receiverType->getObjectClassReflections() as $classReflection) {
            $sink = $this->taintSpec->getMethodSink($classReflection, $methodName);

            if ($sink === null) {
                continue;
            }

            $method = $classReflection->getMethod($methodName, $scope);
            $sources = [];

            foreach ($this->callArguments->ofMethodCall($node, $method, $scope, $sink->parameters) as $arg) {
                $sources = [...$sources, ...$this->expressionFlattener->flatten($arg, $scope)];
            }

            return [
                'sink' => sprintf('%s::%s()', $method->getDeclaringClass()->getName(), $method->getName()),
                'type' => $sink->type->value,
                'sources' => $sources,
                'line' => $node->getStartLine(),
            ];
        }

        return null;
    }
}
