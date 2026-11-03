<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;

/**
 * @implements Collector<StaticCall, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class StaticCallSinkCollector implements Collector
{
    public function __construct(
        private ExpressionFlattener $expressionFlattener,
        private CallArguments $callArguments,
        private ReflectionProvider $reflectionProvider,
        private TaintSpec $taintSpec
    ) {}

    public function getNodeType(): string
    {
        return StaticCall::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node->class instanceof Name || !$node->name instanceof Identifier || $node->isFirstClassCallable()) {
            return null;
        }

        $className = $scope->resolveName($node->class);

        if (!$this->reflectionProvider->hasClass($className)) {
            return null;
        }

        $classReflection = $this->reflectionProvider->getClass($className);
        $methodName = $node->name->toLowerString();
        $sink = $this->taintSpec->getMethodSink($classReflection, $methodName);

        if ($sink === null || !$classReflection->hasMethod($methodName)) {
            return null;
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
}
