<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;

/**
 * @implements SinkCollector<StaticCall>
 */
final readonly class StaticCallSinkCollector implements SinkCollector
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
        $methodName = $node->name->toString();

        if (!$classReflection->hasMethod($methodName)) {
            return null;
        }

        $method = $classReflection->getMethod($methodName, $scope);
        $sink = $node->name->toLowerString() === '__construct'
            ? $this->taintSpec->getConstructorSink($method->getDeclaringClass())
            : $this->taintSpec->getMethodSink($classReflection, $methodName);

        if ($sink === null) {
            return null;
        }

        $sources = [];

        foreach ($this->callArguments->ofMethodCall($node, $method, $scope, $sink->parameters) as $arg) {
            $sources = [...$sources, ...$this->expressionFlattener->flattenSinkArgument($arg, $sink->type, $scope)];
        }

        return [
            'sink' => sprintf('%s::%s()', $method->getDeclaringClass()->getName(), $method->getName()),
            'type' => $sink->type->value,
            'sources' => $sources,
            'line' => $node->name->getStartLine(),
        ];
    }
}
