<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintSpec;
use PhpParser\Node;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;

/**
 * @implements Collector<New_, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class InstantiationSinkCollector implements Collector
{
    public function __construct(
        private ReflectionProvider $reflectionProvider,
        private ExpressionFlattener $expressionFlattener,
        private CallArguments $callArguments,
        private TaintSpec $taintSpec
    ) {}

    public function getNodeType(): string
    {
        return New_::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node->class instanceof Name) {
            return null;
        }

        $className = $scope->resolveName($node->class);

        if (!$this->reflectionProvider->hasClass($className)) {
            return null;
        }

        $class = $this->reflectionProvider->getClass($className);

        if (!$class->hasConstructor()) {
            return null;
        }

        $constructor = $class->getConstructor();
        $sink = $this->taintSpec->getConstructorSink($constructor->getDeclaringClass());

        if ($sink === null) {
            return null;
        }

        $sources = [];

        foreach ($this->callArguments->ofMethodCall($node, $constructor, $scope, $sink->parameters) as $arg) {
            $sources = [...$sources, ...$this->expressionFlattener->flatten($arg, $scope)];
        }

        return [
            'sink' => sprintf('new %s()', $class->getName()),
            'type' => $sink->type->value,
            'sources' => $sources,
            'line' => $node->getStartLine(),
        ];
    }
}
