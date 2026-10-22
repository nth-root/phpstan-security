<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\TypeCombinator;

/**
 * @implements Collector<MethodCall, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class MethodCallSinkCollector implements Collector
{
    private const UNSAFE_METHODS = [
        'PDO' => [
            'query' => ['parameters' => ['query'], 'type' => SinkType::Sql],
            'exec' => ['parameters' => ['statement'], 'type' => SinkType::Sql],
            'prepare' => ['parameters' => ['query'], 'type' => SinkType::Sql],
        ],
    ];

    public function __construct(private ExpressionFlattener $expressionFlattener, private CallArguments $callArguments) {}

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
            foreach (self::UNSAFE_METHODS as $className => $unsafeMethods) {
                if (!isset($unsafeMethods[$methodName]) || !$classReflection->is($className)) {
                    continue;
                }

                $method = $classReflection->getMethod($methodName, $scope);
                $unsafeMethod = $unsafeMethods[$methodName];

                $sources = [];

                foreach ($this->callArguments->ofMethodCall($node, $method, $scope, $unsafeMethod['parameters']) as $arg) {
                    $sources = [...$sources, ...$this->expressionFlattener->flatten($arg, $scope)];
                }

                return [
                    'sink' => sprintf('%s::%s()', $method->getDeclaringClass()->getName(), $method->getName()),
                    'type' => $unsafeMethod['type']->value,
                    'sources' => $sources,
                    'line' => $node->getStartLine(),
                ];
            }
        }

        return null;
    }
}
