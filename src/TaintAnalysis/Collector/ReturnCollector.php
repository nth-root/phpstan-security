<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\FunctionKey;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PhpParser\Node\Stmt\Return_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @implements Collector<Return_, array{to: string, from: string[]}>
 */
final readonly class ReturnCollector implements Collector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Return_::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        // Closures share the enclosing function's key, so their returns would count as its return value
        if ($node->expr === null || $scope->isInAnonymousFunction()) {
            return null;
        }

        $from = $this->expressionFlattener->flatten($node->expr, $scope);

        if ($from === []) {
            return null;
        }

        return [
            'to' => TaintNode::returnValue(FunctionKey::of($scope))->toString(),
            'from' => $from,
        ];
    }
}
