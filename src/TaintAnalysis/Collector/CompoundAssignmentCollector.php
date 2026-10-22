<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\FunctionKey;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PhpParser\Node\Expr\AssignOp;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

use function is_string;

/**
 * @implements Collector<AssignOp, array{to: string, from: string[]}>
 */
final readonly class CompoundAssignmentCollector implements Collector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return AssignOp::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node instanceof AssignOp\Concat && !$node instanceof AssignOp\Coalesce) {
            return null;
        }

        if (!$node->var instanceof Variable || !is_string($node->var->name)) {
            return null;
        }

        $from = $this->expressionFlattener->flatten($node->expr, $scope);

        if ($from === []) {
            return null;
        }

        return [
            'to' => TaintNode::variable(FunctionKey::of($scope), $node->var->name)->toString(),
            'from' => $from,
        ];
    }
}
