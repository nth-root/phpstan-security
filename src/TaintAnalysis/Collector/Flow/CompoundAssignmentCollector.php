<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use PhpParser\Node;
use PhpParser\Node\Expr\AssignOp;
use PHPStan\Analyser\Scope;

/**
 * @implements FlowCollector<AssignOp>
 */
final readonly class CompoundAssignmentCollector implements FlowCollector
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

        $flows = $this->expressionFlattener->flattenAssignment(
            $node->var,
            $this->expressionFlattener->flatten($node->expr, $scope),
            $scope
        );

        return $flows === [] ? null : $flows;
    }
}
