<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PHPStan\Analyser\Scope;

/**
 * @implements FlowCollector<Assign>
 */
final readonly class AssignmentCollector implements FlowCollector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Assign::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        $flow = $this->expressionFlattener->flattenAssignment(
            $node->var,
            $this->expressionFlattener->flatten($node->expr, $scope),
            $scope
        );

        return $flow === null ? null : [$flow];
    }
}
