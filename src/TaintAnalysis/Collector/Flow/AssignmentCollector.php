<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\FunctionKey;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;

use function is_string;

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
        $from = $this->expressionFlattener->flatten($node->expr, $scope);
        $target = $node->var;

        while ($target instanceof ArrayDimFetch) {
            if ($target->dim !== null) {
                $from = [...$from, ...$this->expressionFlattener->flatten($target->dim, $scope)];
            }

            $target = $target->var;
        }

        if (!$target instanceof Variable || !is_string($target->name) || $from === []) {
            return null;
        }

        return [[
            'to' => TaintNode::variable(FunctionKey::of($scope), $target->name)->toString(),
            'from' => $from,
        ]];
    }
}
