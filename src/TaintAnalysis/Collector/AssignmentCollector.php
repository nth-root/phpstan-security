<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\FunctionKey;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

use function is_string;

/**
 * @implements Collector<Assign, array{to: string, from: string[]}>
 */
final readonly class AssignmentCollector implements Collector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Assign::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
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
