<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\FunctionKey;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Stmt\Foreach_;
use PHPStan\Analyser\Scope;

/**
 * @implements FlowCollector<Foreach_>
 */
final readonly class ForeachCollector implements FlowCollector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Foreach_::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        $from = $this->expressionFlattener->flatten($node->expr, $scope);

        if ($from === []) {
            return null;
        }

        $flows = [];

        foreach ([$node->keyVar, $node->valueVar] as $var) {
            if ($var instanceof Variable && is_string($var->name)) {
                $flows[] = [
                    'to' => TaintNode::variable(FunctionKey::of($scope), $var->name)->toString(),
                    'from' => $from,
                ];
            }
        }

        return $flows === [] ? null : $flows;
    }
}
