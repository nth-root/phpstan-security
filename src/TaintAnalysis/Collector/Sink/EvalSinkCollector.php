<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr\Eval_;
use PHPStan\Analyser\Scope;

/**
 * @implements SinkCollector<Eval_>
 */
final readonly class EvalSinkCollector implements SinkCollector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Eval_::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        return [
            'sink' => 'eval',
            'type' => SinkType::Eval->value,
            'sources' => $this->expressionFlattener->flatten($node->expr, $scope),
            'line' => $node->getStartLine(),
        ];
    }
}
