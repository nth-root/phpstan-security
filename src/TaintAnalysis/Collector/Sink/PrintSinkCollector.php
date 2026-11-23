<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr\Print_;
use PHPStan\Analyser\Scope;

/**
 * @implements SinkCollector<Print_>
 */
final readonly class PrintSinkCollector implements SinkCollector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Print_::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        return [
            'sink' => 'print',
            'type' => SinkType::Html->value,
            'sources' => $this->expressionFlattener->flatten($node->expr, $scope),
            'line' => $node->getStartLine(),
        ];
    }
}
