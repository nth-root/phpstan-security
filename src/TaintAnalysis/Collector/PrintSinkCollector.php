<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr\Print_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @implements Collector<Print_, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class PrintSinkCollector implements Collector
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
