<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Stmt\Echo_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @implements Collector<Echo_, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class EchoSinkCollector implements Collector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Echo_::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $sources = [];

        foreach ($node->exprs as $expr) {
            $sources = [...$sources, ...$this->expressionFlattener->flatten($expr, $scope)];
        }

        return [
            'sink' => 'echo',
            'type' => SinkType::Html->value,
            'sources' => $sources,
            'line' => $node->getStartLine(),
        ];
    }
}
