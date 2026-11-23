<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Stmt\Echo_;
use PHPStan\Analyser\Scope;

/**
 * @implements SinkCollector<Echo_>
 */
final readonly class EchoSinkCollector implements SinkCollector
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
