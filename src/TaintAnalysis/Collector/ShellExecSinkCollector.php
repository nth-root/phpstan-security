<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ShellExec;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @implements Collector<ShellExec, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class ShellExecSinkCollector implements Collector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return ShellExec::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $sources = [];

        foreach ($node->parts as $part) {
            if ($part instanceof Expr) {
                $sources = [...$sources, ...$this->expressionFlattener->flatten($part, $scope)];
            }
        }

        return [
            'sink' => 'the backtick operator',
            'type' => SinkType::Shell->value,
            'sources' => $sources,
            'line' => $node->getStartLine(),
        ];
    }
}
