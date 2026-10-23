<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr\Include_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use RuntimeException;

/**
 * @implements Collector<Include_, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class IncludeSinkCollector implements Collector
{
    public function __construct(private ExpressionFlattener $expressionFlattener) {}

    public function getNodeType(): string
    {
        return Include_::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $sources = $this->expressionFlattener->flatten($node->expr, $scope);

        $name = match ($node->type) {
            Include_::TYPE_INCLUDE => 'include',
            Include_::TYPE_INCLUDE_ONCE => 'include_once',
            Include_::TYPE_REQUIRE => 'require',
            Include_::TYPE_REQUIRE_ONCE => 'require_once',
            default => throw new RuntimeException(sprintf('Unknown type "%s"', $node->type)),
        };

        return [
            'sink' => $name,
            'type' => SinkType::FileInclusion->value,
            'sources' => $sources,
            'line' => $node->getStartLine(),
        ];
    }
}
