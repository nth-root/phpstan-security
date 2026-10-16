<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Rules;

use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\SinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

use function array_filter;
use function array_map;
use function array_unique;
use function array_values;
use function implode;
use function sprintf;

/**
 * @implements Rule<CollectedDataNode>
 */
final readonly class TaintRule implements Rule
{
    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $errors = [];

        foreach ($node->get(SinkCollector::class) as $file => $sinks) {
            foreach ($sinks as $sink) {
                $sources = array_values(
                    array_unique(
                        array_filter(
                            $sink['sources'],
                            fn(string $source) => TaintNode::fromString($source)->isSource(),
                        )
                    )
                );

                if ($sources === []) {
                    continue;
                }

                $message = sprintf(
                    'Tainted value from %s is passed to %s()',
                    implode(
                        ', ',
                        array_map(fn(string $source) => TaintNode::fromString($source)->describe(), $sources)
                    ),
                    $sink['sink']
                );

                $errors[] = RuleErrorBuilder::message($message)
                    ->file($file)
                    ->line($sink['line'])
                    ->identifier('taint.shell')
                    ->build();
            }
        }

        return $errors;
    }
}
