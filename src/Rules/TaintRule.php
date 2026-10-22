<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Rules;

use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\ShellExecSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\SinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintGraph;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

use function array_map;
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
        $graph = new TaintGraph();

        foreach ($node->get(AssignmentCollector::class) as $assignments) {
            foreach ($assignments as $assignment) {
                foreach ($assignment['from'] as $from) {
                    $graph->addEdge($from, $assignment['to']);
                }
            }
        }

        $errors = [];

        $sinksByFile = [$node->get(SinkCollector::class), $node->get(ShellExecSinkCollector::class)];

        foreach ($sinksByFile as $collected) {
            foreach ($collected as $file => $sinks) {
                foreach ($sinks as $sink) {
                    $sources = $graph->getSourcesReaching($sink['sources']);

                    if ($sources === []) {
                        continue;
                    }

                    $message = sprintf(
                        'Tainted value from %s is passed to %s',
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
        }

        return $errors;
    }
}
