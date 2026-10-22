<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Rules;

use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\EchoSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\FunctionCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\PrintSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\ShellExecSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
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

        $sinksByFile = [
            $node->get(FunctionCallSinkCollector::class),
            $node->get(ShellExecSinkCollector::class),
            $node->get(EchoSinkCollector::class),
            $node->get(PrintSinkCollector::class),
        ];

        foreach ($sinksByFile as $collected) {
            foreach ($collected as $file => $sinks) {
                foreach ($sinks as $sink) {
                    $sources = $graph->getSourcesReaching($sink['sources']);

                    if ($sources === []) {
                        continue;
                    }

                    $type = SinkType::from($sink['type']);

                    $message = sprintf(
                        'Possible %s: tainted value from %s is passed to %s',
                        $type->describe(),
                        implode(
                            ', ',
                            array_map(fn(string $source) => TaintNode::fromString($source)->describe(), $sources)
                        ),
                        $sink['sink']
                    );

                    $errors[] = RuleErrorBuilder::message($message)
                        ->file($file)
                        ->line($sink['line'])
                        ->identifier($type->identifier())
                        ->build();
                }
            }
        }

        return $errors;
    }
}
