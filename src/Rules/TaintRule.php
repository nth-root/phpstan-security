<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Rules;

use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow\AssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow\CallArgumentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow\CompoundAssignmentCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow\ForeachCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow\ReturnCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow\SymfonyRouteParameterCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\EchoSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\EvalSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\FunctionCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\HeaderSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\IncludeSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\InstantiationSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\MethodCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\PrintSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\ShellExecSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink\StaticCallSinkCollector;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintGraph;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\FileRuleError;
use PHPStan\Rules\LineRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

use function array_map;
use function implode;
use function sprintf;
use function usort;

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

        $assignmentListsByFile = [
            $node->get(AssignmentCollector::class),
            $node->get(CompoundAssignmentCollector::class),
            $node->get(ReturnCollector::class),
            $node->get(CallArgumentCollector::class),
            $node->get(SymfonyRouteParameterCollector::class),
            $node->get(ForeachCollector::class),
        ];

        foreach ($assignmentListsByFile as $collected) {
            foreach ($collected as $assignmentLists) {
                foreach ($assignmentLists as $assignments) {
                    foreach ($assignments as $assignment) {
                        foreach ($assignment['from'] as $from) {
                            $graph->addEdge($from, $assignment['to']);
                        }
                    }
                }
            }
        }

        $errors = [];

        $sinksByFile = [
            $node->get(FunctionCallSinkCollector::class),
            $node->get(MethodCallSinkCollector::class),
            $node->get(StaticCallSinkCollector::class),
            $node->get(HeaderSinkCollector::class),
            $node->get(ShellExecSinkCollector::class),
            $node->get(EchoSinkCollector::class),
            $node->get(PrintSinkCollector::class),
            $node->get(IncludeSinkCollector::class),
            $node->get(EvalSinkCollector::class),
            $node->get(InstantiationSinkCollector::class),
        ];

        foreach ($sinksByFile as $collected) {
            foreach ($collected as $file => $sinks) {
                foreach ($sinks as $sink) {
                    $type = SinkType::from($sink['type']);
                    $sources = $graph->getSourcesReaching($sink['sources'], $type);

                    if ($sources === []) {
                        continue;
                    }

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

        usort($errors, [$this, 'compare']);

        return $errors;
    }

    private function compare(FileRuleError&LineRuleError $a, FileRuleError&LineRuleError $b): int
    {
        return [$a->getFile(), $a->getLine()] <=> [$b->getFile(), $b->getLine()];
    }
}
