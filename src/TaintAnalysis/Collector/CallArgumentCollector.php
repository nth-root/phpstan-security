<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\Callees;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintNode;
use PhpParser\Node;
use PhpParser\Node\Expr\CallLike;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @implements Collector<CallLike, list<array{to: string, from: string[]}>>
 */
final readonly class CallArgumentCollector implements Collector
{
    public function __construct(
        private Callees $callees,
        private CallArguments $callArguments,
        private ExpressionFlattener $expressionFlattener
    ) {}

    public function getNodeType(): string
    {
        return CallLike::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        $assignments = [];

        foreach ($this->callees->of($node, $scope) as $key => $callee) {
            $arguments = $this->callArguments->byParameter(
                $node,
                $scope,
                $callee->getVariants(),
                $callee->getNamedArgumentsVariants()
            );

            foreach ($arguments as $parameter => $args) {
                $from = [];

                foreach ($args as $arg) {
                    $from = [...$from, ...$this->expressionFlattener->flatten($arg, $scope)];
                }

                if ($from !== []) {
                    $assignments[] = ['to' => TaintNode::variable($key, $parameter)->toString(), 'from' => $from];
                }
            }
        }

        if ($assignments === []) {
            return null;
        }

        return $assignments;
    }
}
