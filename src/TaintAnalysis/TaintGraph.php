<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

use function array_keys;
use function array_pop;
use function array_push;

final class TaintGraph
{
    /**
     * @var array<string, list<string>> node id => ids of the nodes it gets its value from
     */
    private array $predecessors = [];

    public function addEdge(string $from, string $to): void
    {
        $this->predecessors[$to][] = $from;
    }

    /**
     * @param string[] $start
     *
     * @return string[]
     */
    public function getSourcesReaching(array $start): array
    {
        $worklist = $start;

        $visited = $found = [];

        while ($worklist !== []) {
            $node = array_pop($worklist);

            if (isset($visited[$node])) {
                continue;
            }

            $visited[$node] = true;

            if (TaintNode::fromString($node)->isSource()) {
                $found[$node] = true;
            }

            array_push($worklist, ...$this->predecessors[$node] ?? []);
        }

        return array_keys($found);
    }
}
