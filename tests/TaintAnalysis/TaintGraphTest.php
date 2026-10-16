<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\TaintAnalysis;

use NthRoot\PhpstanSecurity\TaintAnalysis\TaintGraph;
use PHPUnit\Framework\TestCase;

class TaintGraphTest extends TestCase
{
    public function testDirect(): void
    {
        $graph = new TaintGraph();

        self::assertSame(['source:_GET'], $graph->getSourcesReaching(['source:_GET']));
    }

    public function testChain(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('source:_GET', 'var:f:a');
        $graph->addEdge('var:f:a', 'var:f:b');

        self::assertSame(['source:_GET'], $graph->getSourcesReaching(['var:f:b']));
    }

    public function testNoPath(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('source:_GET', 'var:f:a');

        self::assertSame([], $graph->getSourcesReaching(['var:f:b']));
    }

    public function testCycle(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('var:f:a', 'var:f:b');
        $graph->addEdge('var:f:b', 'var:f:a');

        self::assertSame([], $graph->getSourcesReaching(['var:f:a']));
    }

    public function testTwoSources(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('source:_GET', 'var:f:a');
        $graph->addEdge('source:_POST', 'var:f:a');

        self::assertEqualsCanonicalizing(['source:_GET', 'source:_POST'], $graph->getSourcesReaching(['var:f:a']));
    }
}
