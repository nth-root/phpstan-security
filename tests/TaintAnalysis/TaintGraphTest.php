<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\Tests\TaintAnalysis;

use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use NthRoot\PhpstanSecurity\TaintAnalysis\TaintGraph;
use PHPUnit\Framework\TestCase;

class TaintGraphTest extends TestCase
{
    public function testDirect(): void
    {
        $graph = new TaintGraph();

        $this->assertSame(['source:_GET'], $graph->getSourcesReaching(['source:_GET'], SinkType::Shell));
    }

    public function testChain(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('source:_GET', 'var:f:a');
        $graph->addEdge('var:f:a', 'var:f:b');

        $this->assertSame(['source:_GET'], $graph->getSourcesReaching(['var:f:b'], SinkType::Shell));
    }

    public function testNoPath(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('source:_GET', 'var:f:a');

        $this->assertSame([], $graph->getSourcesReaching(['var:f:b'], SinkType::Shell));
    }

    public function testCycle(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('var:f:a', 'var:f:b');
        $graph->addEdge('var:f:b', 'var:f:a');

        $this->assertSame([], $graph->getSourcesReaching(['var:f:a'], SinkType::Shell));
    }

    public function testTwoSources(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('source:_GET', 'var:f:a');
        $graph->addEdge('source:_POST', 'var:f:a');

        $this->assertEqualsCanonicalizing(
            ['source:_GET', 'source:_POST'],
            $graph->getSourcesReaching(['var:f:a'], SinkType::Shell)
        );
    }

    public function testSanitizedNodeOnlyStopsItsOwnSinkTypes(): void
    {
        $graph = new TaintGraph();
        $graph->addEdge('sanitized:html:source:_GET', 'var:f:a');

        $this->assertSame([], $graph->getSourcesReaching(['var:f:a'], SinkType::Html));
        $this->assertSame(['source:_GET'], $graph->getSourcesReaching(['var:f:a'], SinkType::Shell));
    }

    public function testSanitizedForSeveralSinkTypes(): void
    {
        $graph = new TaintGraph();
        $start = ['sanitized:html,shell:source:_GET'];

        $this->assertSame([], $graph->getSourcesReaching($start, SinkType::Html));
        $this->assertSame([], $graph->getSourcesReaching($start, SinkType::Shell));
        $this->assertSame(['source:_GET'], $graph->getSourcesReaching($start, SinkType::Sql));
    }

    public function testNestedSanitizers(): void
    {
        $graph = new TaintGraph();
        $start = ['sanitized:shell:sanitized:html:source:_GET'];

        $this->assertSame([], $graph->getSourcesReaching($start, SinkType::Html));
        $this->assertSame([], $graph->getSourcesReaching($start, SinkType::Shell));
        $this->assertSame(['source:_GET'], $graph->getSourcesReaching($start, SinkType::Sql));
    }
}
