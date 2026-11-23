<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Sink;

use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PHPStan\Collectors\Collector;

/**
 * @template-covariant TNode of Node
 *
 * @extends Collector<TNode, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
interface SinkCollector extends Collector {}
