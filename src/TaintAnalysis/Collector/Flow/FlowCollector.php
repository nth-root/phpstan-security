<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector\Flow;

use PhpParser\Node;
use PHPStan\Collectors\Collector;

/**
 * @template-covariant TNode of Node
 *
 * @extends Collector<TNode, list<array{to: string, from: string[]}>>
 */
interface FlowCollector extends Collector {}
