<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis\Collector;

use NthRoot\PhpstanSecurity\TaintAnalysis\CallArguments;
use NthRoot\PhpstanSecurity\TaintAnalysis\ExpressionFlattener;
use NthRoot\PhpstanSecurity\TaintAnalysis\SinkType;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

use function sprintf;
use function stripos;

/**
 * @implements Collector<FuncCall, array{sink: string, type: value-of<SinkType>, sources: string[], line: int}>
 */
final readonly class HeaderSinkCollector implements Collector
{
    private const REDIRECT_HEADERS = ['location:', 'refresh:'];

    public function __construct(
        private ReflectionProvider $reflectionProvider,
        private ExpressionFlattener $expressionFlattener,
        private CallArguments $callArguments
    ) {}

    public function getNodeType(): string
    {
        return FuncCall::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node->name instanceof Name) {
            return null;
        }

        if ($node->isFirstClassCallable()) {
            return null;
        }

        $functionName = $this->reflectionProvider->resolveFunctionName($node->name, $scope);

        if ($functionName !== 'header') {
            return null;
        }

        $args = $this->callArguments->ofFunctionCall($node, $node->name, $scope, ['header']);

        if ($args === [] || !$this->isRedirect($args[0], $scope)) {
            return null;
        }

        return [
            'sink' => sprintf('%s()', $functionName),
            'type' => SinkType::RedirectHeader->value,
            'sources' => $this->expressionFlattener->flatten($args[0], $scope),
            'line' => $node->getStartLine(),
        ];
    }

    private function isRedirect(Expr $header, Scope $scope): bool
    {
        while ($header instanceof Concat) {
            $header = $header->left;
        }

        if ($header instanceof InterpolatedString) {
            $first = $header->parts[0] ?? null;

            return $first instanceof InterpolatedStringPart && $this->startsWithRedirectHeader($first->value);
        }

        $prefixes = $scope->getType($header)->getConstantStrings();

        if ($prefixes === []) {
            return false;
        }

        foreach ($prefixes as $prefix) {
            if (!$this->startsWithRedirectHeader($prefix->getValue())) {
                return false;
            }
        }

        return true;
    }

    private function startsWithRedirectHeader(string $header): bool
    {
        foreach (self::REDIRECT_HEADERS as $redirectHeader) {
            if (stripos($header, $redirectHeader) === 0) {
                return true;
            }
        }

        return false;
    }
}
