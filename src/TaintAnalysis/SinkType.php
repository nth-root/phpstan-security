<?php

declare(strict_types=1);

namespace NthRoot\PhpstanSecurity\TaintAnalysis;

enum SinkType: string
{
    case Sql = 'sql';
    case Html = 'html';
    case Shell = 'shell';
    case FileInclusion = 'include';

    public function identifier(): string
    {
        return 'tainted.' . $this->value;
    }

    public function describe(): string
    {
        return match ($this) {
            self::Sql => 'SQL injection',
            self::Html => 'cross-site scripting',
            self::Shell => 'command injection',
            self::FileInclusion => 'file inclusion',
        };
    }
}
