<?php

declare(strict_types=1);

class MagicCallReceiver
{
    public function __call(string $name, array $arguments): mixed
    {
        return null;
    }
}

/**
 * @method void runQuery(string $sql)
 */
class MagicCallReceiverWithTag extends MagicCallReceiver {}

function cases(MagicCallReceiver $receiver, MagicCallReceiverWithTag $receiverWithTag): void
{
    $receiver->runQuery($_GET['sql']); // not checked: sink parameters need the method's reflection
    $receiverWithTag->runQuery($_GET['sql']); // unsafe
}
