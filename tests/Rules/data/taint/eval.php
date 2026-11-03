<?php

declare(strict_types=1);

function cases(): void
{
    eval($_GET['code']); // unsafe
    eval('return ' . $_POST['expression'] . ';'); // unsafe
    eval('return 1 + 1;'); // safe
}
