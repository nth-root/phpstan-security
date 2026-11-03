<?php

declare(strict_types=1);

function cases(): void
{
    unserialize($_COOKIE['cart']); // unsafe
    unserialize($_GET['data'], ['allowed_classes' => false]); // unsafe (reported regardless of allowed_classes)
    unserialize('a:0:{}'); // safe
    unserialize('a:0:{}', ['allowed_classes' => $_GET['classes']]); // safe (only data is a sink)
}
