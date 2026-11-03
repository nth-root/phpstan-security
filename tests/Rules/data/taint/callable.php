<?php

declare(strict_types=1);

function cases(): void
{
    call_user_func($_GET['action']); // unsafe
    call_user_func_array($_POST['handler'], []); // unsafe
    call_user_func(callback: $_GET['action']); // unsafe
    call_user_func('strtolower', $_GET['name']); // safe (only the callback is a sink)
    call_user_func_array('max', $_GET['numbers']); // safe
}
