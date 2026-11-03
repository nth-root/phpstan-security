<?php

declare(strict_types=1);

function cases(): void
{
    echo htmlspecialchars($_GET['name']); // safe
    echo htmlentities($_GET['name']); // safe
    exec(htmlspecialchars($_GET['cmd'])); // unsafe (escaped for HTML, not the shell)
    exec(escapeshellarg($_GET['dir'])); // safe
    echo escapeshellarg($_GET['name']); // unsafe (escaped for the shell, not HTML)
    exec(escapeshellcmd($_GET['cmd'])); // unsafe (allows argument injection)
    exec(escapeshellarg(htmlspecialchars($_GET['x']))); // safe (nested)
    echo trim(htmlspecialchars($_GET['x'])); // safe (flow around a sanitizer)
    echo htmlspecialchars($_GET['a']) . $_POST['b']; // unsafe ($_POST only)

    $name = htmlspecialchars($_GET['name']);
    echo $name; // safe
    exec('ls ' . $name); // unsafe (through a variable)
    include __DIR__ . '/pages/' . basename($_GET['page']); // safe
    file_get_contents('/var/uploads/' . basename($_GET['file'])); // safe
    echo basename($_GET['file']); // unsafe (stripped of directories, not escaped for HTML)
    exec('ls ' . basename($_GET['dir'])); // unsafe
}
