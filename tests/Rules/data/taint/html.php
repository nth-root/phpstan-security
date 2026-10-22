<?php

declare(strict_types=1);

function cases(): void
{
    echo $_GET['name']; // unsafe
    echo 'Hello'; // safe
    echo 'Hello ', $_GET['name']; // unsafe
    echo "Hello {$_POST['name']}"; // unsafe
    echo htmlspecialchars($_GET['name']); // safe
    print $_GET['name']; // unsafe
    print 'Hello'; // safe

    $name = $_GET['name'];
    echo $name; // unsafe
}

?>
<p>Static</p>
<p><?= 'Hello' ?></p>
<p><?= $_GET['name'] ?></p>
