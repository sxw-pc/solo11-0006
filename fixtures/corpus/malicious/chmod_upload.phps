<?php // SYNTHETIC FIXTURE - NOT RUNNABLE. Payload intentionally omitted.
$fixture = __SHELLHUNT_PLACEHOLDER__;
// Primary signal: upload move plus world-writable permission.
move_uploaded_file ( /* $_FILES['pkg'] intentionally omitted */ );
chmod ( /* path intentionally omitted */ 0777 );
