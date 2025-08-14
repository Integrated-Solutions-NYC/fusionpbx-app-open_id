<?php
require_once __DIR__ . "/../../resources/require.php";

session_unset();
session_destroy();
session_start();
$domain = new domains();
$domain->session();
$domain->set();

// Forward to open_id.php with all parameters
$url = "/app/open_id/open_id.php?action=open_id_azure_b2c_provision";
if (isset($_GET['env'])) {
    if ($_GET['env'] != '') {
        $url .= "_" . $_GET['env'];
    }
}
if (isset($_GET['port'])) {
    $url .= "&port=" . intval($_GET['port']);
}
header("Location: " . $url);
exit;
?>