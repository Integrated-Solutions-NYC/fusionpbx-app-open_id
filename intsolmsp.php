<?php
require_once __DIR__ . "/../../resources/require.php";

session_unset();
session_destroy();
session_start();
$domain = new domains();
$domain->session();
$domain->set();

// Forward to open_id.php with all parameters
$provisionPath = "/app/open_id/open_id.php?action=open_id_azure_b2c_provision";
if (isset($_GET['env'])) {
    if ($_GET['env'] != '') {
        $provisionPath .= "_" . $_GET['env'];
    }
}
if (isset($_GET['port'])) {
    $provisionPath .= "&port=" . intval($_GET['port']);
}
$logoutUrl = "https://integratedsolutionsiam.b2clogin.com/integratedsolutionsiam.onmicrosoft.com/B2C_1A_SIGNUP_SIGNIN/oauth2/v2.0/logout?p=B2C_1A_SIGNUP_SIGNIN";
$logoutUrl .= "&post_logout_redirect_uri=https://portal.solutionsdx.com" . urlencode($provisionPath);
header("Location: " . $logoutUrl);
exit;
?>
