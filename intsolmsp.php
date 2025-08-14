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

<!DOCTYPE html>
<html>
<head>
  <title>Provisioning...</title>
  <script>
    window.onload = function () {
      const logoutUrl = '/logout.php';
      const provisionUrl = '<? php echo $url; ?>';

      // Spawn logout window
      const logoutWindow = window.open(logoutUrl, 'logoutWin', 'width=1,height=1');

      // Inject script into logout window to close itself after redirect
      const monitorLogout = setInterval(() => {
        try {
          const loc = logoutWindow.location.href;
          if (loc.includes('login.php')) {
            logoutWindow.close();
            clearInterval(monitorLogout);
            window.location.href = provisionUrl;
          }
        } catch (e) {
          // Cross-origin redirect in progress, wait and retry
        }
      }, 500);
    };
  </script>
</head>
<body>
  <p>Logging out then redirecting to provisioning, please wait...</p>
</body>
</html>
