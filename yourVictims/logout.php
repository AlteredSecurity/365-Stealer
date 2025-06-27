<?php
session_start();
$_SESSION = [];
session_unset();
session_destroy();

// Check if the message is passed via the URL
$message = isset($_GET['message']) ? $_GET['message'] : '';

// Store the message in a session variable
if ($message) {
    session_start();
    $_SESSION['timeout_message'] = $message;
}

// Redirect to the login page
header("Location: login.php");
exit();
?>
