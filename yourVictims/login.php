<?php

    // Ensure the use of a secure connection
// if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off") {
//     $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
//     header("Location: $redirect");
//     exit;
//  }

 // Configure PHP session to use a strong hash function and length
 ini_set('session.hash_function', 'sha256'); // Use SHA-256
 ini_set('session.hash_bits_per_character', 6); // 6 bits per character
 ini_set('session.sid_length', 64); // 64 characters for session ID

    // Set secure cookie parameters
//  session_set_cookie_params([
//     'lifetime' => 0, // Session expires on browser close
//     'path' => '/',
//     'domain' => $_SERVER['HTTP_HOST'], // Current domain
//     'secure' => true, // Only send cookie over HTTPS
//     'httponly' => true, // Prevent JavaScript access to the cookie
//     'samesite' => 'Strict', // Prevent CSRF attacks
//  ]);

 session_start();
 
 if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true); // Regenerate session ID if session does not exist
    $_SESSION['initiated'] = true;
 }

date_default_timezone_set('Asia/Kolkata'); // Replace 'Asia/Kolkata' with the correct time zone, e.g., 'UTC', 'America/Los_Angeles', etc.
include("connection.php");

// Turn off error reporting
error_reporting(0);
mysqli_report(MYSQLI_REPORT_OFF);


$error = '';
$message = isset($_SESSION['message']) ? $_SESSION['message'] : '';
unset($_SESSION['message']);

if (isset($_SESSION['timeout_message'])) {
    if ($error) {
        $error .= ' ';
    }
    $error .= $_SESSION['timeout_message'];
    unset($_SESSION['timeout_message']);
}

// Helper function to get the user's IP address
function getIpAddress() {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

// Function to log a login attempt
function logAttempt($conn, $username, $ip, $success) {
    $stmt = $conn->prepare("INSERT INTO failed_logins (username, ip_address, attempt_time, successful) VALUES (?, ?, NOW(), ?)");
    $stmt->bind_param("ssi", $username, $ip, $success);
    $stmt->execute();
}

// Function to get the number of failed attempts and check if the IP is blocked
function isIpBlocked($conn, $ip) {
    $maxAttempts = 5; // maximum number of allowed failed attempts
    $blockDuration = 15; // Block duration in minutes

    // Get the number of failed attempts in the past hour and the time of the last attempt
    $stmt = $conn->prepare("SELECT COUNT(*) AS attempts, MAX(attempt_time) AS last_attempt FROM failed_logins WHERE ip_address = ? AND successful = 0 AND attempt_time > (NOW() - INTERVAL 1 HOUR)");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();

    // If the IP has exceeded the maximum attempts, check the block duration
    if ($row['attempts'] >= $maxAttempts) {
        $lastAttemptTime = strtotime($row['last_attempt']);
        $currentTime = time();

        // Debugging: Print out values for verification
        // echo "Last Attempt Time: " . date("Y-m-d H:i:s", $lastAttemptTime) . "\n";
        // echo "Current Time: " . date("Y-m-d H:i:s", $currentTime) . "\n";

        $timeDifference = ($currentTime - $lastAttemptTime) / 60; // Time difference in minutes
        
        // If the last attempt was within the block duration, block the IP
        if ($timeDifference < $blockDuration) {
            return true; // IP is blocked
        } else {
            // If the block duration has passed, do not block the IP
            return false;
        }
    }
    return false; // IP is not blocked
}

// Function to reset failed attempts after a successful login
function resetFailedAttempts($conn, $ip) {
    $stmt = $conn->prepare("DELETE FROM failed_logins WHERE ip_address = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    
    $username = htmlspecialchars(trim($_POST['user']));
    $password = htmlspecialchars(trim($_POST['password']));
    $ip = getIpAddress();

    // Check if the IP is blocked
    if (isIpBlocked($conn, $ip)) {
        $error = "Too many failed attempts. Please try again later.";
    } else {
        // Prepared statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT password, is_password_changed, last_password_change, role, status FROM login WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $count = $result->num_rows;

        if ($count == 1 && password_verify($password, $user['password'])) {
            if ($user['status'] == 'inactive') {
                $error = "Your account is currently inactive. Please contact the administrator for assistance.";
            }else{
                logAttempt($conn, $username, $ip, 1); // Log the successful attempt

                resetFailedAttempts($conn, $ip); // Reset failed attempts after successful login

                session_regenerate_id(true); // Regenerate session ID to prevent session fixation

                $_SESSION['user'] = $username; // Set session variable upon successful login
                $_SESSION['password_changed'] = $user['is_password_changed'];
                $_SESSION['role'] = $user['role'];

                if ($user['is_password_changed'] == 0) {
                    header("Location: changepass.php"); // Redirect to change password page if password has not changed
                } else {
                    $lastPasswordChange = new DateTime($user['last_password_change']);
                    $currentDate = new DateTime();
                    $interval = $currentDate->diff($lastPasswordChange);

                    if ($interval->days > 30) {
                        header("Location: changepass.php?expired=true"); // Redirect to change password page with expired flag
                    } else {
                        $_SESSION['loggedin'] = true;
                        header("Location: /"); // Redirect to Dashboard page if password has already been changed and not expired
                    }
                }
                exit();
            }
        } else {
            logAttempt($conn, $username, $ip, 0); // Log the failed attempt
            $error = "Login failed. Invalid Username or Password.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel = "icon" href = "assets/img/Title.png" type = "image/x-icon">
    <title>Login Page</title>
    <link rel="stylesheet" href="assets/css/all.min.css">
    <!-- <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css"> -->
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: 'Arial', sans-serif;
            background: url('assets/img/phishing.png');
            background-repeat: no-repeat;
            background-attachment: fixed;
            background-size: cover;
            background-position: center;
            /* background-size: cover; */
        }

        .login-container {
			background: rgba(255, 255, 255, 0.9);
			padding: 40px 50px;
			border-radius: 10px;
			box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
			text-align: center;
			width: 350px;
			position: relative;
        }

        .login-container h1 {
            margin-bottom: 10px;
            color: #007bff;
            font-size: 24px;
            font-weight: bold;
        }

        .login-container p {
            margin-bottom: 20px;
            color: #555;
            font-size: 16px;
        }

        .input-field {
            width: calc(100% - 5px);
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
            display: inline-block;
        }

        .login-btn {
            width: 100%;
            padding: 10px;
            background-color: #007bff;
            border: none;
            border-radius: 5px;
            color: white;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .login-btn:hover {
            background-color: #0056b3;
        }

        .input-container {
            margin-bottom: 15px;
            position: relative;
        }

        .password-container {
            position: relative;
        }

        .toggle-password {
            position: absolute;
            top: 50%;
            right: 15px;
            transform: translateY(-50%);
            cursor: pointer;
            color: #888;
            display: none;
        }

        .error-message {
            color: red;
            font-size: 14px;
            font-family: 'Arial', sans-serif;
            text-shadow: 1px 1px 2px gray;
            margin-top: 10px;
            border: 1px solid red;
            background-color: rgba(255, 0, 0, 0.1);
            padding: 10px;
            border-radius: 5px;
        }

        .message-box {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-family: Arial, sans-serif;
        }

        .message-box strong {
            font-size: 1.2em;
            display: block;
        }

        @keyframes shake {
            0% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            50% { transform: translateX(5px); }
            75% { transform: translateX(-5px); }
            100% { transform: translateX(0); }
        }

        .shake {
            animation: shake 0.5s;
        }
    </style>
</head>
<body>
    <div class="login-container <?php if ($error) echo 'shake'; ?>">
        <h1>Welcome to 365-Stealer</h1>
        <p>Login to access the dashboard</p>
        <?php if ($message): ?>
            <div class="message-box">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <p class="error-message"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>

        <form name="form" action="login.php" method="POST">
            <div class="input-container">
                <input type="text" class="input-field" placeholder="Username" required name="user" maxlength="12">
            </div>
            <div class="input-container password-container">
                <input type="password" id="password" class="input-field" placeholder="Password" required name="password" maxlength="24">
                <i class="fas fa-eye toggle-password" id="togglePassword"></i>
            </div>
            <button type="submit" class="login-btn" name="login">Login</button>
        </form>
    </div>

    <script>
        const passwordInput = document.getElementById('password');
        const togglePassword = document.getElementById('togglePassword');

        passwordInput.addEventListener('input', function () {
            togglePassword.style.display = this.value ? 'block' : 'none';
        });

        togglePassword.addEventListener('click', function () {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    </script>
</body>
</html>
