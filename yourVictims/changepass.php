<?php

// Ensure the use of a secure connection
// if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off") {
//     $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
//     header("Location: $redirect");
//     exit;
//  }

 session_start();
 
 if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
 }
 
include("connection.php");

// Turn off error reporting
error_reporting(0);
mysqli_report(MYSQLI_REPORT_OFF);


// Check if the user is not logged in
if (!isset($_SESSION['user'])) {
    header("Location: login.php"); // Redirect to login page
    exit();
}

$error = '';
$success = '';
$expiredMessage = isset($_GET['expired']) && $_GET['expired'] == 'true' ? "Password expired. Please change your password." : '';

// Handle change password form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['change_password'])) {
    
    // Sanitize and validate inputs
    $currentPassword = htmlspecialchars(trim($_POST['current_password']));
    $newPassword = htmlspecialchars(trim($_POST['new_password']));
    $confirmPassword = htmlspecialchars(trim($_POST['confirm_new_password']));

    // Password complexity pattern
    $passwordPattern = "/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$/";

    if ($newPassword !== $confirmPassword) {
        // New password and confirm password do not match
        $error = "New password and confirm password do not match.";
        $expiredMessage = '';
    } elseif (!preg_match($passwordPattern, $newPassword)) {
        // New password does not meet complexity requirements
        $error = "Password must be 8+ characters with at least one uppercase, one number, and one special character.";
        $expiredMessage = ''; 
    } else {
        $username = $_SESSION['user'];

        $stmt = $conn->prepare("SELECT password FROM login WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        
        // Check if current password is correct
        if ($user && password_verify($currentPassword, $user['password'])) {
            // Check if old password is the same as the new password
            if (password_verify($newPassword, $user['password'])) {
                $error = "New password cannot be the same as the old password.";
            } else {
                // Hash the new password
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                
                // Update the password
                $stmt = $conn->prepare("UPDATE login SET password = ?, is_password_changed = 1, last_password_change = NOW() WHERE username = ?");
                $stmt->bind_param("ss", $hashedPassword, $username);

                if ($stmt->execute()) {
                    $_SESSION['password_changed'] = 1;
                    $_SESSION['message'] = "Your password has been reset successfully. Please log in with your new password.";
                    unset($_SESSION['user']); // Log out after changing password
                    header("Location: login.php"); // Redirect to login page
                    exit();
                } else {
                    $error = "Failed to update password. Please try again.";
                }
            }
        } else {
            $error = "Current password is incorrect.";
            $expiredMessage = '';
        }
    }
}

$backUrl = isset($_GET['from']) && $_GET['from'] === 'dashboard' ? '/' : 'login.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel = "icon" href = "assets/img/Title.png" type = "image/x-icon">
    <title>Change Password</title>
    <link rel="stylesheet" href="assets/css/all.min.css">
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
        }

        .change-password-container {
            background: rgba(255, 255, 255, 0.9);
            padding: 20px 30px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            text-align: center;
            width: 350px;
            position: relative; 
        }

        .change-password-container h1 {
            margin-bottom: 20px;
            color: #007bff;
            font-size: 24px;
            font-weight: bold;
        }

        .change-password-container p {
            margin-bottom: 20px;
            color: #555;
            font-size: 16px;
        }

        .input-field {
            width: calc(100% - 5px); /* Adjust width to accommodate icon */
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
        }

        .submit-btn {
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

        .submit-btn:hover {
            background-color: #0056b3;
        }

        .input-container {
            margin-bottom: 15px;
            position: relative;
        }

        .toggle-password {
            position: absolute;
            top: 50%;
            right: 15px;
            transform: translateY(-50%);
            cursor: pointer;
            color: #888;
            display: none; /* Hide icon initially */
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

        .success-message {
            color: green;
            margin: 15px 0;
        }

        .back-arrow {
            position: absolute;
            top: 10px;
            left: 10px;
            font-size: 24px;
            color: #007bff;
            cursor: pointer;
        }

        .back-arrow:hover
        {
            color: black;
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
    <script>
        function goBack() {
            window.location.href = '<?php echo $backUrl; ?>';
        }
    </script>
</head>
<body>
<div class="change-password-container <?php if ($error) echo 'shake'; ?>">
        <div class="back-arrow" onclick="goBack()">
            &#8592;
        </div>
        <h1>Change Password</h1>
        <?php if ($expiredMessage && !$error): ?>
            <p class="error-message"><?php echo htmlspecialchars($expiredMessage); ?></p>
        <?php elseif (!$error): ?>
            <p>To enhance security, please change your password.</p>
        <?php endif; ?>

        <?php if ($error): ?>
            <p class="error-message"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>

        <?php if ($success): ?>
            <p class="success-message"><?php echo htmlspecialchars($success); ?></p>
        <?php endif; ?>

        <form method="POST">
            <div class="input-container">
                <input type="password" class="input-field" id="current_password" name="current_password" placeholder="Current Password" required maxlength="24">
                <i class="fas fa-eye toggle-password" onclick="togglePasswordVisibility('current_password')"></i>
            </div>
            <div class="input-container">
                <input type="password" class="input-field" id="new_password" name="new_password" placeholder="New Password" required maxlength="24">
                <i class="fas fa-eye toggle-password" onclick="togglePasswordVisibility('new_password')"></i>
            </div>
            <div class="input-container">
                <input type="password" class="input-field" id="confirm_new_password" name="confirm_new_password" placeholder="Confirm New Password" required maxlength="24">
                <i class="fas fa-eye toggle-password" onclick="togglePasswordVisibility('confirm_new_password')"></i>
            </div>
            <button type="submit" name="change_password" class="submit-btn">Submit</button>
        </form>
    </div>

    <script>
        function togglePasswordVisibility(fieldId) {
            const passwordField = document.getElementById(fieldId);
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            const icon = passwordField.nextElementSibling;
            icon.classList.toggle('fa-eye');
            icon.classList.toggle('fa-eye-slash');
        }

        // Show the eye icon when typing in any password field
        document.querySelectorAll('.input-field[type="password"]').forEach(input => {
            input.addEventListener('input', function () {
                const icon = this.nextElementSibling;
                icon.style.display = this.value ? 'block' : 'none';
            });
        });
    </script>
</body>
</html>
