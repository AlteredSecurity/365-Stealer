<?php
    // if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off") {
    //     $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    //     header("Location: $redirect");
    //     exit;
    // }

    session_start();
    include("connection.php");

    if (!isset($_SESSION['user'])) {
        header("Location: login.php");
        exit();
    }
    
    $username = $_SESSION['user'];
    $is_admin = $_SESSION['role'];
    $unauthorized = false;
    
    // Check if the user is not admin
    if ($is_admin !== 'admin') {
        $unauthorized = true;
    }
    
    error_reporting(0);
    mysqli_report(MYSQLI_REPORT_OFF);

    // Check if form is submitted
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST['action'])) {
            $action = $_POST['action'];            

            if ($action == 'createuser') {
                // Handle Create User action
                $username = htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8');
                $role = htmlspecialchars($_POST['role'], ENT_QUOTES, 'UTF-8');
                $password = htmlspecialchars($_POST['password'], ENT_QUOTES, 'UTF-8');
                $currentDate = date('Y-m-d');
                $hashPassword = password_hash($_POST['password'], PASSWORD_DEFAULT); // Hash the password

                // Check if the user already exists in the database
                $sql = "SELECT * FROM login WHERE username = ?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $username);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    $_SESSION['message'] = "Username already exists!";
                    $_SESSION['messageType'] = "danger";
                } else {

                // Insert the new user into the database
                $sql = "INSERT INTO login (username, password, last_password_change, role, is_password_changed) VALUES (?, ?, ?, ?, 0)";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("ssss", $username, $hashPassword, $currentDate, $role);

                if ($stmt->execute()) {
                    $_SESSION['message'] = "User " . $username . " created successfully!";
                    $_SESSION['messageType'] = "success";
                } else {
                    $_SESSION['message'] = "Error creating user: " . $conn->error;
                    $_SESSION['messageType'] = "danger";
                }

                }
                $stmt->close();
                header("Location: user_management.php");
                exit;
            } elseif ($action == 'manageusers') {
                $username = htmlspecialchars(trim($_POST['originalUsername']));
                $newRole = htmlspecialchars(trim($_POST['editRole']));
                $newStatus = htmlspecialchars(trim($_POST['editStatus']));
                $newPassword = htmlspecialchars(trim($_POST['editPassword']));
                $currentDate = date('Y-m-d'); 

                if($username === 'admin'){
                    $_SESSION['message'] = "Error: You cannot modify the 'admin' account!";
                    $_SESSION['messageType'] = "danger";
                }else{
                    // Initialize the SQL query and parameters
                    $params = [];
                    $query = "UPDATE login SET role = ?, status = ?";

                    // Prepare the query based on whether a new password is provided
                    if (!empty($newPassword)) {
                        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                        $query .= ", last_password_change = ? , is_password_changed = ? , password = ?";
                        $params = [$newRole, $newStatus, $currentDate, 0, $hashedPassword, $username];
                    } else {
                        $params = [$newRole, $newStatus, $username];
                    }

                    $query .= " WHERE username = ?";
                    
                    // Prepare and execute the statement
                    $stmt = $conn->prepare($query);
                    if (!empty($newPassword)) {
                        $stmt->bind_param("sssiss", ...$params);
                    } else {
                        $stmt->bind_param("sss", ...$params);
                    }
                        
                    if ($stmt->execute()) {
                        $_SESSION['message'] = "User " . $username . " updated successfully!";
                        $_SESSION['messageType'] = "success";
                    } else {
                        $_SESSION['message'] = "Error updating user: " . $conn->error;
                        $_SESSION['messageType'] = "danger";
                    }

                    $stmt->close();
                }
                header("Location: user_management.php");
                exit;
            } elseif ($action == 'passwordmanagement') {
                // Handle Password Management action
                $manageUsername = htmlspecialchars(trim($_POST['manageUsername']));
                $newPassword = password_hash($_POST['managePassword'], PASSWORD_DEFAULT); // Hash the new password

                // Update the user's password in the database
                $sql = "UPDATE login SET password = ?, last_password_change = CURDATE(), is_password_changed = 0 WHERE username = ?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("ss", $newPassword, $manageUsername);

                if ($manageUsername === 'admin'){
                    $_SESSION['message'] = "Password update for the user 'admin' cannot be processed.";
                    $_SESSION['messageType'] = "danger";
                }else{
                    if ($stmt->execute()) {
                        $_SESSION['message'] = "Password updated successfully!";
                        $_SESSION['messageType'] = "success";
                    } else {
                        $_SESSION['message'] = "Error updating password: " . $conn->error;
                        $_SESSION['messageType'] = "danger";
                    }
                }

                $stmt->close();
                header("Location: user_management.php");
                exit;
            } elseif ($action == 'deleteuser') {
                // Get the username to be deleted
                $usernameToDelete = htmlspecialchars(trim($_POST['username']));

                // Prepare and execute the deletion query
                $sql = "DELETE FROM login WHERE username = ?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $usernameToDelete);

                if ($stmt->execute()) {
                    $_SESSION['message'] = "User " . $usernameToDelete . " deleted successfully!";
                    $_SESSION['messageType'] = "success";
                } else {
                    $_SESSION['message'] = "Error deleting user: " . $conn->error;
                    $_SESSION['messageType'] = "error";
                }

                $stmt->close();
                // Redirect to the same page to display the message after reloading
                header("Location: user_management.php");
                exit;
            }
        }else{

            // Check if it's an AJAX request for searching users
            if (isset($_POST['query']) || isset($_POST['role'])) {
                $query = htmlspecialchars(trim($_POST['query']));
                $role = htmlspecialchars(trim($_POST['role']));
                        
                if (!empty($role)) {
                    $sql = "SELECT username, last_password_change, role, status 
                        FROM login 
                        WHERE username LIKE ? AND role = ? ORDER BY username ASC";
                }else{
                $sql = "SELECT username, last_password_change, role, status 
                        FROM login 
                        WHERE username LIKE ? ORDER BY username ASC";
                }
                
                $stmt = $conn->prepare($sql);
                $likeQuery = "%$query%";
            
                if (!empty($role)) {
                    $stmt->bind_param("ss", $likeQuery, $role);
                } else {
                    $stmt->bind_param("s", $likeQuery);
                }
            
                $stmt->execute();
                $result = $stmt->get_result();
            
                // Debugging output to see the actual SQL query and data being processed
                // error_log("Executing query: $sql with query = $query and role = $role");
            
                if ($result->num_rows > 0) {
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>
                                <td>" . htmlspecialchars($row['username']) . "</td>
                                <td>" . htmlspecialchars($row['status']) . "</td>
                                <td>" . htmlspecialchars($row['role']) . "</td>
                                <td>" . htmlspecialchars($row['last_password_change']) . "</td>
                                <td>";
                        
                        // Check if the user is not 'admin' before displaying Edit and Delete buttons
                        if ($row['username'] !== 'admin') {
                            echo "<button class='btn btn-warning btn-sm edit-user-btn'
                                    data-username='" . htmlspecialchars($row['username']) . "'
                                    data-role='" . htmlspecialchars($row['role']) . "'
                                    data-status='" . htmlspecialchars($row['status']) . "'
                                    data-toggle='modal' data-target='#editUserModal'>
                                    Edit
                                </button>
                                <form method='POST' action='' style='display:inline;'>
                                    <input type='hidden' name='action' value='deleteuser'>
                                    <input type='hidden' name='username' value='" . htmlspecialchars($row['username']) . "'>
                                    <button type='submit' class='btn btn-danger btn-sm' onclick='return confirm(\"Are you sure you want to delete this user?\");'>
                                        Delete
                                    </button>
                                </form>";
                        }
                
                        echo "</td>
                            </tr>";
                    }
                } else {
                    echo "<tr><td colspan='5' class='text-center'>No users found</td></tr>";
                }                
            
                $stmt->close();
                exit; // End the script after responding to the AJAX request
            } 
        }
    }

    // Fetch users from the database for the Manage Users section
    $users = [];
    $sql = "SELECT username, last_password_change, role, status FROM login ORDER BY username ASC";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
    }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel = "icon" href = "assets/img/Title.png" type = "image/x-icon">
    <title>User Management</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <link rel="stylesheet" href="assets/css/user_management.css">
</head>
<body>
    <!-- Header -->
    <header class="bg-dark text-white text-center py-3">
        <h1>User Management</h1>
    </header>
    
    <?php if ($unauthorized): ?>
        <div class="alert alert-danger text-center">
            Unauthorized Access! User <?php echo $username; ?> do not have permission to view this page.
        </div>
    <?php else: ?>

    <?php if (isset($_SESSION['message'])): ?>
        <div class="alert-container">
            <div class="alert alert-<?php echo $_SESSION['messageType']; ?>" role="alert">
                <strong>Message:</strong> <?php echo $_SESSION['message']; ?>
                <button type="button" class="close-alert" aria-label="Close">
                    &times;
                </button>
            </div>
        </div>
        <?php
        // Clear the message after displaying it
        unset($_SESSION['message']);
        unset($_SESSION['messageType']);
        ?>
    <?php endif; ?>

    <!-- Sidebar and Main Content Wrapper -->
    <div class="d-flex">
        <!-- Sidebar -->
        <nav class=" text-white sidebar p-3">
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link text-white" href="#" onclick="showSection('createUserSection')">Create User</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="#" onclick="showSection('manageUsersSection')">Manage Users</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="#" onclick="showSection('passwordManagementSection')">Password Management</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="#" onclick="showSection('searchFilterSection')">Search Users</a>
                </li>
            </ul>
        </nav>

        <!-- Main Content -->
        <div class="container-fluid p-4">
            <!-- User Creation Section -->
            <section id="createUserSection" class="mb-5">
                <h2>Create New User</h2>
                <form id="createUserForm" method="POST" action="">
                    <input type="hidden" name="action" value="createuser">
                    <div class="form-row">
                        <div class="form-group col-md-4">
                            <label for="username">Username</label>
                            <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" required>
                        </div>
                        <div class="form-group col-md-4">
                            <label for="role">Role</label>
                            <select class="form-control" id="role" name="role" required>
                                <option value="admin">Admin</option>
                                <option value="user" default>User</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group col-md-6">
                            <label for="password">Password</label>
                            <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" required>
                            <br>
                            <label for="confirmPassword">Confirm Password</label>
                            <input type="password" class="form-control" id="confirmPassword" name="confirmPassword" placeholder="Confirm password" required>
                        </div>
                    </div>
                    <div class="form-row align-items-center col-md-6">
                        <button type="submit" class="btn btn-primary">Create User</button>
                        <!-- Placeholder for the error message -->
                        <div id="passwordError" class="text-danger ml-3" style="display: none;">*Passwords do not match!</div>
                    </div>
                </form>
            </section>

            <!-- User Management Dashboard -->
            <section id="manageUsersSection" class="mb-5" style="display: none;">
                <h2>Manage Users</h2>
                <div class="form-row mb-3">
                    <div class="col-md-6">
                        <input type="text" id="searchBar" class="form-control" placeholder="Search by username">
                    </div>
                    <div class="col-md-6">
                        <select id="filterRole" class="form-control">
                            <option value="">Filter by role</option>
                            <option value="admin">Admin</option>
                            <option value="user">User</option>
                        </select>
                    </div>
                </div>
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th scope="col">Username</th>
                            <th scope="col">Account Status</th>
                            <th scope="col">Role</th>
                            <th scope="col">Last Password Change</th>
                            <th scope="col">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="userList">
                    <?php if (!empty($users)): ?>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['status']); ?></td>
                                <td><?php echo htmlspecialchars($user['role']); ?></td>
                                <td><?php echo htmlspecialchars($user['last_password_change']); ?></td>
                                <td>
                                    <?php if ($user['username'] !== 'admin'): ?>
                                        <!-- Action buttons (Edit, Delete) -->
                                        <button class='btn btn-warning btn-sm edit-user-btn'
                                                data-username="<?php echo htmlspecialchars($user['username']); ?>"
                                                data-role="<?php echo htmlspecialchars($user['role']); ?>"
                                                data-status="<?php echo htmlspecialchars($user['status']); ?>"
                                                data-toggle="modal" data-target="#editUserModal">
                                            Edit
                                        </button>
                                        <form method="POST" action="" style="display:inline;">
                                            <input type="hidden" name="action" value="deleteuser">
                                            <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                                            <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Are you sure you want to delete this user: <?php echo htmlspecialchars($user['username']); ?>?');">Delete</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan='5' class='text-center'>No users found</td>
                        </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </section>


            <!-- Edit User Modal -->
            <div class="modal fade" id="editUserModal" tabindex="-1" role="dialog" aria-labelledby="editUserModalLabel" aria-hidden="true">
                <div class="modal-dialog" role="document">
                    <div class="modal-content">
                        <form id="editUserForm" method="POST" action="">
                            <div class="modal-header">
                                <h5 class="modal-title" id="editUserModalLabel">Edit User</h5>
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                    <span aria-hidden="true">&times;</span>
                                </button>
                            </div>
                            <div class="modal-body">
                                <input type="hidden" id="editOriginalUsername" name="originalUsername" value="">
                                <input type="hidden" name="action" value="manageusers">
                                <div class="form-group">
                                    <label for="usernames">Username</label>
                                    <input type="text" class="form-control" id="usernames" name="usernames" readonly>
                                </div>
                                <div class="form-group">
                                    <label for="editRole">Role</label>
                                    <select class="form-control" id="editRole" name="editRole" required>
                                        <option value="admin">Admin</option>
                                        <option value="user">User</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="editStatus">Account Status</label>
                                    <select class="form-control" id="editStatus" name="editStatus" required>
                                        <option value="active">Active</option>
                                        <option value="inactive">Inactive</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="editPassword">Reset Password</label>
                                    <input type="password" class="form-control" id="editPassword" name="editPassword" placeholder="Enter new password">
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                                <button type="submit" class="btn btn-primary">Save changes</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Password Management Section -->
            <section id="passwordManagementSection" class="mb-5" style="display: none;">
                <h2>Password Management</h2>
                <form id="passwordManagementForm" method="POST" action="">
                    <input type="hidden" name="action" value="passwordmanagement">
                    <div class="form-row">
                        <div class="form-group col-md-6">
                            <label for="manageUsername">Username</label>
                            <input type="text" class="form-control" id="manageUsername" name="manageUsername" placeholder="Enter username" required>
                            <br>
                            <label for="managePassword">New Password</label>
                            <input type="password" class="form-control" id="managePassword" name="managePassword" placeholder="Enter new password" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Update Password</button>
                </form>
            </section>

            <!-- Search User Section -->
            <section id="searchFilterSection" class="mb-5" style="display: none;">
            <h2>Search Users</h2>
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th scope="col">Username</th>
                        <th scope="col">Account Status</th>
                        <th scope="col">Role</th>
                        <th scope="col">Last Password Change</th>
                    </tr>
                </thead>
                <tbody id="userList">
                    <?php if (!empty($users)): ?>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['status']); ?></td>
                                <td><?php echo htmlspecialchars($user['role']); ?></td>
                                <td><?php echo htmlspecialchars($user['last_password_change']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan='5' class='text-center'>No users found</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </section>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-white text-center py-3">
        <p>&copy; 2024 Alteres Security. All rights reserved.</p>
    </footer>

    <?php endif; ?>
    <!-- Scripts -->
    <script src="assets/js/jquery.min.js"></script>
    <script src="assets/js/bootstrap.bundle.min.js"></script>
    <script src="assets/js/user_management.js"></script>
    <script>
        document.getElementById('createUserForm').addEventListener('submit', function(event) {
        var password = document.getElementById('password').value;
        var confirmPassword = document.getElementById('confirmPassword').value;
        var passwordError = document.getElementById('passwordError');

        if (password !== confirmPassword) {
            event.preventDefault(); 
            passwordError.style.display = 'block'; // Show the error message
        } else {
            passwordError.style.display = 'none'; // Hide the error message
        }
    });
    </script>
</body>
</html>