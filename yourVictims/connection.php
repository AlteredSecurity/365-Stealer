<?php 
    // Turn off all error reporting  Or, to turn off only MySQL errors
    error_reporting(0);
    mysqli_report(MYSQLI_REPORT_OFF);

    $servername = "localhost";
    $username = "root";
    $password = "your_root_password"; //If the password is set for the root user, update the password variable 
    $db_name = "database-1"; //Provide the name of database
    $conn = new mysqli($servername, $username, $password, $db_name);
    if($conn->connect_error){
        die("Connection Failed".$conn->connect_error);
    }
    echo "";
?>