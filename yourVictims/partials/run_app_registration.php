<?php

function execInBackground($cmd) {
    $descriptorspec = [
        0 => ["pipe", "r"],  // stdin is a pipe that the child will read from
        1 => ["pipe", "w"],  // stdout is a pipe that the child will write to
        2 => ["pipe", "w"]   // stderr is a pipe that the child will write to
    ];

    $process = proc_open($cmd, $descriptorspec, $pipes);

    if (is_resource($process)) {
        // Close stdin pipe immediately
        fclose($pipes[0]);

        // Capture the stdout and stderr
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);

        // Close the stdout and stderr pipes
        fclose($pipes[1]);
        fclose($pipes[2]);

        // Get the return status
        $returnStatus = proc_close($process);

        // Log the command, output, errors, and return status for debugging
        file_put_contents(
            '../command.log', 
            "Executed Command: " . $cmd . "\nDate: " . date('Y-m-d H:i:s') . "\nOutput:\n " . $output . "\nErrors: " . $errors . "\nReturn Status: $returnStatus\n\n", 
            FILE_APPEND
        );

        return ['output' => $output, 'errors' => $errors, 'status' => $returnStatus];
    }

    return ['output' => '', 'errors' => 'Process failed to start', 'status' => 1];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Capture the input data from the form
    $tenantId = escapeshellarg($_POST['tenantId']);
    $appName = escapeshellarg($_POST['appName']);
    $redirectUri = escapeshellarg($_POST['redirectUri']);
    $authMethod = escapeshellarg($_POST['authMethod']);
    $isDefaultPermissions = isset($_POST['isDefaultPermissions']) ? filter_var($_POST['isDefaultPermissions'], FILTER_VALIDATE_BOOLEAN) : false;
    $lowImpact = isset($_POST['lowImpact']) ? filter_var($_POST['lowImpact'], FILTER_VALIDATE_BOOLEAN) : false;


    // Initialize the base command for the Python script
    $command = "python ../../app_registration.py --tenant-id $tenantId --app-name $appName --redirect-uri $redirectUri --auth-method $authMethod";

    // Add the default or custom permissions to the command
    if ($isDefaultPermissions) {
        $command .= " --default-permissions";
    } else if($lowImpact) {
        $command .= " --low-impact";
    } else if (isset($_POST['customPermissions'])) {
        $customPermissions = $_POST['customPermissions'];
        $command .= " --custom-permissions " . escapeshellarg($customPermissions);
        // file_put_contents('auth.log', "Custom Permissions: " . $command . "\n", FILE_APPEND);
    }

    // Add client ID and client secret if OAuth method is selected
    if ($authMethod === '"oauth"') {
        $clientId = ($_POST['clientId']);
        $clientSecret = ($_POST['clientSecret']);
        $command .= " --client-id $clientId --client-secret $clientSecret";
    } else if ($authMethod === '"ROPC_flow"') {
        $username = escapeshellarg($_POST['userName']);
        $password = ($_POST['userPassword']);
        $command .= " --username $username --password $password";
    }

    // Execute the command and capture the output
    $executionResult = execInBackground($command);


    // If the command finished successfully, return a success response
    if ($executionResult['status'] === 0) {
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'success',
            'output' => $executionResult['output']
        ]);
    } else if ($executionResult['status'] !== 0) {
        // Handle errors in case the script failed
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'error',
            'errors' => $executionResult['errors'],
            'output' => $executionResult['output']
        ]);
    }
}
?>
