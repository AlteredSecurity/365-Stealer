<?php

// Ensure the use of a secure connection
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off") {
    $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirect");
    exit;
 }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel = "icon" href = "assets/img/jwt_icon.png" type = "image/x-icon">
    <title>JWT Decoder</title>
    <link href="assets/css/5.3.3_bootstrap.min.css" rel="stylesheet">
    <style>
        .jwt-popup {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background-color: #fff;
            border: 3px solid #FFD700; /* Golden Yellow border */
            padding: 20px;
            z-index: 1000;
            width: 60%;
            max-width: 700px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .jwt-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 999;
        }

        .jwt-section-title {
            font-size: 1.2rem;
            font-weight: bold;
            color: #333;
            border-bottom: 1px solid #ccc;
            margin-bottom: 10px;
            padding-bottom: 5px;
        }

        .jwt-header-content {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            padding: 10px;
            margin-bottom: 20px;
        }

        .jwt-payload-content {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            padding: 10px;
            margin-bottom: 20px;
        }

        .jwt-header-content pre {
            color: red;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
        }

        .jwt-payload-content pre {
            color: purple;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
        }

        .jwt-popup-title {
            text-align: center;
            margin-bottom: 20px;
            font-size: 1.5rem;
        }

        /* Close button "X" */
        .jwt-close-btn {
            position: absolute;
            top: 10px;
            right: 15px;
            font-size: 1.5rem;
            color: #333;
            background: none;
            border: none;
            cursor: pointer;
        }

        .jwt-close-btn:hover {
            color: #FF0000;
        }
    </style>
    <script>
        function decodeJWT(token) {
            try {
                const parts = token.split('.');
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT: JWT must have 3 parts');
                }

                const decodedParts = parts.slice(0, 2).map(part => {
                    const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
                    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }).join(''));
                    return JSON.parse(jsonPayload);
                });

                return {
                    header: decodedParts[0],
                    payload: decodedParts[1]
                };
            } catch (e) {
                console.error("Failed to decode JWT", e);
                return null;
            }
        }

        function displayPopup(decoded) {
            const popup = document.getElementById('jwt-token');
            const content = `
                <div class="jwt-section-title">HEADER: ALGORITHM & TOKEN TYPE</div>
                <div class="jwt-header-content"><pre>${JSON.stringify(decoded.header, null, 2)}</pre></div>
                
                <div class="jwt-section-title">PAYLOAD: DATA</div>
                <div class="jwt-payload-content"><pre>${JSON.stringify(decoded.payload, null, 2)}</pre></div>
            `;
            document.getElementById('jwt-decodedContent').innerHTML = content;
            document.querySelector('.jwt-overlay').style.display = 'block';
            popup.style.display = 'block';
        }

        function handleFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onload = function(e) {
                const token = e.target.result.trim();
                const decoded = decodeJWT(token);
                if (decoded) {
                    displayPopup(decoded);
                }
            };
            reader.readAsText(file);
        }

        function handlePaste() {
            const pastedToken = document.getElementById('jwt-input').value.trim();
            if (pastedToken) {
                const decoded = decodeJWT(pastedToken);
                if (decoded) {
                    displayPopup(decoded);
                }
            }
        }

        function closePopup() {
            document.getElementById('jwt-token').style.display = 'none';
            document.querySelector('.jwt-overlay').style.display = 'none';
        }
    </script>
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-3">JWT Decoder</h1>

        <div class="mb-3">
            <label for="jwt-input">Paste JWT token here:</label>
            <textarea id="jwt-input" class="form-control" rows="3"></textarea>
        </div>
        <button class="btn btn-primary" onclick="handlePaste()">Decode JWT</button>
        <br><br>
        <div class="mb-3">
            <label for="fileInput">Or upload a JWT file:</label>
            <input type="file" id="fileInput" class="form-control">
        </div>

        <button class="btn btn-primary" onclick="handleFile()">Decode from File</button>
    </div>

    <!-- Overlay -->
    <div class="jwt-overlay"></div>

    <!-- Popup window -->
    <div class="jwt-popup" id="jwt-token">
        <!-- Close button 'X' at top-right -->
        <button class="jwt-close-btn" onclick="closePopup()">×</button>
        <div id="jwt-decodedContent"></div>
        <button class="btn btn-danger" style="width: 100%;" onclick="closePopup()">Close</button>
    </div>
    <script src="assets/js/5.3.3_bootstrap.bundle.main.js"></script>
</body>
</html>
