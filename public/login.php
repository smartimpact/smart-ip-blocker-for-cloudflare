<?php
/**
 * Login Controller
 * Security Log Analyzer v2.0
 */

require_once __DIR__ . '/../vendor/autoload.php';

use App\Core\Application;

// Bootstrap application
$app = Application::getInstance();

$error = '';
$success = '';

// Handle logout
if (isset($_GET['logout'])) {
    $app->auth()->logout();
    header('Location: login.php?logged_out=1');
    exit;
}

// Already logged in
if ($app->auth()->check()) {
    header('Location: index.php');
    exit;
}

// Handle session errors
if (isset($_GET['error']) && $_GET['error'] === 'session_invalid') {
    $error = 'Your session has expired or is invalid. Please login again.';
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!$app->auth()->verifyCsrfToken($csrfToken)) {
        $error = 'Invalid request. Please refresh the page and try again.';
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $error = 'Please enter both username and password.';
        } else {
            $result = $app->auth()->attempt($username, $password);

            if ($result === true) {
                header('Location: index.php');
                exit;
            } elseif (is_string($result)) {
                // Lockout message
                $error = htmlspecialchars($result, ENT_QUOTES, 'UTF-8');
            } else {
                $error = 'Invalid username or password.';
            }
        }
    }
}

if (isset($_GET['logged_out'])) {
    $success = 'You have been successfully logged out.';
}

// Render view
$app->view()->display('login', [
    'error' => $error,
    'success' => $success,
]);
