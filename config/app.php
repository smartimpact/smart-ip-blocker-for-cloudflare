<?php
/**
 * Application Configuration
 * Smart IP Blocker for Cloudflare v2.0
 * 
 * Credentials are loaded from .env file
 * Copy .env.example to .env and configure your values
 */

// Load .env file if it exists
$envFile = dirname(__DIR__) . '/.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue; // Skip comments
        if (strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);
        if (!getenv($key)) {
            putenv("$key=$value");
        }
    }
}

// Helper function to get env with default
function env($key, $default = null) {
    $value = getenv($key);
    return $value !== false ? $value : $default;
}

return [
    // Application
    'app' => [
        'name' => 'Smart IP Blocker for Cloudflare',
        'version' => '2.0.0',
        'debug' => env('APP_DEBUG', false),
    ],
    
    // Authentication
    // IMPORTANT: Store the pre-computed password hash in .env, NOT the plaintext password
    // Generate hash with: php -r "echo password_hash('your-password', PASSWORD_BCRYPT);"
    'auth' => [
        'username' => env('AUTH_USERNAME'),
        'password_hash' => env('AUTH_PASSWORD_HASH'),
        'session_timeout' => (int) env('SESSION_TIMEOUT', 3600), // 1 hour
        'cron_secret' => env('CRON_SECRET'),
    ],
    
    // Cloudflare
    'cloudflare' => [
        'api_token' => env('CLOUDFLARE_API_TOKEN', ''),
        'account_id' => env('CLOUDFLARE_ACCOUNT_ID', ''),
        'list_id' => env('CLOUDFLARE_LIST_ID', ''),
    ],
    
    // Paths
    'paths' => [
        'root' => dirname(__DIR__),
        'data' => dirname(__DIR__) . '/data',
        'cache' => dirname(__DIR__) . '/data/cache',
        'logs' => dirname(__DIR__) . '/data/logs',
        'templates' => dirname(__DIR__) . '/templates',
        'default_log' => env('DEFAULT_LOG_PATH', '/var/log/nginx/access.log'),
    ],
    
    // Cache
    'cache' => [
        'expiry' => 86400, // 24 hours
    ],
];
