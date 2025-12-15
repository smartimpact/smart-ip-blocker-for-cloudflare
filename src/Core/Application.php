<?php

namespace App\Core;

/**
 * Application Bootstrap Class
 * Handles initialization and dependency management
 */
class Application
{
    private static ?Application $instance = null;
    private array $config;
    private ?Auth $auth = null;
    private ?View $view = null;
    private ?Logger $logger = null;

    private function __construct()
    {
        $this->loadConfig();
        $this->setSecurityHeaders();
        $this->initSession();
        $this->ensureDirectories();
    }

    /**
     * Get singleton instance
     */
    public static function getInstance(): Application
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Set security headers to prevent common attacks
     */
    private function setSecurityHeaders(): void
    {
        // Prevent clickjacking
        header('X-Frame-Options: DENY');

        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');

        // Enable XSS protection (legacy browsers)
        header('X-XSS-Protection: 1; mode=block');

        // Referrer policy - don't leak URLs to external sites
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // Permissions policy - disable unnecessary features
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

        // Content Security Policy - restrict resource loading
        $csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'", // Allow inline scripts for simplicity
            "style-src 'self' 'unsafe-inline'",  // Allow inline styles
            "img-src 'self' data:",
            "font-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "object-src 'none'",
        ];
        header('Content-Security-Policy: ' . implode('; ', $csp));

        // HTTPS enforcement (when on HTTPS)
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }

        // Cache control - prevent sensitive data caching
        header('Cache-Control: no-store, no-cache, must-revalidate, private');
        header('Pragma: no-cache');
        header('Expires: 0');
    }

    /**
     * Load configuration files
     */
    private function loadConfig(): void
    {
        $configPath = dirname(__DIR__, 2) . '/config/app.php';
        if (!file_exists($configPath)) {
            throw new \RuntimeException('Configuration file not found');
        }
        $this->config = require $configPath;

        // Validate required security credentials are set
        $this->validateRequiredConfig();
    }

    /**
     * Validate that required security credentials are configured
     */
    private function validateRequiredConfig(): void
    {
        $required = [
            'auth.username' => 'AUTH_USERNAME',
            'auth.password_hash' => 'AUTH_PASSWORD_HASH',
            'auth.cron_secret' => 'CRON_SECRET',
        ];

        $missing = [];
        foreach ($required as $configKey => $envVar) {
            $value = $this->config($configKey);
            if (empty($value)) {
                $missing[] = $envVar;
            }
        }

        if (!empty($missing)) {
            throw new \RuntimeException(
                'Security configuration missing. Set these environment variables in .env: ' .
                implode(', ', $missing)
            );
        }

        // Validate password hash format (must be bcrypt/argon2)
        $hash = $this->config('auth.password_hash');
        if (!preg_match('/^\$2[ayb]\$|^\$argon2/', $hash)) {
            throw new \RuntimeException(
                'Invalid AUTH_PASSWORD_HASH format. Generate with: php -r "echo password_hash(\'your-password\', PASSWORD_BCRYPT);"'
            );
        }

        // Validate cron secret is strong enough
        $cronSecret = $this->config('auth.cron_secret');
        if (strlen($cronSecret) < 32) {
            throw new \RuntimeException(
                'CRON_SECRET must be at least 32 characters. Generate with: php -r "echo bin2hex(random_bytes(32));"'
            );
        }
    }

    /**
     * Initialize session with secure configuration
     */
    private function initSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            // Secure session configuration
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');
            ini_set('session.cookie_httponly', '1');
            ini_set('session.cookie_samesite', 'Strict');

            // Use secure cookies if HTTPS
            $isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
            ini_set('session.cookie_secure', $isHttps ? '1' : '0');

            // Session lifetime and garbage collection
            ini_set('session.gc_maxlifetime', '3600');
            ini_set('session.cookie_lifetime', '0'); // Session cookie (expires on browser close)

            // Use stronger session ID
            ini_set('session.sid_length', '48');
            ini_set('session.sid_bits_per_character', '6');

            session_start();
        }
    }

    /**
     * Ensure required directories exist
     */
    private function ensureDirectories(): void
    {
        $dirs = [
            $this->config['paths']['data'],
            $this->config['paths']['cache'],
            $this->config['paths']['logs'],
        ];

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }

    /**
     * Get configuration value
     */
    public function config(string $key, $default = null)
    {
        $keys = explode('.', $key);
        $value = $this->config;

        foreach ($keys as $k) {
            if (!isset($value[$k])) {
                return $default;
            }
            $value = $value[$k];
        }

        return $value;
    }

    /**
     * Get Auth instance
     */
    public function auth(): Auth
    {
        if ($this->auth === null) {
            $this->auth = new Auth($this);
        }
        return $this->auth;
    }

    /**
     * Get View instance
     */
    public function view(): View
    {
        if ($this->view === null) {
            $this->view = new View($this);
        }
        return $this->view;
    }

    /**
     * Get Logger instance
     */
    public function logger(): Logger
    {
        if ($this->logger === null) {
            $this->logger = new Logger($this);
        }
        return $this->logger;
    }

    /**
     * Get application name
     */
    public function name(): string
    {
        return $this->config('app.name', 'Security Log Analyzer');
    }

    /**
     * Get application version
     */
    public function version(): string
    {
        return $this->config('app.version', '2.0.0');
    }

    /**
     * Check if debug mode is enabled
     */
    public function isDebug(): bool
    {
        return (bool) $this->config('app.debug', false);
    }

    /**
     * Get base URL
     */
    public function baseUrl(): string
    {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return "{$protocol}://{$host}";
    }
}
