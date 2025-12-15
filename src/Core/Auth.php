<?php

namespace App\Core;

/**
 * Authentication Handler
 * Manages user authentication, sessions, CSRF protection, and brute force prevention
 */
class Auth
{
    private Application $app;

    // Brute force protection settings
    private int $maxLoginAttempts = 5;
    private int $lockoutDuration = 900; // 15 minutes

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * Check if user is authenticated
     */
    public function check(): bool
    {
        if (!isset($_SESSION['authenticated']) || !isset($_SESSION['login_time'])) {
            return false;
        }

        $timeout = $this->app->config('auth.session_timeout', 3600);
        if (time() - $_SESSION['login_time'] > $timeout) {
            $this->logout();
            return false;
        }

        return $_SESSION['authenticated'] === true;
    }

    /**
     * Check if IP is currently locked out (with atomic file locking)
     */
    private function isLockedOut(): bool
    {
        $ip = $this->getClientIP();
        $lockFile = $this->app->config('paths.data') . '/lockouts.json';

        $lockouts = $this->readLockoutsAtomic($lockFile);
        if ($lockouts === null) {
            return false;
        }

        if (isset($lockouts[$ip])) {
            if ($lockouts[$ip]['locked_until'] > time()) {
                return true;
            }
            // Lockout expired, clear it atomically
            unset($lockouts[$ip]);
            $this->writeLockoutsAtomic($lockFile, $lockouts);
        }

        return false;
    }

    /**
     * Record a failed login attempt (with atomic file locking)
     */
    private function recordFailedAttempt(): void
    {
        $ip = $this->getClientIP();
        $lockFile = $this->app->config('paths.data') . '/lockouts.json';

        // Use atomic read-modify-write operation
        $this->modifyLockoutsAtomic($lockFile, function ($lockouts) use ($ip) {
            if (!isset($lockouts[$ip])) {
                $lockouts[$ip] = ['attempts' => 0, 'first_attempt' => time(), 'locked_until' => 0];
            }

            // Reset if first attempt was too long ago
            if (time() - $lockouts[$ip]['first_attempt'] > $this->lockoutDuration) {
                $lockouts[$ip] = ['attempts' => 0, 'first_attempt' => time(), 'locked_until' => 0];
            }

            $lockouts[$ip]['attempts']++;

            if ($lockouts[$ip]['attempts'] >= $this->maxLoginAttempts) {
                $lockouts[$ip]['locked_until'] = time() + $this->lockoutDuration;
                $this->app->logger()->log('ACCOUNT_LOCKED', "IP: {$ip} locked for {$this->lockoutDuration}s");
            }

            return $lockouts;
        });
    }

    /**
     * Clear failed attempts on successful login (with atomic file locking)
     */
    private function clearFailedAttempts(): void
    {
        $ip = $this->getClientIP();
        $lockFile = $this->app->config('paths.data') . '/lockouts.json';

        $this->modifyLockoutsAtomic($lockFile, function ($lockouts) use ($ip) {
            unset($lockouts[$ip]);
            return $lockouts;
        });
    }

    /**
     * Read lockouts file with shared lock
     */
    private function readLockoutsAtomic(string $lockFile): ?array
    {
        if (!file_exists($lockFile)) {
            return null;
        }

        $handle = @fopen($lockFile, 'r');
        if ($handle === false) {
            return null;
        }

        // Acquire shared lock for reading
        if (!flock($handle, LOCK_SH)) {
            fclose($handle);
            return null;
        }

        $content = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return json_decode($content, true) ?: [];
    }

    /**
     * Write lockouts file with exclusive lock
     */
    private function writeLockoutsAtomic(string $lockFile, array $lockouts): bool
    {
        $handle = @fopen($lockFile, 'c');
        if ($handle === false) {
            return false;
        }

        // Acquire exclusive lock for writing
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            return false;
        }

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($lockouts, JSON_PRETTY_PRINT));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return true;
    }

    /**
     * Atomic read-modify-write for lockouts file
     */
    private function modifyLockoutsAtomic(string $lockFile, callable $modifier): bool
    {
        // Create file if it doesn't exist
        if (!file_exists($lockFile)) {
            file_put_contents($lockFile, '{}');
        }

        $handle = @fopen($lockFile, 'c+');
        if ($handle === false) {
            return false;
        }

        // Acquire exclusive lock for entire operation
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            return false;
        }

        // Read current content
        $content = stream_get_contents($handle);
        $lockouts = json_decode($content, true) ?: [];

        // Apply modification
        $lockouts = $modifier($lockouts);

        // Write back
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($lockouts, JSON_PRETTY_PRINT));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return true;
    }

    /**
     * Get remaining lockout time in seconds
     */
    public function getLockoutRemaining(): int
    {
        $ip = $this->getClientIP();
        $lockFile = $this->app->config('paths.data') . '/lockouts.json';

        if (!file_exists($lockFile)) {
            return 0;
        }

        $lockouts = json_decode(file_get_contents($lockFile), true) ?: [];

        if (isset($lockouts[$ip]) && $lockouts[$ip]['locked_until'] > time()) {
            return $lockouts[$ip]['locked_until'] - time();
        }

        return 0;
    }

    /**
     * Attempt to login with credentials (with brute force protection)
     */
    public function attempt(string $username, string $password): bool|string
    {
        // Check for lockout
        if ($this->isLockedOut()) {
            $remaining = $this->getLockoutRemaining();
            $this->app->logger()->log('LOGIN_BLOCKED', "IP locked, {$remaining}s remaining");
            return "Too many failed attempts. Try again in " . ceil($remaining / 60) . " minutes.";
        }

        $validUsername = $this->app->config('auth.username');
        $validPasswordHash = $this->app->config('auth.password_hash');

        // Timing-safe comparison for username
        $usernameMatch = hash_equals($validUsername, $username);
        $passwordMatch = password_verify($password, $validPasswordHash);

        if ($usernameMatch && $passwordMatch) {
            // Regenerate session ID to prevent session fixation
            session_regenerate_id(true);

            $_SESSION['authenticated'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['username'] = $username;
            $_SESSION['ip'] = $this->getClientIP();
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

            $this->clearFailedAttempts();
            $this->app->logger()->log('LOGIN_SUCCESS', "User: {$username}");
            return true;
        }

        $this->recordFailedAttempt();
        $this->app->logger()->log('LOGIN_FAILED', "Attempted username: {$username}");
        return false;
    }

    /**
     * Verify cron secret key (timing-safe)
     */
    public function verifyCronKey(string $key): bool
    {
        $secret = $this->app->config('auth.cron_secret');
        return hash_equals($secret, $key);
    }

    /**
     * Logout current user
     */
    public function logout(): void
    {
        $username = $_SESSION['username'] ?? 'unknown';
        $this->app->logger()->log('LOGOUT', "User: {$username}");

        // Clear session data
        $_SESSION = [];

        // Delete session cookie
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }

        session_destroy();
    }

    /**
     * Get current username
     */
    public function username(): string
    {
        return $_SESSION['username'] ?? 'Guest';
    }

    /**
     * Require authentication or redirect
     */
    public function requireAuth(): void
    {
        if (!$this->check()) {
            header('Location: login.php');
            exit;
        }

        // Verify session hasn't been hijacked (IP check)
        if (isset($_SESSION['ip']) && $_SESSION['ip'] !== $this->getClientIP()) {
            $this->app->logger()->log('SESSION_HIJACK_ATTEMPT', "IP mismatch");
            $this->logout();
            header('Location: login.php?error=session_invalid');
            exit;
        }
    }

    /**
     * Generate CSRF token
     */
    public function generateCsrfToken(): string
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    /**
     * Verify CSRF token
     */
    public function verifyCsrfToken(?string $token): bool
    {
        if (empty($token) || empty($_SESSION['csrf_token'])) {
            return false;
        }
        return hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Get CSRF token input field HTML
     */
    public function csrfField(): string
    {
        $token = $this->generateCsrfToken();
        return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
    }

    /**
     * Require valid CSRF token or abort
     */
    public function requireCsrf(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
            if (!$this->verifyCsrfToken($token)) {
                $this->app->logger()->log('CSRF_BLOCKED', "Invalid or missing CSRF token");
                http_response_code(403);
                die('Invalid request. Please refresh the page and try again.');
            }
        }
    }

    /**
     * Get client IP address
     */
    private function getClientIP(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
