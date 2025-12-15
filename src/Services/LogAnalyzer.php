<?php

namespace App\Services;

use App\Core\Application;

/**
 * Log Analyzer Service
 * Analyzes server access logs for suspicious activity
 */
class LogAnalyzer
{
    private Application $app;
    private BlocklistManager $blocklist;
    private string $bansLogPath;
    private string $pattern = '/^(\S+) /';

    // Allowed directories for log file access (configurable)
    private array $allowedPaths = [];

    // Allowed file extensions
    private array $allowedExtensions = ['log', 'txt', 'access', 'error'];

    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->blocklist = new BlocklistManager($app);
        $this->bansLogPath = $app->config('paths.logs') . '/bans.log';

        // Configure allowed paths from config or use defaults
        $this->allowedPaths = $app->config('security.allowed_log_paths', [
            '/var/log',
            '/var/www',
            '/home',
        ]);
    }

    /**
     * Analyze a log file (with path traversal protection)
     */
    public function analyze(string $logFilePath): array
    {
        $result = [
            'success' => false,
            'lines_analyzed' => 0,
            'suspicious_count' => 0,
            'suspicious_ips' => [],
            'errors' => []
        ];

        // SECURITY: Validate and sanitize file path
        $validationResult = $this->validateLogFilePath($logFilePath);
        if ($validationResult !== true) {
            $result['errors'][] = $validationResult;
            $this->app->logger()->log('SECURITY_BLOCKED', "Path traversal attempt: {$logFilePath}");
            return $result;
        }

        if (!is_readable($logFilePath)) {
            $result['errors'][] = "Cannot read log file";
            return $result;
        }

        try {
            $logData = $this->parseLogFile($logFilePath);
            $result['lines_analyzed'] = count($logData);

            $suspiciousIPs = $this->blocklist->getSuspiciousIPs();
            $detectedIPs = [];

            foreach ($logData as $entry) {
                $ip = $entry['clientIP'] ?? null;
                if ($ip && isset($suspiciousIPs[$ip])) {
                    $detectedIPs[$ip] = [
                        'ip' => $ip,
                        'source' => $suspiciousIPs[$ip]
                    ];
                }
            }

            $result['success'] = true;
            $result['suspicious_count'] = count($detectedIPs);
            $result['suspicious_ips'] = $detectedIPs;

            // Write to bans log
            $this->writeToBansLog($detectedIPs);

            $this->app->logger()->log(
                'ANALYSIS_COMPLETE',
                "File: {$logFilePath}, Lines: {$result['lines_analyzed']}, IPs: {$result['suspicious_count']}"
            );

        } catch (\Exception $e) {
            $result['errors'][] = $e->getMessage();
            $this->app->logger()->log('ANALYSIS_ERROR', $e->getMessage());
        }

        return $result;
    }

    /**
     * Parse log file
     */
    private function parseLogFile(string $path): array
    {
        $data = [];
        $lines = file($path, FILE_SKIP_EMPTY_LINES);

        if (!is_array($lines)) {
            return $data;
        }

        foreach ($lines as $line) {
            $matches = [];
            if (preg_match($this->pattern, $line, $matches)) {
                $data[] = ['clientIP' => $matches[1]];
            }
        }

        return $data;
    }

    /**
     * Write detected IPs to bans log
     */
    private function writeToBansLog(array $detectedIPs): void
    {
        // Read existing IPs
        $existingIPs = [];
        if (file_exists($this->bansLogPath)) {
            $content = file_get_contents($this->bansLogPath);
            preg_match_all('/deny ([\w.:]+);/i', $content, $matches);
            $existingIPs = $matches[1] ?? [];
        }

        // Append new IPs
        $handle = fopen($this->bansLogPath, 'a');
        foreach ($detectedIPs as $data) {
            $ip = $data['ip'];
            if (!in_array($ip, $existingIPs)) {
                fwrite($handle, "deny {$ip};" . PHP_EOL);
                $existingIPs[] = $ip;
            }
        }
        fclose($handle);
    }

    /**
     * Get recent banned IPs
     */
    public function getRecentBans(int $limit = 20): array
    {
        if (!file_exists($this->bansLogPath)) {
            return [];
        }

        $content = file_get_contents($this->bansLogPath);
        preg_match_all('/deny ([^\s;]+);/', $content, $matches);
        
        $ips = array_unique($matches[1] ?? []);
        return array_slice(array_reverse($ips), 0, $limit);
    }

    /**
     * Get total banned IPs count
     */
    public function getTotalBansCount(): int
    {
        if (!file_exists($this->bansLogPath)) {
            return 0;
        }

        $content = file_get_contents($this->bansLogPath);
        preg_match_all('/deny ([^\s;]+);/', $content, $matches);
        
        return count(array_unique($matches[1] ?? []));
    }

    /**
     * Set custom log pattern
     */
    public function setPattern(string $pattern): self
    {
        $this->pattern = $pattern;
        return $this;
    }

    /**
     * Get blocklist manager
     */
    public function blocklist(): BlocklistManager
    {
        return $this->blocklist;
    }

    /**
     * Validate log file path to prevent path traversal attacks
     * Returns true if valid, or error message string if invalid
     */
    private function validateLogFilePath(string $path): bool|string
    {
        // Remove null bytes (poison null byte attack)
        if (strpos($path, "\0") !== false) {
            return "Invalid file path";
        }

        // Block UNC paths on Windows (\\server\share)
        if (preg_match('/^\\\\\\\\|^\/\//', $path)) {
            return "UNC paths not allowed";
        }

        // Check for path traversal sequences (both Unix and Windows)
        // Matches: ../ ..\ ..\\ /../ \..\ etc
        if (preg_match('/\.\.[\\/\\\\]|[\\/\\\\]\.\./', $path)) {
            return "Path traversal not allowed";
        }

        // Block encoded traversal attempts
        if (preg_match('/%2e%2e|%252e|%c0%ae|%c1%9c/i', $path)) {
            return "Encoded path traversal not allowed";
        }

        // Block Windows drive letters outside allowed paths
        if (preg_match('/^[a-zA-Z]:/', $path)) {
            // Windows absolute path - will be validated against allowed paths below
        }

        // Resolve to real path (handles symlinks and ..)
        $realPath = realpath($path);
        if ($realPath === false) {
            // File doesn't exist - check the directory
            $dir = dirname($path);
            $realDir = realpath($dir);
            if ($realDir === false) {
                return "Log file directory does not exist";
            }
            // Sanitize basename to prevent injection
            $basename = basename($path);
            if (preg_match('/[<>:"|?*]/', $basename)) {
                return "Invalid characters in filename";
            }
            $realPath = $realDir . DIRECTORY_SEPARATOR . $basename;
        }

        // Normalize path separators for comparison
        $normalizedPath = str_replace('\\', '/', strtolower($realPath));

        // Check against allowed paths
        $isAllowed = false;
        foreach ($this->allowedPaths as $allowedPath) {
            $normalizedAllowed = str_replace('\\', '/', strtolower($allowedPath));
            // Ensure we match directory boundaries (not just prefix)
            if (strpos($normalizedPath, $normalizedAllowed) === 0) {
                // Verify it's a proper directory boundary
                $nextChar = substr($normalizedPath, strlen($normalizedAllowed), 1);
                if ($nextChar === '' || $nextChar === '/') {
                    $isAllowed = true;
                    break;
                }
            }
        }

        if (!$isAllowed) {
            return "Access to this path is not allowed";
        }

        // Check file extension
        $extension = strtolower(pathinfo($realPath, PATHINFO_EXTENSION));
        if (!empty($extension) && !in_array($extension, $this->allowedExtensions, true)) {
            return "Invalid file type";
        }

        // Block sensitive files
        $sensitivePatterns = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '.htaccess',
            '.htpasswd',
            'wp-config.php',
            'config.php',
            '.env',
            'web.config',
            'database.yml',
            'credentials',
            'secrets',
        ];

        $basename = strtolower(basename($realPath));
        foreach ($sensitivePatterns as $pattern) {
            $pattern = strtolower($pattern);
            if (strpos($normalizedPath, $pattern) !== false || $basename === $pattern) {
                return "Access to this file is restricted";
            }
        }

        // Final check: ensure file is actually a regular file (not symlink to sensitive location)
        if (file_exists($realPath) && is_link($realPath)) {
            $linkTarget = readlink($realPath);
            if ($linkTarget !== false) {
                // Recursively validate the symlink target
                return $this->validateLogFilePath($linkTarget);
            }
        }

        return true;
    }

    /**
     * Add an allowed path for log file access
     */
    public function addAllowedPath(string $path): self
    {
        $this->allowedPaths[] = $path;
        return $this;
    }
}
