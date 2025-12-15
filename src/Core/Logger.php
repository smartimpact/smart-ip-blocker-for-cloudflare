<?php

namespace App\Core;

/**
 * Activity Logger
 * Handles application activity logging
 */
class Logger
{
    private Application $app;
    private string $logFile;

    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->logFile = $app->config('paths.logs') . '/activity.log';
    }

    /**
     * Log an activity (with injection protection)
     */
    public function log(string $action, string $details = ''): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'CLI';

        // Sanitize inputs to prevent log injection
        $action = $this->sanitizeLogInput($action);
        $details = $this->sanitizeLogInput($details);
        $ip = $this->sanitizeLogInput($ip);

        $logEntry = "[{$timestamp}] [{$ip}] {$action}: {$details}" . PHP_EOL;

        file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Sanitize input for log files to prevent log injection attacks
     */
    private function sanitizeLogInput(string $input): string
    {
        // Remove or encode control characters that could break log parsing
        // Remove newlines, carriage returns, and other control chars
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/', '', $input);

        // Limit length to prevent log flooding
        $sanitized = substr($sanitized, 0, 1024);

        // Escape special characters that could be used for log injection
        $sanitized = str_replace(['[', ']'], ['(', ')'], $sanitized);

        return $sanitized;
    }

    /**
     * Get recent log entries
     */
    public function getRecent(int $lines = 50): array
    {
        if (!file_exists($this->logFile)) {
            return [];
        }

        $content = file_get_contents($this->logFile);
        $allLines = explode(PHP_EOL, trim($content));
        
        return array_slice(array_reverse($allLines), 0, $lines);
    }

    /**
     * Clear log file
     */
    public function clear(): bool
    {
        return file_put_contents($this->logFile, '') !== false;
    }
}
