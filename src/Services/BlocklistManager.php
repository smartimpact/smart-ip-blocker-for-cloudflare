<?php

namespace App\Services;

use App\Core\Application;

/**
 * Blocklist Manager
 * Handles threat intelligence blocklist management with secure HTTP fetching
 */
class BlocklistManager
{
    private Application $app;
    private string $cacheDir;
    private int $cacheExpiry;
    private array $sources;

    // Network security settings
    private int $connectTimeout = 10;
    private int $timeout = 30;
    private int $maxRedirects = 3;
    private int $maxFileSize = 10485760; // 10MB max
    private string $userAgent = 'SecurityLogAnalyzer/2.0 (Threat Intelligence Fetcher)';

    // Parsing security limits
    private int $maxLinesPerFile = 500000;
    private int $maxLineLength = 1024;
    private int $maxIPsPerFile = 100000;

    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->cacheDir = $app->config('paths.cache');
        $this->cacheExpiry = $app->config('cache.expiry', 86400);
        $this->sources = require dirname(__DIR__, 2) . '/config/blocklists.php';
    }

    /**
     * Get all suspicious IPs from blocklists
     */
    public function getSuspiciousIPs(): array
    {
        $this->fetchAndCacheLists();
        
        $suspiciousIPs = [];
        
        foreach ($this->sources as $index => $url) {
            $cacheFile = $this->getCacheFilePath($index);
            
            if (file_exists($cacheFile)) {
                $ips = file($cacheFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if ($this->isValidIP($ip) && !$this->isWhitelisted($ip)) {
                        $suspiciousIPs[$ip] = $url;
                    }
                }
            }
        }
        
        return $suspiciousIPs;
    }

    /**
     * Fetch and cache all blocklists
     */
    private function fetchAndCacheLists(): void
    {
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }

        foreach ($this->sources as $index => $url) {
            $cacheFile = $this->getCacheFilePath($index);
            
            // Skip if cache is still valid
            if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $this->cacheExpiry) {
                continue;
            }

            $this->fetchList($url, $cacheFile);
        }
    }

    /**
     * Fetch a single blocklist with secure cURL settings
     */
    private function fetchList(string $url, string $cacheFile): void
    {
        // Validate URL before fetching
        if (!$this->isValidUrl($url)) {
            $this->app->logger()->log('BLOCKLIST_FETCH_ERROR', "Invalid URL rejected: {$url}");
            return;
        }

        $ch = curl_init();

        curl_setopt_array($ch, [
            // URL and transfer settings
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,

            // Timeouts - prevent hanging connections
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,

            // SSL/TLS Security - VERIFY certificates
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2, // Minimum TLS 1.2

            // Redirect handling - limit redirects to prevent loops
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => $this->maxRedirects,
            CURLOPT_AUTOREFERER => true,

            // Size limits - prevent memory exhaustion
            CURLOPT_MAXFILESIZE => $this->maxFileSize,

            // Protocol restrictions - only allow HTTP/HTTPS
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,

            // Headers
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => [
                'Accept: text/plain, text/csv, application/json',
                'Accept-Encoding: gzip, deflate',
                'Connection: close',
            ],
            CURLOPT_ENCODING => '', // Accept all encodings, auto-decompress

            // Security - disable potentially dangerous features
            CURLOPT_FILETIME => false,
            CURLOPT_NOBODY => false,

            // DNS settings
            CURLOPT_DNS_CACHE_TIMEOUT => 120,
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4, // IPv4 only for consistency

            // Fail on HTTP errors
            CURLOPT_FAILONERROR => true,
        ]);

        $content = curl_exec($ch);
        $error = curl_error($ch);
        $errno = curl_errno($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        // Log fetch attempt
        $status = $info['http_code'] ?? 0;
        $downloadSize = $info['size_download'] ?? 0;
        $totalTime = round($info['total_time'] ?? 0, 2);

        if ($content === false || $errno !== 0) {
            $this->app->logger()->log(
                'BLOCKLIST_FETCH_ERROR',
                "URL: {$url} | Error: {$error} (code: {$errno})"
            );
            return;
        }

        if ($status !== 200) {
            $this->app->logger()->log(
                'BLOCKLIST_FETCH_ERROR',
                "URL: {$url} | HTTP Status: {$status}"
            );
            return;
        }

        // Validate content before processing
        if (empty($content)) {
            $this->app->logger()->log('BLOCKLIST_FETCH_ERROR', "Empty response from: {$url}");
            return;
        }

        // Extract and save IPs
        $ips = $this->extractIPs($content);
        $ipCount = count($ips);

        if ($ipCount > 0) {
            file_put_contents($cacheFile, implode(PHP_EOL, $ips), LOCK_EX);
            $this->app->logger()->log(
                'BLOCKLIST_FETCH_SUCCESS',
                "URL: {$url} | IPs: {$ipCount} | Size: {$downloadSize}B | Time: {$totalTime}s"
            );
        }
    }

    /**
     * Validate URL before fetching
     */
    private function isValidUrl(string $url): bool
    {
        // Must be valid URL format
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $parsed = parse_url($url);

        // Must use HTTP or HTTPS
        $scheme = strtolower($parsed['scheme'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false;
        }

        // Must have a host
        if (empty($parsed['host'])) {
            return false;
        }

        // Block localhost and private IPs
        $host = $parsed['host'];
        if ($this->isPrivateHost($host)) {
            return false;
        }

        return true;
    }

    /**
     * Check if host is private/internal (comprehensive SSRF protection)
     */
    private function isPrivateHost(string $host): bool
    {
        $host = strtolower(trim($host));

        // Block localhost variations and special hostnames
        $blockedHosts = [
            'localhost',
            'localhost.localdomain',
            '127.0.0.1',
            '::1',
            '0.0.0.0',
            '0',
            '[::1]',
            '[::ffff:127.0.0.1]',
        ];

        if (in_array($host, $blockedHosts, true)) {
            return true;
        }

        // Block .local and .internal domains
        if (preg_match('/\.(local|internal|localhost|localdomain|home|lan|corp)$/i', $host)) {
            return true;
        }

        // Block IP-like hostnames with leading zeros (octal bypass)
        if (preg_match('/^[0-9]+(\.[0-9]+)*$/', $host)) {
            // Direct IP address - validate it
            $ip = $host;
        } else {
            // Resolve hostname - use gethostbynamel for all IPs
            $ips = @gethostbynamel($host);
            if ($ips === false || empty($ips)) {
                // DNS resolution failed - BLOCK for safety (not allow)
                return true;
            }
            // Check ALL resolved IPs (DNS may return multiple)
            foreach ($ips as $ip) {
                if ($this->isPrivateIP($ip)) {
                    return true;
                }
            }
            return false;
        }

        return $this->isPrivateIP($ip);
    }

    /**
     * Check if an IP address is private/reserved
     */
    private function isPrivateIP(string $ip): bool
    {
        // Validate IP format first
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return true; // Invalid = block
        }

        // Check for IPv4 private/reserved ranges
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Use filter_var for standard private/reserved check
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return true;
            }

            // Additional checks for edge cases filter_var misses
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                $first = (int)$parts[0];
                // Block 0.x.x.x (current network)
                if ($first === 0) return true;
                // Block 100.64-127.x.x (Carrier-grade NAT)
                if ($first === 100 && (int)$parts[1] >= 64 && (int)$parts[1] <= 127) return true;
            }

            return false;
        }

        // Check for IPv6 private/reserved ranges
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Block loopback ::1
            if ($ip === '::1') return true;

            // Block link-local fe80::/10
            if (stripos($ip, 'fe80:') === 0 || stripos($ip, 'fe8') === 0 ||
                stripos($ip, 'fe9') === 0 || stripos($ip, 'fea') === 0 || stripos($ip, 'feb') === 0) {
                return true;
            }

            // Block unique local fc00::/7 (fd00::/8 and fc00::/8)
            if (stripos($ip, 'fc') === 0 || stripos($ip, 'fd') === 0) {
                return true;
            }

            // Block IPv4-mapped IPv6 ::ffff:x.x.x.x
            if (stripos($ip, '::ffff:') === 0) {
                $ipv4Part = substr($ip, 7);
                return $this->isPrivateIP($ipv4Part);
            }

            return false;
        }

        return true; // Unknown format = block
    }

    /**
     * Extract IPs from content with secure parsing
     */
    private function extractIPs(string $content): array
    {
        $ips = [];
        $lineCount = 0;
        $invalidCount = 0;

        // Sanitize content - remove null bytes and control characters (except newlines/tabs)
        $content = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $content);

        // Check for binary/non-text content
        if ($this->isBinaryContent($content)) {
            return [];
        }

        // Split by any line ending (CRLF, LF, CR)
        $lines = preg_split('/\R/', $content, $this->maxLinesPerFile + 1);

        // Check if file exceeds max lines
        if (count($lines) > $this->maxLinesPerFile) {
            $lines = array_slice($lines, 0, $this->maxLinesPerFile);
        }

        foreach ($lines as $line) {
            $lineCount++;

            // Skip overly long lines (possible attack/malformed data)
            if (strlen($line) > $this->maxLineLength) {
                $invalidCount++;
                continue;
            }

            // Sanitize and extract IP from line
            $ip = $this->sanitizeAndExtractIP($line);

            if ($ip === null) {
                continue;
            }

            // Handle CIDR notation
            if (strpos($ip, '/') !== false) {
                $expanded = $this->expandCIDRSecure($ip);
                foreach ($expanded as $expandedIp) {
                    if (count($ips) >= $this->maxIPsPerFile) {
                        break 2;
                    }
                    $ips[$expandedIp] = true; // Use as key for deduplication
                }
            } else {
                if (count($ips) >= $this->maxIPsPerFile) {
                    break;
                }
                $ips[$ip] = true;
            }
        }

        return array_keys($ips);
    }

    /**
     * Check if content appears to be binary (not a text blocklist)
     */
    private function isBinaryContent(string $content): bool
    {
        // Check first 8KB for binary signatures
        $sample = substr($content, 0, 8192);

        // Check for common binary file signatures
        $binarySignatures = [
            "\x89PNG",      // PNG
            "\xFF\xD8\xFF", // JPEG
            "GIF8",         // GIF
            "PK\x03\x04",   // ZIP
            "\x1F\x8B",     // GZIP
            "%PDF",         // PDF
            "\x7FELF",      // ELF
            "MZ",           // EXE
        ];

        foreach ($binarySignatures as $sig) {
            if (strpos($sample, $sig) === 0) {
                return true;
            }
        }

        // Check ratio of printable vs non-printable characters
        $printable = preg_match_all('/[\x20-\x7E\x09\x0A\x0D]/', $sample);
        $total = strlen($sample);

        if ($total > 0 && ($printable / $total) < 0.85) {
            return true;
        }

        return false;
    }

    /**
     * Sanitize a line and extract IP address
     */
    private function sanitizeAndExtractIP(string $line): ?string
    {
        // Trim whitespace
        $line = trim($line);

        // Skip empty lines
        if ($line === '') {
            return null;
        }

        // Skip comment lines (various formats)
        if (preg_match('/^[#;\/\/]/', $line)) {
            return null;
        }

        // Remove inline comments
        $line = preg_replace('/\s*[#;].*$/', '', $line);
        $line = trim($line);

        if ($line === '') {
            return null;
        }

        // Handle CSV/TSV formats - extract first column
        if (preg_match('/[,\t;|]/', $line)) {
            // Use regex to safely extract first field (handles quotes)
            if (preg_match('/^"?([^",\t;|]+)"?/', $line, $matches)) {
                $line = trim($matches[1]);
            } else {
                return null;
            }
        }

        // Handle "ip - description" format
        if (preg_match('/^(\S+)\s+-\s+/', $line, $matches)) {
            $line = $matches[1];
        }

        // Handle JSON-like format {"ip": "1.2.3.4"}
        if (strpos($line, '{') !== false) {
            if (preg_match('/"ip"\s*:\s*"([^"]+)"/', $line, $matches)) {
                $line = $matches[1];
            } else {
                return null;
            }
        }

        // Final sanitization - only allow IP-valid characters
        $line = preg_replace('/[^0-9a-fA-F.:\/]/', '', $line);

        // Validate as IP or CIDR
        if (strpos($line, '/') !== false) {
            return $this->isValidCIDR($line) ? $line : null;
        }

        return $this->isValidIP($line) ? $line : null;
    }

    /**
     * Validate CIDR notation
     */
    private function isValidCIDR(string $cidr): bool
    {
        $parts = explode('/', $cidr);

        if (count($parts) !== 2) {
            return false;
        }

        [$ip, $bits] = $parts;

        // Validate IP part
        if (!$this->isValidIP($ip)) {
            return false;
        }

        // Validate prefix length
        if (!ctype_digit($bits)) {
            return false;
        }

        $bits = (int)$bits;

        // IPv4: 0-32, IPv6: 0-128
        $maxBits = (strpos($ip, ':') !== false) ? 128 : 32;

        return $bits >= 0 && $bits <= $maxBits;
    }

    /**
     * Expand CIDR notation to individual IPs (with security limits)
     */
    private function expandCIDRSecure(string $cidr): array
    {
        if (!$this->isValidCIDR($cidr)) {
            return [];
        }

        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int)$bits;

        // IPv6 - don't expand, just return as-is
        if (strpos($subnet, ':') !== false) {
            return [$cidr];
        }

        // Only expand small ranges (max /24 = 256 IPs)
        // Larger ranges are kept as CIDR notation
        if ($bits < 24) {
            return [$cidr];
        }

        $ipLong = ip2long($subnet);
        if ($ipLong === false) {
            return [];
        }

        $mask = -1 << (32 - $bits);
        $network = $ipLong & $mask;
        $broadcast = $network | (~$mask & 0xFFFFFFFF);

        // Safety limit - max 256 IPs per CIDR expansion
        $count = $broadcast - $network + 1;
        if ($count > 256) {
            return [$cidr];
        }

        $ips = [];
        for ($i = $network; $i <= $broadcast; $i++) {
            $ips[] = long2ip($i);
        }

        return $ips;
    }

    /**
     * Check if IP is valid (IPv4 or IPv6)
     */
    private function isValidIP(string $ip): bool
    {
        // Must pass PHP's filter validation
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        // Additional checks - reject obviously invalid IPs
        // (filter_var allows some edge cases)

        // Reject 0.0.0.0 (but allow in CIDR ranges)
        if ($ip === '0.0.0.0') {
            return false;
        }

        return true;
    }

    /**
     * Check if IP is whitelisted (Cloudflare ranges)
     */
    private function isWhitelisted(string $ip): bool
    {
        $cfRanges = [
            '199.27.128.0/21',
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/12',
        ];

        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return false;
        }

        foreach ($cfRanges as $range) {
            list($network, $bits) = explode('/', $range);
            $networkLong = ip2long($network);
            $mask = -1 << (32 - (int)$bits);
            
            if (($ipLong & $mask) === ($networkLong & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Clear cache (force refresh)
     */
    public function clearCache(): int
    {
        $files = glob($this->cacheDir . '/*.txt');
        $deleted = 0;

        foreach ($files as $file) {
            if (is_file($file) && unlink($file)) {
                $deleted++;
            }
        }

        $this->app->logger()->log('CACHE_CLEARED', "Deleted {$deleted} cached files");
        return $deleted;
    }

    /**
     * Get cache file path for a source
     */
    private function getCacheFilePath(int $index): string
    {
        return $this->cacheDir . '/' . $index . '.txt';
    }

    /**
     * Get number of sources
     */
    public function getSourceCount(): int
    {
        return count($this->sources);
    }
}
