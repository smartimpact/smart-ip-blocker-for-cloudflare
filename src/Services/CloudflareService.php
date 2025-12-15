<?php

namespace App\Services;

use App\Core\Application;

/**
 * Cloudflare Service
 * Handles Cloudflare API integration with secure HTTP
 */
class CloudflareService
{
    private Application $app;
    private string $token;
    private string $accountId;
    private string $listId;

    // Secure cURL settings
    private int $connectTimeout = 10;
    private int $timeout = 30;

    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->token = $app->config('cloudflare.api_token') ?? '';
        $this->accountId = $app->config('cloudflare.account_id') ?? '';
        $this->listId = $app->config('cloudflare.list_id') ?? '';
    }

    /**
     * Check if Cloudflare is configured
     */
    public function isConfigured(): bool
    {
        return !empty($this->token) && !empty($this->accountId) && !empty($this->listId);
    }

    /**
     * Get secure cURL options for Cloudflare API
     */
    private function getSecureCurlOptions(): array
    {
        return [
            // SSL/TLS Security
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,

            // Timeouts
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,

            // Transfer settings
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false, // Don't follow redirects for API

            // Protocol restrictions
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,

            // Headers
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $this->token,
                'Content-Type: application/json; charset=utf-8',
                'User-Agent: SecurityLogAnalyzer/2.0',
            ],
        ];
    }

    /**
     * Push IPs to Cloudflare list
     */
    public function pushIPs(array $ips): array
    {
        $result = [
            'ok' => false,
            'added' => 0,
            'errors' => []
        ];

        if (!$this->isConfigured()) {
            $result['errors'][] = 'Cloudflare is not configured';
            return $result;
        }

        // Filter valid IPs
        $ips = array_filter($ips, function ($ip) {
            return filter_var($ip, FILTER_VALIDATE_IP) !== false;
        });

        if (empty($ips)) {
            $result['ok'] = true;
            $result['errors'][] = 'No valid IPs to push';
            return $result;
        }

        // Verify credentials
        if (!$this->verifyCredentials()) {
            $result['errors'][] = 'Cloudflare authentication failed';
            return $result;
        }

        // Push in batches
        $chunks = array_chunk(array_values($ips), 1000);
        $result['ok'] = true;

        foreach ($chunks as $chunk) {
            $batchResult = $this->pushBatch($chunk);
            if ($batchResult['ok']) {
                $result['added'] += $batchResult['added'];
            } else {
                $result['ok'] = false;
                $result['errors'] = array_merge($result['errors'], $batchResult['errors']);
            }
        }

        $this->app->logger()->log(
            $result['ok'] ? 'CLOUDFLARE_PUSH' : 'CLOUDFLARE_ERROR',
            "Added: {$result['added']}, Errors: " . count($result['errors'])
        );

        return $result;
    }

    /**
     * Verify Cloudflare credentials
     */
    private function verifyCredentials(): bool
    {
        // Sanitize IDs to prevent injection
        $accountId = preg_replace('/[^a-f0-9]/', '', $this->accountId);
        $listId = preg_replace('/[^a-f0-9]/', '', $this->listId);

        $url = "https://api.cloudflare.com/client/v4/accounts/{$accountId}/rules/lists/{$listId}";

        $ch = curl_init($url);
        curl_setopt_array($ch, $this->getSecureCurlOptions());

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false) {
            $this->app->logger()->log('CLOUDFLARE_ERROR', "cURL error: {$error}");
            return false;
        }

        if ($status < 200 || $status >= 300) {
            return false;
        }

        $json = json_decode($response, true);
        return isset($json['success']) && $json['success'] === true;
    }

    /**
     * Push a batch of IPs
     */
    private function pushBatch(array $ips): array
    {
        // Sanitize IDs
        $accountId = preg_replace('/[^a-f0-9]/', '', $this->accountId);
        $listId = preg_replace('/[^a-f0-9]/', '', $this->listId);

        $url = "https://api.cloudflare.com/client/v4/accounts/{$accountId}/rules/lists/{$listId}/items";

        $items = array_map(function ($ip) {
            return ['ip' => $ip];
        }, $ips);

        $payload = json_encode($items, JSON_UNESCAPED_SLASHES);

        $ch = curl_init($url);
        $options = $this->getSecureCurlOptions();
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = $payload;
        $options[CURLOPT_HTTPHEADER][] = 'Content-Length: ' . strlen($payload);
        curl_setopt_array($ch, $options);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $result = ['ok' => false, 'added' => 0, 'errors' => []];

        if ($response === false) {
            $result['errors'][] = 'Request failed';
            $this->app->logger()->log('CLOUDFLARE_ERROR', "cURL error: {$error}");
            return $result;
        }

        $json = json_decode($response, true);

        if ($status >= 200 && $status < 300 && isset($json['success']) && $json['success']) {
            $result['ok'] = true;
            $result['added'] = isset($json['result']) && is_array($json['result'])
                ? count($json['result'])
                : count($ips);
        } else {
            if (isset($json['errors']) && is_array($json['errors'])) {
                foreach ($json['errors'] as $err) {
                    $result['errors'][] = $err['message'] ?? 'Unknown error';
                }
            } else {
                $result['errors'][] = "HTTP {$status}";
            }
        }

        return $result;
    }
}
