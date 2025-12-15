<?php
/**
 * Cron Endpoint Controller
 * Security Log Analyzer v2.0
 *
 * Usage:
 *   GET /cron.php?key=your-secret-key
 *   GET /cron.php?key=your-secret-key&log=/path/to/logfile
 *   GET /cron.php?key=your-secret-key&cloudflare=1
 */

require_once __DIR__ . '/../vendor/autoload.php';

use App\Core\Application;
use App\Services\LogAnalyzer;
use App\Services\CloudflareService;

// Set content type
$format = strtolower($_GET['format'] ?? 'json');
if (!in_array($format, ['json', 'text'], true)) {
    $format = 'json';
}
header('Content-Type: ' . ($format === 'json' ? 'application/json' : 'text/plain') . '; charset=utf-8');

// Bootstrap application
$app = Application::getInstance();

// Check if verbose mode (only for authenticated requests)
$verbose = isset($_GET['verbose']) && $_GET['verbose'] === '1';

// Response helper (with info disclosure protection)
function respond(array $response, string $format, bool $verbose = false): void {
    // Remove sensitive data if not in verbose mode
    if (!$verbose && isset($response['data'])) {
        // Don't expose full file paths
        if (isset($response['data']['log_file'])) {
            $response['data']['log_file'] = basename($response['data']['log_file']);
        }
        // Don't expose full IP list in response (just count)
        if (isset($response['data']['suspicious_ips'])) {
            unset($response['data']['suspicious_ips']);
        }
        // Don't expose cloudflare errors details
        if (isset($response['data']['cloudflare']['errors'])) {
            $response['data']['cloudflare']['error_count'] = count($response['data']['cloudflare']['errors']);
            unset($response['data']['cloudflare']['errors']);
        }
    }

    // Sanitize error messages
    if (isset($response['errors'])) {
        $response['errors'] = array_map(function($error) {
            // Remove file paths from error messages
            return preg_replace('/\/[^\s:]+/', '[path]', $error);
        }, $response['errors']);
    }

    if ($format === 'json') {
        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } else {
        echo "=== Security Log Analyzer - Cron Report ===" . PHP_EOL;
        echo "Timestamp: " . $response['timestamp'] . PHP_EOL;
        echo "Status: " . ($response['success'] ? 'SUCCESS' : 'FAILED') . PHP_EOL . PHP_EOL;

        if ($response['success'] && isset($response['data'])) {
            echo "Lines Analyzed: " . ($response['data']['lines_analyzed'] ?? 0) . PHP_EOL;
            echo "Suspicious IPs: " . ($response['data']['suspicious_count'] ?? 0) . PHP_EOL;

            if (isset($response['data']['cloudflare'])) {
                echo PHP_EOL . "Cloudflare:" . PHP_EOL;
                echo "  Added: " . ($response['data']['cloudflare']['added'] ?? 0) . PHP_EOL;
            }
        }

        if (!empty($response['errors'])) {
            echo PHP_EOL . "Errors:" . PHP_EOL;
            foreach ($response['errors'] as $error) {
                echo "  - {$error}" . PHP_EOL;
            }
        }
    }
    exit;
}

// Initialize response
$response = [
    'success' => false,
    'timestamp' => date('Y-m-d H:i:s'),
    'data' => null,
    'errors' => []
];

// Verify authentication
$cronKey = $_GET['key'] ?? '';

if (empty($cronKey)) {
    $response['errors'][] = 'Authentication required';
    $app->logger()->log('CRON_UNAUTHORIZED', 'Missing key');
    http_response_code(401);
    respond($response, $format, false);
}

if (!$app->auth()->verifyCronKey($cronKey)) {
    $response['errors'][] = 'Authentication failed';
    $app->logger()->log('CRON_UNAUTHORIZED', 'Invalid key');
    http_response_code(403);
    respond($response, $format, false);
}

// Run analysis
$app->logger()->log('CRON_STARTED', 'Cron job initiated');

try {
    $analyzer = new LogAnalyzer($app);
    $cloudflare = new CloudflareService($app);

    $logFilePath = $_GET['log'] ?? $app->config('paths.default_log');
    $sendToCloudflare = isset($_GET['cloudflare']) && $_GET['cloudflare'] === '1';

    $analysisResult = $analyzer->analyze($logFilePath);

    if (!$analysisResult['success']) {
        throw new \Exception('Analysis failed');
    }

    $response['success'] = true;
    $response['data'] = [
        'log_file' => $logFilePath,
        'lines_analyzed' => $analysisResult['lines_analyzed'],
        'suspicious_count' => $analysisResult['suspicious_count'],
        'suspicious_ips' => array_keys($analysisResult['suspicious_ips']),
    ];

    // Push to Cloudflare
    if ($sendToCloudflare && $analysisResult['suspicious_count'] > 0) {
        $ips = array_keys($analysisResult['suspicious_ips']);
        $cfResult = $cloudflare->pushIPs($ips);

        $response['data']['cloudflare'] = [
            'success' => $cfResult['ok'],
            'added' => $cfResult['added'],
            'errors' => $cfResult['errors']
        ];
    }

    $app->logger()->log('CRON_COMPLETED',
        "Lines: {$analysisResult['lines_analyzed']}, IPs: {$analysisResult['suspicious_count']}"
    );

} catch (\Exception $e) {
    $response['success'] = false;
    $response['errors'][] = 'Analysis error occurred';
    $app->logger()->log('CRON_ERROR', $e->getMessage());
    http_response_code(500);
}

respond($response, $format, $verbose);
