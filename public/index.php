<?php
/**
 * Front Controller - Dashboard
 * Security Log Analyzer v2.0
 */

require_once __DIR__ . '/../vendor/autoload.php';

use App\Core\Application;
use App\Services\LogAnalyzer;
use App\Services\CloudflareService;

// Bootstrap application
$app = Application::getInstance();
$app->auth()->requireAuth();

// CSRF protection for all POST requests
$app->auth()->requireCsrf();

// Initialize services
$analyzer = new LogAnalyzer($app);
$cloudflare = new CloudflareService($app);

// Handle actions
$success = null;
$error = null;
$analysisData = null;

// Handle reload lists
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reload_lists'])) {
    try {
        $deleted = $analyzer->blocklist()->clearCache();
        $success = "Cache cleared! Deleted {$deleted} cached blocklist files. Lists will be re-downloaded on next analysis.";
    } catch (\Exception $e) {
        $error = "Failed to reload lists: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    }
}

// Handle log analysis
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['analyze'])) {
    $logFilePath = $_POST['logfile'] ?? '';

    if (empty($logFilePath)) {
        $logFilePath = $app->config('paths.default_log');
    }

    $analysisData = $analyzer->analyze($logFilePath);

    if ($analysisData['success']) {
        $success = "Analysis complete! Analyzed {$analysisData['lines_analyzed']} lines, found {$analysisData['suspicious_count']} suspicious IPs.";

        // Push to Cloudflare if requested
        if (isset($_POST['send_cloudflare']) && $analysisData['suspicious_count'] > 0) {
            $ips = array_keys($analysisData['suspicious_ips']);
            $cfResult = $cloudflare->pushIPs($ips);

            if ($cfResult['ok']) {
                $success .= " Successfully sent {$cfResult['added']} IPs to Cloudflare.";
            } else {
                $error = "Failed to send IPs to Cloudflare: " . htmlspecialchars(implode(' | ', $cfResult['errors']), ENT_QUOTES, 'UTF-8');
            }
        }
    } else {
        $error = htmlspecialchars(implode(' | ', $analysisData['errors']), ENT_QUOTES, 'UTF-8');
    }
}

// Get data for display
$recentBans = $analyzer->getRecentBans(20);
$totalBans = $analyzer->getTotalBansCount();
$threatFeeds = $analyzer->blocklist()->getSourceCount();

// Render view
$app->view()->display('dashboard', [
    'success' => $success,
    'error' => $error,
    'analysisData' => $analysisData,
    'recentBans' => $recentBans,
    'totalBans' => $totalBans,
    'threatFeeds' => $threatFeeds,
    'defaultLogPath' => htmlspecialchars($_POST['logfile'] ?? $app->config('paths.default_log'), ENT_QUOTES, 'UTF-8'),
]);
