<?php

namespace App\Core;

/**
 * View/Template Renderer
 * Handles template rendering with data injection
 */
class View
{
    private Application $app;
    private array $data = [];

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * Set data for templates
     */
    public function with(string $key, $value): self
    {
        $this->data[$key] = $value;
        return $this;
    }

    /**
     * Set multiple data items
     */
    public function withData(array $data): self
    {
        $this->data = array_merge($this->data, $data);
        return $this;
    }

    /**
     * Render a template (secure - no extract())
     */
    public function render(string $template, array $data = []): string
    {
        // Merge data with safe defaults
        $__viewData = array_merge($this->data, $data, [
            'app' => $this->app,
            'auth' => $this->app->auth(),
        ]);

        // Whitelist allowed variable names to prevent variable injection
        $__allowedVars = [
            'app', 'auth', 'success', 'error', 'analysisData', 'recentBans',
            'totalBans', 'threatFeeds', 'defaultLogPath', 'title', 'content',
        ];

        // Only extract whitelisted variables
        foreach ($__allowedVars as $__varName) {
            if (array_key_exists($__varName, $__viewData)) {
                $$__varName = $__viewData[$__varName];
            }
        }

        $__templatePath = $this->app->config('paths.templates') . '/' . $template . '.php';

        if (!file_exists($__templatePath)) {
            throw new \RuntimeException("Template not found: {$template}");
        }

        ob_start();
        include $__templatePath;
        return ob_get_clean();
    }

    /**
     * Render and output a template
     */
    public function display(string $template, array $data = []): void
    {
        echo $this->render($template, $data);
    }

    /**
     * Render a partial template
     */
    public function partial(string $partial, array $data = []): string
    {
        return $this->render('partials/' . $partial, $data);
    }

    /**
     * Escape HTML entities
     */
    public function escape($value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Alias for escape
     */
    public function e($value): string
    {
        return $this->escape($value);
    }
}
