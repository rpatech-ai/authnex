<?php

namespace AuthNex;

class Middleware
{
    private AuthNex $auth;
    private array $options;

    public function __construct(AuthNex $auth, array $options = [])
    {
        $this->auth = $auth;
        $this->options = array_merge([
            'login_url' => '/login',
            'excluded_paths' => ['/login', '/register', '/forgot-password', '/reset-password'],
            'role_map' => [],       // e.g. ['/admin/*' => 'admin']
            'permission_map' => [], // e.g. ['/api/users' => 'users:read']
        ], $options);
    }

    /**
     * Handle an incoming request. Call at the entry point of your app.
     * Returns true if the request should proceed, or redirects/throws if not.
     */
    public function handle(?string $requestPath = null): bool
    {
        $path = $requestPath ?? ($_SERVER['REQUEST_URI'] ?? '/');
        $path = parse_url($path, PHP_URL_PATH);

        // Skip excluded paths
        foreach ($this->options['excluded_paths'] as $excluded) {
            if ($this->pathMatches($path, $excluded)) {
                return true;
            }
        }

        // Require authentication
        $this->auth->protect($this->options['login_url']);

        // Check role-based restrictions
        foreach ($this->options['role_map'] as $pattern => $role) {
            if ($this->pathMatches($path, $pattern)) {
                $this->auth->requireRole($role);
            }
        }

        // Check permission-based restrictions
        foreach ($this->options['permission_map'] as $pattern => $permission) {
            if ($this->pathMatches($path, $pattern)) {
                $this->auth->requirePermission($permission);
            }
        }

        return true;
    }

    /**
     * Get the current authenticated user from session.
     */
    public function getUser(): ?array
    {
        return $this->auth->getUser();
    }

    /**
     * Check if request is from an authenticated user.
     */
    public function isAuthenticated(): bool
    {
        return $this->auth->isAuthenticated();
    }

    /**
     * Simple glob-style path matching (supports * wildcard).
     */
    private function pathMatches(string $path, string $pattern): bool
    {
        if ($pattern === $path) return true;
        $regex = str_replace(['*', '/'], ['[^/]*', '\/'], $pattern);
        // Support ** for any depth
        $regex = str_replace('[^/]*[^/]*', '.*', $regex);
        return (bool) preg_match('/^' . $regex . '$/', $path);
    }
}
