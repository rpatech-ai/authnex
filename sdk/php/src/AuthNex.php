<?php

namespace AuthNex;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class AuthNex
{
    private Client $http;
    private TokenVerifier $verifier;
    private string $apiUrl;
    private string $tenant;
    private ?string $apiKey;
    private ?array $session = null;

    public function __construct(array $config)
    {
        $this->apiUrl = rtrim($config['api_url'] ?? '', '/');
        $this->tenant = $config['tenant'] ?? '';
        $this->apiKey = $config['api_key'] ?? null;

        if (!$this->apiUrl) throw new AuthNexException('api_url is required');
        if (!$this->tenant) throw new AuthNexException('tenant is required');

        $this->http = new Client([
            'base_uri' => $this->apiUrl,
            'timeout' => 15,
            'headers' => array_filter([
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'X-Tenant-Slug' => $this->tenant,
                'X-API-Key' => $this->apiKey,
            ]),
        ]);

        $this->verifier = new TokenVerifier($this->apiUrl);
    }

    // --- Authentication ---

    /**
     * Login with email and password. Returns tokens + user data.
     */
    public function login(string $email, string $password, bool $rememberMe = true): array
    {
        $data = $this->post('/api/auth/login', [
            'email' => $email,
            'password' => $password,
            'tenant_slug' => $this->tenant,
            'remember_me' => $rememberMe,
        ]);

        if (isset($data['access_token'])) {
            $this->setSession($data);
        }

        return $data;
    }

    /**
     * Register a new user.
     */
    public function register(string $email, string $password, array $metadata = []): array
    {
        return $this->post('/api/auth/register', [
            'email' => $email,
            'password' => $password,
            'tenant_slug' => $this->tenant,
            'metadata' => $metadata,
        ]);
    }

    /**
     * Refresh the access token using a refresh token.
     */
    public function refresh(?string $refreshToken = null): array
    {
        $token = $refreshToken ?? $this->getSessionValue('refresh_token');
        if (!$token) throw new UnauthorizedException('No refresh token available');

        $data = $this->post('/api/auth/refresh', ['refresh_token' => $token]);

        if (isset($data['access_token'])) {
            $this->setSession($data);
        }

        return $data;
    }

    /**
     * Logout — revokes current tokens.
     */
    public function logout(): void
    {
        $token = $this->getAccessToken();
        if ($token) {
            try {
                $this->post('/api/auth/logout', [], $token);
            } catch (\Exception $e) {
                // Ignore errors on logout
            }
        }
        $this->clearSession();
    }

    /**
     * Verify an email address with a verification token.
     */
    public function verifyEmail(string $token): array
    {
        return $this->post('/api/auth/verify-email', ['token' => $token]);
    }

    /**
     * Request a password reset email.
     */
    public function forgotPassword(string $email): array
    {
        return $this->post('/api/auth/forgot-password', ['email' => $email]);
    }

    /**
     * Reset password with a reset token.
     */
    public function resetPassword(string $token, string $newPassword): array
    {
        return $this->post('/api/auth/reset-password', [
            'token' => $token,
            'password' => $newPassword,
        ]);
    }

    // --- Route Protection ---

    /**
     * Protect a route — redirects to login if not authenticated.
     * Call at the top of any page that requires authentication.
     */
    public function protect(?string $loginUrl = null): void
    {
        $this->startSessionIfNeeded();

        $token = $this->getAccessToken();
        if (!$token) {
            $this->redirectToLogin($loginUrl);
            return;
        }

        try {
            $this->verifier->verify($token);
        } catch (TokenExpiredException $e) {
            // Try to refresh
            $refreshToken = $this->getSessionValue('refresh_token');
            if ($refreshToken) {
                try {
                    $this->refresh($refreshToken);
                    return;
                } catch (\Exception $e) {
                    // Refresh also failed
                }
            }
            $this->clearSession();
            $this->redirectToLogin($loginUrl);
        } catch (\Exception $e) {
            $this->clearSession();
            $this->redirectToLogin($loginUrl);
        }
    }

    /**
     * Check if user has a required role. Throws ForbiddenException if not.
     */
    public function requireRole(string $role): void
    {
        $token = $this->getAccessToken();
        if (!$token) throw new UnauthorizedException('Not authenticated');

        if (!$this->verifier->hasRole($token, $role)) {
            throw new ForbiddenException("Required role: $role");
        }
    }

    /**
     * Check if user has a required permission. Throws ForbiddenException if not.
     */
    public function requirePermission(string $permission): void
    {
        $token = $this->getAccessToken();
        if (!$token) throw new UnauthorizedException('Not authenticated');

        if (!$this->verifier->hasPermission($token, $permission)) {
            throw new ForbiddenException("Required permission: $permission");
        }
    }

    // --- User Data ---

    /**
     * Get the current authenticated user's data.
     */
    public function getUser(): ?array
    {
        return $this->getSessionValue('user');
    }

    /**
     * Get the current user's profile from the API.
     */
    public function getProfile(): array
    {
        $token = $this->getAccessToken();
        if (!$token) throw new UnauthorizedException('Not authenticated');
        return $this->get('/api/user/profile', $token);
    }

    /**
     * Check if user is currently authenticated with a valid token.
     */
    public function isAuthenticated(): bool
    {
        $this->startSessionIfNeeded();
        $token = $this->getAccessToken();
        if (!$token) return false;

        try {
            $this->verifier->verify($token);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if the current user has a specific role.
     */
    public function hasRole(string $role): bool
    {
        $token = $this->getAccessToken();
        if (!$token) return false;
        try {
            return $this->verifier->hasRole($token, $role);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check if the current user has a specific permission.
     */
    public function hasPermission(string $permission): bool
    {
        $token = $this->getAccessToken();
        if (!$token) return false;
        try {
            return $this->verifier->hasPermission($token, $permission);
        } catch (\Exception $e) {
            return false;
        }
    }

    // --- Session Management ---

    private function startSessionIfNeeded(): void
    {
        if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
            session_start();
        }
    }

    private function setSession(array $data): void
    {
        $this->startSessionIfNeeded();
        $_SESSION['authnex'] = [
            'access_token' => $data['access_token'] ?? null,
            'refresh_token' => $data['refresh_token'] ?? null,
            'expires_in' => $data['expires_in'] ?? 900,
            'user' => $data['user'] ?? null,
            'tenant' => $data['tenant'] ?? null,
            'authenticated_at' => time(),
        ];
        $this->session = $_SESSION['authnex'];
    }

    private function clearSession(): void
    {
        $this->startSessionIfNeeded();
        unset($_SESSION['authnex']);
        $this->session = null;
    }

    private function getAccessToken(): ?string
    {
        $this->startSessionIfNeeded();
        return $_SESSION['authnex']['access_token'] ?? $this->session['access_token'] ?? null;
    }

    private function getSessionValue(string $key): mixed
    {
        $this->startSessionIfNeeded();
        return $_SESSION['authnex'][$key] ?? $this->session[$key] ?? null;
    }

    private function redirectToLogin(?string $loginUrl = null): void
    {
        $url = $loginUrl ?? '/login';
        if (!headers_sent()) {
            header("Location: $url");
            exit;
        }
        throw new UnauthorizedException('Not authenticated — redirect to ' . $url);
    }

    // --- HTTP helpers ---

    private function post(string $path, array $body, ?string $bearerToken = null): array
    {
        $headers = [];
        if ($bearerToken) {
            $headers['Authorization'] = 'Bearer ' . $bearerToken;
        }

        try {
            $response = $this->http->post($path, [
                'json' => $body,
                'headers' => $headers,
            ]);

            $data = json_decode($response->getBody()->getContents(), true);
            if (isset($data['success']) && !$data['success']) {
                $error = $data['error'] ?? [];
                throw new AuthNexException(
                    $error['message'] ?? 'Request failed',
                    $error['code'] ?? 'ERROR',
                    $response->getStatusCode()
                );
            }
            return $data['data'] ?? $data;
        } catch (RequestException $e) {
            $this->handleRequestException($e);
        }
    }

    private function get(string $path, ?string $bearerToken = null): array
    {
        $headers = [];
        if ($bearerToken) {
            $headers['Authorization'] = 'Bearer ' . $bearerToken;
        }

        try {
            $response = $this->http->get($path, ['headers' => $headers]);
            $data = json_decode($response->getBody()->getContents(), true);
            if (isset($data['success']) && !$data['success']) {
                $error = $data['error'] ?? [];
                throw new AuthNexException(
                    $error['message'] ?? 'Request failed',
                    $error['code'] ?? 'ERROR',
                    $response->getStatusCode()
                );
            }
            return $data['data'] ?? $data;
        } catch (RequestException $e) {
            $this->handleRequestException($e);
        }
    }

    private function handleRequestException(RequestException $e): never
    {
        $response = $e->getResponse();
        if ($response) {
            $body = json_decode($response->getBody()->getContents(), true);
            $error = $body['error'] ?? [];
            $code = $error['code'] ?? 'ERROR';
            $message = $error['message'] ?? $e->getMessage();
            $status = $response->getStatusCode();

            match (true) {
                $status === 401 => throw new UnauthorizedException($message, $e),
                $status === 403 => throw new ForbiddenException($message, $e),
                $status === 429 => throw new RateLimitException($message, $e),
                default => throw new AuthNexException($message, $code, $status, [], $e),
            };
        }
        throw new AuthNexException('Network error: ' . $e->getMessage(), 'NETWORK_ERROR', 0, [], $e);
    }
}
