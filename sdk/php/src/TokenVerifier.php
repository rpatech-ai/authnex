<?php

namespace AuthNex;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;

class TokenVerifier
{
    private string $apiUrl;
    private ?array $jwks = null;
    private int $jwksCachedAt = 0;
    private int $cacheTtl;

    public function __construct(string $apiUrl, int $cacheTtl = 3600)
    {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->cacheTtl = $cacheTtl;
    }

    /**
     * Verify an access token and return its decoded payload.
     * @return object Decoded JWT payload with sub, email, tid, roles, permissions, etc.
     * @throws TokenExpiredException|UnauthorizedException
     */
    public function verify(string $token): object
    {
        $keys = $this->getKeys();
        try {
            $decoded = JWT::decode($token, $keys);
            return $decoded;
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new TokenExpiredException('Access token expired', $e);
        } catch (\Exception $e) {
            throw new UnauthorizedException('Token verification failed: ' . $e->getMessage(), $e);
        }
    }

    /**
     * Get the user ID (sub claim) from a verified token.
     */
    public function getUserId(string $token): int
    {
        $payload = $this->verify($token);
        return (int) $payload->sub;
    }

    /**
     * Get the tenant ID from a verified token.
     */
    public function getTenantId(string $token): ?int
    {
        $payload = $this->verify($token);
        return isset($payload->tid) ? (int) $payload->tid : null;
    }

    /**
     * Check if token has a specific role.
     */
    public function hasRole(string $token, string $role): bool
    {
        $payload = $this->verify($token);
        $roles = $payload->roles ?? [];
        return in_array($role, $roles, true);
    }

    /**
     * Check if token has a specific permission.
     */
    public function hasPermission(string $token, string $permission): bool
    {
        $payload = $this->verify($token);
        $perms = $payload->permissions ?? [];
        if (in_array('*', $perms, true)) return true;
        if (in_array($permission, $perms, true)) return true;
        [$resource] = explode(':', $permission);
        return in_array("$resource:*", $perms, true);
    }

    /**
     * Fetch and cache JWKS keys from the AuthNex API.
     * @return array<string, Key>
     */
    private function getKeys(): array
    {
        if ($this->jwks !== null && (time() - $this->jwksCachedAt) < $this->cacheTtl) {
            return $this->jwks;
        }

        $url = $this->apiUrl . '/api/auth/jwks';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || !$response) {
            throw new AuthNexException('Failed to fetch JWKS from ' . $url, 'JWKS_FETCH_FAILED', 500);
        }

        $jwksData = json_decode($response, true);
        if (!$jwksData || !isset($jwksData['keys'])) {
            throw new AuthNexException('Invalid JWKS response', 'JWKS_INVALID', 500);
        }

        $this->jwks = JWK::parseKeySet($jwksData, 'RS256');
        $this->jwksCachedAt = time();
        return $this->jwks;
    }

    /**
     * Force refresh of cached JWKS keys.
     */
    public function refreshKeys(): void
    {
        $this->jwksCachedAt = 0;
        $this->jwks = null;
    }
}
