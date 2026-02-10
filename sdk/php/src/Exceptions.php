<?php

namespace AuthNex;

class AuthNexException extends \RuntimeException
{
    private string $errorCode;
    private array $details;

    public function __construct(string $message, string $errorCode = 'ERROR', int $httpStatus = 400, array $details = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $httpStatus, $previous);
        $this->errorCode = $errorCode;
        $this->details = $details;
    }

    public function getErrorCode(): string { return $this->errorCode; }
    public function getDetails(): array { return $this->details; }
    public function getHttpStatus(): int { return $this->getCode(); }
}

class TokenExpiredException extends AuthNexException
{
    public function __construct(string $message = 'Token has expired', ?\Throwable $previous = null)
    {
        parent::__construct($message, 'TOKEN_EXPIRED', 401, [], $previous);
    }
}

class UnauthorizedException extends AuthNexException
{
    public function __construct(string $message = 'Unauthorized', ?\Throwable $previous = null)
    {
        parent::__construct($message, 'UNAUTHORIZED', 401, [], $previous);
    }
}

class ForbiddenException extends AuthNexException
{
    public function __construct(string $message = 'Access denied', ?\Throwable $previous = null)
    {
        parent::__construct($message, 'FORBIDDEN', 403, [], $previous);
    }
}

class RateLimitException extends AuthNexException
{
    public function __construct(string $message = 'Too many requests', ?\Throwable $previous = null)
    {
        parent::__construct($message, 'RATE_LIMITED', 429, [], $previous);
    }
}
