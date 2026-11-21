<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class BaccaratApiException extends BaccaratSdkException
{
    public readonly string $traceId;
    public readonly string $status;
    /** @var array<string, string>|null */
    public readonly ?array $validation;
    public readonly int $httpStatus;

    /** @param array<string, string>|null $validation */
    public function __construct(
        string $status,
        string $message = '',
        string $traceId = '',
        ?array $validation = null,
        int $httpStatus = 200
    ) {
        parent::__construct($message !== '' ? $message : "B2B API error: {$status}", $status);
        $this->status = $status;
        $this->traceId = $traceId;
        $this->validation = $validation;
        $this->httpStatus = $httpStatus;
    }

    public function isRetryable(): bool
    {
        return StatusCode::isRetryable($this->status);
    }
}
