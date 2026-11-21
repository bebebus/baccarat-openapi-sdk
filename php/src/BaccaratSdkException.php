<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

use RuntimeException;

class BaccaratSdkException extends RuntimeException
{
    public readonly string $errorCode;

    public function __construct(string $message, string $errorCode = 'SDK_ERROR')
    {
        parent::__construct($message);
        $this->errorCode = $errorCode;
    }
}
