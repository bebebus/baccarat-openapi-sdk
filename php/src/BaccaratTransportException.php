<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class BaccaratTransportException extends BaccaratSdkException
{
    public function __construct(string $message, string $errorCode = StatusCode::SC_OPERATOR_TIMEOUT)
    {
        parent::__construct($message, $errorCode);
    }
}
