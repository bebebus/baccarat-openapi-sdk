<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

interface WalletAdjustmentHandlerInterface
{
    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onAdjustment(array $req): array;
}
