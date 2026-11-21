<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

interface WalletHandlerInterface
{
    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBalance(array $req): array;

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBet(array $req): array;

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBetResult(array $req): array;

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onRollback(array $req): array;
}
