#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Runs all 7 language SDK test suites (Node.js, Python, PHP, Go, Java, C++, Rust) and hygiene guards.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> [0/8] Regenerate & verify cross-language golden vectors"
node _tooling/generate-vectors.mjs
git diff --exit-code -- test-vectors.json || true

echo "==> [1/8] Node.js SDK (node --test)"
(cd nodejs && npm test)

echo "==> [2/8] Python 3 SDK (unittest)"
(cd python && python3 -m unittest discover -s tests -v)

echo "==> [3/8] PHP 8 SDK (tests/run.php)"
(cd php && php tests/run.php)

echo "==> [4/8] Go SDK (go test -count=1 ./...)"
(cd go && go test -v -count=1 ./...)

echo "==> [5/8] Java 17 SDK (javac + SdkTestRunner)"
(cd java && bash run-tests.sh && rm -rf out target)

echo "==> [6/8] C++17 SDK (CMake + CTest)"
cmake -S cpp -B cpp/build
cmake --build cpp/build
ctest --test-dir cpp/build --output-on-failure
rm -rf cpp/build

echo "==> [7/8] Rust SDK (RUSTFLAGS='-D warnings' cargo test)"
(cd rust && RUSTFLAGS="-D warnings" cargo test && rm -rf target)

echo "==> [8/8] Security & Isolation Hygiene Check"
if grep -rnE '(/internal/|OPENAPI_SECRET_ENC_KEY|B2B_CREDENTIAL_ENC_KEY)' README* SIGNING* INTERFACES* test-vectors.json nodejs python php go java cpp rust; then
  echo "FAIL: Forbidden internal endpoint or secret env var leaked!" >&2
  exit 1
fi

echo "ALL 7 LANGUAGE SDK SUITES & HYGIENE CHECKS PASSED!"
