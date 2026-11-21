#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

cd "$(dirname "$0")"
rm -rf out
mkdir -p out/main out/test

javac --release 17 -encoding UTF-8 -d out/main src/main/java/cloud/cniia/baccarat/sdk/*.java
javac --release 17 -encoding UTF-8 -cp out/main -d out/test src/test/java/cloud/cniia/baccarat/sdk/*.java
java -ea -cp "out/main:out/test" cloud.cniia.baccarat.sdk.SdkTestRunner
