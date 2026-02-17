#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

find "$ROOT/bin" "$ROOT/lib" "$ROOT/test" \
  -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) \
  -exec clang-format -i --style=file {} +
