#!/bin/bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec make -C "$root" ARCH="${1:-${ARCH:-x86_64}}" "${2:-run}"
