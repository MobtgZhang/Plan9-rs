#!/bin/bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-all}" in
    build) target=kernel ;;
    image|iso|all) target=iso ;;
    run) target=run ;;
    clean) target=clean ;;
    help|--help|-h) target=help ;;
    *) printf 'Unknown command: %s\n' "$1" >&2; exit 2 ;;
esac
exec make -C "$root" ARCH="${ARCH:-x86_64}" "$target"
