#!/bin/sh
# Stops and removes the RustFS test containers started by rustfs-up.sh.
# Data is on tmpfs, so removal discards it. Missing containers are not an error.
#
# Usage: scripts/rustfs-down.sh [single|multi]   (no argument: both)
set -eu

case "${1:-all}" in
single | multi) names="vlt-rustfs-$1" ;;
all) names='vlt-rustfs-single vlt-rustfs-multi' ;;
*)
    echo "usage: $0 [single|multi]" >&2
    exit 2
    ;;
esac

for name in $names; do
    docker rm -f "$name" >/dev/null 2>&1 || true
done
