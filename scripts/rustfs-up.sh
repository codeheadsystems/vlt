#!/bin/sh
# Starts a throwaway RustFS server in Docker for vlt integration tests.
#
# Usage: scripts/rustfs-up.sh <single|multi>
#
#   single  one drive (/data), port 19000, container vlt-rustfs-single
#   multi   four drives (/data/rustfs0..3, erasure-coded), port 19001,
#           container vlt-rustfs-multi
#
# Data lives on tmpfs mounts, so every start is empty and nothing survives
# rustfs-down.sh. Each drive is its own tmpfs, which also satisfies RustFS's
# check that erasure drives sit on distinct devices.
#
# Creates two buckets as the admin user: vlt-test (versioning enabled) and
# vlt-test-plain (unversioned). Prints shell-style VAR=value lines on stdout.
# Needs docker and curl 7.75 or later (for --aws-sigv4).
set -eu

IMAGE='rustfs/rustfs:1.0.1@sha256:1803faef57627e2d9c2e7d89d655d712ddded5389040054987163043fecb6a3c'
ACCESS_KEY='vltadmin'
SECRET_KEY='vltadminsecret'
REGION='us-east-1'

layout=${1:-}
case "$layout" in
single)
    port=${VLT_RUSTFS_PORT:-19000}
    volumes='/data'
    mounts='--tmpfs /data:uid=10001,gid=10001,size=512m'
    ;;
multi)
    port=${VLT_RUSTFS_PORT:-19001}
    volumes='/data/rustfs{0...3}'
    mounts=''
    for i in 0 1 2 3; do
        mounts="$mounts --tmpfs /data/rustfs$i:uid=10001,gid=10001,size=256m"
    done
    ;;
*)
    echo "usage: $0 <single|multi>" >&2
    exit 2
    ;;
esac

name="vlt-rustfs-$layout"
endpoint="http://127.0.0.1:$port"

docker rm -f "$name" >/dev/null 2>&1 || true
# $mounts is word-split on purpose; it holds only fixed option strings.
# shellcheck disable=SC2086
docker run -d --name "$name" -p "127.0.0.1:$port:9000" \
    -e RUSTFS_ACCESS_KEY="$ACCESS_KEY" -e RUSTFS_SECRET_KEY="$SECRET_KEY" \
    -e RUSTFS_VOLUMES="$volumes" $mounts "$IMAGE" >/dev/null

i=0
until curl -sf "$endpoint/health" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "rustfs-up: $name not ready after 30 s" >&2
        docker logs "$name" >&2 || true
        exit 1
    fi
    sleep 1
done

s3() {
    # s3 METHOD PATH [curl args]; fails on any HTTP error.
    m=$1
    p=$2
    shift 2
    curl -sSf -o /dev/null -X "$m" --aws-sigv4 "aws:amz:$REGION:s3" \
        --user "$ACCESS_KEY:$SECRET_KEY" "$@" "$endpoint$p"
}

s3 PUT /vlt-test
s3 PUT /vlt-test-plain
body='<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>'
s3 PUT '/vlt-test?versioning' -H 'Content-Type: application/xml' --data-binary "$body"

cat <<OUT
VLT_RUSTFS_CONTAINER=$name
VLT_RUSTFS_ENDPOINT=$endpoint
VLT_RUSTFS_REGION=$REGION
VLT_RUSTFS_ACCESS_KEY=$ACCESS_KEY
VLT_RUSTFS_SECRET_KEY=$SECRET_KEY
VLT_RUSTFS_BUCKET=vlt-test
VLT_RUSTFS_BUCKET_UNVERSIONED=vlt-test-plain
OUT
