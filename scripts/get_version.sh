#!/usr/bin/env bash

set -euo pipefail

GIT=${1:-git}
REPO=${2:-.}

# Try to get version with tags first, fallback to commit hash if no tags exist
if "$GIT" -C "$REPO" describe --long 2>/dev/null; then
    "$GIT" -C "$REPO" describe --long | tr -d '\n'
else
    # Fallback to commit hash with "dev" suffix if no tags are available
    "$GIT" -C "$REPO" rev-parse --short HEAD | tr -d '\n'
    echo -n "-dev"
fi
