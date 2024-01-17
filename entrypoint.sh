#!/usr/bin/env bash
set -eu -o pipefail

export SAFETY_OS_TYPE="docker"
export SAFETY_OS_RELEASE=""
export SAFETY_OS_DESCRIPTION="run"

exec python -m safety $@
