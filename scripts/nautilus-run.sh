#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
mode=${1:?Missing LiteSign operation}
shift
if (( $# == 0 )); then
    message='No accessible local files selected. Select files in a local or mounted folder.'
    printf '%s\n' "$message" >&2
    if command -v notify-send >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        timeout 3 notify-send --app-name=LiteSign --urgency=critical -- LiteSign "$message" >/dev/null 2>&1 || true
    fi
    exit 2
fi
case "$mode" in
    pades|cades) options=(--no-prompt --format "$mode") ;;
    extract) options=(--extract) ;;
    *) printf 'Unknown LiteSign operation: %s\n' "$mode" >&2; exit 2 ;;
esac
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$script_dir/../.venv/bin/python" "$script_dir/../litesign.py" "${options[@]}" -- "$@"
