#!/usr/bin/env bash
# OVERSEER — arranca el visor local de auditorías.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 server.py --open "$@"
