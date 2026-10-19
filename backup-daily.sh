#!/bin/sh
set -eu
# Run daily with systemd timer/cron in the VPS; .env remains on the server.
# Writes locally first, uploads encrypted bytes, then independently reads them back.
cd "$(dirname "$0")"
docker compose exec -T app python backup.py --upload
# Monitor exit status. A failed run must alert the administrator via the chosen monitoring system.
