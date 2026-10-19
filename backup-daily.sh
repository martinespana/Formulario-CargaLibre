#!/bin/sh
set -eu
# Run daily with systemd timer/cron in the VPS; .env remains on the server.
# Writes an encrypted snapshot to /data/backups inside the records volume.
cd "$(dirname "$0")"
docker compose exec -T app python backup.py
# Monitor exit status. A failed run must alert the administrator via the chosen monitoring system.
