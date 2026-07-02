#!/usr/bin/env bash
# Self-hosted deploy: chạy trên GitHub runner ở Synology.
# Build image local + recreate container (raw docker, chỉ cần docker CLI).
set -euo pipefail

ENV_FILE="${ENV_FILE:-/volume2/docker/barcode-wms/.env}"
IMAGE="${IMAGE:-barcode-wms:ci}"
NAME="${NAME:-barcode-wms}"
EXPORTS_VOL="${EXPORTS_VOL:-barcode-wms_exports}"
PORT="${PORT:-7777}"

[ -f "$ENV_FILE" ] || { echo "❌ Không thấy ENV_FILE: $ENV_FILE (đặt .env trên Synology)"; exit 1; }

echo "▶ Build image $IMAGE ..."
docker build -t "$IMAGE" .

echo "▶ Đảm bảo volume $EXPORTS_VOL ..."
docker volume create "$EXPORTS_VOL" >/dev/null 2>&1 || true

echo "▶ Recreate container $NAME ..."
docker stop "$NAME" >/dev/null 2>&1 || true
docker rm   "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  -p "${PORT}:3000" \
  --env-file "$ENV_FILE" \
  -v "${EXPORTS_VOL}:/app/public/exports" \
  "$IMAGE"

echo "✓ Container $NAME đang chạy (image=$IMAGE port=$PORT env=$ENV_FILE)"
