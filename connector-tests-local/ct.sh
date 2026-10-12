#!/usr/bin/env bash
# connector_tests_local — a disposable test PC in Docker for /internal/connector-tests.
#   ./ct.sh build    build the image (bundles your installed bridge binary)
#   ./ct.sh login    one-time device login, registers as "connector_tests_local"
#   ./ct.sh up       start the bridge (restarts with Docker)
#   ./ct.sh reset    wipe $HOME (installed tools + logins) — credentials are kept
#   ./ct.sh down | logs | shell | id
set -euo pipefail
cd "$(dirname "$0")"
NAME=connector-tests-local IMAGE=todoforai/connector-tests-local
HOME_VOL=ct-home CRED_VOL=ct-bridge-creds DEVICE=connector_tests_local
# Bridge credentials live on their own volume, so `reset` never forces a re-login.
RUN=(--network host -v "$HOME_VOL:/root" -v "$CRED_VOL:/root/.config/todoforai")

case "${1:-}" in
  build) cp "$(readlink -f "$(command -v todoforai-bridge || echo ~/.todoforai/bin/todoforai-bridge)")" todoforai-bridge
         docker build -t "$IMAGE" . && rm todoforai-bridge ;;
  login) docker run --rm -it "${RUN[@]}" "$IMAGE" todoforai-bridge login --device-name "$DEVICE" --no-browser ;;
  up)    docker rm -f "$NAME" >/dev/null 2>&1 || true
         docker run -d --name "$NAME" --restart unless-stopped "${RUN[@]}" "$IMAGE" >/dev/null && echo "$NAME up" ;;
  down)  docker rm -f "$NAME" ;;
  reset) docker rm -f "$NAME" >/dev/null 2>&1 || true
         docker volume rm "$HOME_VOL" >/dev/null 2>&1 || true
         echo "home wiped; ./ct.sh up to start clean" ;;
  logs)  docker logs -f "$NAME" ;;
  shell) docker exec -it "$NAME" bash ;;
  id)    docker run --rm "${RUN[@]}" "$IMAGE" sh -c 'jq -r ".deviceName+\" \"+.deviceId" /root/.config/todoforai/credentials.json' ;;
  *)     sed -n '2,8p' "$0"; exit 1 ;;
esac
