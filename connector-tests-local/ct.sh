#!/usr/bin/env bash
# connector_tests_local — disposable test PCs in Docker for /internal/connector-tests.
#   ./ct.sh build        build the image (bundles your installed bridge binary)
#   ./ct.sh login        one-time device login, registers as "connector_tests_local"
#   ./ct.sh up           start the bridge (restarts with Docker)
#   ./ct.sh reset        wipe $HOME (installed tools + logins) — credentials are kept
#   ./ct.sh down | logs | shell | id
# Parallel pool: CT=<n> selects instance n (connector-tests-local-<n>, device "connector_tests_local_<n>").
#   CT=3 ./ct.sh enroll  register instance 3 with a token minted by the base instance (no browser)
#   ./ct.sh pool <N>     enroll+start instances 1..N; prints their device ids (allowlist them for the Lab)
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=todoforai/connector-tests-local
BASE=connector-tests-local
SUFFIX=${CT:+-$CT}
NAME=$BASE$SUFFIX HOME_VOL=ct-home$SUFFIX CRED_VOL=ct-bridge-creds$SUFFIX DEVICE=connector_tests_local${CT:+_$CT}
# Bridge credentials live on their own volume, so `reset` never forces a re-login.
RUN=(--network host -v "$HOME_VOL:/root" -v "$CRED_VOL:/root/.config/todoforai")
id_of() { docker run --rm "${RUN[@]}" "$IMAGE" sh -c 'jq -r ".deviceName+\" \"+.deviceId" /root/.config/todoforai/credentials.json'; }

case "${1:-}" in
  build) cp "$(readlink -f "$(command -v todoforai-bridge || echo ~/.todoforai/bin/todoforai-bridge)")" todoforai-bridge
         docker build -t "$IMAGE" . && rm todoforai-bridge ;;
  login) docker run --rm -it "${RUN[@]}" "$IMAGE" todoforai-bridge login --device-name "$DEVICE" --no-browser ;;
  enroll) token=$(docker exec "$BASE" todoforai-bridge enroll 2>/dev/null)
         # login --token keeps running as the bridge once enrolled; stop it when credentials exist.
         docker run -d --name "$NAME-enroll" "${RUN[@]}" "$IMAGE" todoforai-bridge login --token "$token" --device-name "$DEVICE" >/dev/null
         for _ in $(seq 60); do id_of >/dev/null 2>&1 && break; sleep 1; done
         docker rm -f "$NAME-enroll" >/dev/null; id_of >/dev/null ;;
  up)    docker rm -f "$NAME" >/dev/null 2>&1 || true
         docker run -d --name "$NAME" --restart unless-stopped "${RUN[@]}" "$IMAGE" >/dev/null && echo "$NAME up" ;;
  down)  docker rm -f "$NAME" ;;
  reset) docker rm -f "$NAME" >/dev/null 2>&1 || true
         docker volume rm "$HOME_VOL" >/dev/null 2>&1 || true
         echo "home wiped; ./ct.sh up to start clean" ;;
  pool)  for i in $(seq 1 "${2:?pool size}"); do
           docker volume inspect "ct-bridge-creds-$i" >/dev/null 2>&1 || CT=$i "$0" enroll
           CT=$i "$0" up >/dev/null; CT=$i "$0" id
         done ;;
  logs)  docker logs -f "$NAME" ;;
  shell) docker exec -it "$NAME" bash ;;
  id)    id_of ;;
  *)     sed -n '2,10p' "$0"; exit 1 ;;
esac
