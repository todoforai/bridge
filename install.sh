#!/bin/sh
# TODOforAI Bridge installer.
#
#   curl -fsSL https://todofor.ai/bridge | sh
#   curl -fsSL https://todofor.ai/bridge | sh -s -- --token ENROLL_TOKEN
#   curl -fsSL https://todofor.ai/bridge | sh -s -- --token TOK --name host-02
#
# Options:
#   --token TOKEN     redeem an enrollment token (non-interactive login)
#   --name NAME       device name to register under
#   --prefix DIR      install dir (default: $HOME/.todoforai/bin)
#   --tag TAG         specific release tag (default: latest)
#   --no-service      skip systemd/launchd supervisor setup
#   --no-start        install but don't start the bridge
#
# Environment overrides: TODOFORAI_PREFIX, TODOFORAI_TAG.

set -eu

REPO="todoforai/bridge"
PREFIX="${TODOFORAI_PREFIX:-$HOME/.todoforai/bin}"
TAG="${TODOFORAI_TAG:-}"
TOKEN=""
DEVICE_NAME=""
DO_SERVICE=1
DO_START=1

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m::\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
TODOforAI Bridge installer.

  curl -fsSL https://todofor.ai/bridge | sh
  curl -fsSL https://todofor.ai/bridge | sh -s -- --token ENROLL_TOKEN
  curl -fsSL https://todofor.ai/bridge | sh -s -- --token TOK --name host-02

Options:
  --token TOKEN     redeem an enrollment token (non-interactive login)
  --name NAME       device name to register under
  --prefix DIR      install dir (default: $HOME/.todoforai/bin)
  --tag TAG         specific release tag (default: latest)
  --no-service      skip systemd/launchd supervisor setup
  --no-start        install but don't start the bridge
EOF
}

need_val() { [ -n "${2:-}" ] || die "$1 requires a value"; }

# ── parse args ──────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --token)      need_val "$1" "${2:-}"; TOKEN=$2;       shift 2 ;;
        --name)       need_val "$1" "${2:-}"; DEVICE_NAME=$2; shift 2 ;;
        --prefix)     need_val "$1" "${2:-}"; PREFIX=$2;      shift 2 ;;
        --tag)        need_val "$1" "${2:-}"; TAG=$2;         shift 2 ;;
        --no-service) DO_SERVICE=0; shift ;;
        --no-start)   DO_START=0; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

# ── detect OS / arch ────────────────────────────────────────────────────────
uname_s=$(uname -s)
uname_m=$(uname -m)
case "$uname_s" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    *)      die "unsupported OS: $uname_s (Windows coming soon)" ;;
esac
case "$uname_m" in
    x86_64|amd64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported arch: $uname_m" ;;
esac
asset="bridge-${os}-${arch}"

# ── fetch tool ──────────────────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q "$1" -O "$2"; }
else
    die "need curl or wget"
fi

# ── resolve release tag (default: latest) ──────────────────────────────────
if [ -z "$TAG" ]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [ -z "$TAG" ] && die "could not determine latest release (see https://github.com/$REPO/releases)"
fi
url="https://github.com/$REPO/releases/download/$TAG/$asset"
sha_url="${url}.sha256"

# ── download + verify ───────────────────────────────────────────────────────
mkdir -p "$PREFIX"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

info "downloading $asset ($TAG)"
fetch "$url"     "$tmp/bridge"     || die "download failed: $url"
fetch "$sha_url" "$tmp/bridge.sha" || die "checksum fetch failed: $sha_url"

expected=$(awk '{print $1}' "$tmp/bridge.sha")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/bridge" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/bridge" | awk '{print $1}')
else
    die "need sha256sum or shasum"
fi
[ "$expected" = "$actual" ] || die "sha256 mismatch: expected $expected, got $actual"

chmod +x "$tmp/bridge"
mv "$tmp/bridge" "$PREFIX/bridge"
size=$(wc -c <"$PREFIX/bridge" | tr -d ' ')
human=$(awk -v b="$size" 'BEGIN{ s="BKMGT"; for(i=1; b>=1024 && i<5; i++) b/=1024; printf (i==1?"%d %s":"%.1f %siB"), b, substr(s,i,1) }')
ok "installed $PREFIX/bridge ($human, $TAG)"

BRIDGE="$PREFIX/bridge"
CMD="$BRIDGE"   # what to suggest in user-facing messages

# ── PATH setup ──────────────────────────────────────────────────────────────
# 1) prefix already on PATH → done
# 2) ~/.local/bin on PATH → symlink there (no rc mutation)
# 3) fallback → append to active shell's rc file
case ":$PATH:" in
    *":$PREFIX:"*)
        CMD=bridge
        ;;
    *)
        case ":$PATH:" in
            *":$HOME/.local/bin:"*)
                mkdir -p "$HOME/.local/bin"
                ln -sf "$PREFIX/bridge" "$HOME/.local/bin/bridge"
                ok "linked into ~/.local/bin → run \`bridge\`"
                CMD=bridge
                ;;
            *)
                line="export PATH=\"$PREFIX:\$PATH\""
                case "${SHELL##*/}" in
                    zsh)  rc="$HOME/.zshrc" ;;
                    bash) rc="$HOME/.bashrc" ;;
                    *)    rc="$HOME/.profile" ;;
                esac
                if ! grep -qsF "$line" "$rc" 2>/dev/null; then
                    # ensure trailing newline before appending
                    [ -s "$rc" ] && [ -n "$(tail -c1 "$rc" 2>/dev/null)" ] && printf '\n' >>"$rc"
                    printf '\n# added by todoforai bridge installer\n%s\n' "$line" >>"$rc"
                    ok "added $PREFIX to PATH in $rc → run \`bridge\` in a new shell"
                fi
                info "for this shell: $line"
                ;;
        esac
        ;;
esac

# ── login ───────────────────────────────────────────────────────────────────
if [ -n "$TOKEN" ]; then
    info "redeeming enrollment token"
    if [ -n "$DEVICE_NAME" ]; then
        "$BRIDGE" login --token "$TOKEN" --device-name "$DEVICE_NAME"
    else
        "$BRIDGE" login --token "$TOKEN"
    fi
    ok "enrolled"
else
    info "authenticate with: $CMD login"
fi

# ── supervisor setup ────────────────────────────────────────────────────────
install_systemd_user() {
    unit_dir="$HOME/.config/systemd/user"
    mkdir -p "$unit_dir"
    cat >"$unit_dir/bridge.service" <<EOF
[Unit]
Description=TODOforAI Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BRIDGE
Restart=always
RestartSec=2
StartLimitIntervalSec=60
StartLimitBurst=10

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    if [ "$DO_START" = 1 ]; then
        systemctl --user enable --now bridge.service
        command -v loginctl >/dev/null 2>&1 && loginctl enable-linger "$USER" 2>/dev/null || true
        ok "systemd user service enabled and started"
    else
        systemctl --user enable bridge.service
        ok "systemd user service enabled (not started)"
    fi
}

install_launchd() {
    plist="$HOME/Library/LaunchAgents/ai.todofor.bridge.plist"
    mkdir -p "$(dirname "$plist")"
    cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.todofor.bridge</string>
  <key>ProgramArguments</key><array><string>$BRIDGE</string></array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  <key>ThrottleInterval</key><integer>2</integer>
  <key>StandardOutPath</key><string>/tmp/bridge.log</string>
  <key>StandardErrorPath</key><string>/tmp/bridge.log</string>
</dict>
</plist>
EOF
    if [ "$DO_START" = 1 ]; then
        launchctl unload "$plist" 2>/dev/null || true
        launchctl load -w "$plist"
        ok "launchd agent loaded"
    else
        ok "launchd plist written (not loaded)"
    fi
}

install_loop_fallback() {
    loop="$PREFIX/bridge-loop"
    cat >"$loop" <<EOF
#!/bin/sh
while :; do
    "$BRIDGE"
    rc=\$?
    case \$rc in 0|143) sleep 1 ;; *) sleep 5 ;; esac
done
EOF
    chmod +x "$loop"
    ok "restart loop written to $loop"
    info "start in background:  nohup $loop >/tmp/bridge.log 2>&1 &"
    info "persist across reboot: add '@reboot $loop >/tmp/bridge.log 2>&1 &' to crontab"
}

if [ "$DO_SERVICE" = 1 ]; then
    if [ "$os" = linux ] && command -v systemctl >/dev/null 2>&1 && \
       systemctl --user show-environment >/dev/null 2>&1; then
        install_systemd_user
    elif [ "$os" = darwin ]; then
        install_launchd
    else
        install_loop_fallback
    fi
fi

ok "done"
