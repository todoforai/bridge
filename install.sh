#!/bin/sh
# TODOforAI Bridge installer. Run -h for usage.
# Env overrides: TODOFORAI_PREFIX, TODOFORAI_TAG.

set -eu

REPO="todoforai/bridge"
PREFIX="${TODOFORAI_PREFIX:-$HOME/.todoforai/bin}"
TAG="${TODOFORAI_TAG:-}"
TOKEN=""
DEVICE_NAME=""
DO_SERVICE=0

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m::\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
TODOforAI Bridge installer.

  curl -fsSL https://todofor.ai/bridge | sh
  curl -fsSL https://todofor.ai/bridge | sh -s -- --token ENROLL_TOKEN
  curl -fsSL https://todofor.ai/bridge | sh -s -- --name host-02

Options:
  --token TOKEN     enrollment token (printed in the suggested start command)
  --name NAME       device name to register under
  --prefix DIR      install dir (default: $HOME/.todoforai/bin)
  --tag TAG         specific release tag (default: latest)
  --service         install systemd/launchd supervisor so bridge auto-starts at login
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
        --service)    DO_SERVICE=1; shift ;;
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
asset="todoforai-bridge-${os}-${arch}"

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

fetch "$url"     "$tmp/todoforai-bridge"     || die "download failed: $url"
fetch "$sha_url" "$tmp/todoforai-bridge.sha" || die "checksum fetch failed: $sha_url"

expected=$(awk '{print $1}' "$tmp/todoforai-bridge.sha")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/todoforai-bridge" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/todoforai-bridge" | awk '{print $1}')
else
    die "need sha256sum or shasum"
fi
[ "$expected" = "$actual" ] || die "sha256 mismatch: expected $expected, got $actual"

size=$(wc -c <"$tmp/todoforai-bridge" | tr -d ' ')
human=$(awk -v b="$size" 'BEGIN{ s="BKMGT"; for(i=1; b>=1024 && i<5; i++) b/=1024; printf (i==1?"%d %s":"%.1f %siB"), b, substr(s,i,1) }')
ok "downloaded $asset $TAG ($human)"

chmod +x "$tmp/todoforai-bridge"
mv "$tmp/todoforai-bridge" "$PREFIX/todoforai-bridge"

BRIDGE="$PREFIX/todoforai-bridge"
CMD="$BRIDGE"   # what to suggest in user-facing messages
WHERE="$PREFIX/todoforai-bridge"
HINT=""

# ── PATH setup ──────────────────────────────────────────────────────────────
# An installer in a `curl | sh` pipe runs in a child process, so it can't
# mutate the parent shell's PATH. To make `todoforai-bridge` work in the
# SAME shell, we instead symlink the binary into a dir that's already on PATH.
# 1) prefix already on PATH → bare name works
# 2) writable dir already on PATH → symlink there → bare name works NOW
# 3) fallback → append to active shell's rc file (only new shells get it)

# Pick a writable dir already on PATH to symlink into. Prefer dirs under $HOME;
# otherwise take the first writable one (e.g. Homebrew's /opt/homebrew/bin or
# /usr/local/bin on macOS, which are user-writable and already on PATH).
pick_link_dir() {
    pref=""
    IFS=:
    for d in $PATH; do
        [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] || continue
        [ "$d" = "$PREFIX" ] && continue          # don't link into ourselves
        case "$d" in
            "$HOME"/*) unset IFS; printf '%s\n' "$d"; return 0 ;;  # home dirs first
            *) [ -z "$pref" ] && pref="$d" ;;                      # else first writable
        esac
    done
    unset IFS
    [ -n "$pref" ] && { printf '%s\n' "$pref"; return 0; }
    return 1
}

case ":$PATH:" in
    *":$PREFIX:"*)
        CMD=todoforai-bridge
        ;;
    *)
        if link_dir=$(pick_link_dir); then
            ln -sf "$PREFIX/todoforai-bridge" "$link_dir/todoforai-bridge"
            CMD=todoforai-bridge
            case "$link_dir" in
                "$HOME"/*) WHERE="$WHERE, linked into ~/${link_dir#$HOME/}" ;;
                *)         WHERE="$WHERE, linked into $link_dir" ;;
            esac
        else
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
                WHERE="$WHERE, added to PATH in ~/${rc#$HOME/}"
            fi
            # rc changes only apply to *new* shells; suggest the absolute
            # path so the Start command works in this shell right now.
            CMD="$BRIDGE"
            HINT=" (new shells get it on PATH; this shell: run the full path below)"
        fi
        ;;
esac
ok "installed $WHERE$HINT"

# ── next step ───────────────────────────────────────────────────────────────
# `todoforai-bridge` auto-launches login on first run (interactive or via
# --token), then runs the agent in the same process. So the installer just
# tells the user the one command to start.
next_cmd="$CMD"
if [ -n "$TOKEN" ] || [ -n "$DEVICE_NAME" ]; then
    next_cmd="$next_cmd login"
    [ -n "$TOKEN" ]       && next_cmd="$next_cmd --token $TOKEN"
    [ -n "$DEVICE_NAME" ] && next_cmd="$next_cmd --device-name $DEVICE_NAME"
fi
printf '\n  \033[1mStart the bridge:\033[0m\n\n' >&2
printf '      \033[1;36m$\033[0m \033[1;32m%s\033[0m\n\n' "$next_cmd" >&2

# ── supervisor setup ────────────────────────────────────────────────────────
install_systemd_user() {
    unit_dir="$HOME/.config/systemd/user"
    mkdir -p "$unit_dir"
    cat >"$unit_dir/todoforai-bridge.service" <<EOF
[Unit]
Description=TODOforAI Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BRIDGE
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now todoforai-bridge.service
    command -v loginctl >/dev/null 2>&1 && loginctl enable-linger "${USER:-$(id -un)}" 2>/dev/null || true
    ok "systemd user service enabled and started"
}

install_launchd() {
    plist="$HOME/Library/LaunchAgents/ai.todofor.todoforai-bridge.plist"
    mkdir -p "$(dirname "$plist")"
    cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.todofor.todoforai-bridge</string>
  <key>ProgramArguments</key><array><string>$BRIDGE</string></array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  <key>ThrottleInterval</key><integer>2</integer>
  <key>StandardOutPath</key><string>/tmp/todoforai-bridge.log</string>
  <key>StandardErrorPath</key><string>/tmp/todoforai-bridge.log</string>
</dict>
</plist>
EOF
    launchctl unload "$plist" 2>/dev/null || true
    launchctl load -w "$plist"
    ok "launchd agent loaded"
}

if [ "$DO_SERVICE" = 1 ]; then
    if [ "$os" = linux ] && command -v systemctl >/dev/null 2>&1 && \
       systemctl --user show-environment >/dev/null 2>&1; then
        install_systemd_user
    elif [ "$os" = darwin ]; then
        install_launchd
    else
        info "no supervisor detected; run manually: nohup $BRIDGE >/tmp/todoforai-bridge.log 2>&1 &"
    fi
fi


