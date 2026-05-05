CC      ?= cc
CFLAGS  ?= -Os -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wno-unused-function \
           -ffunction-sections -fdata-sections -fomit-frame-pointer \
           -DMG_TLS=MG_TLS_NONE -DMG_ENABLE_PACKED_FS=0 -DMG_ENABLE_FILE=0 \
           -DMG_ENABLE_MQTT=0 -DMG_ENABLE_SSI=0 -DMG_ENABLE_DIRECTORY_LISTING=0 \
           -DMG_ENABLE_LOG=0 -DMG_ENABLE_CUSTOM_RANDOM=1 \
           -I../todoforai-c-core/noise -I../todoforai-c-core/cli \
           -I../todoforai-c-core/login -I../todoforai-c-core/vendor/mongoose
LDFLAGS ?= -Wl,--gc-sections
LIBS    ?= -lutil

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS =
  LIBS    =
endif

CORE = ../todoforai-c-core
COMMON_SRCS = main.c noise_ws.c identity.c subcmd.c tools.c update.c \
       $(CORE)/noise/noise.c $(CORE)/noise/vendor/monocypher.c \
       $(CORE)/vendor/mongoose/mongoose.c
SRCS = $(COMMON_SRCS) pty_posix.c
WIN_SRCS = $(COMMON_SRCS) pty_win.c
HDRS = noise_ws.h pty.h pty_win.c identity.h subcmd.h tools.h update.h \
       $(CORE)/noise/noise.h $(CORE)/noise/vendor/monocypher.h \
       $(CORE)/cli/args.h $(CORE)/cli/vendor/ketopt.h $(CORE)/login/login.h \
       $(CORE)/vendor/mongoose/mongoose.h

.PHONY: all clean

all: build/todoforai-bridge

build/todoforai-bridge: $(SRCS) $(HDRS) | build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LIBS)
	strip $@ 2>/dev/null || true

build:
	mkdir -p build

# Static musl build via zig cc (drop-anywhere binary, no deps).
# Requires `zig` in PATH.
.PHONY: static
static: | build
	zig cc -target x86_64-linux-musl -static $(CFLAGS) -o build/todoforai-bridge-static \
	    $(SRCS) -lutil
	strip build/todoforai-bridge-static 2>/dev/null || true

# ── Release targets ─────────────────────────────────────────────────────────
# Produce a single stripped artifact named build/todoforai-bridge-<os>-<arch>.
# Used by CI; locally requires `zig` (Linux) or Xcode clang (macOS).

.PHONY: release-linux-x64 release-linux-arm64 release-darwin-x64 release-darwin-arm64 release-windows-x64

release-linux-x64: | build
	zig cc -target x86_64-linux-musl -static $(CFLAGS) -o build/todoforai-bridge-linux-x64 $(SRCS) -lutil
	strip build/todoforai-bridge-linux-x64 2>/dev/null || true

release-linux-arm64: | build
	zig cc -target aarch64-linux-musl -static $(CFLAGS) -o build/todoforai-bridge-linux-arm64 $(SRCS) -lutil
	strip build/todoforai-bridge-linux-arm64 2>/dev/null || true

# macOS: link to system libc (no static option on darwin); Xcode's clang picks the SDK.
# _DARWIN_C_SOURCE re-enables BSD extensions (memmem, strcasestr, SIGWINCH)
# that _POSIX_C_SOURCE otherwise hides.
release-darwin-x64: | build
	clang -target x86_64-apple-macos11 -D_DARWIN_C_SOURCE $(CFLAGS) -o build/todoforai-bridge-darwin-x64 $(SRCS)
	strip build/todoforai-bridge-darwin-x64 2>/dev/null || true

release-darwin-arm64: | build
	clang -target arm64-apple-macos11 -D_DARWIN_C_SOURCE $(CFLAGS) -o build/todoforai-bridge-darwin-arm64 $(SRCS)
	strip build/todoforai-bridge-darwin-arm64 2>/dev/null || true

# Windows: ConPTY backend (pty_win.c) + winsock; mongoose auto-selects its
# Win32 arch via _WIN32. zig cc bundles a recent mingw-w64.
# _WIN32_WINNT=0x0A00 unlocks CreatePseudoConsole (Win10 1809+).
release-windows-x64: | build
	zig cc -target x86_64-windows-gnu \
	    -U_WIN32_WINNT -UNTDDI_VERSION -UWINVER \
	    -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000006 -DWINVER=0x0A00 \
	    -Wno-macro-redefined \
	    $(CFLAGS) \
	    -o build/todoforai-bridge-windows-x64.exe $(WIN_SRCS) \
	    -lws2_32 -ladvapi32 -luserenv -lshell32 -lole32
	strip build/todoforai-bridge-windows-x64.exe 2>/dev/null || true

# Sentinel-scanner smoke test: spawns a real PTY with echo off, runs a few
# wrapped commands, asserts the bridge's emit/parse logic matches.
.PHONY: test-run
test-run: | build
	$(CC) -O0 -g -Wall -Wextra -o build/test-run test_run.c pty_posix.c -lutil
	./build/test-run

clean:
	rm -rf build
