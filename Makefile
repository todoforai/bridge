CC      ?= cc
CFLAGS  ?= -Os -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wno-unused-function \
           -ffunction-sections -fdata-sections -fomit-frame-pointer \
           -DMG_TLS=MG_TLS_NONE -DMG_ENABLE_PACKED_FS=0 -DMG_ENABLE_FILE=0 \
           -DMG_ENABLE_MQTT=0 -DMG_ENABLE_SSI=0 -DMG_ENABLE_DIRECTORY_LISTING=0 \
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
SRCS = main.c noise_ws.c pty_posix.c identity.c tools.c update.c \
       $(CORE)/noise/noise.c $(CORE)/noise/vendor/monocypher.c \
       $(CORE)/vendor/mongoose/mongoose.c
HDRS = noise_ws.h pty.h identity.h tools.h update.h \
       $(CORE)/noise/noise.h $(CORE)/noise/vendor/monocypher.h \
       $(CORE)/cli/args.h $(CORE)/cli/vendor/ketopt.h $(CORE)/login/login.h \
       $(CORE)/vendor/mongoose/mongoose.h

.PHONY: all clean

all: build/bridge

build/bridge: $(SRCS) $(HDRS) | build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LIBS)

build:
	mkdir -p build

# Static musl build via zig cc (drop-anywhere binary, no deps).
# Requires `zig` in PATH.
.PHONY: static
static: | build
	zig cc -target x86_64-linux-musl -static $(CFLAGS) -o build/bridge-static \
	    $(SRCS) -lutil

# ── Release targets ─────────────────────────────────────────────────────────
# Produce a single stripped artifact named build/bridge-<os>-<arch>.
# Used by CI; locally requires `zig` (Linux) or Xcode clang (macOS).

.PHONY: release-linux-x64 release-linux-arm64 release-darwin-x64 release-darwin-arm64

release-linux-x64: | build
	zig cc -target x86_64-linux-musl -static $(CFLAGS) -o build/bridge-linux-x64 $(SRCS) -lutil
	strip build/bridge-linux-x64 2>/dev/null || true

release-linux-arm64: | build
	zig cc -target aarch64-linux-musl -static $(CFLAGS) -o build/bridge-linux-arm64 $(SRCS) -lutil
	strip build/bridge-linux-arm64 2>/dev/null || true

# macOS: link to system libc (no static option on darwin); Xcode's clang picks the SDK.
# _DARWIN_C_SOURCE re-enables BSD extensions (memmem, strcasestr, SIGWINCH)
# that _POSIX_C_SOURCE otherwise hides.
release-darwin-x64: | build
	clang -target x86_64-apple-macos11 -D_DARWIN_C_SOURCE $(CFLAGS) -o build/bridge-darwin-x64 $(SRCS)
	strip build/bridge-darwin-x64 2>/dev/null || true

release-darwin-arm64: | build
	clang -target arm64-apple-macos11 -D_DARWIN_C_SOURCE $(CFLAGS) -o build/bridge-darwin-arm64 $(SRCS)
	strip build/bridge-darwin-arm64 2>/dev/null || true

# Sentinel-scanner smoke test: spawns a real PTY with echo off, runs a few
# wrapped commands, asserts the bridge's emit/parse logic matches.
.PHONY: test-run
test-run: | build
	$(CC) -O0 -g -Wall -Wextra -o build/test-run test_run.c pty_posix.c -lutil
	./build/test-run

clean:
	rm -rf build
