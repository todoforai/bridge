CC      ?= cc

# Locate todoforai-c-core: prefer vendored submodule, else sibling checkout.
# An uninitialized submodule (empty vendor/todoforai-c-core dir) falls through
# to the sibling path; if neither exists, fail loudly instead of cryptic
# "no such file" from the compiler.
CORE := $(if $(wildcard vendor/todoforai-c-core/noise),vendor/todoforai-c-core,$(if $(wildcard ../todoforai-c-core/noise),../todoforai-c-core,))
ifeq ($(CORE),)
$(error todoforai-c-core not found. Run: git submodule update --init --recursive)
endif

# Version string baked into the binary. Derived from git so a tag is the
# single source of truth (no hand-edited #define to drift). Falls back to
# "dev" outside a git checkout (e.g. tarball builds).
BRIDGE_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

CFLAGS  ?= -Os -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wno-unused-function \
           -ffunction-sections -fdata-sections -fomit-frame-pointer \
           -DBRIDGE_VERSION=\"$(BRIDGE_VERSION)\" \
           -I$(CORE)/noise -I$(CORE)/cli -I$(CORE)/login
LDFLAGS ?= -Wl,--gc-sections
LIBS    ?= -lutil -lpthread

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS =
  LIBS    =
endif

COMMON_SRCS = main.c noise_ws.c identity.c subcmd.c tools.c update.c json.c ws.c \
       $(CORE)/noise/noise.c $(CORE)/noise/vendor/monocypher.c
SRCS = $(COMMON_SRCS) pty_posix.c
WIN_SRCS = $(COMMON_SRCS) pty_win.c
HDRS = noise_ws.h pty.h pty_win.c identity.h subcmd.h tools.h update.h json.h ws.h \
       $(CORE)/noise/noise.h $(CORE)/noise/vendor/monocypher.h \
       $(CORE)/cli/args.h $(CORE)/cli/vendor/ketopt.h $(CORE)/login/login.h

.PHONY: all clean dev

# Dev build: dynamic glibc (~113 KiB). Smaller than release (~161 KiB) only
# because libc isn't embedded. For release-equivalent static musl, use
# `make static` or `make release-linux-x64`.
all: build/todoforai-bridge

# Stamp the resolved version into a file; rewrite (and bump mtime) only when
# it changes. Make depends on this so a HEAD bump triggers a rebuild even
# though no .c/.h changed (BRIDGE_VERSION is baked in at compile time).
# Recursive `$(shell)` trick: re-evaluate every make invocation, but only
# touch the file when content differs.
_VERSION_CHECK := $(shell mkdir -p build; \
    echo "$(BRIDGE_VERSION)" | cmp -s - build/.version-stamp 2>/dev/null \
    || echo "$(BRIDGE_VERSION)" > build/.version-stamp)

build/todoforai-bridge: $(SRCS) $(HDRS) build/.version-stamp | build
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

# Windows: ConPTY backend (pty_win.c) + winsock (ws.c uses WSAPoll). zig cc
# bundles a recent mingw-w64.
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

# Static analysis: GCC analyzer + cppcheck + clang static analyzer (if present).
# Only scans bridge sources, not vendored todoforai-c-core / monocypher.
BRIDGE_SRCS := main.c noise_ws.c identity.c subcmd.c tools.c update.c json.c ws.c pty_posix.c
ANALYZE_INCLUDES := -I$(CORE)/noise -I$(CORE)/cli -I$(CORE)/login
ANALYZE_DEFS := -DBRIDGE_VERSION='"analyze"'

.PHONY: analyze analyze-gcc analyze-cppcheck analyze-scan-build
analyze: analyze-gcc analyze-cppcheck analyze-scan-build

analyze-gcc: | build
	@mkdir -p build/analysis
	@: > build/analysis/gcc-analyze.log
	@for f in $(BRIDGE_SRCS); do \
	    echo "=== $$f ===" >> build/analysis/gcc-analyze.log; \
	    $(CC) -fanalyzer -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
	        -Wnull-dereference -Wstrict-prototypes -Wmissing-prototypes \
	        -Wno-unused-function $(ANALYZE_DEFS) $(ANALYZE_INCLUDES) \
	        -c $$f -o /dev/null 2>> build/analysis/gcc-analyze.log; \
	done
	@echo "gcc -fanalyzer: $$(grep -c '^[^:]*:[0-9]*:[0-9]*: warning' build/analysis/gcc-analyze.log) warning(s) -> build/analysis/gcc-analyze.log"

analyze-cppcheck: | build
	@mkdir -p build/analysis
	@command -v cppcheck >/dev/null || { echo "cppcheck not installed; skipping"; exit 0; }
	@cppcheck --enable=all --inconclusive --std=c11 \
	    --suppress=missingIncludeSystem --suppress=unusedFunction \
	    --suppress=checkersReport \
	    $(ANALYZE_INCLUDES) -I. $(BRIDGE_SRCS) 2> build/analysis/cppcheck.log || true
	@echo "cppcheck: $$(grep -cE '^[^:]+:[0-9]+:[0-9]+:' build/analysis/cppcheck.log) finding(s) -> build/analysis/cppcheck.log"

analyze-scan-build: | build
	@mkdir -p build/analysis
	@command -v scan-build >/dev/null || { echo "scan-build not installed; skipping"; exit 0; }
	@scan-build -o build/analysis/scan-build $(CC) -O0 -g -Wall -Wextra \
	    -Wno-unused-function $(ANALYZE_DEFS) $(ANALYZE_INCLUDES) \
	    -o /tmp/_bridge_sb $(SRCS) $(LIBS) > build/analysis/scan-build.log 2>&1 || true
	@grep -E 'bug(s)? found|No bugs found' build/analysis/scan-build.log | tail -1

# Local dev: build + drop into ~/.todoforai/bin/ (on PATH) + print version.
dev: build/todoforai-bridge
	install -m755 $< $(HOME)/.todoforai/bin/todoforai-bridge
	@$(HOME)/.todoforai/bin/todoforai-bridge --version

clean:
	rm -rf build
