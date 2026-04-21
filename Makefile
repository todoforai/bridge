CC      ?= cc
CFLAGS  ?= -Os -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wno-unused-function \
           -ffunction-sections -fdata-sections -fomit-frame-pointer \
           -I../todoforai-c-core/noise -I../todoforai-c-core/cli -I../todoforai-c-core/login
LDFLAGS ?= -Wl,--gc-sections
LIBS    ?= -lutil

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS =
  LIBS    =
endif

CORE = ../todoforai-c-core
SRCS = main.c conn.c pty.c identity.c update.c util.c \
       $(CORE)/noise/noise.c $(CORE)/noise/vendor/monocypher.c $(CORE)/noise/vendor/blake2s.c
HDRS = conn.h pty.h identity.h update.h util.h json.h \
       $(CORE)/noise/noise.h $(CORE)/noise/vendor/monocypher.h \
       $(CORE)/noise/vendor/blake2.h $(CORE)/noise/vendor/blake2-impl.h \
       $(CORE)/cli/args.h $(CORE)/cli/vendor/ketopt.h $(CORE)/login/login.h

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

clean:
	rm -rf build
