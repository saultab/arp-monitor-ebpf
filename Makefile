# SPDX-License-Identifier: MIT
# Makefile for arp-monitor-ebpf
#
# Follows libbpf-bootstrap conventions.
# Requires: clang, llvm-strip, bpftool, libelf-dev, zlib

OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(shell which bpftool 2>/dev/null || echo $(abspath ./bpftool/src/bpftool))
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
VMLINUX := $(OUTPUT)/vmlinux.h

INCLUDES := -I$(OUTPUT) -Iinclude -Isrc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compiler flags
# Note: -pedantic omitted because libbpf LIBBPF_OPTS macro uses GCC statement expressions
CFLAGS := -g -O2 -Wall -Wextra -Werror -std=gnu11
LDFLAGS := -lelf -lz

# Sanitizer support (opt-in: make SANITIZE=1)
ifdef SANITIZE
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

APP := arp-monitor
BPF_SRC := src/bpf/arp_monitor.bpf.c
USER_SRCS := src/arp_monitor.c src/log.c src/spoof_detect.c

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all clean format check test

all: $(APP)

# ─── vmlinux.h generation ─────────────────────────────────────────────────
$(VMLINUX): | $(OUTPUT)
	$(call msg,VMLINUX,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ─── Build libbpf (static) ───────────────────────────────────────────────
$(OUTPUT)/libbpf:
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# ─── Build BPF object ────────────────────────────────────────────────────
$(OUTPUT)/arp_monitor.bpf.o: $(BPF_SRC) $(LIBBPF_OBJ) $(VMLINUX) include/arp_monitor.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(OUTPUT) -Iinclude \
		-c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@

# ─── Generate BPF skeleton ───────────────────────────────────────────────
$(OUTPUT)/arp_monitor.skel.h: $(OUTPUT)/arp_monitor.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# ─── Build userspace objects ─────────────────────────────────────────────
$(OUTPUT)/arp_monitor.o: src/arp_monitor.c $(OUTPUT)/arp_monitor.skel.h include/arp_monitor.h src/log.h src/spoof_detect.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/log.o: src/log.c src/log.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/spoof_detect.o: src/spoof_detect.c src/spoof_detect.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ─── Link final binary ───────────────────────────────────────────────────
$(APP): $(OUTPUT)/arp_monitor.o $(OUTPUT)/log.o $(OUTPUT)/spoof_detect.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# ─── Tests ────────────────────────────────────────────────────────────────
TEST_BIN := $(OUTPUT)/test_spoof_detect

$(OUTPUT)/test_spoof_detect: tests/test_spoof_detect.c src/spoof_detect.c src/spoof_detect.h | $(OUTPUT)
	$(call msg,TEST,$@)
	$(Q)$(CC) $(CFLAGS) -Isrc -Iinclude tests/test_spoof_detect.c src/spoof_detect.c -o $@

test: $(TEST_BIN)
	$(call msg,RUN,tests)
	$(Q)$(TEST_BIN)

# ─── Integration test ─────────────────────────────────────────────────────
.PHONY: integration-test
integration-test: $(APP)
	$(call msg,ITEST,tests/integration/test_veth.sh)
	$(Q)sudo tests/integration/test_veth.sh ./$(APP)

# ─── Static analysis ─────────────────────────────────────────────────────
.PHONY: check
check:
	$(Q)cppcheck --enable=all --suppress=missingIncludeSystem \
		--suppress=unusedFunction -Iinclude -Isrc src/*.c 2>&1
	$(Q)echo "Static analysis passed"

# ─── Format ───────────────────────────────────────────────────────────────
.PHONY: format format-check
format:
	$(Q)find src include tests -name '*.[ch]' | xargs clang-format -i

format-check:
	$(Q)find src include tests -name '*.[ch]' | xargs clang-format --dry-run -Werror

# ─── Directory creation ──────────────────────────────────────────────────
$(OUTPUT):
	$(Q)mkdir -p $@

# ─── Clean ────────────────────────────────────────────────────────────────
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP)

.DELETE_ON_ERROR:
.SECONDARY:
