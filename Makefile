CXX ?= c++
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
BUILD := build
BPF_ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/ppc64le/powerpc/' -e 's/riscv64/riscv/')

CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -Werror
BPF_CFLAGS ?= -O2 -g
BPF_CFLAGS += -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I$(BUILD) -I/usr/include
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)

.PHONY: all check clean

all: $(BUILD)/syzcall-trace

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/syzcall.bpf.o: syzcall.bpf.c event.h $(BUILD)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/syzcall.skel.h: $(BUILD)/syzcall.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/syzcall-trace: syzcall.cpp format.hpp event.h $(BUILD)/syzcall.skel.h
	$(CXX) $(CXXFLAGS) $(LIBBPF_CFLAGS) -I$(BUILD) syzcall.cpp -o $@ $(LIBBPF_LIBS) -lelf -lz

$(BUILD)/format-test: format_test.cpp format.hpp event.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -I. format_test.cpp -o $@

check: $(BUILD)/format-test
	$(BUILD)/format-test

clean:
	rm -rf $(BUILD)
