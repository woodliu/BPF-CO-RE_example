# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/local/bin/bpftool
LIBBPF_SRC := $(abspath ../libbpf/src/)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = xdp_redirect_map
KERNEL_REL := $(shell uname -r)
VMLINUX_BTF := /root/linux-5.10.5/vmlinux
VMLINUX_BTF_PATHS := /sys/kernel/btf/vmlinux /boot/vmlinux-$(KERNEL_REL)
VMLINUX_BTF_PATH := $(or $(VMLINUX_BTF),$(firstword                            \
					$(wildcard $(VMLINUX_BTF_PATHS))))

.PHONY: all
all: $(APPS)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ)  | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ &&		      \
	$(LLVM_STRIP) -g $@

$(OUTPUT)/vmlinux.h: $(VMLINUX_BTF_PATH) | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN,$@)
	$(Q)if [ ! -e "$(VMLINUX_BTF_PATH)" ] ; then \
		echo "Couldn't find kernel BTF; set VMLINUX_BTF to"            \
			"specify its location." >&2;                           \
		exit 1;\
	fi
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

