REPO_ROOT := $(abspath .)
include $(REPO_ROOT)/repo.mk

SMOKE_SRC := $(REPO_ROOT)/targets/hpc_smoke/main.c
SMOKE_BIN := $(BUILD_DIR)/bin/hpc_smoke

.PHONY: all smoke clean print-config

all: smoke
smoke: $(SMOKE_BIN)

$(SMOKE_BIN): $(SMOKE_SRC)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

print-config:
	@echo "REPO_ROOT=$(REPO_ROOT)"
	@echo "BUILD_DIR=$(BUILD_DIR)"
	@echo "CC=$(CC)"
	@echo "CFLAGS=$(CFLAGS)"

clean:
	rm -rf $(BUILD_DIR)

# BEGIN HPC-X86 RAVI EXPLOITING DETERMINISM

RAVI_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
RAVI_DIL_DIR := $(RAVI_PQCLEAN_ROOT)/crypto_sign/dilithium2/clean
RAVI_COMMON_DIR := $(RAVI_PQCLEAN_ROOT)/common
RAVI_TARGET_DIR := $(REPO_ROOT)/targets/ravi_exploiting_determinism
RAVI_BIN_DIR := $(BUILD_DIR)/bin/ravi_exploiting_determinism

RAVI_DIL_SRCS := \
	$(RAVI_DIL_DIR)/ntt.c \
	$(RAVI_DIL_DIR)/packing.c \
	$(RAVI_DIL_DIR)/poly.c \
	$(RAVI_DIL_DIR)/polyvec.c \
	$(RAVI_DIL_DIR)/reduce.c \
	$(RAVI_DIL_DIR)/rounding.c \
	$(RAVI_DIL_DIR)/sign.c \
	$(RAVI_DIL_DIR)/symmetric-shake.c \
	$(RAVI_DIL_DIR)/ravi_z_generation_x86.c

RAVI_COMMON_SRCS := \
	$(RAVI_COMMON_DIR)/fips202.c \
	$(RAVI_COMMON_DIR)/randombytes.c

RAVI_ALL_SRCS := \
	$(RAVI_TARGET_DIR)/main.c \
	$(RAVI_DIL_SRCS) \
	$(RAVI_COMMON_SRCS)

RAVI_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_DILITHIUM2_RAVI_X86=1 \
	-I$(RAVI_DIL_DIR) \
	-I$(RAVI_COMMON_DIR)

RAVI_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto

RAVI_BASE_BIN := $(RAVI_BIN_DIR)/ravi_z_baseline
RAVI_SKIP_Y_BIN := $(RAVI_BIN_DIR)/ravi_z_skip_y
RAVI_SKIP_CS1_BIN := $(RAVI_BIN_DIR)/ravi_z_skip_cs1
RAVI_SKIP_STORE_BIN := $(RAVI_BIN_DIR)/ravi_z_skip_store

.PHONY: ravi ravi-clean

ravi: \
	$(RAVI_BASE_BIN) \
	$(RAVI_SKIP_Y_BIN) \
	$(RAVI_SKIP_CS1_BIN) \
	$(RAVI_SKIP_STORE_BIN)

$(RAVI_BASE_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) \
		-DRAVI_Z_BUILD_MODE=0 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_SKIP_Y_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) \
		-DRAVI_Z_BUILD_MODE=1 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_SKIP_CS1_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) \
		-DRAVI_Z_BUILD_MODE=2 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_SKIP_STORE_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) \
		-DRAVI_Z_BUILD_MODE=3 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

ravi-clean:
	rm -rf $(RAVI_BIN_DIR)

# END HPC-X86 RAVI EXPLOITING DETERMINISM

# BEGIN HPC-X86 RAVI NUMBER NOT USED ONCE
include $(REPO_ROOT)/scripts/Number_Not_Used_Once/exp.mk
# END HPC-X86 RAVI NUMBER NOT USED ONCE

# BEGIN HPC-X86 PESSL CCA KEM
include $(REPO_ROOT)/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/exp.mk
# END HPC-X86 PESSL CCA KEM

# BEGIN HPC-X86 XAGAWA ROUND3 KEM FAULT
include $(REPO_ROOT)/scripts/Fault-Injection_Attacks_against_NISTs_PQC_Round_3_KEM_Candidates/exp.mk
# END HPC-X86 XAGAWA ROUND3 KEM FAULT
