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
	$(RAVI_DIL_DIR)/ravi_z_generation_x86.c \
	$(RAVI_DIL_DIR)/ravi_z_targets_x86_64.S

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

RAVI_V1_BASE_BIN := $(RAVI_BIN_DIR)/ravi_v1_baseline
RAVI_V1_ATTACK_BIN := $(RAVI_BIN_DIR)/ravi_v1_skip_store
RAVI_V2_BASE_BIN := $(RAVI_BIN_DIR)/ravi_v2_baseline
RAVI_V2_ATTACK_BIN := $(RAVI_BIN_DIR)/ravi_v2_skip_store
RAVI_V3_BASE_BIN := $(RAVI_BIN_DIR)/ravi_v3_baseline
RAVI_V3_ATTACK_BIN := $(RAVI_BIN_DIR)/ravi_v3_skip_add

.PHONY: ravi ravi-clean ravi-verify

ravi: \
	$(RAVI_V1_BASE_BIN) \
	$(RAVI_V1_ATTACK_BIN) \
	$(RAVI_V2_BASE_BIN) \
	$(RAVI_V2_ATTACK_BIN) \
	$(RAVI_V3_BASE_BIN) \
	$(RAVI_V3_ATTACK_BIN)

$(RAVI_V1_BASE_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) -DRAVI_Z_BUILD_MODE=0 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_V1_ATTACK_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) -DRAVI_Z_BUILD_MODE=1 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_V2_BASE_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) -DRAVI_Z_BUILD_MODE=2 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_V2_ATTACK_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) -DRAVI_Z_BUILD_MODE=3 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_V3_BASE_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) -DRAVI_Z_BUILD_MODE=4 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

$(RAVI_V3_ATTACK_BIN): $(RAVI_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(RAVI_CPPFLAGS) $(RAVI_CFLAGS) -DRAVI_Z_BUILD_MODE=5 \
		$(RAVI_ALL_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

ravi-verify: ravi
	$(REPO_ROOT)/scripts/Exploiting_Determinism_in_Lattice_based_Signatures/verify_paper_assembly.sh

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


# BEGIN HPC-X86 ISLAM SIGNATURE CORRECTION
include $(REPO_ROOT)/scripts/Islam_Signature_Correction_Attack/exp.mk
# END HPC-X86 ISLAM SIGNATURE CORRECTION

# BEGIN HPC-X86 RAVI FIDDLING TWIDDLE
include $(REPO_ROOT)/scripts/Fiddling_the_Twiddle_Constants/exp.mk
# END HPC-X86 RAVI FIDDLING TWIDDLE

# BEGIN HPC-X86 KRAHMER CORRECTION FAULT
include $(REPO_ROOT)/scripts/Correction_Fault_Attacks_on_Randomized_Dilithium/exp.mk
# END HPC-X86 KRAHMER CORRECTION FAULT

# BEGIN HPC-X86 JENDRAL HEDGED FAULT
include $(REPO_ROOT)/scripts/A_Single_Trace_Fault_Injection_Attack_on_Hedged_CRYSTALS_Dilithium/exp.mk
# END HPC-X86 JENDRAL HEDGED FAULT


# BEGIN HPC-X86 KUNDU CARRY YOUR FAULT
include $(REPO_ROOT)/scripts/Carry_Your_Fault/exp.mk
# END HPC-X86 KUNDU CARRY YOUR FAULT

# BEGIN HPC-X86 MIND THE FAULTY KECCAK
include $(REPO_ROOT)/scripts/Mind_the_Faulty_KECCAK/exp.mk
# END HPC-X86 MIND THE FAULTY KECCAK

# BEGIN HPC-X86 WHEN RANDOMNESS ISNT RANDOM
include $(REPO_ROOT)/scripts/When_Randomness_Isnt_Random/exp.mk
# END HPC-X86 WHEN RANDOMNESS ISNT RANDOM

# BEGIN HPC-X86 DU BREAKING SHIELD
include $(REPO_ROOT)/scripts/Breaking_the_Shield/exp.mk
# END HPC-X86 DU BREAKING SHIELD

# BEGIN HPC-X86 WANG SECRET IN ONEPIECE
include $(REPO_ROOT)/scripts/Secret_in_OnePiece/exp.mk
# END HPC-X86 WANG SECRET IN ONEPIECE

# BEGIN HPC-X86 DELVAUX ROULETTE
include $(REPO_ROOT)/scripts/Delvaux_Roulette/exp.mk
# END HPC-X86 DELVAUX ROULETTE
