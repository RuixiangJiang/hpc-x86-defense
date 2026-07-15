JENDRAL_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
JENDRAL_DIL_DIR := $(JENDRAL_PQCLEAN_ROOT)/crypto_sign/dilithium2/clean
JENDRAL_COMMON_DIR := $(JENDRAL_PQCLEAN_ROOT)/common
JENDRAL_TARGET_DIR := $(REPO_ROOT)/targets/jendral_hedged_fault
JENDRAL_BIN_DIR := $(BUILD_DIR)/bin/jendral_hedged_fault

JENDRAL_PMU_TYPE ?= 4
JENDRAL_LOAD_CONFIG ?= 0x81d0
JENDRAL_STORE_CONFIG ?= 0x82d0

JENDRAL_DIL_SRCS := \
	$(JENDRAL_DIL_DIR)/ntt.c \
	$(JENDRAL_DIL_DIR)/packing.c \
	$(JENDRAL_DIL_DIR)/poly.c \
	$(JENDRAL_DIL_DIR)/polyvec.c \
	$(JENDRAL_DIL_DIR)/reduce.c \
	$(JENDRAL_DIL_DIR)/rounding.c \
	$(JENDRAL_DIL_DIR)/sign.c \
	$(JENDRAL_DIL_DIR)/symmetric-shake.c \
	$(JENDRAL_DIL_DIR)/jendral_hedged_fault_x86.c

JENDRAL_COMMON_SRCS := \
	$(JENDRAL_COMMON_DIR)/fips202.c \
	$(JENDRAL_COMMON_DIR)/randombytes.c

JENDRAL_ALL_SRCS := \
	$(JENDRAL_TARGET_DIR)/main.c \
	$(JENDRAL_DIL_SRCS) \
	$(JENDRAL_COMMON_SRCS)

JENDRAL_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_DILITHIUM2_JENDRAL_X86=1 \
	-DJENDRAL_PMU_TYPE=$(JENDRAL_PMU_TYPE) \
	-DJENDRAL_LOAD_CONFIG=$(JENDRAL_LOAD_CONFIG) \
	-DJENDRAL_STORE_CONFIG=$(JENDRAL_STORE_CONFIG) \
	-I$(JENDRAL_DIL_DIR) \
	-I$(JENDRAL_COMMON_DIR)

JENDRAL_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-ffunction-sections \
	-fdata-sections

JENDRAL_LDFLAGS := -Wl,--gc-sections

JENDRAL_BASE_BIN := $(JENDRAL_BIN_DIR)/hedged_baseline
JENDRAL_ATTACK_BIN := $(JENDRAL_BIN_DIR)/skip_key_absorb

.PHONY: jendral-hedged-fault jendral-hedged-fault-clean

jendral-hedged-fault: $(JENDRAL_BASE_BIN) $(JENDRAL_ATTACK_BIN)

$(JENDRAL_BASE_BIN): $(JENDRAL_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(JENDRAL_CPPFLAGS) $(JENDRAL_CFLAGS) \
		-DJENDRAL_ATTACK_BUILD=0 \
		$(JENDRAL_ALL_SRCS) \
		$(JENDRAL_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

$(JENDRAL_ATTACK_BIN): $(JENDRAL_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(JENDRAL_CPPFLAGS) $(JENDRAL_CFLAGS) \
		-DJENDRAL_ATTACK_BUILD=1 \
		$(JENDRAL_ALL_SRCS) \
		$(JENDRAL_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

jendral-hedged-fault-clean:
	rm -rf $(JENDRAL_BIN_DIR)
