KRAHMER_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
KRAHMER_DIL_DIR := $(KRAHMER_PQCLEAN_ROOT)/crypto_sign/dilithium2/clean
KRAHMER_COMMON_DIR := $(KRAHMER_PQCLEAN_ROOT)/common
KRAHMER_TARGET_DIR := $(REPO_ROOT)/targets/krahmer_correction_fault
KRAHMER_BIN_DIR := $(BUILD_DIR)/bin/krahmer_correction_fault

KRAHMER_PMU_TYPE ?= 4
KRAHMER_LOAD_CONFIG ?= 0x81d0
KRAHMER_STORE_CONFIG ?= 0x82d0

KRAHMER_DIL_SRCS := \
	$(KRAHMER_DIL_DIR)/ntt.c \
	$(KRAHMER_DIL_DIR)/packing.c \
	$(KRAHMER_DIL_DIR)/poly.c \
	$(KRAHMER_DIL_DIR)/polyvec.c \
	$(KRAHMER_DIL_DIR)/reduce.c \
	$(KRAHMER_DIL_DIR)/rounding.c \
	$(KRAHMER_DIL_DIR)/sign.c \
	$(KRAHMER_DIL_DIR)/symmetric-shake.c \
	$(KRAHMER_DIL_DIR)/krahmer_correction_fault_x86.c

KRAHMER_COMMON_SRCS := \
	$(KRAHMER_COMMON_DIR)/fips202.c \
	$(KRAHMER_COMMON_DIR)/randombytes.c

KRAHMER_ALL_SRCS := \
	$(KRAHMER_TARGET_DIR)/main.c \
	$(KRAHMER_DIL_SRCS) \
	$(KRAHMER_COMMON_SRCS)

KRAHMER_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_DILITHIUM2_KRAHMER_X86=1 \
	-DKRAHMER_PMU_TYPE=$(KRAHMER_PMU_TYPE) \
	-DKRAHMER_LOAD_CONFIG=$(KRAHMER_LOAD_CONFIG) \
	-DKRAHMER_STORE_CONFIG=$(KRAHMER_STORE_CONFIG) \
	-I$(KRAHMER_DIL_DIR) \
	-I$(KRAHMER_COMMON_DIR)

KRAHMER_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-fno-ipa-icf \
	-ffunction-sections \
	-fdata-sections

KRAHMER_LDFLAGS := -Wl,--gc-sections

KRAHMER_CORR_BASE := $(KRAHMER_BIN_DIR)/correction_baseline
KRAHMER_CORR_ATTACK := $(KRAHMER_BIN_DIR)/correction_skip_add

KRAHMER_A_BASE_STRUCT := $(KRAHMER_BIN_DIR)/a_baseline_structural
KRAHMER_A_ATTACK_STRUCT := $(KRAHMER_BIN_DIR)/a_load_zero_structural
KRAHMER_A_BASE_L1D := $(KRAHMER_BIN_DIR)/a_baseline_cache_l1d
KRAHMER_A_ATTACK_L1D := $(KRAHMER_BIN_DIR)/a_load_zero_cache_l1d
KRAHMER_A_BASE_LLC_DTLB := $(KRAHMER_BIN_DIR)/a_baseline_cache_llc_dtlb
KRAHMER_A_ATTACK_LLC_DTLB := $(KRAHMER_BIN_DIR)/a_load_zero_cache_llc_dtlb

.PHONY: krahmer-correction-fault krahmer-correction-fault-clean

krahmer-correction-fault: \
	$(KRAHMER_CORR_BASE) \
	$(KRAHMER_CORR_ATTACK) \
	$(KRAHMER_A_BASE_STRUCT) \
	$(KRAHMER_A_ATTACK_STRUCT) \
	$(KRAHMER_A_BASE_L1D) \
	$(KRAHMER_A_ATTACK_L1D) \
	$(KRAHMER_A_BASE_LLC_DTLB) \
	$(KRAHMER_A_ATTACK_LLC_DTLB)

define KRAHMER_BUILD
$1: $(KRAHMER_ALL_SRCS)
	mkdir -p $$(dir $$@)
	$$(CC) $$(KRAHMER_CPPFLAGS) $$(KRAHMER_CFLAGS) \
		-DKRAHMER_VARIANT=$2 \
		-DKRAHMER_ATTACK_BUILD=$3 \
		-DKRAHMER_COUNTER_SET=$4 \
		$$(KRAHMER_ALL_SRCS) \
		$$(KRAHMER_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@
endef

$(eval $(call KRAHMER_BUILD,$(KRAHMER_CORR_BASE),1,0,0))
$(eval $(call KRAHMER_BUILD,$(KRAHMER_CORR_ATTACK),1,1,0))

$(eval $(call KRAHMER_BUILD,$(KRAHMER_A_BASE_STRUCT),2,0,0))
$(eval $(call KRAHMER_BUILD,$(KRAHMER_A_ATTACK_STRUCT),2,1,0))
$(eval $(call KRAHMER_BUILD,$(KRAHMER_A_BASE_L1D),2,0,1))
$(eval $(call KRAHMER_BUILD,$(KRAHMER_A_ATTACK_L1D),2,1,1))
$(eval $(call KRAHMER_BUILD,$(KRAHMER_A_BASE_LLC_DTLB),2,0,2))
$(eval $(call KRAHMER_BUILD,$(KRAHMER_A_ATTACK_LLC_DTLB),2,1,2))

krahmer-correction-fault-clean:
	rm -rf $(KRAHMER_BIN_DIR)
