SIGNCORR_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
SIGNCORR_DIL_DIR := $(SIGNCORR_PQCLEAN_ROOT)/crypto_sign/dilithium2/clean
SIGNCORR_COMMON_DIR := $(SIGNCORR_PQCLEAN_ROOT)/common
SIGNCORR_TARGET_DIR := $(REPO_ROOT)/targets/islam_signature_correction
SIGNCORR_BIN_DIR := $(BUILD_DIR)/bin/islam_signature_correction

SIGNCORR_PMU_TYPE ?= 4
SIGNCORR_LOAD_CONFIG ?= 0x81d0
SIGNCORR_STORE_CONFIG ?= 0x82d0

SIGNCORR_DIL_SRCS := \
	$(SIGNCORR_DIL_DIR)/ntt.c \
	$(SIGNCORR_DIL_DIR)/packing.c \
	$(SIGNCORR_DIL_DIR)/poly.c \
	$(SIGNCORR_DIL_DIR)/polyvec.c \
	$(SIGNCORR_DIL_DIR)/reduce.c \
	$(SIGNCORR_DIL_DIR)/rounding.c \
	$(SIGNCORR_DIL_DIR)/sign.c \
	$(SIGNCORR_DIL_DIR)/symmetric-shake.c \
	$(SIGNCORR_DIL_DIR)/signature_correction_x86.c

SIGNCORR_COMMON_SRCS := \
	$(SIGNCORR_COMMON_DIR)/fips202.c \
	$(SIGNCORR_COMMON_DIR)/randombytes.c

SIGNCORR_ALL_SRCS := \
	$(SIGNCORR_TARGET_DIR)/main.c \
	$(SIGNCORR_DIL_SRCS) \
	$(SIGNCORR_COMMON_SRCS)

SIGNCORR_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_DILITHIUM2_SIGNATURE_CORRECTION_X86=1 \
	-DSIGNCORR_PMU_TYPE=$(SIGNCORR_PMU_TYPE) \
	-DSIGNCORR_LOAD_CONFIG=$(SIGNCORR_LOAD_CONFIG) \
	-DSIGNCORR_STORE_CONFIG=$(SIGNCORR_STORE_CONFIG) \
	-I$(SIGNCORR_DIL_DIR) \
	-I$(SIGNCORR_COMMON_DIR)

SIGNCORR_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-ffunction-sections \
	-fdata-sections

SIGNCORR_LDFLAGS := -Wl,--gc-sections

SIGNCORR_BIN := \
	$(SIGNCORR_BIN_DIR)/signature_correction_dilithium2

.PHONY: signcorr signcorr-clean

signcorr: $(SIGNCORR_BIN)

$(SIGNCORR_BIN): $(SIGNCORR_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(SIGNCORR_CPPFLAGS) $(SIGNCORR_CFLAGS) \
		$(SIGNCORR_ALL_SRCS) \
		$(SIGNCORR_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

signcorr-clean:
	rm -rf $(SIGNCORR_BIN_DIR)
