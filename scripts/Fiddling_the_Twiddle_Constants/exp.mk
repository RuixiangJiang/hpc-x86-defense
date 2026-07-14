FIDDLE_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
FIDDLE_DIL_DIR := $(FIDDLE_PQCLEAN_ROOT)/crypto_sign/dilithium2/clean
FIDDLE_COMMON_DIR := $(FIDDLE_PQCLEAN_ROOT)/common
FIDDLE_TARGET_DIR := $(REPO_ROOT)/targets/ravi_fiddling_twiddle
FIDDLE_BIN_DIR := $(BUILD_DIR)/bin/ravi_fiddling_twiddle

FIDDLE_PMU_TYPE ?= 4
FIDDLE_LOAD_CONFIG ?= 0x81d0
FIDDLE_STORE_CONFIG ?= 0x82d0

FIDDLE_DIL_SRCS := \
	$(FIDDLE_DIL_DIR)/ntt.c \
	$(FIDDLE_DIL_DIR)/packing.c \
	$(FIDDLE_DIL_DIR)/poly.c \
	$(FIDDLE_DIL_DIR)/polyvec.c \
	$(FIDDLE_DIL_DIR)/reduce.c \
	$(FIDDLE_DIL_DIR)/rounding.c \
	$(FIDDLE_DIL_DIR)/sign.c \
	$(FIDDLE_DIL_DIR)/symmetric-shake.c \
	$(FIDDLE_DIL_DIR)/fiddling_twiddle_x86.c

FIDDLE_COMMON_SRCS := \
	$(FIDDLE_COMMON_DIR)/fips202.c \
	$(FIDDLE_COMMON_DIR)/randombytes.c

FIDDLE_ALL_SRCS := \
	$(FIDDLE_TARGET_DIR)/main.c \
	$(FIDDLE_DIL_SRCS) \
	$(FIDDLE_COMMON_SRCS)

FIDDLE_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_DILITHIUM2_FIDDLE_TWIDDLE_X86=1 \
	-DFIDDLE_TWIDDLE_PMU_TYPE=$(FIDDLE_PMU_TYPE) \
	-DFIDDLE_TWIDDLE_LOAD_CONFIG=$(FIDDLE_LOAD_CONFIG) \
	-DFIDDLE_TWIDDLE_STORE_CONFIG=$(FIDDLE_STORE_CONFIG) \
	-I$(FIDDLE_DIL_DIR) \
	-I$(FIDDLE_COMMON_DIR)

FIDDLE_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-ffunction-sections \
	-fdata-sections

FIDDLE_LDFLAGS := -Wl,--gc-sections

FIDDLE_BASE_BIN := \
	$(FIDDLE_BIN_DIR)/fiddling_twiddle_baseline
FIDDLE_ATTACK_BIN := \
	$(FIDDLE_BIN_DIR)/fiddling_twiddle_zero

.PHONY: fiddle-twiddle fiddle-twiddle-clean

fiddle-twiddle: $(FIDDLE_BASE_BIN) $(FIDDLE_ATTACK_BIN)

$(FIDDLE_BASE_BIN): $(FIDDLE_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(FIDDLE_CPPFLAGS) $(FIDDLE_CFLAGS) \
		-DFIDDLE_TWIDDLE_BUILD_MODE=0 \
		$(FIDDLE_ALL_SRCS) \
		$(FIDDLE_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

$(FIDDLE_ATTACK_BIN): $(FIDDLE_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(FIDDLE_CPPFLAGS) $(FIDDLE_CFLAGS) \
		-DFIDDLE_TWIDDLE_BUILD_MODE=1 \
		$(FIDDLE_ALL_SRCS) \
		$(FIDDLE_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

fiddle-twiddle-clean:
	rm -rf $(FIDDLE_BIN_DIR)
