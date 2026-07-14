NNUO_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
NNUO_DIL_DIR := $(NNUO_PQCLEAN_ROOT)/crypto_sign/dilithium2/clean
NNUO_COMMON_DIR := $(NNUO_PQCLEAN_ROOT)/common
NNUO_TARGET_DIR := $(REPO_ROOT)/targets/number_not_used_once
NNUO_BIN_DIR := $(BUILD_DIR)/bin/number_not_used_once

NNUO_DIL_SRCS := \
	$(NNUO_DIL_DIR)/poly.c \
	$(NNUO_DIL_DIR)/ntt.c \
	$(NNUO_DIL_DIR)/reduce.c \
	$(NNUO_DIL_DIR)/rounding.c \
	$(NNUO_DIL_DIR)/symmetric-shake.c \
	$(NNUO_DIL_DIR)/ravi_nnuo_x86.c

NNUO_COMMON_SRCS := \
	$(NNUO_COMMON_DIR)/fips202.c

NNUO_ALL_SRCS := \
	$(NNUO_TARGET_DIR)/main.c \
	$(NNUO_DIL_SRCS) \
	$(NNUO_COMMON_SRCS)

NNUO_CPPFLAGS := \
	-D_GNU_SOURCE \
	-I$(NNUO_DIL_DIR) \
	-I$(NNUO_COMMON_DIR)

NNUO_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-ffunction-sections \
	-fdata-sections

NNUO_LINK_FLAGS := -Wl,--gc-sections

NNUO_BASE_BIN := $(NNUO_BIN_DIR)/nnuo_baseline
NNUO_ATTACK_BIN := $(NNUO_BIN_DIR)/nnuo_skip_increment

.PHONY: nnuo nnuo-clean

nnuo: $(NNUO_BASE_BIN) $(NNUO_ATTACK_BIN)

$(NNUO_BASE_BIN): $(NNUO_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(NNUO_CPPFLAGS) $(NNUO_CFLAGS) \
		-DNNUO_X86_BUILD_MODE=0 \
		$(NNUO_ALL_SRCS) $(LDFLAGS) $(NNUO_LINK_FLAGS) $(LDLIBS) -o $@

$(NNUO_ATTACK_BIN): $(NNUO_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(NNUO_CPPFLAGS) $(NNUO_CFLAGS) \
		-DNNUO_X86_BUILD_MODE=1 \
		$(NNUO_ALL_SRCS) $(LDFLAGS) $(NNUO_LINK_FLAGS) $(LDLIBS) -o $@

nnuo-clean:
	rm -rf $(NNUO_BIN_DIR)
