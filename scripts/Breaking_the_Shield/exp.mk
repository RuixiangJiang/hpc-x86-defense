BTS_TARGET_DIR := $(REPO_ROOT)/targets/breaking_the_shield
BTS_SCRIPT_DIR := $(REPO_ROOT)/scripts/Breaking_the_Shield
BTS_BIN_DIR := $(BUILD_DIR)/bin/breaking_the_shield
BTS_PMU_TYPE ?= 4
BTS_LOAD_CONFIG ?= 0x81d0
BTS_STORE_CONFIG ?= 0x82d0

BTS_SRCS := \
	$(BTS_TARGET_DIR)/main.c \
	$(BTS_TARGET_DIR)/breaking_the_shield_x86.c

BTS_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DBTS_PMU_TYPE=$(BTS_PMU_TYPE) \
	-DBTS_LOAD_CONFIG=$(BTS_LOAD_CONFIG) \
	-DBTS_STORE_CONFIG=$(BTS_STORE_CONFIG) \
	-I$(BTS_TARGET_DIR) \
	-I$(BTS_SCRIPT_DIR)

BTS_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-ffixed-r12 \
	-fno-ipa-icf \
	-ffunction-sections \
	-fdata-sections

BTS_LDFLAGS := -Wl,--gc-sections
BTS_BIN := $(BTS_BIN_DIR)/bts_single

.PHONY: breaking-the-shield breaking-the-shield-clean
breaking-the-shield: $(BTS_BIN)

$(BTS_BIN): $(BTS_SRCS) $(BTS_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $(dir $@)
	$(CC) $(BTS_CPPFLAGS) $(BTS_CFLAGS) \
		$(BTS_SRCS) $(BTS_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

breaking-the-shield-clean:
	rm -rf $(BTS_BIN_DIR)
