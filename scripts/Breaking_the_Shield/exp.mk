BTS_TARGET_DIR := $(REPO_ROOT)/targets/breaking_the_shield
BTS_BIN_DIR := $(BUILD_DIR)/bin/breaking_the_shield

BTS_PMU_TYPE ?= 4
BTS_LOAD_CONFIG ?= 0x81d0

BTS_SRCS := \
	$(BTS_TARGET_DIR)/main.c \
	$(BTS_TARGET_DIR)/breaking_the_shield_x86.c \
	$(BTS_TARGET_DIR)/breaking_the_shield_fault.S

BTS_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DBTS_PMU_TYPE=$(BTS_PMU_TYPE) \
	-DBTS_LOAD_CONFIG=$(BTS_LOAD_CONFIG) \
	-I$(BTS_TARGET_DIR)

BTS_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-ipa-icf \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-ffunction-sections \
	-fdata-sections

BTS_LDFLAGS := -Wl,--gc-sections

BTS_BINS := \
	$(BTS_BIN_DIR)/bts_region1_baseline \
	$(BTS_BIN_DIR)/bts_region1_attack \
	$(BTS_BIN_DIR)/bts_region2_baseline \
	$(BTS_BIN_DIR)/bts_region2_attack

.PHONY: breaking-the-shield breaking-the-shield-clean
breaking-the-shield: $(BTS_BINS)

$(BTS_BIN_DIR)/bts_region1_baseline: $(BTS_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(BTS_CPPFLAGS) $(BTS_CFLAGS) \
		-DBTS_REGION=1 -DBTS_ATTACK=0 \
		$(BTS_SRCS) $(BTS_LDFLAGS) \
		$(LDFLAGS) $(LDLIBS) -o $@

$(BTS_BIN_DIR)/bts_region1_attack: $(BTS_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(BTS_CPPFLAGS) $(BTS_CFLAGS) \
		-DBTS_REGION=1 -DBTS_ATTACK=1 \
		$(BTS_SRCS) $(BTS_LDFLAGS) \
		$(LDFLAGS) $(LDLIBS) -o $@

$(BTS_BIN_DIR)/bts_region2_baseline: $(BTS_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(BTS_CPPFLAGS) $(BTS_CFLAGS) \
		-DBTS_REGION=2 -DBTS_ATTACK=0 \
		$(BTS_SRCS) $(BTS_LDFLAGS) \
		$(LDFLAGS) $(LDLIBS) -o $@

$(BTS_BIN_DIR)/bts_region2_attack: $(BTS_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(BTS_CPPFLAGS) $(BTS_CFLAGS) \
		-DBTS_REGION=2 -DBTS_ATTACK=1 \
		$(BTS_SRCS) $(BTS_LDFLAGS) \
		$(LDFLAGS) $(LDLIBS) -o $@

breaking-the-shield-clean:
	rm -rf $(BTS_BIN_DIR)
