WRIR_TARGET_DIR := $(REPO_ROOT)/targets/when_randomness_isnt_random
WRIR_SCRIPT_DIR := $(REPO_ROOT)/scripts/When_Randomness_Isnt_Random
WRIR_BIN_DIR := $(BUILD_DIR)/bin/when_randomness_isnt_random

WRIR_INTENDED_DOMAIN ?= 4
WRIR_WRONG_DOMAIN ?= 0
WRIR_REDIRECT_BYTE ?= 0xa5
WRIR_PMU_TYPE ?= 4
WRIR_LOAD_CONFIG ?= 0x81d0
WRIR_STORE_CONFIG ?= 0x82d0

WRIR_SRCS := \
	$(WRIR_TARGET_DIR)/main.c \
	$(WRIR_TARGET_DIR)/when_randomness_isnt_random_x86.c

WRIR_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DWRIR_INTENDED_DOMAIN=$(WRIR_INTENDED_DOMAIN) \
	-DWRIR_WRONG_DOMAIN=$(WRIR_WRONG_DOMAIN) \
	-DWRIR_REDIRECT_BYTE=$(WRIR_REDIRECT_BYTE) \
	-DWRIR_PMU_TYPE=$(WRIR_PMU_TYPE) \
	-DWRIR_LOAD_CONFIG=$(WRIR_LOAD_CONFIG) \
	-DWRIR_STORE_CONFIG=$(WRIR_STORE_CONFIG) \
	-I$(WRIR_TARGET_DIR) \
	-I$(WRIR_SCRIPT_DIR)

WRIR_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-ffunction-sections \
	-fdata-sections

WRIR_LDFLAGS := -Wl,--gc-sections

WRIR_PASSES := \
	structural-instructions \
	structural-branches \
	structural-branch-misses \
	structural-loads \
	structural-stores \
	cache-l1d \
	cache-l1i \
	cache-llc \
	cache-dtlb \
	cache-references \
	cache-misses \
	cache-l1d-replacements \
	cache-l2-request-misses \
	load-l1-hit \
	load-l2-hit \
	load-l3-hit \
	load-l1-miss \
	load-l2-miss \
	load-l3-miss \
	long-latency-loads \
	stalls-frontend \
	stalls-backend \
	stalls-l1d-miss \
	stalls-mem-any \
	recovery-machine-clears \
	recovery-memory-ordering \
	recovery-cycles \
	recovery-cycles-any \
	uops-retired \
	uops-issued \
	uops-executed \
	frontend-uops-undelivered \
	frontend-mite-uops \
	frontend-dsb-uops \
	frontend-ms-uops \
	branch-conditional \
	branch-conditional-taken \
	branch-conditional-not-taken \
	branch-mispred-conditional \
	resource-stalls-scoreboard \
	resource-stalls-store-buffer \
	execution-bound-loads

WRIR_BIN := $(WRIR_BIN_DIR)/wrir_single

.PHONY: when-randomness-isnt-random when-randomness-isnt-random-clean
when-randomness-isnt-random: $(WRIR_BIN)

$(WRIR_BIN): $(WRIR_SRCS) $(WRIR_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $(dir $@)
	$(CC) $(WRIR_CPPFLAGS) $(WRIR_CFLAGS) \
		$(WRIR_SRCS) $(WRIR_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

when-randomness-isnt-random-clean:
	rm -rf $(WRIR_BIN_DIR)
