MFK_TARGET_DIR := $(REPO_ROOT)/targets/mind_faulty_keccak
MFK_SCRIPT_DIR := $(REPO_ROOT)/scripts/Mind_the_Faulty_KECCAK
MFK_BIN_DIR := $(BUILD_DIR)/bin/mind_faulty_keccak

MFK_ATTACK_ROUNDS ?= 8
MFK_SKIP_ROUND ?= 8
MFK_PMU_TYPE ?= 4
MFK_LOAD_CONFIG ?= 0x81d0
MFK_STORE_CONFIG ?= 0x82d0

MFK_SRCS := \
	$(MFK_TARGET_DIR)/main.c \
	$(MFK_TARGET_DIR)/mind_faulty_keccak_x86.c

MFK_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DMFK_ATTACK_ROUNDS=$(MFK_ATTACK_ROUNDS) \
	-DMFK_SKIP_ROUND=$(MFK_SKIP_ROUND) \
	-DMFK_PMU_TYPE=$(MFK_PMU_TYPE) \
	-DMFK_LOAD_CONFIG=$(MFK_LOAD_CONFIG) \
	-DMFK_STORE_CONFIG=$(MFK_STORE_CONFIG) \
	-I$(MFK_TARGET_DIR) \
	-I$(MFK_SCRIPT_DIR)

MFK_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-ffunction-sections \
	-fdata-sections

MFK_LDFLAGS := -Wl,--gc-sections

MFK_PASSES := \
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
	recovery-cycles-any

MFK_BINS := $(foreach pass,$(MFK_PASSES), \
	$(MFK_BIN_DIR)/mfk_abort_baseline_$(pass) \
	$(MFK_BIN_DIR)/mfk_loop_abort_$(pass) \
	$(MFK_BIN_DIR)/mfk_skip_baseline_$(pass) \
	$(MFK_BIN_DIR)/mfk_skip_round_$(pass))

.PHONY: mind-faulty-keccak mind-faulty-keccak-clean
mind-faulty-keccak: $(MFK_BINS)

define MFK_DEFINE_PASS
$(MFK_BIN_DIR)/mfk_abort_baseline_$(1): $(MFK_SRCS) $(MFK_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $$(dir $$@)
	$$(CC) $$(MFK_CPPFLAGS) $$(MFK_CFLAGS) -DMFK_VARIANT=0 -DMFK_COUNTER_SET=$(2) \
		$$(MFK_SRCS) $$(MFK_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@

$(MFK_BIN_DIR)/mfk_loop_abort_$(1): $(MFK_SRCS) $(MFK_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $$(dir $$@)
	$$(CC) $$(MFK_CPPFLAGS) $$(MFK_CFLAGS) -DMFK_VARIANT=1 -DMFK_COUNTER_SET=$(2) \
		$$(MFK_SRCS) $$(MFK_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@

$(MFK_BIN_DIR)/mfk_skip_baseline_$(1): $(MFK_SRCS) $(MFK_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $$(dir $$@)
	$$(CC) $$(MFK_CPPFLAGS) $$(MFK_CFLAGS) -DMFK_VARIANT=2 -DMFK_COUNTER_SET=$(2) \
		$$(MFK_SRCS) $$(MFK_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@

$(MFK_BIN_DIR)/mfk_skip_round_$(1): $(MFK_SRCS) $(MFK_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $$(dir $$@)
	$$(CC) $$(MFK_CPPFLAGS) $$(MFK_CFLAGS) -DMFK_VARIANT=3 -DMFK_COUNTER_SET=$(2) \
		$$(MFK_SRCS) $$(MFK_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@
endef

$(eval $(call MFK_DEFINE_PASS,structural-instructions,1))
$(eval $(call MFK_DEFINE_PASS,structural-branches,2))
$(eval $(call MFK_DEFINE_PASS,structural-branch-misses,3))
$(eval $(call MFK_DEFINE_PASS,structural-loads,4))
$(eval $(call MFK_DEFINE_PASS,structural-stores,5))
$(eval $(call MFK_DEFINE_PASS,cache-l1d,6))
$(eval $(call MFK_DEFINE_PASS,cache-l1i,7))
$(eval $(call MFK_DEFINE_PASS,cache-llc,8))
$(eval $(call MFK_DEFINE_PASS,cache-dtlb,9))
$(eval $(call MFK_DEFINE_PASS,cache-references,10))
$(eval $(call MFK_DEFINE_PASS,cache-misses,11))
$(eval $(call MFK_DEFINE_PASS,cache-l1d-replacements,12))
$(eval $(call MFK_DEFINE_PASS,cache-l2-request-misses,13))
$(eval $(call MFK_DEFINE_PASS,load-l1-hit,14))
$(eval $(call MFK_DEFINE_PASS,load-l2-hit,15))
$(eval $(call MFK_DEFINE_PASS,load-l3-hit,16))
$(eval $(call MFK_DEFINE_PASS,load-l1-miss,17))
$(eval $(call MFK_DEFINE_PASS,load-l2-miss,18))
$(eval $(call MFK_DEFINE_PASS,load-l3-miss,19))
$(eval $(call MFK_DEFINE_PASS,long-latency-loads,20))
$(eval $(call MFK_DEFINE_PASS,stalls-frontend,21))
$(eval $(call MFK_DEFINE_PASS,stalls-backend,22))
$(eval $(call MFK_DEFINE_PASS,stalls-l1d-miss,23))
$(eval $(call MFK_DEFINE_PASS,stalls-mem-any,24))
$(eval $(call MFK_DEFINE_PASS,recovery-machine-clears,25))
$(eval $(call MFK_DEFINE_PASS,recovery-memory-ordering,26))
$(eval $(call MFK_DEFINE_PASS,recovery-cycles,27))
$(eval $(call MFK_DEFINE_PASS,recovery-cycles-any,28))

mind-faulty-keccak-clean:
	rm -rf $(MFK_BIN_DIR)
