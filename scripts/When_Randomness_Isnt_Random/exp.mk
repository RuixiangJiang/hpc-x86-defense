WRIR_TARGET_DIR := $(REPO_ROOT)/targets/when_randomness_isnt_random
WRIR_BIN_DIR := $(BUILD_DIR)/bin/when_randomness_isnt_random

WRIR_PMU_TYPE ?= 4
WRIR_LOAD_CONFIG ?= 0x81d0
WRIR_STORE_CONFIG ?= 0x82d0

WRIR_SRCS := \
	$(WRIR_TARGET_DIR)/main.c \
	$(WRIR_TARGET_DIR)/when_randomness_isnt_random_x86.c \
	$(WRIR_TARGET_DIR)/when_randomness_isnt_random_fault.S

WRIR_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DWRIR_PMU_TYPE=$(WRIR_PMU_TYPE) \
	-DWRIR_LOAD_CONFIG=$(WRIR_LOAD_CONFIG) \
	-DWRIR_STORE_CONFIG=$(WRIR_STORE_CONFIG) \
	-I$(WRIR_TARGET_DIR)

WRIR_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-ipa-icf \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-ffunction-sections \
	-fdata-sections

WRIR_LDFLAGS := -Wl,--gc-sections

WRIR_PASS_instructions := 1
WRIR_PASS_retired-loads := 2
WRIR_PASS_retired-stores := 3
WRIR_PASS_l1d-misses := 4
WRIR_PASS_llc-misses := 5
WRIR_PASS_dtlb-misses := 6
WRIR_PASS_cache-references := 7
WRIR_PASS_cache-misses := 8

WRIR_CACHE_PASSES := \
	instructions \
	retired-loads \
	retired-stores \
	l1d-misses \
	llc-misses \
	dtlb-misses \
	cache-references \
	cache-misses

WRIR_MODE_baseline := 0
WRIR_MODE_attack := 1

define WRIR_DEFINE_BIN
$(WRIR_BIN_DIR)/wrir_r$(1)_$(2)_$(3): $(WRIR_SRCS)
	mkdir -p $$(dir $$@)
	$$(CC) $$(WRIR_CPPFLAGS) $$(WRIR_CFLAGS) \
		-DWRIR_REGION=$(1) \
		-DWRIR_ATTACK=$$(WRIR_MODE_$(2)) \
		-DWRIR_COUNTER_SET=$$(WRIR_PASS_$(3)) \
		$$(WRIR_SRCS) $$(WRIR_LDFLAGS) \
		$$(LDFLAGS) $$(LDLIBS) -o $$@
endef

$(foreach mode,baseline attack, \
	$(eval $(call WRIR_DEFINE_BIN,1,$(mode),instructions)))

$(foreach region,2 3, \
	$(foreach mode,baseline attack, \
		$(foreach pass,$(WRIR_CACHE_PASSES), \
			$(eval $(call WRIR_DEFINE_BIN,$(region),$(mode),$(pass))))))

WRIR_BINS := \
	$(foreach mode,baseline attack, \
		$(WRIR_BIN_DIR)/wrir_r1_$(mode)_instructions) \
	$(foreach region,2 3, \
		$(foreach mode,baseline attack, \
			$(foreach pass,$(WRIR_CACHE_PASSES), \
				$(WRIR_BIN_DIR)/wrir_r$(region)_$(mode)_$(pass))))

.PHONY: when-randomness-isnt-random when-randomness-isnt-random-clean
when-randomness-isnt-random: $(WRIR_BINS)

when-randomness-isnt-random-clean:
	rm -rf $(WRIR_BIN_DIR)
