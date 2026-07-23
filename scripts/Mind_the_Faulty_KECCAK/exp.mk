MFK_TARGET_DIR := $(REPO_ROOT)/targets/mind_faulty_keccak
MFK_BIN_DIR := $(BUILD_DIR)/bin/mind_faulty_keccak

MFK_PMU_TYPE ?= 4
MFK_LOAD_CONFIG ?= 0x81d0
MFK_STORE_CONFIG ?= 0x82d0

MFK_SRCS := \
	$(MFK_TARGET_DIR)/main.c \
	$(MFK_TARGET_DIR)/mind_faulty_keccak_x86.c \
	$(MFK_TARGET_DIR)/mind_faulty_keccak_control.S

MFK_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DMFK_PMU_TYPE=$(MFK_PMU_TYPE) \
	-DMFK_LOAD_CONFIG=$(MFK_LOAD_CONFIG) \
	-DMFK_STORE_CONFIG=$(MFK_STORE_CONFIG) \
	-I$(MFK_TARGET_DIR)

MFK_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-ipa-icf \
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
	structural-stores

MFK_structural-instructions_ID := 1
MFK_structural-branches_ID := 2
MFK_structural-branch-misses_ID := 3
MFK_structural-loads_ID := 4
MFK_structural-stores_ID := 5

define MFK_DEFINE_PASS
MFK_BASE_$(1) := $(MFK_BIN_DIR)/mfk_movs_baseline_$(1)
MFK_ATTACK_$(1) := $(MFK_BIN_DIR)/mfk_movs_skip_$(1)

$$(MFK_BASE_$(1)): $$(MFK_SRCS)
	mkdir -p $$(dir $$@)
	$$(CC) $$(MFK_CPPFLAGS) $$(MFK_CFLAGS) \
		-DMFK_MOVS_SKIP_BUILD=0 \
		-DMFK_COUNTER_SET=$$(MFK_$(1)_ID) \
		$$(MFK_SRCS) $$(MFK_LDFLAGS) \
		$$(LDFLAGS) $$(LDLIBS) -o $$@

$$(MFK_ATTACK_$(1)): $$(MFK_SRCS)
	mkdir -p $$(dir $$@)
	$$(CC) $$(MFK_CPPFLAGS) $$(MFK_CFLAGS) \
		-DMFK_MOVS_SKIP_BUILD=1 \
		-DMFK_COUNTER_SET=$$(MFK_$(1)_ID) \
		$$(MFK_SRCS) $$(MFK_LDFLAGS) \
		$$(LDFLAGS) $$(LDLIBS) -o $$@
endef

$(foreach pass,$(MFK_PASSES),$(eval $(call MFK_DEFINE_PASS,$(pass))))

MFK_BINS := $(foreach pass,$(MFK_PASSES), \
	$(MFK_BASE_$(pass)) $(MFK_ATTACK_$(pass)))

.PHONY: mind-faulty-keccak mind-faulty-keccak-clean
mind-faulty-keccak: $(MFK_BINS)

mind-faulty-keccak-clean:
	rm -rf $(MFK_BIN_DIR)
