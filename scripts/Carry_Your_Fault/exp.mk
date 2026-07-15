CYF_TARGET_DIR := $(REPO_ROOT)/targets/carry_your_fault
CYF_SCRIPT_DIR := $(REPO_ROOT)/scripts/Carry_Your_Fault
CYF_BIN_DIR := $(BUILD_DIR)/bin/carry_your_fault

CYF_PMU_TYPE ?= 4
CYF_LOAD_CONFIG ?= 0x81d0
CYF_STORE_CONFIG ?= 0x82d0

CYF_SRCS := \
	$(CYF_TARGET_DIR)/main.c \
	$(CYF_TARGET_DIR)/carry_your_fault_a2b.c

CYF_HEADERS := \
	$(CYF_TARGET_DIR)/carry_your_fault_a2b.h \
	$(CYF_TARGET_DIR)/carry_your_fault_microarch_events_generated.h

CYF_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DCYF_PMU_TYPE=$(CYF_PMU_TYPE) \
	-DCYF_LOAD_CONFIG=$(CYF_LOAD_CONFIG) \
	-DCYF_STORE_CONFIG=$(CYF_STORE_CONFIG) \
	-I$(CYF_TARGET_DIR)

CYF_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-ipa-icf \
	-ffunction-sections \
	-fdata-sections

CYF_LDFLAGS := -Wl,--gc-sections

CYF_PASSES := \
	structural \
	cache \
	cache-detail \
	load-hits \
	load-misses-latency \
	stalls \
	recovery

CYF_structural_ID := 0
CYF_cache_ID := 1
CYF_cache-detail_ID := 2
CYF_load-hits_ID := 3
CYF_load-misses-latency_ID := 4
CYF_stalls_ID := 5
CYF_recovery_ID := 6

CYF_WINDOWS := exact-a2b post-fault
CYF_exact-a2b_ID := 0
CYF_post-fault_ID := 1

define CYF_DEFINE_BINARIES
CYF_BASE_$(1)_$(2) := $(CYF_BIN_DIR)/$(1)/$(2)/carry_your_fault_baseline
CYF_ATTACK_$(1)_$(2) := $(CYF_BIN_DIR)/$(1)/$(2)/carry_your_fault_stuck_at_1

$$(CYF_BASE_$(1)_$(2)): $$(CYF_SRCS) $$(CYF_HEADERS)
	mkdir -p $$(dir $$@)
	$$(CC) $$(CYF_CPPFLAGS) $$(CYF_CFLAGS) \
		-DCYF_BUILD_MODE=0 \
		-DCYF_WINDOW_MODE=$$(CYF_$(1)_ID) \
		-DCYF_COUNTER_SET=$$(CYF_$(2)_ID) \
		$$(CYF_SRCS) \
		$$(CYF_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@

$$(CYF_ATTACK_$(1)_$(2)): $$(CYF_SRCS) $$(CYF_HEADERS)
	mkdir -p $$(dir $$@)
	$$(CC) $$(CYF_CPPFLAGS) $$(CYF_CFLAGS) \
		-DCYF_BUILD_MODE=1 \
		-DCYF_WINDOW_MODE=$$(CYF_$(1)_ID) \
		-DCYF_COUNTER_SET=$$(CYF_$(2)_ID) \
		$$(CYF_SRCS) \
		$$(CYF_LDFLAGS) $$(LDFLAGS) $$(LDLIBS) -o $$@
endef

$(foreach window,$(CYF_WINDOWS), \
  $(foreach pass,$(CYF_PASSES), \
    $(eval $(call CYF_DEFINE_BINARIES,$(window),$(pass)))))

CYF_ALL_BINS := $(foreach window,$(CYF_WINDOWS), \
  $(foreach pass,$(CYF_PASSES), \
    $(CYF_BASE_$(window)_$(pass)) $(CYF_ATTACK_$(window)_$(pass))))

.PHONY: carry-your-fault carry-your-fault-clean

carry-your-fault: $(CYF_ALL_BINS)

carry-your-fault-clean:
	rm -rf $(CYF_BIN_DIR)

CYF_CACHE_DETAIL_BINS := $(foreach window,$(CYF_WINDOWS), \
  $(CYF_BASE_$(window)_cache-detail) $(CYF_ATTACK_$(window)_cache-detail))

.PHONY: carry-your-fault-cache-detail
carry-your-fault-cache-detail: $(CYF_CACHE_DETAIL_BINS)
