XAGAWA_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
XAGAWA_KYBER_DIR := $(XAGAWA_PQCLEAN_ROOT)/crypto_kem/kyber512/clean
XAGAWA_COMMON_DIR := $(XAGAWA_PQCLEAN_ROOT)/common
XAGAWA_TARGET_DIR := $(REPO_ROOT)/targets/xagawa_round3_kem_fault
XAGAWA_BIN_DIR := $(BUILD_DIR)/bin/xagawa_round3_kem_fault

XAGAWA_PMU_TYPE ?= 4
XAGAWA_LOAD_CONFIG ?= 0x81d0
XAGAWA_STORE_CONFIG ?= 0x82d0

XAGAWA_KYBER_SRCS := \
	$(XAGAWA_KYBER_DIR)/cbd.c \
	$(XAGAWA_KYBER_DIR)/indcpa.c \
	$(XAGAWA_KYBER_DIR)/kem.c \
	$(XAGAWA_KYBER_DIR)/ntt.c \
	$(XAGAWA_KYBER_DIR)/poly.c \
	$(XAGAWA_KYBER_DIR)/polyvec.c \
	$(XAGAWA_KYBER_DIR)/reduce.c \
	$(XAGAWA_KYBER_DIR)/symmetric-shake.c \
	$(XAGAWA_KYBER_DIR)/verify.c \
	$(XAGAWA_KYBER_DIR)/xagawa_failure_handling_x86.c

XAGAWA_COMMON_SRCS := \
	$(XAGAWA_COMMON_DIR)/fips202.c \
	$(XAGAWA_COMMON_DIR)/randombytes.c

XAGAWA_ALL_SRCS := \
	$(XAGAWA_TARGET_DIR)/main.c \
	$(XAGAWA_KYBER_SRCS) \
	$(XAGAWA_COMMON_SRCS)

XAGAWA_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_KYBER512_XAGAWA_X86=1 \
	-DXAGAWA_PMU_TYPE=$(XAGAWA_PMU_TYPE) \
	-DXAGAWA_LOAD_CONFIG=$(XAGAWA_LOAD_CONFIG) \
	-DXAGAWA_STORE_CONFIG=$(XAGAWA_STORE_CONFIG) \
	-I$(XAGAWA_KYBER_DIR) \
	-I$(XAGAWA_COMMON_DIR)

XAGAWA_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-ffunction-sections \
	-fdata-sections

XAGAWA_LDFLAGS := -Wl,--gc-sections

XAGAWA_BASE_BIN := $(XAGAWA_BIN_DIR)/xagawa_cmov_baseline
XAGAWA_ATTACK_BIN := $(XAGAWA_BIN_DIR)/xagawa_cmov_skip

.PHONY: xagawa-round3-kem xagawa-round3-kem-clean

xagawa-round3-kem: $(XAGAWA_BASE_BIN) $(XAGAWA_ATTACK_BIN)

$(XAGAWA_BASE_BIN): $(XAGAWA_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(XAGAWA_CPPFLAGS) $(XAGAWA_CFLAGS) \
		-DXAGAWA_FAILURE_BUILD_MODE=0 \
		$(XAGAWA_ALL_SRCS) \
		$(XAGAWA_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

$(XAGAWA_ATTACK_BIN): $(XAGAWA_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(XAGAWA_CPPFLAGS) $(XAGAWA_CFLAGS) \
		-DXAGAWA_FAILURE_BUILD_MODE=1 \
		$(XAGAWA_ALL_SRCS) \
		$(XAGAWA_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

xagawa-round3-kem-clean:
	rm -rf $(XAGAWA_BIN_DIR)

# BEGIN XAGAWA OS CALL-PAIR DETECTOR
#
# These binaries are separate from the PMU result binaries.  The linker is
# forced to retain the cmov symbol in the skip binary so that a uprobe can be
# attached even though the call edge itself is intentionally absent.
XAGAWA_OS_PAIR_BASE_BIN := \
	$(XAGAWA_BIN_DIR)/xagawa_cmov_baseline_os_pair
XAGAWA_OS_PAIR_ATTACK_BIN := \
	$(XAGAWA_BIN_DIR)/xagawa_cmov_skip_os_pair

XAGAWA_OS_PAIR_KEEP_SYMBOL := \
	-Wl,--undefined=PQCLEAN_KYBER512_CLEAN_cmov

.PHONY: xagawa-round3-kem-os-pair

xagawa-round3-kem-os-pair: \
	$(XAGAWA_OS_PAIR_BASE_BIN) \
	$(XAGAWA_OS_PAIR_ATTACK_BIN)

$(XAGAWA_OS_PAIR_BASE_BIN): $(XAGAWA_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(XAGAWA_CPPFLAGS) $(XAGAWA_CFLAGS) \
		-DXAGAWA_FAILURE_BUILD_MODE=0 \
		$(XAGAWA_ALL_SRCS) \
		$(XAGAWA_LDFLAGS) $(XAGAWA_OS_PAIR_KEEP_SYMBOL) \
		$(LDFLAGS) $(LDLIBS) -o $@

$(XAGAWA_OS_PAIR_ATTACK_BIN): $(XAGAWA_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(XAGAWA_CPPFLAGS) $(XAGAWA_CFLAGS) \
		-DXAGAWA_FAILURE_BUILD_MODE=1 \
		$(XAGAWA_ALL_SRCS) \
		$(XAGAWA_LDFLAGS) $(XAGAWA_OS_PAIR_KEEP_SYMBOL) \
		$(LDFLAGS) $(LDLIBS) -o $@
# END XAGAWA OS CALL-PAIR DETECTOR
