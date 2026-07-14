PESSL_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
PESSL_KYBER_DIR := $(PESSL_PQCLEAN_ROOT)/crypto_kem/kyber512/clean
PESSL_COMMON_DIR := $(PESSL_PQCLEAN_ROOT)/common
PESSL_TARGET_DIR := $(REPO_ROOT)/targets/pessl_fault_cca_kem
PESSL_BIN_DIR := $(BUILD_DIR)/bin/pessl_fault_cca_kem

PESSL_PMU_TYPE ?= 4
PESSL_LOAD_CONFIG ?= 0x81d0
PESSL_STORE_CONFIG ?= 0x82d0

PESSL_KYBER_SRCS := \
	$(PESSL_KYBER_DIR)/cbd.c \
	$(PESSL_KYBER_DIR)/indcpa.c \
	$(PESSL_KYBER_DIR)/kem.c \
	$(PESSL_KYBER_DIR)/ntt.c \
	$(PESSL_KYBER_DIR)/poly.c \
	$(PESSL_KYBER_DIR)/polyvec.c \
	$(PESSL_KYBER_DIR)/reduce.c \
	$(PESSL_KYBER_DIR)/symmetric-shake.c \
	$(PESSL_KYBER_DIR)/verify.c \
	$(PESSL_KYBER_DIR)/pessl_decode_x86.c

PESSL_COMMON_SRCS := \
	$(PESSL_COMMON_DIR)/fips202.c \
	$(PESSL_COMMON_DIR)/randombytes.c

PESSL_ALL_SRCS := \
	$(PESSL_TARGET_DIR)/main.c \
	$(PESSL_KYBER_SRCS) \
	$(PESSL_COMMON_SRCS)

PESSL_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DPQCLEAN_KYBER512_PESSL_X86=1 \
	-DPESSL_PMU_TYPE=$(PESSL_PMU_TYPE) \
	-DPESSL_LOAD_CONFIG=$(PESSL_LOAD_CONFIG) \
	-DPESSL_STORE_CONFIG=$(PESSL_STORE_CONFIG) \
	-I$(PESSL_KYBER_DIR) \
	-I$(PESSL_COMMON_DIR)

PESSL_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-ffunction-sections \
	-fdata-sections

PESSL_LDFLAGS := -Wl,--gc-sections

PESSL_BASE_BIN := $(PESSL_BIN_DIR)/pessl_decode_baseline
PESSL_ATTACK_BIN := $(PESSL_BIN_DIR)/pessl_decode_skip_shift

.PHONY: pessl-cca pessl-cca-clean

pessl-cca: $(PESSL_BASE_BIN) $(PESSL_ATTACK_BIN)

$(PESSL_BASE_BIN): $(PESSL_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(PESSL_CPPFLAGS) $(PESSL_CFLAGS) \
		-DPESSL_DECODE_BUILD_MODE=0 \
		$(PESSL_ALL_SRCS) \
		$(PESSL_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

$(PESSL_ATTACK_BIN): $(PESSL_ALL_SRCS)
	mkdir -p $(dir $@)
	$(CC) $(PESSL_CPPFLAGS) $(PESSL_CFLAGS) \
		-DPESSL_DECODE_BUILD_MODE=1 \
		$(PESSL_ALL_SRCS) \
		$(PESSL_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

pessl-cca-clean:
	rm -rf $(PESSL_BIN_DIR)
