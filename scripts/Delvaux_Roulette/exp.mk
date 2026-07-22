ROU_PQCLEAN_ROOT := $(REPO_ROOT)/third_party/pqm4/mupq/pqclean
ROU_KYBER_DIR := $(ROU_PQCLEAN_ROOT)/crypto_kem/kyber768/clean
ROU_COMMON_DIR := $(ROU_PQCLEAN_ROOT)/common
ROU_TARGET_DIR := $(REPO_ROOT)/targets/delvaux_roulette
ROU_SCRIPT_DIR := $(REPO_ROOT)/scripts/Delvaux_Roulette
ROU_BIN_DIR := $(BUILD_DIR)/bin/delvaux_roulette
ROU_PMU_TYPE ?= 4
ROU_LOAD_CONFIG ?= 0x81d0
ROU_STORE_CONFIG ?= 0x82d0
ROU_KYBER_SRCS := $(ROU_KYBER_DIR)/cbd.c $(ROU_KYBER_DIR)/indcpa.c $(ROU_KYBER_DIR)/kem.c \
	$(ROU_KYBER_DIR)/ntt.c $(ROU_KYBER_DIR)/poly.c $(ROU_KYBER_DIR)/polyvec.c \
	$(ROU_KYBER_DIR)/reduce.c $(ROU_KYBER_DIR)/symmetric-shake.c $(ROU_KYBER_DIR)/verify.c \
	$(ROU_KYBER_DIR)/roulette_masked_invntt_x86.c \
	$(ROU_KYBER_DIR)/roulette_targets_x86_64.S
ROU_COMMON_SRCS := $(ROU_COMMON_DIR)/fips202.c $(ROU_COMMON_DIR)/randombytes.c
ROU_SRCS := $(ROU_TARGET_DIR)/main.c $(ROU_KYBER_SRCS) $(ROU_COMMON_SRCS)
ROU_CPPFLAGS := -D_GNU_SOURCE -DPQCLEAN_KYBER768_ROULETTE_X86=1 \
	-DROU_PMU_TYPE=$(ROU_PMU_TYPE) -DROU_LOAD_CONFIG=$(ROU_LOAD_CONFIG) -DROU_STORE_CONFIG=$(ROU_STORE_CONFIG) \
	-I$(ROU_KYBER_DIR) -I$(ROU_COMMON_DIR) -I$(ROU_TARGET_DIR) -I$(ROU_SCRIPT_DIR)
ROU_CFLAGS := -O2 -g -std=c11 -Wall -Wextra -Wpedantic -fno-omit-frame-pointer -fno-lto \
	-fno-stack-protector -fno-tree-vectorize -fno-ipa-icf -ffunction-sections -fdata-sections
ROU_LDFLAGS := -Wl,--gc-sections
ROU_BIN := $(ROU_BIN_DIR)/rou_single
.PHONY: delvaux-roulette delvaux-roulette-clean
delvaux-roulette: $(ROU_BIN)
$(ROU_BIN): $(ROU_SRCS) $(ROU_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $(dir $@)
	$(CC) $(ROU_CPPFLAGS) $(ROU_CFLAGS) $(ROU_SRCS) $(ROU_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@
delvaux-roulette-clean:
	rm -rf $(ROU_BIN_DIR)
