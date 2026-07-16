SIO_TARGET_DIR := $(REPO_ROOT)/targets/secret_in_onepiece
SIO_SCRIPT_DIR := $(REPO_ROOT)/scripts/Secret_in_OnePiece
SIO_BIN_DIR := $(BUILD_DIR)/bin/secret_in_onepiece
SIO_PMU_TYPE ?= 4
SIO_LOAD_CONFIG ?= 0x81d0
SIO_STORE_CONFIG ?= 0x82d0

SIO_SRCS := \
	$(SIO_TARGET_DIR)/main.c \
	$(SIO_TARGET_DIR)/secret_in_onepiece_x86.c

SIO_CPPFLAGS := \
	-D_GNU_SOURCE \
	-DSIO_PMU_TYPE=$(SIO_PMU_TYPE) \
	-DSIO_LOAD_CONFIG=$(SIO_LOAD_CONFIG) \
	-DSIO_STORE_CONFIG=$(SIO_STORE_CONFIG) \
	-I$(SIO_TARGET_DIR) \
	-I$(SIO_SCRIPT_DIR)

SIO_CFLAGS := \
	-O2 -g -std=c11 \
	-Wall -Wextra -Wpedantic \
	-fno-omit-frame-pointer \
	-fno-lto \
	-fno-stack-protector \
	-fno-tree-vectorize \
	-fno-ipa-icf \
	-ffunction-sections \
	-fdata-sections

SIO_LDFLAGS := -Wl,--gc-sections
SIO_BIN := $(SIO_BIN_DIR)/sio_single

.PHONY: secret-in-onepiece secret-in-onepiece-clean
secret-in-onepiece: $(SIO_BIN)

$(SIO_BIN): $(SIO_SRCS) $(SIO_SCRIPT_DIR)/microarch_events_generated.h
	mkdir -p $(dir $@)
	$(CC) $(SIO_CPPFLAGS) $(SIO_CFLAGS) \
		$(SIO_SRCS) $(SIO_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

secret-in-onepiece-clean:
	rm -rf $(SIO_BIN_DIR)
