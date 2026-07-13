REPO_ROOT := $(abspath .)
include $(REPO_ROOT)/repo.mk

SMOKE_SRC := $(REPO_ROOT)/targets/hpc_smoke/main.c
SMOKE_BIN := $(BUILD_DIR)/bin/hpc_smoke

.PHONY: all smoke clean print-config

all: smoke
smoke: $(SMOKE_BIN)

$(SMOKE_BIN): $(SMOKE_SRC)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

print-config:
	@echo "REPO_ROOT=$(REPO_ROOT)"
	@echo "BUILD_DIR=$(BUILD_DIR)"
	@echo "CC=$(CC)"
	@echo "CFLAGS=$(CFLAGS)"

clean:
	rm -rf $(BUILD_DIR)
