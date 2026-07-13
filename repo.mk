# Global Makefile configuration for hpc-x86-defense.
# Keep only project-wide settings here.

REPO_ROOT ?= $(abspath .)
BUILD_DIR ?= $(REPO_ROOT)/build
RESULTS_DIR ?= $(REPO_ROOT)/results
THIRD_PARTY_DIR ?= $(REPO_ROOT)/third_party

CC ?= gcc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic -fno-omit-frame-pointer
CPPFLAGS ?= -D_GNU_SOURCE
LDFLAGS ?=
LDLIBS ?=
