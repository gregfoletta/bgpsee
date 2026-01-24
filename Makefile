# Allow CC override from command line or environment; default to gcc
ifeq ($(origin CC),default)
CC := gcc
endif

SRC_DIR := src
OBJ_DIR := obj
OBJ_DEBUG_DIR := obj-debug
TEST_DIR := tests

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJ_DEBUG := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DEBUG_DIR)/%.o)

BIN := bgpsee

# Warning flags (shared between release and debug)
WARN_FLAGS := -Wall -Wshadow -Wextra -fvisibility=hidden -Wvla -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion

# GCC-only flags (not supported by clang)
IS_GCC := $(shell $(CC) -v 2>&1 | grep -q "gcc version" && echo 1)
ifeq ($(IS_GCC),1)
  GCC_ANALYZER := -fanalyzer
  GCC_STATIC_ASAN := -static-libasan
endif

# macOS: add Homebrew include/lib paths
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null)
  ifneq ($(HOMEBREW_PREFIX),)
    BREW_CFLAGS := -I$(HOMEBREW_PREFIX)/include
    BREW_LDFLAGS := -L$(HOMEBREW_PREFIX)/lib
  endif
endif

# Release build flags
CFLAGS := $(WARN_FLAGS) $(BREW_CFLAGS) -O2
LDFLAGS := -ljansson -pthread $(BREW_LDFLAGS)

# Debug build flags
DEBUG_CFLAGS := $(WARN_FLAGS) $(BREW_CFLAGS) -g3 $(GCC_ANALYZER) -fsanitize=address,undefined
DEBUG_LDFLAGS := -ljansson -pthread $(BREW_LDFLAGS) $(GCC_STATIC_ASAN) -fsanitize=address,undefined

# Test flags
TEST_CFLAGS := -Wall -g3 -Wno-unused-parameter $(BREW_CFLAGS) -fsanitize=address,undefined
TEST_LDFLAGS := -ljansson -pthread $(BREW_LDFLAGS) -fsanitize=address,undefined

.PHONY: all debug clean test test-byte-conv test-bgp-message

# Default target: optimized release build
all: $(BIN)

# Debug target: build with debug flags
debug: $(BIN)-debug

$(BIN): $(OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

$(BIN)-debug: $(OBJ_DEBUG)
	$(CC) $^ $(DEBUG_LDFLAGS) -o $(BIN)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DEBUG_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DEBUG_DIR)
	$(CC) $(DEBUG_CFLAGS) -c $< -o $@

$(OBJ_DIR) $(OBJ_DEBUG_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(OBJ_DIR) $(OBJ_DEBUG_DIR) $(BIN) $(TEST_DIR)/test_byte_conv $(TEST_DIR)/test_bgp_message

# Test targets (use debug flags for better error detection)
test: test-byte-conv test-bgp-message
	@echo "All tests completed"

test-byte-conv: $(TEST_DIR)/test_byte_conv
	@echo "Running byte conversion tests..."
	@./$(TEST_DIR)/test_byte_conv

test-bgp-message: $(OBJ_DEBUG) $(TEST_DIR)/test_bgp_message
	@echo "Running BGP message parsing tests..."
	@./$(TEST_DIR)/test_bgp_message

$(TEST_DIR)/test_byte_conv: $(TEST_DIR)/test_byte_conv.c $(TEST_DIR)/testhelp.h
	$(CC) $(TEST_CFLAGS) -o $@ $<

$(TEST_DIR)/test_bgp_message: $(TEST_DIR)/test_bgp_message.c $(TEST_DIR)/testhelp.h $(OBJ_DEBUG_DIR)/bgp_message.o $(OBJ_DEBUG_DIR)/bgp_capability.o $(OBJ_DEBUG_DIR)/log.o $(OBJ_DEBUG_DIR)/sds.o | $(OBJ_DEBUG_DIR)
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_DIR)/test_bgp_message.c $(OBJ_DEBUG_DIR)/bgp_message.o $(OBJ_DEBUG_DIR)/bgp_capability.o $(OBJ_DEBUG_DIR)/log.o $(OBJ_DEBUG_DIR)/sds.o $(TEST_LDFLAGS)
