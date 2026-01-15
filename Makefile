CC   := gcc
SRC_DIR := src
OBJ_DIR := obj
TEST_DIR := tests

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BIN := bgpsee

FSANITIZE = -fsanitize=address,undefined
DEBUG_FLAGS := -g3 -fanalyzer $(FSANITISZE)
#DEBUG_FLAGS := -g0

CFLAGS += -Wall -Wshadow  -Wextra -fvisibility=hidden -Wvla -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion $(DEBUG_FLAGS)
LDFLAGS = -ljansson -pthread -static-libasan $(FSANITIZE)

# Test flags (less strict for test files)
TEST_CFLAGS := -Wall -g3 -Wno-unused-parameter $(FSANITIZE)
TEST_LDFLAGS := -ljansson -pthread $(FSANITIZE)

all: $(BIN)

.PHONY: all clean test test-byte-conv test-bgp-message

$(BIN): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(OBJ_DIR) $(BIN) $(TEST_DIR)/test_byte_conv $(TEST_DIR)/test_bgp_message

# Test targets
test: test-byte-conv test-bgp-message
	@echo "All tests completed"

test-byte-conv: $(TEST_DIR)/test_byte_conv
	@echo "Running byte conversion tests..."
	@./$(TEST_DIR)/test_byte_conv

test-bgp-message: $(OBJ) $(TEST_DIR)/test_bgp_message
	@echo "Running BGP message parsing tests..."
	@./$(TEST_DIR)/test_bgp_message

$(TEST_DIR)/test_byte_conv: $(TEST_DIR)/test_byte_conv.c $(TEST_DIR)/testhelp.h
	$(CC) $(TEST_CFLAGS) -o $@ $<

# Test needs: bgp_message.o, log.o, sds.o for dependencies
$(TEST_DIR)/test_bgp_message: $(TEST_DIR)/test_bgp_message.c $(TEST_DIR)/testhelp.h $(OBJ_DIR)/bgp_message.o $(OBJ_DIR)/log.o $(OBJ_DIR)/sds.o
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_DIR)/test_bgp_message.c $(OBJ_DIR)/bgp_message.o $(OBJ_DIR)/log.o $(OBJ_DIR)/sds.o $(TEST_LDFLAGS)


