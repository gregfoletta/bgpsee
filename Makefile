CC   := gcc
SRC_DIR := src
OBJ_DIR := obj

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BIN := bgpsee

FSANITIZE = -fsanitize=address,undefined 
DEBUG_FLAGS := -g3 -fanalyzer $(FSANITISZE)
#DEBUG_FLAGS := -g0 

CFLAGS += -Wall -Wshadow  -Wextra -fvisibility=hidden -Wvla -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion $(DEBUG_FLAGS)
LDFLAGS = -ljansson -pthread -static-libasan $(FSANITIZE)

all: $(BIN)

.PHONY: all clean

$(BIN): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ -o $@  

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(OBJ_DIR) $(BIN)


