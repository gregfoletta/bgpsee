CC   := gcc
SRC_DIR := src
OBJ_DIR := obj

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BIN := bgpsee

CFLAGS += -g3 -Wall -Wshadow -fanalyzer -Wextra -fvisibility=hidden -Wvla -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion $(FSANITIZE)

FSANITIZE = -fsanitize=address,undefined 
LDFLAGS = -lm -ljansson -pthread $(FSANITIZE)

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


