#include <stdio.h>
#include <time.h>

void debug_enable();
void debug_disable();
int is_debug();

#define DEBUG_PRINT(...) if (is_debug()) { fprintf(stderr, "[%lu] ", time(NULL)); fprintf(stderr, "[DEBUG] "); fprintf((stderr), __VA_ARGS__); }
